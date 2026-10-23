#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "robot_ota/config.h"
#include "robot_ota/crypto.h"
#include "robot_ota/http_server.h"
#include "robot_ota/ota_service.h"
#include "robot_ota/util.h"

namespace {

constexpr const char* kVersion = "1.0.0";
constexpr const char* kDefaultConfig = "./config/server.json";

void print_usage(std::ostream& out) {
  out << "Usage: robot-ota-server [options]\n"
         "\n"
         "Options:\n"
         "  --config PATH     Configuration file (default: " << kDefaultConfig
      << ")\n"
         "  --check-config    Validate the configuration and exit\n"
         "  --export-device-pubkey PATH\n"
         "                    Export the RSA public key (SPKI PEM) used for\n"
         "                    DEK wrapping, then exit\n"
         "  --verbose         Enable debug logging\n"
         "  --version         Print the version and exit\n"
         "  --help            Print this help and exit\n";
}

bool arg_value(const std::string& arg, const std::string& name,
               std::string* value) {
  const std::string prefix = name + "=";
  if (arg.compare(0, prefix.size(), prefix) == 0) {
    *value = arg.substr(prefix.size());
    return true;
  }
  return false;
}

int export_device_public_key(const robot_ota::AppConfig& config,
                             const std::string& path) {
  try {
    std::unique_ptr<robot_ota::IDeviceKey> device_key;
    if (config.crypto.key_provider == "software") {
      device_key = robot_ota::make_software_device_key(
          config.crypto.device_private_key_file);
    } else {
      robot_ota::SeOptions options;
      options.lib_path = config.se.lib_path;
      options.key_index = config.se.key_index;
      options.export_platform_ca = false;
      std::vector<robot_ota::Bytes> unused_certs;
      device_key = robot_ota::make_se_device_key(options, &unused_certs);
    }
    const std::string pem = robot_ota::rsa_public_key_pem(
        device_key->modulus(), device_key->exponent());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
      std::cerr << "cannot open " << path << " for writing\n";
      return 1;
    }
    out << pem;
    if (!out) {
      std::cerr << "failed to write " << path << "\n";
      return 1;
    }
    std::cout << "device public key: " << path << "\n"
              << "recipient_spki_sha256=" << device_key->spki_sha256() << "\n"
              << "rsa_bits=" << (device_key->modulus_bytes() * 8) << "\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "failed to export the device public key: " << e.what() << "\n";
    return 1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path = kDefaultConfig;
  std::string export_pubkey_path;
  bool check_only = false;
  bool verbose = false;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    std::string value;
    if (arg == "--help" || arg == "-h") {
      print_usage(std::cout);
      return 0;
    }
    if (arg == "--version") {
      std::cout << "robot-ota-server " << kVersion << "\n";
      return 0;
    }
    if (arg == "--check-config") {
      check_only = true;
      continue;
    }
    if (arg == "--verbose" || arg == "-v") {
      verbose = true;
      continue;
    }
    if (arg == "--config") {
      if (i + 1 >= argc) {
        std::cerr << "--config requires a path\n";
        return 2;
      }
      config_path = argv[++i];
      continue;
    }
    if (arg_value(arg, "--config", &value)) {
      if (value.empty()) {
        std::cerr << "--config requires a non-empty path\n";
        return 2;
      }
      config_path = value;
      continue;
    }
    if (arg == "--export-device-pubkey") {
      if (i + 1 >= argc) {
        std::cerr << "--export-device-pubkey requires a path\n";
        return 2;
      }
      export_pubkey_path = argv[++i];
      continue;
    }
    if (arg_value(arg, "--export-device-pubkey", &value)) {
      if (value.empty()) {
        std::cerr << "--export-device-pubkey requires a non-empty path\n";
        return 2;
      }
      export_pubkey_path = value;
      continue;
    }
    std::cerr << "unknown argument: " << arg << "\n";
    print_usage(std::cerr);
    return 2;
  }

  robot_ota::set_log_verbose(verbose);

  robot_ota::AppConfig config;
  try {
    config = robot_ota::load_config(config_path);
  } catch (const std::exception& e) {
    std::cerr << "configuration error: " << e.what() << "\n";
    return 1;
  }

  if (check_only) {
    std::cout << "configuration OK: " << config_path << "\n"
              << "  data_dir: " << config.data_dir << "\n"
              << "  listen: " << config.http.bind_address << ":"
              << config.http.port << "\n"
              << "  key_provider: " << config.crypto.key_provider << "\n"
              << "  install.engine: " << config.install.engine << "\n";
    return 0;
  }

  if (!export_pubkey_path.empty()) {
    return export_device_public_key(config, export_pubkey_path);
  }

  robot_ota::configure_logging(config.log.dir);

  // Block the shutdown signals before any thread is created so every thread
  // inherits the mask. The main thread receives them synchronously with
  // sigwait().
  sigset_t signals;
  sigemptyset(&signals);
  sigaddset(&signals, SIGINT);
  sigaddset(&signals, SIGTERM);
  if (sigprocmask(SIG_BLOCK, &signals, nullptr) != 0) {
    std::cerr << "failed to block signals: " << std::strerror(errno) << "\n";
    return 1;
  }
  std::signal(SIGPIPE, SIG_IGN);

  try {
    robot_ota::OtaService service(config);
    robot_ota::HttpServer server(service, config);
    service.start();
    server.start();

    int received = 0;
    while (sigwait(&signals, &received) != 0) {
    }
    robot_ota::log_info("received signal " + std::to_string(received) +
                        ", shutting down");

    // Stop accepting requests first, then stop the background workers. Pending
    // session state is already durable, so a restart resumes safely.
    server.stop();
    service.stop();
  } catch (const std::exception& e) {
    robot_ota::log_error(std::string("fatal: ") + e.what());
    return 1;
  }
  return 0;
}
