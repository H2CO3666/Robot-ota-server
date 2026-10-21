#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include "robot_ota/config.h"
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

}  // namespace

int main(int argc, char** argv) {
  std::string config_path = kDefaultConfig;
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
