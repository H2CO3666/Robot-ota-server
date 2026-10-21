#include "robot_ota/config.h"

#include <sys/stat.h>

#include <json/json.h>

#include <cctype>
#include <climits>
#include <memory>
#include <set>
#include <stdexcept>

#include "robot_ota/util.h"

namespace robot_ota {
namespace {

constexpr size_t kConfigFileLimit = 1024 * 1024;

// Platform identity files present on production robots. When a file exists it
// overrides the corresponding device.* config value; the config value remains
// the fallback for development and integration tests.
constexpr const char* kRobotSnPath = "/unitree/robot/basic/code";
constexpr const char* kProductModelPath =
    "/unitree/module/network_manager/upper_bluetooth/model";
constexpr const char* kVersionJsonPath =
    "/unitree/robot/pkg/version/version.json";

bool has_control_chars(const std::string& value) {
  for (unsigned char c : value) {
    if (c < 0x20 || c == 0x7f) {
      return true;
    }
  }
  return false;
}

std::string get_string(const Json::Value& object, const char* key,
                       const std::string& fallback, bool required = false) {
  if (!object.isMember(key)) {
    if (required) {
      throw std::runtime_error(std::string("missing required config key: ") + key);
    }
    return fallback;
  }
  const Json::Value& value = object[key];
  if (!value.isString()) {
    throw std::runtime_error(std::string("config key must be a string: ") + key);
  }
  return value.asString();
}

uint64_t get_u64(const Json::Value& object, const char* key, uint64_t fallback,
                 bool required = false) {
  if (!object.isMember(key)) {
    if (required) {
      throw std::runtime_error(std::string("missing required config key: ") + key);
    }
    return fallback;
  }
  const Json::Value& value = object[key];
  if (value.type() == Json::intValue) {
    const Json::Int64 v = value.asInt64();
    if (v < 0) {
      throw std::runtime_error(std::string("config key must be >= 0: ") + key);
    }
    return static_cast<uint64_t>(v);
  }
  if (value.type() == Json::uintValue) {
    return value.asUInt64();
  }
  throw std::runtime_error(std::string("config key must be an integer: ") + key);
}

bool get_bool(const Json::Value& object, const char* key, bool fallback) {
  if (!object.isMember(key)) {
    return fallback;
  }
  const Json::Value& value = object[key];
  if (!value.isBool()) {
    throw std::runtime_error(std::string("config key must be a boolean: ") + key);
  }
  return value.asBool();
}

const Json::Value& get_object(const Json::Value& object, const char* key,
                              bool required = false) {
  static const Json::Value kNull;
  if (!object.isMember(key)) {
    if (required) {
      throw std::runtime_error(std::string("missing required config section: ") + key);
    }
    return kNull;
  }
  if (!object[key].isObject()) {
    throw std::runtime_error(std::string("config section must be an object: ") + key);
  }
  return object[key];
}

std::string resolve_path(const std::string& config_dir, const std::string& path) {
  if (path.empty()) {
    return path;
  }
  if (path[0] == '/') {
    return path;
  }
  return join_path(config_dir, path);
}

void require_existing_file(const std::string& path, const char* what) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
    throw std::runtime_error(std::string(what) + " does not exist or is not a file: " +
                             path);
  }
}

bool regular_file_exists(const std::string& path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string trim_ascii_whitespace(std::string value) {
  size_t begin = 0;
  size_t end = value.size();
  while (begin < end) {
    const unsigned char c = static_cast<unsigned char>(value[begin]);
    if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
      break;
    }
    ++begin;
  }
  while (end > begin) {
    const unsigned char c = static_cast<unsigned char>(value[end - 1]);
    if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
      break;
    }
    --end;
  }
  return value.substr(begin, end - begin);
}

// Production robots carry their identity in well-known platform files. Override
// the config fallbacks with those files when they are present, so a single
// generic config can run unchanged across units.
void apply_platform_identity(AppConfig& cfg) {
  // robot_sn is a plain text serial number.
  if (regular_file_exists(kRobotSnPath)) {
    const std::string sn =
        trim_ascii_whitespace(read_text_file_limited(kRobotSnPath, 256));
    if (!sn.empty()) {
      cfg.device.robot_sn = sn;
      log_info("robot_sn overridden from " + std::string(kRobotSnPath));
    }
  }

  // product_id is the Bluetooth model name with its trailing '_' stripped.
  if (regular_file_exists(kProductModelPath)) {
    std::string model = trim_ascii_whitespace(
        read_text_file_limited(kProductModelPath, 256));
    if (!model.empty() && model.back() == '_') {
      model.pop_back();
    }
    if (!model.empty()) {
      cfg.device.product_id = model;
      log_info("product_id overridden from " + std::string(kProductModelPath));
    }
  }

  // firmware_version is the "Package" field of the platform version manifest.
  if (regular_file_exists(kVersionJsonPath)) {
    const std::string text = read_text_file_limited(kVersionJsonPath, 64 * 1024);
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value root;
    std::string errors;
    if (reader->parse(text.data(), text.data() + text.size(), &root, &errors) &&
        root.isObject() && root.isMember("Package") &&
        root["Package"].isString()) {
      const std::string package =
          trim_ascii_whitespace(root["Package"].asString());
      if (!package.empty()) {
        cfg.device.firmware_version = package;
        log_info("firmware_version overridden from " +
                 std::string(kVersionJsonPath));
      }
    }
  }
}

bool valid_robot_sn(const std::string& sn) {
  if (sn.empty() || sn.size() > 64) {
    return false;
  }
  for (size_t i = 0; i < sn.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(sn[i]);
    const bool alpha_num = std::isalnum(c) != 0;
    if (!alpha_num && c != '_' && c != '-' && c != '.' && c != ':') {
      return false;
    }
    if (i == 0 && !alpha_num) {
      return false;
    }
  }
  return true;
}

void validate_config(AppConfig& cfg) {
  if (!valid_robot_sn(cfg.device.robot_sn)) {
    throw std::runtime_error("device.robot_sn is empty or has an invalid format");
  }
  if (cfg.device.product_id.empty() || cfg.device.product_id.size() > 128 ||
      has_control_chars(cfg.device.product_id)) {
    throw std::runtime_error("device.product_id is invalid");
  }
  if (cfg.device.hw_revision.empty() || cfg.device.hw_revision.size() > 128 ||
      has_control_chars(cfg.device.hw_revision)) {
    throw std::runtime_error("device.hw_revision is invalid");
  }
  if (cfg.device.firmware_version.empty() || cfg.device.firmware_version.size() > 128 ||
      has_control_chars(cfg.device.firmware_version)) {
    throw std::runtime_error("device.firmware_version is invalid");
  }
  if (cfg.device.max_plaintext_bytes == 0 ||
      cfg.device.max_plaintext_bytes > 16ULL * 1024 * 1024 * 1024) {
    throw std::runtime_error("device.max_plaintext_bytes must be in [1, 16GiB]");
  }
  if (cfg.device.max_chunk_bytes < 1024 ||
      cfg.device.max_chunk_bytes > 64U * 1024 * 1024) {
    throw std::runtime_error("device.max_chunk_bytes must be in [1024, 64MiB]");
  }

  if (cfg.crypto.key_provider != "software" && cfg.crypto.key_provider != "se") {
    throw std::runtime_error("crypto.key_provider must be 'software' or 'se'");
  }
  if (cfg.crypto.signature_scheme != "RSA_PKCS1_SHA256" &&
      cfg.crypto.signature_scheme != "RSA_PSS_SHA256") {
    throw std::runtime_error(
        "crypto.signature_scheme must be RSA_PKCS1_SHA256 or RSA_PSS_SHA256");
  }
  if (cfg.crypto.sign_domain_prefix.empty() ||
      cfg.crypto.sign_domain_prefix.size() > 128 ||
      has_control_chars(cfg.crypto.sign_domain_prefix)) {
    throw std::runtime_error("crypto.sign_domain_prefix is invalid");
  }
  if (cfg.crypto.key_provider == "software") {
    if (cfg.crypto.device_private_key_file.empty()) {
      throw std::runtime_error(
          "crypto.device_private_key_file is required for key_provider=software");
    }
    require_existing_file(cfg.crypto.device_private_key_file, "device private key");
  } else {
    if (cfg.se.lib_path.empty()) {
      throw std::runtime_error("se.lib_path is required for key_provider=se");
    }
    if (cfg.se.key_index < 0) {
      throw std::runtime_error("se.key_index must be >= 0");
    }
  }
  if (!cfg.crypto.plat_ca_file.empty()) {
    require_existing_file(cfg.crypto.plat_ca_file, "platform CA file");
  } else if (!(cfg.crypto.key_provider == "se" && cfg.se.export_platform_ca)) {
    throw std::runtime_error(
        "crypto.plat_ca_file is required unless key_provider=se and "
        "se.export_platform_ca=true");
  }

  if (cfg.http.bind_address.empty()) {
    throw std::runtime_error("bind address is empty");
  }
  if (cfg.http.port == 0) {
    throw std::runtime_error("port must be in [1, 65535]");
  }
  if (cfg.http.threads == 0 || cfg.http.threads > 64) {
    throw std::runtime_error("http.threads must be in [1, 64]");
  }
  if (cfg.http.idle_timeout_seconds == 0 || cfg.http.idle_timeout_seconds > 3600) {
    throw std::runtime_error("http.idle_timeout_seconds must be in [1, 3600]");
  }
  if (cfg.http.max_queued_connections == 0 ||
      cfg.http.max_queued_connections > 4096) {
    throw std::runtime_error("http.max_queued_connections must be in [1, 4096]");
  }
  const uint64_t min_body =
      static_cast<uint64_t>(cfg.device.max_chunk_bytes) + 65536ULL;
  if (cfg.http.max_body_bytes < min_body) {
    throw std::runtime_error(
        "http.max_body_bytes must be at least device.max_chunk_bytes + 65536");
  }
  if (cfg.http.max_header_bytes < 1024 || cfg.http.max_header_bytes > 1024U * 1024) {
    throw std::runtime_error("http.max_header_bytes must be in [1024, 1MiB]");
  }

  if (cfg.session.receiving_ttl_hours > 24U * 365U) {
    throw std::runtime_error("session.receiving_ttl_hours is too large");
  }
  if (cfg.install.engine != "disabled") {
    throw std::runtime_error(
        "install.engine: this build only supports 'disabled' (install execution is "
        "not implemented yet)");
  }
}

}  // namespace

AppConfig load_config(const std::string& path) {
  const std::string absolute = absolute_path(path);
  AppConfig cfg;
  cfg.config_dir = dir_name(absolute);

  const std::string text = read_text_file_limited(absolute, kConfigFileLimit);

  Json::CharReaderBuilder builder;
  builder["collectComments"] = false;
  builder["allowComments"] = true;
  builder["strictMode"] = true;
  builder["rejectDupKeys"] = true;
  builder["stackLimit"] = 32;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value root;
  std::string errors;
  if (!reader->parse(text.data(), text.data() + text.size(), &root, &errors)) {
    throw std::runtime_error("failed to parse config JSON: " + errors);
  }
  if (!root.isObject()) {
    throw std::runtime_error("config root must be an object");
  }

  cfg.data_dir = resolve_path(cfg.config_dir,
                              get_string(root, "data_dir", "./data"));

  const Json::Value& device = get_object(root, "device", true);
  cfg.device.robot_sn = get_string(device, "robot_sn", "", true);
  cfg.device.product_id = get_string(device, "product_id", "", true);
  cfg.device.hw_revision = get_string(device, "hw_revision", "", true);
  cfg.device.firmware_version = get_string(device, "firmware_version", "", true);
  cfg.device.security_version = get_u64(device, "security_version", 0);
  cfg.device.max_plaintext_bytes =
      get_u64(device, "max_plaintext_bytes", cfg.device.max_plaintext_bytes);
  const uint64_t max_chunk = get_u64(device, "max_chunk_bytes", cfg.device.max_chunk_bytes);
  if (max_chunk > 0xFFFFFFFFULL) {
    throw std::runtime_error("device.max_chunk_bytes is too large");
  }
  cfg.device.max_chunk_bytes = static_cast<uint32_t>(max_chunk);

  const Json::Value& crypto = get_object(root, "crypto", true);
  cfg.crypto.key_provider = get_string(crypto, "key_provider", "software");
  cfg.crypto.device_private_key_file = resolve_path(
      cfg.config_dir, get_string(crypto, "device_private_key_file", ""));
  cfg.crypto.plat_ca_file =
      resolve_path(cfg.config_dir, get_string(crypto, "plat_ca_file", ""));
  cfg.crypto.signature_scheme =
      get_string(crypto, "signature_scheme", "RSA_PKCS1_SHA256");
  cfg.crypto.sign_domain_prefix = get_string(
      crypto, "sign_domain_prefix", "ROBOT_OFFLINE_OTA_MANIFEST_V1");
  cfg.crypto.check_cert_validity = get_bool(crypto, "check_cert_validity", true);

  const Json::Value& se = get_object(root, "se");
  if (!se.isNull()) {
    cfg.se.lib_path = get_string(se, "lib_path", cfg.se.lib_path);
  const uint64_t key_index = get_u64(
      se, "key_index", static_cast<uint64_t>(cfg.se.key_index));
  if (key_index > static_cast<uint64_t>(INT_MAX)) {
    throw std::runtime_error("se.key_index is too large");
  }
  cfg.se.key_index = static_cast<int>(key_index);
    cfg.se.export_platform_ca =
        get_bool(se, "export_platform_ca", cfg.se.export_platform_ca);
  }

  const Json::Value& http = get_object(root, "http");
  if (!http.isNull()) {
    cfg.http.bind_address = get_string(http, "bind", cfg.http.bind_address);
    const uint64_t port = get_u64(http, "port", cfg.http.port);
    if (port > 65535) {
      throw std::runtime_error("port must be in [1, 65535]");
    }
    cfg.http.port = static_cast<uint16_t>(port);
    const uint64_t threads = get_u64(http, "threads", cfg.http.threads);
    if (threads > 64) {
      throw std::runtime_error("http.threads must be in [1, 64]");
    }
    cfg.http.threads = static_cast<uint32_t>(threads);
    cfg.http.max_body_bytes =
        get_u64(http, "max_body_bytes", cfg.http.max_body_bytes);
    const uint64_t idle = get_u64(http, "idle_timeout_seconds",
                                  cfg.http.idle_timeout_seconds);
    if (idle > 3600) {
      throw std::runtime_error("http.idle_timeout_seconds must be in [1, 3600]");
    }
    cfg.http.idle_timeout_seconds = static_cast<uint32_t>(idle);
    const uint64_t max_queued = get_u64(http, "max_queued_connections",
                                        cfg.http.max_queued_connections);
    if (max_queued > 4096) {
      throw std::runtime_error(
          "http.max_queued_connections must be in [1, 4096]");
    }
    cfg.http.max_queued_connections = static_cast<uint32_t>(max_queued);
    const uint64_t max_header =
        get_u64(http, "max_header_bytes", cfg.http.max_header_bytes);
    if (max_header > 1024ULL * 1024ULL) {
      throw std::runtime_error("http.max_header_bytes must be in [1024, 1MiB]");
    }
    cfg.http.max_header_bytes = static_cast<uint32_t>(max_header);
  }

  const Json::Value& session = get_object(root, "session");
  if (!session.isNull()) {
    const uint64_t ttl = get_u64(session, "receiving_ttl_hours",
                                 cfg.session.receiving_ttl_hours);
    if (ttl > 24ULL * 365ULL) {
      throw std::runtime_error("session.receiving_ttl_hours is too large");
    }
    cfg.session.receiving_ttl_hours = static_cast<uint32_t>(ttl);
  }

  const Json::Value& install = get_object(root, "install");
  if (!install.isNull()) {
    cfg.install.engine = get_string(install, "engine", cfg.install.engine);
  }

  const Json::Value& log = get_object(root, "log");
  if (!log.isNull()) {
    cfg.log.dir = resolve_path(cfg.config_dir, get_string(log, "dir", cfg.log.dir));
  }

  apply_platform_identity(cfg);
  validate_config(cfg);
  return cfg;
}

}  // namespace robot_ota
