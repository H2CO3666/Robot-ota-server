#pragma once

#include <cstdint>
#include <string>

namespace robot_ota {

struct DeviceConfig {
  std::string robot_sn;
  std::string product_id;
  std::string hw_revision;
  std::string firmware_version;
  uint64_t security_version = 0;
  uint64_t max_plaintext_bytes = 4ULL * 1024 * 1024 * 1024;
  uint32_t max_chunk_bytes = 4U * 1024 * 1024;
};

struct CryptoConfig {
  // "software": load a PEM private key (development / integration tests).
  // "se": use the platform SE SDK through dlopen/dlsym (production).
  std::string key_provider = "software";
  std::string device_private_key_file;
  std::string plat_ca_file;
  // RSA_PKCS1_SHA256 or RSA_PSS_SHA256. Must match the cloud KMS setup.
  std::string signature_scheme = "RSA_PKCS1_SHA256";
  // Domain separation prefix for the signature input:
  //   prefix_bytes || 0x00 || JCS(manifest)
  // Must match the cloud signer byte-for-byte.
  std::string sign_domain_prefix = "ROBOT_OFFLINE_OTA_MANIFEST_V1";
  bool check_cert_validity = true;
};

struct SeConfig {
  std::string lib_path = "/unitree/lib/libsesdk.so";
  int key_index = 1;  // RSA_KEY_INDEX in se_sdk.h
  bool export_platform_ca = true;
};

struct HttpConfig {
  std::string bind_address = "0.0.0.0";
  uint16_t port = 8080;
  uint32_t threads = 4;
  uint64_t max_body_bytes = 8ULL * 1024 * 1024;
  uint32_t idle_timeout_seconds = 60;
  uint32_t max_queued_connections = 32;
  uint32_t max_header_bytes = 64U * 1024;
};

struct SessionConfig {
  // 0 disables expiration. Only RECEIVING sessions expire.
  uint32_t receiving_ttl_hours = 0;
};

struct InstallConfig {
  // The current build intentionally does not execute installs. The value must
  // be "disabled"; IOtaEngine is the seam for a later integration.
  std::string engine = "disabled";
};

struct LogConfig {
  // Where the server writes its runtime log (server.log) and upgrade records
  // (ota.log). Empty disables file logging (stderr only).
  std::string dir = "/unitree/var/log/robot_offline_server";
};

struct AppConfig {
  std::string config_dir;
  std::string data_dir = "./data";

  DeviceConfig device;
  CryptoConfig crypto;
  SeConfig se;
  HttpConfig http;
  SessionConfig session;
  InstallConfig install;
  LogConfig log;
};

// Throws std::runtime_error with a human readable message on invalid input.
AppConfig load_config(const std::string& path);

}  // namespace robot_ota
