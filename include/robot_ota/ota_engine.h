#pragma once

#include <memory>
#include <string>

#include "robot_ota/config.h"

namespace robot_ota {

enum class InstallStartResult {
  Accepted,
  Rejected,
  Unsupported,
  Unknown,
};

struct InstallRequest {
  std::string session_id;
  std::string install_id;
  std::string package_id;
  std::string firmware_path;
  uint64_t firmware_size = 0;
  std::string firmware_version;
  std::string plaintext_sha256;
  uint64_t security_version = 0;
};

struct InstallStatus {
  enum class State {
    Installing,
    Success,
    Failed,
    Unknown,
  };
  State state = State::Unknown;
  std::string running_version;
  std::string error_code;
  std::string message;
};

// Seam for integrating the existing OTA installation engine. This build ships
// a disabled implementation only: POST /install returns 501 and the session
// stays READY. A production adapter must:
//   - persist/recover its own install status keyed by install_id,
//   - never start a second install for the same install_id,
//   - report Unknown when it cannot prove whether an install was accepted.
class IOtaEngine {
 public:
  virtual ~IOtaEngine() = default;
  virtual bool enabled() const = 0;
  virtual InstallStartResult start(const InstallRequest& request) = 0;
  virtual InstallStatus query(const InstallRequest& request) = 0;
};

std::unique_ptr<IOtaEngine> make_ota_engine(const InstallConfig& config);

}  // namespace robot_ota
