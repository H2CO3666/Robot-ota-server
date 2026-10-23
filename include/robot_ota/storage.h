#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <json/json.h>

#include "robot_ota/manifest.h"
#include "robot_ota/util.h"

namespace robot_ota {

enum class SessionState {
  Receiving,
  Verifying,
  Ready,
  Installing,
  Success,
  Failed,
  Expired,
  RecoveryRequired,
};

const char* session_state_name(SessionState state);
bool parse_session_state(const std::string& text, SessionState* state);
bool is_terminal_state(SessionState state);
bool is_active_state(SessionState state);

struct SessionRecord {
  std::string session_id;
  std::string package_id;
  std::string manifest_hash;
  Manifest manifest;
  std::string signature_b64;
  std::string signer_cert_b64;
  SessionState state = SessionState::Receiving;
  uint64_t offset = 0;
  uint64_t total = 0;
  Json::Value result = Json::Value(Json::nullValue);
  std::string created_at;
  int64_t created_at_uptime = 0;  // cumulative powered-on seconds at creation
  int64_t ready_at_uptime = 0;    // cumulative powered-on seconds at READY
  std::string updated_at;
  std::string install_id;
};

// Durable session storage:
//   <data_dir>/sessions/<session_id>/meta.json
//   <data_dir>/sessions/<session_id>/payload.enc
//   <data_dir>/sessions/<session_id>/firmware.bin   (after verification)
//   <data_dir>/quarantine/...
//   <data_dir>/lock
class SessionStore {
 public:
  explicit SessionStore(std::string data_dir);
  ~SessionStore();
  SessionStore(const SessionStore&) = delete;
  SessionStore& operator=(const SessionStore&) = delete;

  // Creates directories and takes an exclusive lock on the data directory.
  void init();

  // Loads every valid session. Meta files that fail validation are moved to
  // quarantine and skipped.
  std::vector<SessionRecord> load_all(const ManifestLimits& limits);

  void create(const SessionRecord& record);
  void save(const SessionRecord& record);

  // Writes at the exact durable offset and fsyncs before returning. The caller
  // must not ACK the chunk before this returns.
  void append_payload(const std::string& session_id, uint64_t offset,
                      const uint8_t* data, size_t size);
  void truncate_payload(const std::string& session_id, uint64_t size);
  uint64_t payload_size(const std::string& session_id) const;
  bool payload_exists(const std::string& session_id) const;

  void remove_firmware(const std::string& session_id);
  void remove_payload(const std::string& session_id);

  std::string session_dir(const std::string& session_id) const;
  std::string payload_path(const std::string& session_id) const;
  std::string firmware_path(const std::string& session_id) const;
  std::string data_dir() const { return data_dir_; }

  std::string quarantine(const std::string& session_id);

  static bool valid_session_id(const std::string& session_id);

 private:
  std::string data_dir_;
  std::string sessions_dir_;
  std::string quarantine_dir_;
  int lock_fd_ = -1;
};

}  // namespace robot_ota
