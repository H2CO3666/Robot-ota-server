#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <json/json.h>

#include "robot_ota/config.h"
#include "robot_ota/crypto.h"
#include "robot_ota/ota_engine.h"
#include "robot_ota/storage.h"

namespace robot_ota {

class OtaService {
 public:
  explicit OtaService(AppConfig config);
  ~OtaService();
  OtaService(const OtaService&) = delete;
  OtaService& operator=(const OtaService&) = delete;

  // Starts the verification worker and the housekeeping thread. Any session
  // found in VERIFYING during startup is already queued.
  void start();
  void stop();

  Json::Value device_info() const;

  struct CreateResult {
    bool created = false;
    Json::Value body;
  };
  CreateResult create_or_resume_session(const Json::Value& bundle);

  Json::Value get_session(const std::string& session_id);

  // Returns the new durable offset. Only call the HTTP layer after this
  // returns, because this method fsyncs before returning.
  uint64_t patch_payload(const std::string& session_id, uint64_t offset,
                         const uint8_t* data, size_t size);

  struct InstallResult {
    int http_status = 200;
    Json::Value body;
  };
  InstallResult install(const std::string& session_id,
                        const Json::Value& bundle);

  uint64_t min_security_version() const;

 private:
  struct VerifiedBundle {
    Manifest manifest;
    std::string signature_b64;
    std::string signer_cert_b64;
  };

  VerifiedBundle verify_bundle(const Json::Value& bundle);
  void verify_device_binding(const Manifest& manifest);

  void load_or_init_min_security_version();
  void persist_min_security_version(uint64_t value);
  void recover_sessions();

  std::shared_ptr<SessionRecord> find_session_locked(
      const std::string& session_id) const;
  bool has_active_session_locked() const;
  Json::Value session_json(const SessionRecord& record) const;
  static Json::Value result_object(const std::string& code,
                                   const std::string& message);

  void enqueue_verification(const std::string& session_id);
  void verification_worker();
  void verify_session(const std::string& session_id);
  void mark_verification_failed(const std::string& session_id,
                                const std::string& message);

  void housekeeping_worker();
  void expire_sessions();
  void refresh_install_state(const std::string& session_id);
  void remove_package_artifacts(const std::string& session_id);

  // Cumulative powered-on time (survives reboots) used by the TTLs.
  void load_uptime_base();
  int64_t cumulative_uptime_seconds();
  void persist_uptime_base_if_due();

  AppConfig config_;
  std::unique_ptr<SessionStore> store_;
  std::unique_ptr<IDeviceKey> device_key_;
  std::unique_ptr<CertVerifier> cert_verifier_;
  std::unique_ptr<IOtaEngine> engine_;

  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::shared_ptr<SessionRecord>> sessions_;
  std::unordered_map<std::string, std::string> package_index_;
  uint64_t min_security_version_ = 0;

  // Cumulative powered-on time (seconds) that keeps counting across reboots.
  mutable std::mutex uptime_mutex_;
  int64_t uptime_base_ = 0;
  std::chrono::steady_clock::time_point uptime_monotonic_base_;
  int64_t uptime_last_persisted_ = 0;

  std::thread verify_thread_;
  std::mutex verify_mutex_;
  std::condition_variable verify_cv_;
  std::deque<std::string> verify_queue_;

  std::thread housekeeping_thread_;
  std::mutex housekeeping_mutex_;
  std::condition_variable housekeeping_cv_;

  std::atomic<bool> stopping_{false};
  bool started_ = false;
};

}  // namespace robot_ota
