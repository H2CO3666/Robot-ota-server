#include "robot_ota/ota_service.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <utility>
#include <vector>

#include "robot_ota/errors.h"
#include "robot_ota/util.h"

namespace robot_ota {
namespace {

std::string trim_ascii_whitespace(const std::string& text) {
  size_t begin = 0;
  while (begin < text.size() &&
         (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r' ||
          text[begin] == '\n')) {
    ++begin;
  }
  size_t end = text.size();
  while (end > begin &&
         (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r' ||
          text[end - 1] == '\n')) {
    --end;
  }
  return text.substr(begin, end - begin);
}

std::string truncate_message(const std::string& message, size_t limit) {
  if (message.size() <= limit) {
    return message;
  }
  return message.substr(0, limit) + "...";
}

}  // namespace

OtaService::OtaService(AppConfig config)
    : config_(std::move(config)),
      store_(std::make_unique<SessionStore>(config_.data_dir)) {
  store_->init();
  load_or_init_min_security_version();

  if (config_.crypto.key_provider == "software") {
    device_key_ =
        make_software_device_key(config_.crypto.device_private_key_file);
    cert_verifier_ = std::make_unique<CertVerifier>(
        config_.crypto.plat_ca_file, std::vector<Bytes>{},
        config_.crypto.check_cert_validity);
    log_warn("running with a software device key; use key_provider=se in production");
  } else {
    SeOptions options;
    options.lib_path = config_.se.lib_path;
    options.key_index = config_.se.key_index;
    options.export_platform_ca = config_.se.export_platform_ca;
    std::vector<Bytes> se_certs;
    device_key_ = make_se_device_key(options, &se_certs);
    cert_verifier_ = std::make_unique<CertVerifier>(
        config_.crypto.plat_ca_file, se_certs, config_.crypto.check_cert_validity);
  }

  engine_ = make_ota_engine(config_.install);
  recover_sessions();
  log_info("device key ready, recipient_spki_sha256=" + device_key_->spki_sha256());
}

OtaService::~OtaService() { stop(); }

void OtaService::start() {
  if (started_) {
    return;
  }
  started_ = true;
  verify_thread_ = std::thread([this]() { verification_worker(); });
  housekeeping_thread_ = std::thread([this]() { housekeeping_worker(); });
}

void OtaService::stop() {
  stopping_.store(true);
  verify_cv_.notify_all();
  housekeeping_cv_.notify_all();
  if (verify_thread_.joinable()) {
    verify_thread_.join();
  }
  if (housekeeping_thread_.joinable()) {
    housekeeping_thread_.join();
  }
}

void OtaService::load_or_init_min_security_version() {
  const std::string path =
      join_path(join_path(config_.data_dir, "state"), "min_security_version");
  if (file_exists(path)) {
    const std::string text = trim_ascii_whitespace(read_text_file_limited(path, 64));
    uint64_t value = 0;
    if (!parse_u64(text, &value)) {
      throw std::runtime_error("invalid min_security_version file: " + path);
    }
    min_security_version_ = value;
  } else {
    min_security_version_ = config_.device.security_version;
    persist_min_security_version(min_security_version_);
  }
}

void OtaService::persist_min_security_version(uint64_t value) {
  const std::string path =
      join_path(join_path(config_.data_dir, "state"), "min_security_version");
  write_file_atomic(path, std::to_string(value) + "\n", 0600);
}

void OtaService::recover_sessions() {
  const ManifestLimits limits{config_.device.max_plaintext_bytes};
  std::vector<SessionRecord> records = store_->load_all(limits);
  std::vector<std::string> verify_ids;
  uint64_t raised_min = min_security_version_;

  const auto fail = [&](SessionRecord* record, const std::string& message) {
    record->state = SessionState::Failed;
    record->result = result_object("STORAGE_INCONSISTENT", message);
    record->updated_at = now_rfc3339();
    try {
      store_->save(*record);
    } catch (const std::exception& e) {
      log_error("failed to persist a recovery failure for " +
                record->session_id + ": " + e.what());
    }
  };

  for (SessionRecord& record : records) {
    const std::string id = record.session_id;
    try {
      switch (record.state) {
        case SessionState::Receiving: {
          if (!store_->payload_exists(id)) {
            fail(&record, "payload file is missing");
            break;
          }
          uint64_t size = store_->payload_size(id);
          if (size > record.offset) {
            // Bytes beyond the last ACKed offset were never acknowledged.
            store_->truncate_payload(id, record.offset);
            log_warn("truncated unacknowledged payload bytes for " + id +
                     " from " + std::to_string(size) + " to " +
                     std::to_string(record.offset));
            size = record.offset;
          }
          if (size < record.offset) {
            fail(&record, "payload is shorter than the durable offset");
          } else if (record.offset == record.total) {
            record.state = SessionState::Verifying;
            record.updated_at = now_rfc3339();
            store_->save(record);
            verify_ids.push_back(id);
          }
          break;
        }
        case SessionState::Verifying: {
          if (record.offset != record.total || !store_->payload_exists(id) ||
              store_->payload_size(id) != record.total) {
            fail(&record, "verifying session does not have the complete payload");
          } else {
            verify_ids.push_back(id);
          }
          break;
        }
        case SessionState::Ready: {
          if (!file_exists(store_->firmware_path(id))) {
            if (store_->payload_exists(id) &&
                record.offset == record.total &&
                store_->payload_size(id) == record.total) {
              record.state = SessionState::Verifying;
              record.updated_at = now_rfc3339();
              store_->save(record);
              verify_ids.push_back(id);
              log_warn("re-verifying " + id + " because firmware.bin is missing");
            } else {
              fail(&record, "firmware.bin is missing and the payload is incomplete");
            }
          }
          break;
        }
        case SessionState::Installing: {
          // The install engine is not part of this build. We cannot prove
          // whether an install was accepted before the restart, so the only
          // safe state is RECOVERY_REQUIRED (no automatic reinstall).
          record.state = SessionState::RecoveryRequired;
          record.result = result_object(
              "INSTALL_STATE_UNKNOWN",
              "install execution is not available in this build; manual check required");
          record.updated_at = now_rfc3339();
          store_->save(record);
          break;
        }
        case SessionState::Success:
          raised_min = std::max(raised_min, record.manifest.security_version);
          break;
        case SessionState::Failed:
        case SessionState::Expired:
        case SessionState::RecoveryRequired:
          break;
      }
    } catch (const std::exception& e) {
      log_error("failed to recover session " + id + ": " + e.what());
      fail(&record, std::string("recovery failed: ") + e.what());
    }

    auto shared = std::make_shared<SessionRecord>(std::move(record));
    sessions_[shared->session_id] = shared;
    auto existing = package_index_.find(shared->package_id);
    if (existing == package_index_.end()) {
      package_index_[shared->package_id] = shared->session_id;
    } else {
      log_warn("multiple sessions share package_id " + shared->package_id +
               "; keeping the newest for resume lookup");
      const auto other = sessions_.find(existing->second);
      if (other == sessions_.end() ||
          shared->created_at_unix > other->second->created_at_unix) {
        existing->second = shared->session_id;
      }
    }
  }

  if (raised_min > min_security_version_) {
    min_security_version_ = raised_min;
    try {
      persist_min_security_version(min_security_version_);
    } catch (const std::exception& e) {
      log_error(std::string("failed to persist min_security_version: ") + e.what());
    }
  }

  size_t active = 0;
  for (const auto& entry : sessions_) {
    if (is_active_state(entry.second->state)) {
      ++active;
    }
  }
  if (active > 1) {
    log_warn("multiple active OTA sessions found (" + std::to_string(active) +
             "); new sessions will be rejected with OTA_BUSY");
  }

  for (const std::string& id : verify_ids) {
    enqueue_verification(id);
  }
  log_info("loaded " + std::to_string(sessions_.size()) + " OTA session(s), " +
           std::to_string(verify_ids.size()) + " queued for verification");
}

std::shared_ptr<SessionRecord> OtaService::find_session_locked(
    const std::string& session_id) const {
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return nullptr;
  }
  return it->second;
}

bool OtaService::has_active_session_locked() const {
  for (const auto& entry : sessions_) {
    if (is_active_state(entry.second->state)) {
      return true;
    }
  }
  return false;
}

Json::Value OtaService::result_object(const std::string& code,
                                      const std::string& message) {
  Json::Value result;
  result["code"] = code;
  if (!message.empty()) {
    result["message"] = message;
  }
  return result;
}

Json::Value OtaService::session_json(const SessionRecord& record) const {
  Json::Value body;
  body["session_id"] = record.session_id;
  body["state"] = session_state_name(record.state);
  body["offset"] = Json::Value::UInt64(record.offset);
  body["total"] = Json::Value::UInt64(record.total);
  body["result"] = record.result;
  return body;
}

Json::Value OtaService::device_info() const {
  Json::Value info;
  info["robot_sn"] = config_.device.robot_sn;
  info["product_id"] = config_.device.product_id;
  info["hw_revision"] = config_.device.hw_revision;
  info["firmware_version"] = config_.device.firmware_version;
  info["ota_api_version"] = 1;
  info["manifest_versions"].append(1);
  info["max_chunk_bytes"] = Json::Value::UInt(config_.device.max_chunk_bytes);
  return info;
}

uint64_t OtaService::min_security_version() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return min_security_version_;
}

OtaService::VerifiedBundle OtaService::verify_bundle(const Json::Value& bundle) {
  if (!bundle.isObject()) {
    throw OtaError(400, "INVALID_REQUEST", "SignedManifestBundle must be an object");
  }
  if (!bundle.isMember("manifest") || !bundle["manifest"].isObject()) {
    throw OtaError(400, "INVALID_REQUEST",
                   "SignedManifestBundle.manifest must be an object");
  }
  if (!bundle.isMember("signature_b64") || !bundle["signature_b64"].isString() ||
      !bundle.isMember("signer_cert_b64") ||
      !bundle["signer_cert_b64"].isString()) {
    throw OtaError(400, "INVALID_REQUEST",
                   "SignedManifestBundle requires signature_b64 and signer_cert_b64");
  }

  const ManifestLimits limits{config_.device.max_plaintext_bytes};
  Manifest manifest = parse_manifest(bundle["manifest"], limits);

  const std::string signature_b64 = bundle["signature_b64"].asString();
  const std::string signer_cert_b64 = bundle["signer_cert_b64"].asString();

  Bytes signature;
  Bytes signer_cert;
  try {
    signature = base64_decode_strict(signature_b64);
    signer_cert = base64_decode_strict(signer_cert_b64);
  } catch (const std::exception& e) {
    throw OtaError(400, "INVALID_REQUEST",
                   std::string("invalid base64 in the bundle: ") + e.what());
  }
  if (signature.empty() || signature.size() > 1024) {
    throw OtaError(400, "SIGNATURE_INVALID", "signature has an invalid length");
  }
  if (signer_cert.empty() || signer_cert.size() > 64 * 1024) {
    throw OtaError(400, "CERT_INVALID", "signer certificate has an invalid length");
  }

  const Bytes sign_input =
      make_sign_input(config_.crypto.sign_domain_prefix, manifest.canonical);
  try {
    cert_verifier_->verify(signer_cert, config_.crypto.signature_scheme,
                           sign_input.data(), sign_input.size(),
                           signature.data(), signature.size());
  } catch (const CryptoError& e) {
    const std::string message = e.what();
    const bool certificate_failure =
        message.find("certificate") != std::string::npos ||
        message.find("CA") != std::string::npos;
    throw OtaError(400, certificate_failure ? "CERT_INVALID" : "SIGNATURE_INVALID",
                   message);
  }

  verify_device_binding(manifest);

  VerifiedBundle verified;
  verified.manifest = std::move(manifest);
  verified.signature_b64 = signature_b64;
  verified.signer_cert_b64 = signer_cert_b64;
  return verified;
}

void OtaService::verify_device_binding(const Manifest& manifest) {
  if (manifest.robot_sn != config_.device.robot_sn) {
    throw OtaError(400, "DEVICE_MISMATCH",
                   "manifest target robot_sn does not match this device");
  }
  if (!constant_time_equal(manifest.recipient_spki_sha256,
                           device_key_->spki_sha256())) {
    throw OtaError(400, "SPKI_MISMATCH",
                   "manifest recipient_spki_sha256 does not match this device key");
  }
  if (manifest.product_id != config_.device.product_id ||
      manifest.hw_revision != config_.device.hw_revision) {
    throw OtaError(400, "FIRMWARE_MISMATCH",
                   "manifest product_id/hw_revision do not match this device");
  }
  if (manifest.wrapped_dek.size() != device_key_->modulus_bytes()) {
    throw OtaError(400, "INVALID_MANIFEST",
                   "wrapped_dek length does not match the device RSA modulus");
  }
  if (manifest.security_version < min_security_version()) {
    throw OtaError(400, "VERSION_ROLLBACK",
                   "manifest security_version is below the minimum security version");
  }
}

OtaService::CreateResult OtaService::create_or_resume_session(
    const Json::Value& bundle) {
  VerifiedBundle verified = verify_bundle(bundle);
  const std::string manifest_hash = verified.manifest.canonical_sha256;

  std::lock_guard<std::mutex> lock(mutex_);
  const auto package = package_index_.find(verified.manifest.package_id);
  if (package != package_index_.end()) {
    std::shared_ptr<SessionRecord> existing = find_session_locked(package->second);
    if (existing != nullptr) {
      if (!constant_time_equal(existing->manifest_hash, manifest_hash)) {
        throw OtaError(409, "PACKAGE_ID_CONFLICT",
                       "package_id already exists with a different manifest");
      }
      log_info("resuming OTA session " + existing->session_id + " for package_id " +
               existing->package_id);
      log_upgrade("session=" + existing->session_id +
                  " package=" + existing->package_id +
                  " version=" + existing->manifest.version + " event=RESUMED");
      return CreateResult{false, session_json(*existing)};
    }
    package_index_.erase(package);
  }

  if (has_active_session_locked()) {
    throw OtaError(409, "OTA_BUSY", "another OTA task is active");
  }

  SessionRecord record;
  record.session_id = "ota_" + random_hex(16);
  record.package_id = verified.manifest.package_id;
  record.manifest_hash = manifest_hash;
  record.manifest = verified.manifest;
  record.signature_b64 = verified.signature_b64;
  record.signer_cert_b64 = verified.signer_cert_b64;
  record.state = SessionState::Receiving;
  record.offset = 0;
  record.total = verified.manifest.ciphertext_size;
  record.created_at = now_rfc3339();
  record.created_at_unix = now_unix_seconds();
  record.updated_at = record.created_at;

  try {
    store_->create(record);
  } catch (const std::exception& e) {
    throw OtaError(500, "STORAGE_ERROR",
                   std::string("failed to create the session: ") + e.what());
  }

  auto shared = std::make_shared<SessionRecord>(std::move(record));
  const std::string id = shared->session_id;
  const std::string package_id = shared->package_id;
  sessions_[id] = shared;
  package_index_[package_id] = id;
  log_info("created OTA session " + id + " for package_id " + package_id +
           ", total=" + std::to_string(shared->total));
  log_upgrade("session=" + id + " package=" + package_id +
              " version=" + shared->manifest.version +
              " event=CREATED total=" + std::to_string(shared->total));
  return CreateResult{true, session_json(*shared)};
}

Json::Value OtaService::get_session(const std::string& session_id) {
  if (!SessionStore::valid_session_id(session_id)) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
    if (record == nullptr) {
      throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
    }
    if (record->state != SessionState::Installing || !engine_->enabled()) {
      return session_json(*record);
    }
  }
  refresh_install_state(session_id);
  std::lock_guard<std::mutex> lock(mutex_);
  const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
  if (record == nullptr) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  return session_json(*record);
}

uint64_t OtaService::patch_payload(const std::string& session_id,
                                   uint64_t offset, const uint8_t* data,
                                   size_t size) {
  if (!SessionStore::valid_session_id(session_id)) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  std::lock_guard<std::mutex> lock(mutex_);
  const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
  if (record == nullptr) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  if (record->state != SessionState::Receiving) {
    throw OtaError(409, "INVALID_STATE",
                   std::string("session is in state ") +
                       session_state_name(record->state) +
                       " and does not accept payload data");
  }
  if (offset != record->offset) {
    throw OtaError(409, "OFFSET_MISMATCH", "Upload-Offset does not match");
  }
  if (size == 0) {
    throw OtaError(400, "INVALID_REQUEST", "empty payload chunk");
  }
  if (size > config_.device.max_chunk_bytes) {
    throw OtaError(413, "CHUNK_TOO_LARGE", "payload chunk exceeds max_chunk_bytes");
  }
  if (record->offset > record->total || size > record->total - record->offset) {
    throw OtaError(413, "PAYLOAD_TOO_LARGE",
                   "payload chunk exceeds the declared ciphertext_size");
  }

  const uint64_t previous_offset = record->offset;
  const bool completes = (offset + size == record->total);
  try {
    // This fsyncs before returning; only then may the client receive an ACK.
    store_->append_payload(session_id, offset, data, size);
    record->offset += size;
    record->updated_at = now_rfc3339();
    if (completes) {
      record->state = SessionState::Verifying;
    }
    store_->save(*record);
  } catch (const std::exception& e) {
    // Keep the in-memory state consistent with the durable payload.
    record->offset = previous_offset;
    if (completes) {
      record->state = SessionState::Receiving;
    }
    try {
      store_->truncate_payload(session_id, previous_offset);
    } catch (const std::exception& truncate_error) {
      log_error("failed to roll back payload for " + session_id + ": " +
                truncate_error.what());
    }
    throw OtaError(500, "STORAGE_ERROR",
                   std::string("failed to persist the payload chunk: ") + e.what());
  }

  const uint64_t new_offset = record->offset;
  if (completes) {
    log_info("session " + session_id + " payload complete, verifying");
    log_upgrade("session=" + session_id + " package=" + record->package_id +
                " version=" + record->manifest.version +
                " event=PAYLOAD_RECEIVED total=" +
                std::to_string(record->total));
    enqueue_verification(session_id);
  }
  return new_offset;
}

OtaService::InstallResult OtaService::install(const std::string& session_id,
                                              const Json::Value& bundle) {
  if (!SessionStore::valid_session_id(session_id)) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  VerifiedBundle verified = verify_bundle(bundle);
  const std::string manifest_hash = verified.manifest.canonical_sha256;

  std::unique_lock<std::mutex> lock(mutex_);
  std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
  if (record == nullptr) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  if (!constant_time_equal(record->manifest_hash, manifest_hash)) {
    throw OtaError(409, "MANIFEST_MISMATCH",
                   "the submitted manifest does not match this session");
  }

  switch (record->state) {
    case SessionState::Installing:
    case SessionState::Success:
    case SessionState::Failed:
    case SessionState::RecoveryRequired:
      // Install is idempotent: return the current task state, never start a
      // second install.
      return InstallResult{200, session_json(*record)};
    case SessionState::Receiving:
    case SessionState::Verifying:
    case SessionState::Expired:
      throw OtaError(409, "INVALID_STATE",
                     std::string("session is in state ") +
                         session_state_name(record->state) +
                         " and cannot be installed");
    case SessionState::Ready:
      break;
  }

  if (!engine_->enabled()) {
    // Deliberate boundary: receiving/verifying is implemented, installation is
    // not. Leave the session READY so it can be installed once an engine is
    // wired in. Never fake SUCCESS.
    throw OtaError(
        501, "INSTALL_NOT_SUPPORTED",
        "install execution is not implemented in this build; session remains READY");
  }

  record->install_id = random_hex(16);
  record->state = SessionState::Installing;
  record->updated_at = now_rfc3339();
  record->result = Json::Value(Json::nullValue);
  InstallRequest request;
  request.session_id = record->session_id;
  request.install_id = record->install_id;
  request.package_id = record->package_id;
  request.firmware_path = store_->firmware_path(record->session_id);
  request.firmware_size = record->manifest.plaintext_size;
  request.firmware_version = record->manifest.version;
  request.plaintext_sha256 = record->manifest.plaintext_sha256;
  request.security_version = record->manifest.security_version;
  try {
    store_->save(*record);
  } catch (const std::exception& e) {
    record->state = SessionState::Ready;
    record->install_id.clear();
    throw OtaError(500, "STORAGE_ERROR",
                   std::string("failed to persist INSTALLING: ") + e.what());
  }
  log_info("session " + record->session_id + " install started, install_id=" +
           record->install_id);
  log_upgrade("session=" + record->session_id +
              " package=" + record->package_id +
              " version=" + record->manifest.version +
              " event=INSTALL_STARTED install_id=" + record->install_id);
  lock.unlock();

  InstallStartResult start_result = InstallStartResult::Unknown;
  std::string start_error;
  try {
    start_result = engine_->start(request);
  } catch (const std::exception& e) {
    start_error = e.what();
    start_result = InstallStartResult::Unknown;
  }

  lock.lock();
  record = find_session_locked(session_id);
  if (record == nullptr) {
    throw OtaError(404, "SESSION_NOT_FOUND", "session does not exist");
  }
  if (record->state != SessionState::Installing) {
    return InstallResult{200, session_json(*record)};
  }

  switch (start_result) {
    case InstallStartResult::Accepted:
      return InstallResult{202, session_json(*record)};
    case InstallStartResult::Rejected:
      record->state = SessionState::Failed;
      record->result =
          result_object("INSTALL_REJECTED",
                        start_error.empty() ? "install engine rejected the request"
                                            : start_error);
      record->updated_at = now_rfc3339();
      try {
        store_->save(*record);
      } catch (const std::exception& e) {
        log_error("failed to persist INSTALL_REJECTED: " + std::string(e.what()));
      }
      log_warn("session " + record->session_id + " install rejected: " +
               (start_error.empty() ? "unknown reason" : start_error));
      log_upgrade("session=" + record->session_id +
                  " package=" + record->package_id +
                  " version=" + record->manifest.version +
                  " event=INSTALL_REJECTED reason=" +
                  (start_error.empty() ? "unknown"
                                       : truncate_message(start_error, 256)));
      return InstallResult{200, session_json(*record)};
    case InstallStartResult::Unsupported:
      record->state = SessionState::Ready;
      record->install_id.clear();
      try {
        store_->save(*record);
      } catch (const std::exception&) {
      }
      throw OtaError(501, "INSTALL_NOT_SUPPORTED",
                     "the configured install engine does not support installation");
    case InstallStartResult::Unknown:
      record->state = SessionState::RecoveryRequired;
      record->result = result_object(
          "INSTALL_STATE_UNKNOWN",
          start_error.empty()
              ? "could not determine whether the install engine accepted the request"
              : start_error);
      record->updated_at = now_rfc3339();
      try {
        store_->save(*record);
      } catch (const std::exception& e) {
        log_error("failed to persist RECOVERY_REQUIRED: " + std::string(e.what()));
      }
      log_error("session " + record->session_id + " install state unknown: " +
                (start_error.empty() ? "no detail" : start_error));
      log_upgrade("session=" + record->session_id +
                  " package=" + record->package_id +
                  " version=" + record->manifest.version +
                  " event=INSTALL_STATE_UNKNOWN reason=" +
                  (start_error.empty() ? "unknown"
                                       : truncate_message(start_error, 256)));
      return InstallResult{200, session_json(*record)};
  }
  throw OtaError(500, "INTERNAL_ERROR", "unreachable install state");
}

void OtaService::enqueue_verification(const std::string& session_id) {
  {
    std::lock_guard<std::mutex> lock(verify_mutex_);
    verify_queue_.push_back(session_id);
  }
  verify_cv_.notify_one();
}

void OtaService::verification_worker() {
  for (;;) {
    std::string session_id;
    {
      std::unique_lock<std::mutex> lock(verify_mutex_);
      verify_cv_.wait(lock, [this]() {
        return stopping_.load() || !verify_queue_.empty();
      });
      if (stopping_.load()) {
        return;
      }
      session_id = verify_queue_.front();
      verify_queue_.pop_front();
    }
    try {
      verify_session(session_id);
    } catch (const std::exception& e) {
      log_error("verification of " + session_id + " failed: " + e.what());
      mark_verification_failed(session_id, e.what());
    }
  }
}

void OtaService::verify_session(const std::string& session_id) {
  Manifest manifest;
  std::string payload_path;
  std::string firmware_path;
  uint64_t total = 0;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
    if (record == nullptr || record->state != SessionState::Verifying) {
      return;
    }
    manifest = record->manifest;
    total = record->total;
  }
  payload_path = store_->payload_path(session_id);
  firmware_path = store_->firmware_path(session_id);
  const std::string tmp_path = firmware_path + ".tmp";
  remove_file_if_exists(tmp_path);
  store_->remove_firmware(session_id);

  Bytes dek;
  try {
    const uint64_t size = store_->payload_size(session_id);
    if (size != total) {
      throw CryptoError("ciphertext size does not match the declared size");
    }
    const HashedFile ciphertext = sha256_file(payload_path, total);
    const std::string ciphertext_hex =
        to_hex(ciphertext.hash.data(), ciphertext.hash.size());
    if (ciphertext.size != total ||
        !constant_time_equal(ciphertext_hex, manifest.ciphertext_sha256)) {
      throw CryptoError("ciphertext SHA-256 mismatch");
    }

    if (manifest.wrapped_dek.size() != device_key_->modulus_bytes()) {
      throw CryptoError("wrapped DEK length does not match the device key");
    }
    const Bytes encoded_message = device_key_->raw_private(manifest.wrapped_dek);
    dek = oaep_sha256_decode(encoded_message, device_key_->modulus());
    if (dek.size() != 32) {
      throw CryptoError("the unwrapped DEK is not 32 bytes");
    }

    Sha256Digest key{};
    std::copy(dek.begin(), dek.end(), key.begin());
    const GcmResult plaintext = aes256_gcm_decrypt_file(
        payload_path, tmp_path, key, manifest.nonce, manifest.tag,
        manifest.plaintext_size);
    const std::string plaintext_hex =
        to_hex(plaintext.plaintext_sha256.data(),
               plaintext.plaintext_sha256.size());
    if (plaintext.plaintext_size != manifest.plaintext_size ||
        !constant_time_equal(plaintext_hex, manifest.plaintext_sha256)) {
      throw CryptoError("plaintext size or SHA-256 mismatch");
    }

    if (std::rename(tmp_path.c_str(), firmware_path.c_str()) != 0) {
      throw CryptoError("failed to move the verified firmware into place");
    }
    fsync_dir(store_->session_dir(session_id));

    std::lock_guard<std::mutex> lock(mutex_);
    const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
    if (record == nullptr || record->state != SessionState::Verifying) {
      return;
    }
    record->state = SessionState::Ready;
    record->offset = record->total;
    record->result = Json::Value(Json::nullValue);
    record->updated_at = now_rfc3339();
    try {
      store_->save(*record);
    } catch (const std::exception& e) {
      throw CryptoError(std::string("failed to persist READY: ") + e.what());
    }
    log_info("session " + session_id + " verified and READY");
    log_upgrade("session=" + session_id + " package=" + record->package_id +
                " version=" + record->manifest.version + " event=VERIFIED");
  } catch (...) {
    remove_file_if_exists(tmp_path);
    if (!dek.empty()) {
      OPENSSL_cleanse(dek.data(), dek.size());
    }
    throw;
  }
  if (!dek.empty()) {
    OPENSSL_cleanse(dek.data(), dek.size());
  }
}

void OtaService::mark_verification_failed(const std::string& session_id,
                                          const std::string& message) {
  std::lock_guard<std::mutex> lock(mutex_);
  const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
  if (record == nullptr || record->state != SessionState::Verifying) {
    return;
  }
  record->state = SessionState::Failed;
  record->result = result_object("VERIFY_FAILED", truncate_message(message, 512));
  record->updated_at = now_rfc3339();
  try {
    store_->save(*record);
  } catch (const std::exception& e) {
    log_error("failed to persist VERIFY_FAILED for " + session_id + ": " + e.what());
  }
  store_->remove_firmware(session_id);
  log_error("session " + session_id + " FAILED: " + message);
  log_upgrade("session=" + session_id + " package=" + record->package_id +
              " version=" + record->manifest.version + " event=VERIFY_FAILED reason=" +
              truncate_message(message, 256));
}

void OtaService::expire_sessions() {
  if (config_.session.receiving_ttl_hours == 0) {
    return;
  }
  const int64_t ttl_seconds =
      static_cast<int64_t>(config_.session.receiving_ttl_hours) * 3600;
  const int64_t now = now_unix_seconds();
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& entry : sessions_) {
    const std::shared_ptr<SessionRecord>& record = entry.second;
    if (record->state != SessionState::Receiving) {
      continue;
    }
    if (now - record->created_at_unix <= ttl_seconds) {
      continue;
    }
    record->state = SessionState::Expired;
    record->result =
        result_object("SESSION_EXPIRED", "receiving TTL expired");
    record->updated_at = now_rfc3339();
    try {
      store_->save(*record);
      log_warn("session " + record->session_id + " expired");
      log_upgrade("session=" + record->session_id +
                  " package=" + record->package_id +
                  " version=" + record->manifest.version + " event=EXPIRED");
    } catch (const std::exception& e) {
      log_error("failed to persist EXPIRED for " + record->session_id + ": " +
                e.what());
    }
  }
}

void OtaService::refresh_install_state(const std::string& session_id) {
  if (!engine_->enabled()) {
    return;
  }
  InstallRequest request;
  uint64_t security_version = 0;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
    if (record == nullptr || record->state != SessionState::Installing) {
      return;
    }
    request.session_id = record->session_id;
    request.install_id = record->install_id;
    request.package_id = record->package_id;
    request.firmware_path = store_->firmware_path(record->session_id);
    request.firmware_size = record->manifest.plaintext_size;
    request.firmware_version = record->manifest.version;
    request.plaintext_sha256 = record->manifest.plaintext_sha256;
    request.security_version = record->manifest.security_version;
    security_version = record->manifest.security_version;
  }

  InstallStatus status;
  try {
    status = engine_->query(request);
  } catch (const std::exception& e) {
    status.state = InstallStatus::State::Unknown;
    status.message = e.what();
  }

  std::lock_guard<std::mutex> lock(mutex_);
  const std::shared_ptr<SessionRecord> record = find_session_locked(session_id);
  if (record == nullptr || record->state != SessionState::Installing) {
    return;
  }
  switch (status.state) {
    case InstallStatus::State::Installing:
      return;
    case InstallStatus::State::Success:
      record->state = SessionState::Success;
      record->result = result_object("SUCCESS", "");
      if (!status.running_version.empty()) {
        record->result["running_version"] = status.running_version;
      }
      record->updated_at = now_rfc3339();
      if (security_version > min_security_version_) {
        min_security_version_ = security_version;
        try {
          persist_min_security_version(min_security_version_);
        } catch (const std::exception& e) {
          log_error("failed to persist min_security_version: " +
                    std::string(e.what()));
        }
      }
      log_info("session " + record->session_id + " install succeeded" +
               (status.running_version.empty()
                    ? ""
                    : " running_version=" + status.running_version));
      log_upgrade("session=" + record->session_id +
                  " package=" + record->package_id +
                  " version=" + record->manifest.version + " event=INSTALL_SUCCESS" +
                  (status.running_version.empty()
                       ? ""
                       : " running_version=" + status.running_version));
      break;
    case InstallStatus::State::Failed:
      record->state = SessionState::Failed;
      record->result = result_object(
          status.error_code.empty() ? "INSTALL_FAILED" : status.error_code,
          status.message);
      record->updated_at = now_rfc3339();
      log_error("session " + record->session_id + " install failed: " +
                status.message);
      log_upgrade("session=" + record->session_id +
                  " package=" + record->package_id +
                  " version=" + record->manifest.version +
                  " event=INSTALL_FAILED code=" +
                  (status.error_code.empty() ? "INSTALL_FAILED"
                                             : status.error_code) +
                  " reason=" + truncate_message(status.message, 256));
      break;
    case InstallStatus::State::Unknown:
      record->state = SessionState::RecoveryRequired;
      record->result = result_object(
          "INSTALL_STATE_UNKNOWN",
          status.message.empty()
              ? "the install engine cannot confirm the task state"
              : status.message);
      record->updated_at = now_rfc3339();
      log_error("session " + record->session_id + " install state unknown: " +
                status.message);
      log_upgrade("session=" + record->session_id +
                  " package=" + record->package_id +
                  " version=" + record->manifest.version +
                  " event=INSTALL_STATE_UNKNOWN reason=" +
                  truncate_message(status.message, 256));
      break;
  }
  try {
    store_->save(*record);
  } catch (const std::exception& e) {
    log_error("failed to persist install state for " + session_id + ": " +
              e.what());
  }
}

void OtaService::housekeeping_worker() {
  std::unique_lock<std::mutex> lock(housekeeping_mutex_);
  while (!stopping_.load()) {
    housekeeping_cv_.wait_for(lock, std::chrono::seconds(1));
    if (stopping_.load()) {
      break;
    }
    lock.unlock();
    expire_sessions();
    if (engine_->enabled()) {
      std::vector<std::string> installing;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        for (const auto& entry : sessions_) {
          if (entry.second->state == SessionState::Installing) {
            installing.push_back(entry.first);
          }
        }
      }
      for (const std::string& id : installing) {
        refresh_install_state(id);
      }
    }
    lock.lock();
  }
}

}  // namespace robot_ota
