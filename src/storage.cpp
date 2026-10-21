#include "robot_ota/storage.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <json/json.h>

#include "robot_ota/crypto.h"
#include "robot_ota/errors.h"
#include "robot_ota/jcs.h"

namespace robot_ota {
namespace {

constexpr size_t kMetaFileLimit = 16 * 1024 * 1024;

std::string errno_string() { return std::strerror(errno); }

bool path_exists(const std::string& path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0;
}

std::string json_to_string(const Json::Value& value) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  builder["emitUTF8"] = true;
  std::string out = Json::writeString(builder, value);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
    out.pop_back();
  }
  return out;
}

Json::Value parse_json_text(const std::string& text, const std::string& what) {
  Json::CharReaderBuilder builder;
  builder["collectComments"] = false;
  builder["strictMode"] = true;
  builder["rejectDupKeys"] = true;
  builder["stackLimit"] = 32;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value root;
  std::string errors;
  if (!reader->parse(text.data(), text.data() + text.size(), &root, &errors)) {
    throw std::runtime_error("failed to parse " + what + ": " + errors);
  }
  return root;
}

uint64_t required_u64(const Json::Value& object, const char* key,
                      const std::string& where) {
  const Json::Value& value = object[key];
  switch (value.type()) {
    case Json::intValue: {
      const Json::Int64 v = value.asInt64();
      if (v < 0) {
        throw std::runtime_error(where + "." + key + " is negative");
      }
      return static_cast<uint64_t>(v);
    }
    case Json::uintValue:
      return value.asUInt64();
    default:
      throw std::runtime_error(where + "." + key + " is not an integer");
  }
}

std::string required_string(const Json::Value& object, const char* key,
                            const std::string& where) {
  const Json::Value& value = object[key];
  if (!value.isString()) {
    throw std::runtime_error(where + "." + key + " is not a string");
  }
  return value.asString();
}

void pwrite_all(int fd, const uint8_t* data, size_t size, uint64_t offset) {
  size_t done = 0;
  while (done < size) {
    const ssize_t n =
        ::pwrite(fd, data + done, size - done, static_cast<off_t>(offset + done));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw std::runtime_error("pwrite failed: " + errno_string());
    }
    if (n == 0) {
      throw std::runtime_error("pwrite returned 0");
    }
    done += static_cast<size_t>(n);
  }
}

}  // namespace

const char* session_state_name(SessionState state) {
  switch (state) {
    case SessionState::Receiving:
      return "RECEIVING";
    case SessionState::Verifying:
      return "VERIFYING";
    case SessionState::Ready:
      return "READY";
    case SessionState::Installing:
      return "INSTALLING";
    case SessionState::Success:
      return "SUCCESS";
    case SessionState::Failed:
      return "FAILED";
    case SessionState::Expired:
      return "EXPIRED";
    case SessionState::RecoveryRequired:
      return "RECOVERY_REQUIRED";
  }
  return "UNKNOWN";
}

bool parse_session_state(const std::string& text, SessionState* state) {
  if (text == "RECEIVING") {
    *state = SessionState::Receiving;
  } else if (text == "VERIFYING") {
    *state = SessionState::Verifying;
  } else if (text == "READY") {
    *state = SessionState::Ready;
  } else if (text == "INSTALLING") {
    *state = SessionState::Installing;
  } else if (text == "SUCCESS") {
    *state = SessionState::Success;
  } else if (text == "FAILED") {
    *state = SessionState::Failed;
  } else if (text == "EXPIRED") {
    *state = SessionState::Expired;
  } else if (text == "RECOVERY_REQUIRED") {
    *state = SessionState::RecoveryRequired;
  } else {
    return false;
  }
  return true;
}

bool is_terminal_state(SessionState state) {
  return state == SessionState::Success || state == SessionState::Failed ||
         state == SessionState::Expired;
}

bool is_active_state(SessionState state) {
  return state == SessionState::Receiving || state == SessionState::Verifying ||
         state == SessionState::Ready || state == SessionState::Installing ||
         state == SessionState::RecoveryRequired;
}

SessionStore::SessionStore(std::string data_dir)
    : data_dir_(std::move(data_dir)),
      sessions_dir_(join_path(data_dir_, "sessions")),
      quarantine_dir_(join_path(data_dir_, "quarantine")) {}

SessionStore::~SessionStore() {
  if (lock_fd_ >= 0) {
    ::close(lock_fd_);
  }
}

void SessionStore::init() {
  ensure_dir(data_dir_, 0700);
  ensure_dir(sessions_dir_, 0700);
  ensure_dir(quarantine_dir_, 0700);
  ensure_dir(join_path(data_dir_, "state"), 0700);

  const std::string lock_path = join_path(data_dir_, "lock");
  lock_fd_ = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (lock_fd_ < 0) {
    throw std::runtime_error("open(" + lock_path + ") failed: " + errno_string());
  }
  if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
    throw std::runtime_error(
        "another robot-ota-server instance is already using " + data_dir_);
  }
}

bool SessionStore::valid_session_id(const std::string& session_id) {
  if (session_id.size() < 20 || session_id.size() > 68 ||
      session_id.compare(0, 4, "ota_") != 0) {
    return false;
  }
  for (size_t i = 4; i < session_id.size(); ++i) {
    const char c = session_id[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

std::string SessionStore::session_dir(const std::string& session_id) const {
  return join_path(sessions_dir_, session_id);
}

std::string SessionStore::payload_path(const std::string& session_id) const {
  return join_path(session_dir(session_id), "payload.enc");
}

std::string SessionStore::firmware_path(const std::string& session_id) const {
  return join_path(session_dir(session_id), "firmware.bin");
}

bool SessionStore::payload_exists(const std::string& session_id) const {
  return file_exists(payload_path(session_id));
}

uint64_t SessionStore::payload_size(const std::string& session_id) const {
  return file_size_or_throw(payload_path(session_id));
}

void SessionStore::create(const SessionRecord& record) {
  if (!valid_session_id(record.session_id)) {
    throw std::runtime_error("invalid session id");
  }
  const std::string dir = session_dir(record.session_id);
  ensure_dir(dir, 0700);

  // Create the payload first. A crash before meta.json exists leaves an orphan
  // directory that load_all() will quarantine rather than treat as a session.
  const std::string payload = payload_path(record.session_id);
  const int fd = ::open(payload.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                        0600);
  if (fd < 0) {
    throw std::runtime_error("open(" + payload + ") failed: " + errno_string());
  }
  if (::fsync(fd) != 0) {
    const std::string message = errno_string();
    ::close(fd);
    throw std::runtime_error("fsync(" + payload + ") failed: " + message);
  }
  ::close(fd);
  fsync_dir(dir);

  save(record);
}

void SessionStore::save(const SessionRecord& record) {
  Json::Value meta;
  meta["meta_version"] = 1;
  meta["session_id"] = record.session_id;
  meta["package_id"] = record.package_id;
  meta["manifest_hash"] = record.manifest_hash;
  meta["manifest_canonical"] = record.manifest.canonical;
  meta["signature_b64"] = record.signature_b64;
  meta["signer_cert_b64"] = record.signer_cert_b64;
  meta["state"] = session_state_name(record.state);
  meta["offset"] = Json::Value::UInt64(record.offset);
  meta["total"] = Json::Value::UInt64(record.total);
  meta["result"] = record.result;
  meta["created_at"] = record.created_at;
  meta["created_at_unix"] = Json::Value::Int64(record.created_at_unix);
  meta["updated_at"] = record.updated_at;
  meta["install_id"] = record.install_id;
  meta["security_version"] =
      Json::Value::UInt64(record.manifest.security_version);
  meta["firmware_version"] = record.manifest.version;

  const std::string text = json_to_string(meta);
  if (text.size() > kMetaFileLimit) {
    throw std::runtime_error("session metadata is too large");
  }
  write_file_atomic(join_path(session_dir(record.session_id), "meta.json"), text,
                    0600);
}

std::vector<SessionRecord> SessionStore::load_all(const ManifestLimits& limits) {
  std::vector<SessionRecord> records;
  DIR* dir = ::opendir(sessions_dir_.c_str());
  if (dir == nullptr) {
    throw std::runtime_error("opendir(" + sessions_dir_ + ") failed: " +
                             errno_string());
  }
  std::vector<std::string> names;
  while (dirent* entry = ::readdir(dir)) {
    const std::string name(entry->d_name);
    if (name == "." || name == "..") {
      continue;
    }
    names.push_back(name);
  }
  ::closedir(dir);

  for (const std::string& name : names) {
    if (!valid_session_id(name)) {
      log_warn("ignoring unexpected directory in sessions/: " + name);
      continue;
    }
    const std::string meta_path =
        join_path(session_dir(name), "meta.json");
    try {
      const std::string text = read_text_file_limited(meta_path, kMetaFileLimit);
      const Json::Value meta = parse_json_text(text, meta_path);
      if (!meta.isObject()) {
        throw std::runtime_error("meta root is not an object");
      }
      if (required_u64(meta, "meta_version", "meta") != 1) {
        throw std::runtime_error("unsupported meta_version");
      }
      SessionRecord record;
      record.session_id = required_string(meta, "session_id", "meta");
      if (record.session_id != name) {
        throw std::runtime_error("session_id does not match the directory name");
      }
      record.package_id = required_string(meta, "package_id", "meta");
      record.manifest_hash = required_string(meta, "manifest_hash", "meta");
      const std::string canonical =
          required_string(meta, "manifest_canonical", "meta");
      const Json::Value manifest_json =
          parse_json_text(canonical, "manifest_canonical");
      record.manifest = parse_manifest(manifest_json, limits);
      if (!constant_time_equal(record.manifest.canonical_sha256,
                               record.manifest_hash)) {
        throw std::runtime_error("manifest hash does not match the canonical form");
      }
      if (record.package_id != record.manifest.package_id) {
        throw std::runtime_error("package_id does not match the manifest");
      }
      record.signature_b64 = required_string(meta, "signature_b64", "meta");
      record.signer_cert_b64 = required_string(meta, "signer_cert_b64", "meta");
      // Validate the stored encodings so a corrupt meta file cannot reach the
      // install path as a surprise.
      (void)base64_decode_strict(record.signature_b64);
      (void)base64_decode_strict(record.signer_cert_b64);
      record.state = SessionState::Receiving;
      if (!parse_session_state(required_string(meta, "state", "meta"),
                               &record.state)) {
        throw std::runtime_error("unknown session state");
      }
      record.offset = required_u64(meta, "offset", "meta");
      record.total = required_u64(meta, "total", "meta");
      if (record.total != record.manifest.ciphertext_size) {
        throw std::runtime_error("session total does not match the manifest");
      }
      if (record.offset > record.total) {
        throw std::runtime_error("session offset exceeds total");
      }
      const Json::Value& result = meta["result"];
      if (!result.isNull() && !result.isObject()) {
        throw std::runtime_error("session result is not null or an object");
      }
      record.result = result;
      record.created_at = required_string(meta, "created_at", "meta");
      record.created_at_unix = static_cast<int64_t>(
          required_u64(meta, "created_at_unix", "meta"));
      record.updated_at = required_string(meta, "updated_at", "meta");
      record.install_id = required_string(meta, "install_id", "meta");
      records.push_back(std::move(record));
    } catch (const std::exception& e) {
      log_error("quarantining session " + name + ": " + e.what());
      quarantine(name);
    }
  }
  return records;
}

void SessionStore::append_payload(const std::string& session_id, uint64_t offset,
                                  const uint8_t* data, size_t size) {
  const std::string path = payload_path(session_id);
  const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("open(" + path + ") failed: " + errno_string());
  }
  try {
    struct stat st {};
    if (::fstat(fd, &st) != 0) {
      throw std::runtime_error("fstat(" + path + ") failed: " + errno_string());
    }
    if (static_cast<uint64_t>(st.st_size) != offset) {
      throw std::runtime_error("payload size does not match the durable offset");
    }
    pwrite_all(fd, data, size, offset);
    if (::fsync(fd) != 0) {
      throw std::runtime_error("fsync(" + path + ") failed: " + errno_string());
    }
  } catch (...) {
    ::close(fd);
    throw;
  }
  ::close(fd);
}

void SessionStore::truncate_payload(const std::string& session_id,
                                    uint64_t size) {
  const std::string path = payload_path(session_id);
  const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("open(" + path + ") failed: " + errno_string());
  }
  if (::ftruncate(fd, static_cast<off_t>(size)) != 0) {
    const std::string message = errno_string();
    ::close(fd);
    throw std::runtime_error("ftruncate(" + path + ") failed: " + message);
  }
  if (::fsync(fd) != 0) {
    const std::string message = errno_string();
    ::close(fd);
    throw std::runtime_error("fsync(" + path + ") failed: " + message);
  }
  ::close(fd);
}

void SessionStore::remove_firmware(const std::string& session_id) {
  remove_file_if_exists(firmware_path(session_id));
  remove_file_if_exists(firmware_path(session_id) + ".tmp");
}

std::string SessionStore::quarantine(const std::string& session_id) {
  ensure_dir(quarantine_dir_, 0700);
  const std::string source = session_dir(session_id);
  std::string destination =
      join_path(quarantine_dir_,
                session_id + "." + std::to_string(now_unix_seconds()));
  if (path_exists(destination)) {
    destination += "." + random_hex(4);
  }
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    log_error("failed to quarantine " + source + ": " + errno_string());
    return "";
  }
  fsync_dir(sessions_dir_);
  fsync_dir(quarantine_dir_);
  return destination;
}

}  // namespace robot_ota
