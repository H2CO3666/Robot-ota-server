#include "robot_ota/util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace robot_ota {
namespace {

std::mutex g_log_mutex;
std::mutex g_upgrade_mutex;
bool g_verbose = false;
int g_log_fd = -1;
int g_upgrade_log_fd = -1;

std::string make_log_line(const char* level, const std::string& message) {
  const auto now = std::chrono::system_clock::now();
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  localtime_r(&t, &tm);
  char stamp[32];
  std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);
  char msbuf[8];
  std::snprintf(msbuf, sizeof(msbuf), "%03d", static_cast<int>(ms.count()));
  std::string line;
  line.reserve(message.size() + 64);
  line += stamp;
  line += '.';
  line += msbuf;
  line += " [";
  line += level;
  line += "] ";
  line += message;
  line += '\n';
  return line;
}

// Best-effort append: a full disk or a closed fd must never crash the server.
void append_ignore_errors(int fd, const std::string& text) {
  const char* p = text.data();
  size_t remaining = text.size();
  while (remaining > 0) {
    const ssize_t n = ::write(fd, p, remaining);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return;
    }
    if (n == 0) {
      return;
    }
    p += static_cast<size_t>(n);
    remaining -= static_cast<size_t>(n);
  }
}

int open_append_log(const std::string& path) {
  return ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
}

void log_line(const char* level, const std::string& message) {
  const std::string line = make_log_line(level, message);
  std::lock_guard<std::mutex> lock(g_log_mutex);
  std::cerr << line;
  std::cerr.flush();
  if (g_log_fd >= 0) {
    append_ignore_errors(g_log_fd, line);
  }
}

std::string errno_string() { return std::strerror(errno); }

void write_all(int fd, const void* data, size_t size) {
  const auto* p = static_cast<const uint8_t*>(data);
  size_t remaining = size;
  while (remaining > 0) {
    const ssize_t n = ::write(fd, p, remaining);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw std::runtime_error("write failed: " + errno_string());
    }
    if (n == 0) {
      throw std::runtime_error("write returned 0");
    }
    p += static_cast<size_t>(n);
    remaining -= static_cast<size_t>(n);
  }
}

}  // namespace

void set_log_verbose(bool verbose) { g_verbose = verbose; }
bool log_verbose_enabled() { return g_verbose; }

void log_info(const std::string& message) { log_line("INFO", message); }
void log_warn(const std::string& message) { log_line("WARN", message); }
void log_error(const std::string& message) { log_line("ERROR", message); }

void log_debug(const std::string& message) {
  if (g_verbose) {
    log_line("DEBUG", message);
  }
}

void configure_logging(const std::string& dir) {
  if (dir.empty()) {
    return;
  }
  try {
    ensure_dir(dir, 0755);
  } catch (const std::exception& e) {
    std::cerr << "failed to create log directory " << dir << ": " << e.what()
              << std::endl;
    return;
  }
  const int server_fd = open_append_log(join_path(dir, "server.log"));
  const int ota_fd = open_append_log(join_path(dir, "ota.log"));
  std::lock_guard<std::mutex> lock(g_log_mutex);
  if (g_log_fd >= 0) {
    ::close(g_log_fd);
  }
  if (g_upgrade_log_fd >= 0) {
    ::close(g_upgrade_log_fd);
  }
  g_log_fd = server_fd;
  g_upgrade_log_fd = ota_fd;
  if (server_fd < 0 || ota_fd < 0) {
    std::cerr << "failed to open log files under " << dir << std::endl;
  }
}

void log_upgrade(const std::string& message) {
  const std::string line = make_log_line("OTA", message);
  std::lock_guard<std::mutex> lock(g_upgrade_mutex);
  if (g_upgrade_log_fd >= 0) {
    append_ignore_errors(g_upgrade_log_fd, line);
  }
}

std::string now_rfc3339() {
  const std::time_t t = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buffer[32];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buffer);
}

int64_t now_unix_seconds() {
  return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count());
}

Bytes random_bytes(size_t count) {
  Bytes out(count);
  int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("open(/dev/urandom) failed: " + errno_string());
  }
  size_t done = 0;
  while (done < count) {
    const ssize_t n = ::read(fd, out.data() + done, count - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      ::close(fd);
      throw std::runtime_error("read(/dev/urandom) failed: " + errno_string());
    }
    if (n == 0) {
      ::close(fd);
      throw std::runtime_error("short read from /dev/urandom");
    }
    done += static_cast<size_t>(n);
  }
  ::close(fd);
  return out;
}

std::string random_hex(size_t byte_count) {
  const Bytes bytes = random_bytes(byte_count);
  return to_hex(bytes);
}

std::string to_hex(const uint8_t* data, size_t size) {
  static const char* kDigits = "0123456789abcdef";
  std::string out;
  out.resize(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out[2 * i] = kDigits[data[i] >> 4];
    out[2 * i + 1] = kDigits[data[i] & 0x0f];
  }
  return out;
}

std::string to_hex(const Bytes& data) { return to_hex(data.data(), data.size()); }

bool is_lower_hex(const std::string& value, size_t expected_chars) {
  if (value.size() != expected_chars) {
    return false;
  }
  for (char c : value) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool constant_time_equal(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) {
    return false;
  }
  return constant_time_equal(reinterpret_cast<const uint8_t*>(a.data()),
                             reinterpret_cast<const uint8_t*>(b.data()), a.size());
}

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t size) {
  uint8_t diff = 0;
  for (size_t i = 0; i < size; ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

bool parse_u64(const std::string& text, uint64_t* out) {
  if (text.empty() || text.size() > 20) {
    return false;
  }
  uint64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    const uint64_t digit = static_cast<uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  *out = value;
  return true;
}

bool file_exists(const std::string& path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

uint64_t file_size_or_throw(const std::string& path) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) {
    throw std::runtime_error("stat(" + path + ") failed: " + errno_string());
  }
  if (!S_ISREG(st.st_mode)) {
    throw std::runtime_error(path + " is not a regular file");
  }
  return static_cast<uint64_t>(st.st_size);
}

void ensure_dir(const std::string& path, unsigned int mode) {
  if (path.empty() || path == "/") {
    return;
  }
  const std::string parent = dir_name(path);
  if (!parent.empty() && parent != path) {
    ensure_dir(parent, mode);
  }
  if (::mkdir(path.c_str(), static_cast<mode_t>(mode)) != 0 && errno != EEXIST) {
    throw std::runtime_error("mkdir(" + path + ") failed: " + errno_string());
  }
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
    throw std::runtime_error(path + " is not a directory");
  }
}

void fsync_dir(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("open dir(" + path + ") failed: " + errno_string());
  }
  if (::fsync(fd) != 0) {
    const std::string message = errno_string();
    ::close(fd);
    throw std::runtime_error("fsync dir(" + path + ") failed: " + message);
  }
  ::close(fd);
}

void fsync_file(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("open(" + path + ") failed: " + errno_string());
  }
  if (::fsync(fd) != 0) {
    const std::string message = errno_string();
    ::close(fd);
    throw std::runtime_error("fsync(" + path + ") failed: " + message);
  }
  ::close(fd);
}

void write_file_atomic(const std::string& path, const void* data, size_t size,
                       unsigned int mode) {
  const std::string tmp = path + ".tmp." + random_hex(8);
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  static_cast<mode_t>(mode));
  if (fd < 0) {
    throw std::runtime_error("open(" + tmp + ") failed: " + errno_string());
  }
  try {
    if (::fchmod(fd, static_cast<mode_t>(mode)) != 0) {
      throw std::runtime_error("fchmod(" + tmp + ") failed: " + errno_string());
    }
    write_all(fd, data, size);
    if (::fsync(fd) != 0) {
      throw std::runtime_error("fsync(" + tmp + ") failed: " + errno_string());
    }
    ::close(fd);
    fd = -1;
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
      throw std::runtime_error("rename(" + tmp + " -> " + path +
                               ") failed: " + errno_string());
    }
    fsync_dir(dir_name(path));
  } catch (...) {
    if (fd >= 0) {
      ::close(fd);
    }
    ::unlink(tmp.c_str());
    throw;
  }
}

void write_file_atomic(const std::string& path, const std::string& data,
                       unsigned int mode) {
  write_file_atomic(path, data.data(), data.size(), mode);
}

Bytes read_file_limited(const std::string& path, size_t max_bytes) {
  const uint64_t size = file_size_or_throw(path);
  if (size > max_bytes) {
    throw std::runtime_error("file " + path + " exceeds size limit");
  }
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("open(" + path + ") failed: " + errno_string());
  }
  Bytes out(static_cast<size_t>(size));
  size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::read(fd, out.data() + done, out.size() - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      const std::string message = errno_string();
      ::close(fd);
      throw std::runtime_error("read(" + path + ") failed: " + message);
    }
    if (n == 0) {
      break;
    }
    done += static_cast<size_t>(n);
  }
  ::close(fd);
  out.resize(done);
  return out;
}

std::string read_text_file_limited(const std::string& path, size_t max_bytes) {
  const Bytes bytes = read_file_limited(path, max_bytes);
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

void remove_file_if_exists(const std::string& path) {
  if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
    log_warn("unlink(" + path + ") failed: " + errno_string());
  }
}

std::string join_path(const std::string& a, const std::string& b) {
  if (a.empty()) {
    return b;
  }
  if (b.empty()) {
    return a;
  }
  if (a.back() == '/') {
    return a + b;
  }
  return a + "/" + b;
}

std::string dir_name(const std::string& path) {
  const size_t pos = path.find_last_of('/');
  if (pos == std::string::npos) {
    return ".";
  }
  if (pos == 0) {
    return "/";
  }
  return path.substr(0, pos);
}

std::string base_name(const std::string& path) {
  const size_t pos = path.find_last_of('/');
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

std::string absolute_path(const std::string& path) {
  if (!path.empty() && path[0] == '/') {
    return path;
  }
  char cwd[4096];
  if (::getcwd(cwd, sizeof(cwd)) == nullptr) {
    throw std::runtime_error("getcwd failed: " + errno_string());
  }
  return join_path(std::string(cwd), path);
}

}  // namespace robot_ota
