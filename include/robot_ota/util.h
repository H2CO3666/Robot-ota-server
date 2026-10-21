#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace robot_ota {

using Bytes = std::vector<uint8_t>;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
void set_log_verbose(bool verbose);
bool log_verbose_enabled();
void log_info(const std::string& message);
void log_warn(const std::string& message);
void log_error(const std::string& message);
void log_debug(const std::string& message);

// ---------------------------------------------------------------------------
// Time / random / encoding
// ---------------------------------------------------------------------------
std::string now_rfc3339();
int64_t now_unix_seconds();

// Cryptographically strong random bytes from /dev/urandom.
Bytes random_bytes(size_t count);
std::string random_hex(size_t byte_count);

std::string to_hex(const uint8_t* data, size_t size);
std::string to_hex(const Bytes& data);
bool is_lower_hex(const std::string& value, size_t expected_chars);
bool constant_time_equal(const std::string& a, const std::string& b);
bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t size);

bool parse_u64(const std::string& text, uint64_t* out);

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------
bool file_exists(const std::string& path);
uint64_t file_size_or_throw(const std::string& path);
void ensure_dir(const std::string& path, unsigned int mode = 0700);
void fsync_dir(const std::string& path);
void fsync_file(const std::string& path);

// Writes to a temporary file in the same directory, fsyncs it, renames it over
// `path`, then fsyncs the directory. The file mode is applied before any data
// is written.
void write_file_atomic(const std::string& path, const void* data, size_t size,
                       unsigned int mode = 0600);
void write_file_atomic(const std::string& path, const std::string& data,
                       unsigned int mode = 0600);

Bytes read_file_limited(const std::string& path, size_t max_bytes);
std::string read_text_file_limited(const std::string& path, size_t max_bytes);
void remove_file_if_exists(const std::string& path);

std::string join_path(const std::string& a, const std::string& b);
std::string dir_name(const std::string& path);
std::string base_name(const std::string& path);
std::string absolute_path(const std::string& path);

}  // namespace robot_ota
