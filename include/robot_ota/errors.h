#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace robot_ota {

// An error that maps directly onto the documented HTTP error schema:
//   {"error": {"code": "...", "message": "..."}}
class OtaError : public std::runtime_error {
 public:
  OtaError(int http_status, std::string code, const std::string& message)
      : std::runtime_error(message),
        http_status_(http_status),
        code_(std::move(code)) {}

  int http_status() const noexcept { return http_status_; }
  const std::string& code() const noexcept { return code_; }

 private:
  int http_status_;
  std::string code_;
};

// Low-level cryptographic failure. Callers translate this into a session
// result (VERIFY_FAILED) rather than exposing internals to the client.
class CryptoError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

}  // namespace robot_ota
