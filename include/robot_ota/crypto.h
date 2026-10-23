#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "robot_ota/util.h"

namespace robot_ota {

using Sha256Digest = std::array<uint8_t, 32>;

std::string base64_encode(const uint8_t* data, size_t size);
std::string base64_encode(const Bytes& data);
// Strict standard Base64: no whitespace, canonical padding bits required.
Bytes base64_decode_strict(const std::string& text);

Sha256Digest sha256(const uint8_t* data, size_t size);
Sha256Digest sha256(const Bytes& data);
std::string sha256_hex(const std::string& data);

struct HashedFile {
  uint64_t size = 0;
  Sha256Digest hash{};
};
// Streams the file. Throws if it is larger than max_bytes.
HashedFile sha256_file(const std::string& path, uint64_t max_bytes);

struct GcmResult {
  uint64_t plaintext_size = 0;
  Sha256Digest plaintext_sha256{};
};

// AES-256-GCM with an empty AAD. Decrypts input_path into output_path while
// computing the plaintext SHA-256. The output file is removed if anything
// fails (including tag verification).
GcmResult aes256_gcm_decrypt_file(const std::string& input_path,
                                  const std::string& output_path,
                                  const Sha256Digest& key, const Bytes& nonce,
                                  const Bytes& tag,
                                  uint64_t max_plaintext_bytes);

// Software OAEP-SHA256 decode of an RSA raw-private result (EM). This is the
// exact operation performed after the SE returns EM for the raw RSA operation.
Bytes oaep_sha256_decode(const Bytes& encoded_message, const Bytes& modulus);

// Verifies a leaf certificate against a trust store and then verifies a
// signature made with the leaf key.
class CertVerifier {
 public:
  CertVerifier(const std::string& ca_file,
               const std::vector<Bytes>& extra_ca_certs, bool check_time);
  ~CertVerifier();
  CertVerifier(const CertVerifier&) = delete;
  CertVerifier& operator=(const CertVerifier&) = delete;

  // scheme: RSA_PKCS1_SHA256 or RSA_PSS_SHA256.
  void verify(const Bytes& leaf_der, const std::string& scheme,
              const uint8_t* data, size_t size, const uint8_t* signature,
              size_t signature_size) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Device RSA key abstraction. Production is backed by the SE (raw private
// operation only); development/tests use a PEM software key.
class IDeviceKey {
 public:
  virtual ~IDeviceKey() = default;
  virtual size_t modulus_bytes() const = 0;
  virtual Bytes modulus() const = 0;
  virtual Bytes exponent() const = 0;
  // Raw RSA private operation with no padding. Input and output are both
  // modulus_bytes() long.
  virtual Bytes raw_private(const Bytes& input) = 0;
  // Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo.
  virtual std::string spki_sha256() const = 0;
};

std::unique_ptr<IDeviceKey> make_software_device_key(const std::string& pem_path);

// Serializes an RSA public key (big-endian modulus and exponent) as a
// SubjectPublicKeyInfo PEM. Used to export the SE public key for the cloud,
// which must wrap the DEK to exactly this key.
std::string rsa_public_key_pem(const Bytes& modulus, const Bytes& exponent);

struct SeOptions {
  std::string lib_path;
  int key_index = 1;
  bool export_platform_ca = true;
};

// Loads libsesdk.so with dlopen/dlsym (same pattern as btgatt-server.c).
// If export_platform_ca is true, the platform/root CA certificates are
// exported from the SE into *exported_ca_certs (DER).
std::unique_ptr<IDeviceKey> make_se_device_key(
    const SeOptions& options, std::vector<Bytes>* exported_ca_certs);

}  // namespace robot_ota
