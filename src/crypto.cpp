#include "robot_ota/crypto.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <stdexcept>

#include "robot_ota/errors.h"

namespace robot_ota {
namespace {

constexpr size_t kIoBuffer = 1024 * 1024;

std::string openssl_errors() {
  std::string out;
  unsigned long code = 0;
  while ((code = ERR_get_error()) != 0) {
    char buffer[256];
    ERR_error_string_n(code, buffer, sizeof(buffer));
    if (!out.empty()) {
      out += "; ";
    }
    out += buffer;
  }
  return out.empty() ? "unknown OpenSSL error" : out;
}

std::string errno_string() { return std::strerror(errno); }

void write_all_fd(int fd, const uint8_t* data, size_t size) {
  size_t done = 0;
  while (done < size) {
    const ssize_t n = ::write(fd, data + done, size - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw CryptoError("write failed: " + errno_string());
    }
    if (n == 0) {
      throw CryptoError("write returned 0");
    }
    done += static_cast<size_t>(n);
  }
}

Bytes mgf1_sha256(const Bytes& seed, size_t out_length) {
  Bytes out;
  out.reserve(out_length);
  for (uint32_t counter = 0; out.size() < out_length; ++counter) {
    Bytes input = seed;
    input.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
    input.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
    input.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
    input.push_back(static_cast<uint8_t>(counter & 0xFF));
    const Sha256Digest digest = sha256(input);
    const size_t needed = std::min<size_t>(digest.size(), out_length - out.size());
    out.insert(out.end(), digest.begin(), digest.begin() + needed);
  }
  return out;
}

void xor_in_place(Bytes* target, const Bytes& mask) {
  if (target->size() != mask.size()) {
    throw CryptoError("internal XOR size mismatch");
  }
  for (size_t i = 0; i < target->size(); ++i) {
    (*target)[i] = static_cast<uint8_t>((*target)[i] ^ mask[i]);
  }
}

Bytes bn_to_bytes(const BIGNUM* bn, size_t width) {
  if (bn == nullptr) {
    throw CryptoError("null BIGNUM");
  }
  const int bytes = BN_num_bytes(bn);
  if (bytes < 0 || static_cast<size_t>(bytes) > width) {
    throw CryptoError("BIGNUM does not fit the requested width");
  }
  Bytes out(width, 0);
  const int written = BN_bn2bin(bn, out.data() + (width - static_cast<size_t>(bytes)));
  if (written != bytes) {
    throw CryptoError("BN_bn2bin wrote an unexpected length");
  }
  return out;
}

std::string public_key_spki_sha256(EVP_PKEY* key) {
  unsigned char* der = nullptr;
  const int length = i2d_PUBKEY(key, &der);
  if (length <= 0) {
    throw CryptoError("i2d_PUBKEY failed: " + openssl_errors());
  }
  const Sha256Digest digest = sha256(der, static_cast<size_t>(length));
  OPENSSL_free(der);
  return to_hex(digest.data(), digest.size());
}

void verify_with_pkey(EVP_PKEY* key, const std::string& scheme,
                      const uint8_t* data, size_t size, const uint8_t* signature,
                      size_t signature_size) {
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  if (md == nullptr) {
    throw CryptoError("EVP_MD_CTX_new failed");
  }
  struct MdDeleter {
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
  };
  std::unique_ptr<EVP_MD_CTX, MdDeleter> md_guard(md);

  EVP_PKEY_CTX* pctx = nullptr;
  if (EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), nullptr, key) != 1) {
    throw CryptoError("EVP_DigestVerifyInit failed: " + openssl_errors());
  }
  if (scheme == "RSA_PSS_SHA256") {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
      throw CryptoError("failed to configure RSA-PSS: " + openssl_errors());
    }
  } else {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1) {
      throw CryptoError("failed to configure RSA PKCS#1 v1.5: " + openssl_errors());
    }
  }

  const uint8_t dummy = 0;
  if (EVP_DigestVerifyUpdate(md, size == 0 ? &dummy : data, size) != 1) {
    throw CryptoError("EVP_DigestVerifyUpdate failed: " + openssl_errors());
  }
  const int rc = EVP_DigestVerifyFinal(md, signature, signature_size);
  if (rc != 1) {
    throw CryptoError("signature verification failed");
  }
}

int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

struct PkeyDeleter {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct X509Deleter {
  void operator()(X509* p) const { X509_free(p); }
};
struct StoreDeleter {
  void operator()(X509_STORE* p) const { X509_STORE_free(p); }
};
struct StoreCtxDeleter {
  void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); }
};
struct BioDeleter {
  void operator()(BIO* p) const { BIO_free(p); }
};
struct RsaDeleter {
  void operator()(RSA* p) const { RSA_free(p); }
};
struct CipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};

int no_password_callback(char*, int, int, void*) { return 0; }

class SoftwareDeviceKey final : public IDeviceKey {
 public:
  explicit SoftwareDeviceKey(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (bio == nullptr) {
      throw CryptoError("cannot open device private key: " + path);
    }
    std::unique_ptr<BIO, BioDeleter> bio_guard(bio);
    pkey_ = PEM_read_bio_PrivateKey(bio, nullptr, no_password_callback, nullptr);
    if (pkey_ == nullptr) {
      throw CryptoError("failed to parse PEM private key " + path + ": " +
                        openssl_errors());
    }
    std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey_guard(pkey_);
    if (EVP_PKEY_base_id(pkey_) != EVP_PKEY_RSA) {
      throw CryptoError("device private key is not an RSA key");
    }
    rsa_ = EVP_PKEY_get1_RSA(pkey_);
    if (rsa_ == nullptr) {
      throw CryptoError("EVP_PKEY_get1_RSA failed: " + openssl_errors());
    }
    const int size = RSA_size(rsa_);
    if (size < 256 || size > 512) {
      throw CryptoError("device RSA key must be 2048..4096 bits");
    }
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa_, &n, &e, nullptr);
    modulus_ = bn_to_bytes(n, static_cast<size_t>(size));
    exponent_ = bn_to_bytes(e, static_cast<size_t>(BN_num_bytes(e)));
    spki_ = public_key_spki_sha256(pkey_);
    pkey_guard.release();
  }

  ~SoftwareDeviceKey() override {
    if (rsa_ != nullptr) {
      RSA_free(rsa_);
    }
    if (pkey_ != nullptr) {
      EVP_PKEY_free(pkey_);
    }
  }

  size_t modulus_bytes() const override { return modulus_.size(); }
  Bytes modulus() const override { return modulus_; }
  Bytes exponent() const override { return exponent_; }
  std::string spki_sha256() const override { return spki_; }

  Bytes raw_private(const Bytes& input) override {
    if (input.size() != modulus_.size()) {
      throw CryptoError("raw RSA input length does not match the modulus");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes output(modulus_.size());
    const int written = RSA_private_encrypt(static_cast<int>(input.size()),
                                            input.data(), output.data(), rsa_,
                                            RSA_NO_PADDING);
    if (written != static_cast<int>(output.size())) {
      throw CryptoError("RSA raw private operation failed: " + openssl_errors());
    }
    return output;
  }

 private:
  EVP_PKEY* pkey_ = nullptr;
  RSA* rsa_ = nullptr;
  Bytes modulus_;
  Bytes exponent_;
  std::string spki_;
  std::mutex mutex_;
};

}  // namespace

std::string base64_encode(const uint8_t* data, size_t size) {
  static const char* kTable =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((size + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= size) {
    const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8) |
                       static_cast<uint32_t>(data[i + 2]);
    out.push_back(kTable[(v >> 18) & 0x3F]);
    out.push_back(kTable[(v >> 12) & 0x3F]);
    out.push_back(kTable[(v >> 6) & 0x3F]);
    out.push_back(kTable[v & 0x3F]);
    i += 3;
  }
  if (size - i == 1) {
    const uint32_t v = static_cast<uint32_t>(data[i]) << 16;
    out.push_back(kTable[(v >> 18) & 0x3F]);
    out.push_back(kTable[(v >> 12) & 0x3F]);
    out += "==";
  } else if (size - i == 2) {
    const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8);
    out.push_back(kTable[(v >> 18) & 0x3F]);
    out.push_back(kTable[(v >> 12) & 0x3F]);
    out.push_back(kTable[(v >> 6) & 0x3F]);
    out.push_back('=');
  }
  return out;
}

std::string base64_encode(const Bytes& data) {
  return base64_encode(data.data(), data.size());
}

Bytes base64_decode_strict(const std::string& text) {
  if (text.empty()) {
    return {};
  }
  if (text.size() % 4 != 0) {
    throw CryptoError("invalid base64 length");
  }
  Bytes out;
  out.reserve((text.size() / 4) * 3);
  for (size_t i = 0; i < text.size(); i += 4) {
    const bool last = (i + 4 == text.size());
    const char c0 = text[i];
    const char c1 = text[i + 1];
    const char c2 = text[i + 2];
    const char c3 = text[i + 3];
    if (c0 == '=' || c1 == '=') {
      throw CryptoError("invalid base64 padding");
    }
    const int v0 = base64_value(c0);
    const int v1 = base64_value(c1);
    if (v0 < 0 || v1 < 0) {
      throw CryptoError("invalid base64 character");
    }
    out.push_back(static_cast<uint8_t>((v0 << 2) | (v1 >> 4)));
    if (c2 == '=') {
      if (!last || c3 != '=' || (v1 & 0x0F) != 0) {
        throw CryptoError("invalid base64 padding");
      }
      continue;
    }
    const int v2 = base64_value(c2);
    if (v2 < 0) {
      throw CryptoError("invalid base64 character");
    }
    out.push_back(static_cast<uint8_t>(((v1 & 0x0F) << 4) | (v2 >> 2)));
    if (c3 == '=') {
      if (!last || (v2 & 0x03) != 0) {
        throw CryptoError("invalid base64 padding");
      }
      continue;
    }
    const int v3 = base64_value(c3);
    if (v3 < 0) {
      throw CryptoError("invalid base64 character");
    }
    out.push_back(static_cast<uint8_t>(((v2 & 0x03) << 6) | v3));
  }
  return out;
}

Sha256Digest sha256(const uint8_t* data, size_t size) {
  Sha256Digest out{};
  unsigned int length = 0;
  const uint8_t dummy = 0;
  if (EVP_Digest(size == 0 ? &dummy : data, size, out.data(), &length,
                 EVP_sha256(), nullptr) != 1 ||
      length != out.size()) {
    throw CryptoError("SHA-256 failed: " + openssl_errors());
  }
  return out;
}

Sha256Digest sha256(const Bytes& data) {
  return sha256(data.data(), data.size());
}

std::string sha256_hex(const std::string& data) {
  const Sha256Digest digest =
      sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
  return to_hex(digest.data(), digest.size());
}

HashedFile sha256_file(const std::string& path, uint64_t max_bytes) {
  const uint64_t size = file_size_or_throw(path);
  if (size > max_bytes) {
    throw CryptoError("file exceeds the allowed size");
  }
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    throw CryptoError("open(" + path + ") failed: " + errno_string());
  }
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  if (md == nullptr) {
    ::close(fd);
    throw CryptoError("EVP_MD_CTX_new failed");
  }
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_guard(md,
                                                                  EVP_MD_CTX_free);
  if (EVP_DigestInit_ex(md, EVP_sha256(), nullptr) != 1) {
    ::close(fd);
    throw CryptoError("EVP_DigestInit_ex failed: " + openssl_errors());
  }
  std::vector<uint8_t> buffer(kIoBuffer);
  uint64_t total = 0;
  HashedFile result;
  try {
    for (;;) {
      const ssize_t n = ::read(fd, buffer.data(), buffer.size());
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw CryptoError("read(" + path + ") failed: " + errno_string());
      }
      if (n == 0) {
        break;
      }
      total += static_cast<uint64_t>(n);
      if (total > max_bytes) {
        throw CryptoError("file grew past the allowed size");
      }
      if (EVP_DigestUpdate(md, buffer.data(), static_cast<size_t>(n)) != 1) {
        throw CryptoError("EVP_DigestUpdate failed");
      }
    }
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(md, result.hash.data(), &length) != 1 ||
        length != result.hash.size()) {
      throw CryptoError("EVP_DigestFinal_ex failed");
    }
  } catch (...) {
    ::close(fd);
    throw;
  }
  ::close(fd);
  result.size = total;
  return result;
}

GcmResult aes256_gcm_decrypt_file(const std::string& input_path,
                                  const std::string& output_path,
                                  const Sha256Digest& key, const Bytes& nonce,
                                  const Bytes& tag,
                                  uint64_t max_plaintext_bytes) {
  if (nonce.size() != 12) {
    throw CryptoError("AES-GCM nonce must be 12 bytes");
  }
  if (tag.size() != 16) {
    throw CryptoError("AES-GCM tag must be 16 bytes");
  }
  const int in_fd = ::open(input_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (in_fd < 0) {
    throw CryptoError("open(" + input_path + ") failed: " + errno_string());
  }
  const int out_fd =
      ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (out_fd < 0) {
    ::close(in_fd);
    throw CryptoError("open(" + output_path + ") failed: " + errno_string());
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  if (ctx == nullptr || md == nullptr) {
    if (ctx != nullptr) {
      EVP_CIPHER_CTX_free(ctx);
    }
    if (md != nullptr) {
      EVP_MD_CTX_free(md);
    }
    ::close(in_fd);
    ::close(out_fd);
    ::unlink(output_path.c_str());
    throw CryptoError("failed to allocate OpenSSL contexts");
  }

  GcmResult result;
  bool ok = false;
  try {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
      throw CryptoError("AES-GCM initialization failed: " + openssl_errors());
    }
    if (EVP_DigestInit_ex(md, EVP_sha256(), nullptr) != 1) {
      throw CryptoError("SHA-256 initialization failed");
    }

    std::vector<uint8_t> in_buffer(kIoBuffer);
    std::vector<uint8_t> out_buffer(kIoBuffer + 32);
    uint64_t total = 0;
    for (;;) {
      const ssize_t n = ::read(in_fd, in_buffer.data(), in_buffer.size());
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw CryptoError("read(" + input_path + ") failed: " + errno_string());
      }
      if (n == 0) {
        break;
      }
      int out_length = 0;
      if (EVP_DecryptUpdate(ctx, out_buffer.data(), &out_length, in_buffer.data(),
                            static_cast<int>(n)) != 1) {
        throw CryptoError("AES-GCM decrypt failed: " + openssl_errors());
      }
      if (out_length > 0) {
        total += static_cast<uint64_t>(out_length);
        if (total > max_plaintext_bytes) {
          throw CryptoError("plaintext exceeds the allowed size");
        }
        write_all_fd(out_fd, out_buffer.data(), static_cast<size_t>(out_length));
        if (EVP_DigestUpdate(md, out_buffer.data(),
                             static_cast<size_t>(out_length)) != 1) {
          throw CryptoError("SHA-256 update failed");
        }
      }
    }

    // The tag is stored outside the ciphertext file, so verify it explicitly.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            const_cast<uint8_t*>(tag.data())) != 1) {
      throw CryptoError("failed to set the AES-GCM tag");
    }
    int final_length = 0;
    if (EVP_DecryptFinal_ex(ctx, out_buffer.data(), &final_length) != 1) {
      throw CryptoError("AES-GCM authentication tag mismatch");
    }
    if (final_length > 0) {
      total += static_cast<uint64_t>(final_length);
      write_all_fd(out_fd, out_buffer.data(), static_cast<size_t>(final_length));
      if (EVP_DigestUpdate(md, out_buffer.data(),
                           static_cast<size_t>(final_length)) != 1) {
        throw CryptoError("SHA-256 final update failed");
      }
    }
    unsigned int hash_length = 0;
    if (EVP_DigestFinal_ex(md, result.plaintext_sha256.data(), &hash_length) != 1 ||
        hash_length != result.plaintext_sha256.size()) {
      throw CryptoError("SHA-256 finalization failed");
    }
    result.plaintext_size = total;
    if (::fsync(out_fd) != 0) {
      throw CryptoError("fsync(" + output_path + ") failed: " + errno_string());
    }
    ok = true;
  } catch (...) {
    EVP_CIPHER_CTX_free(ctx);
    EVP_MD_CTX_free(md);
    ::close(in_fd);
    ::close(out_fd);
    ::unlink(output_path.c_str());
    throw;
  }
  EVP_CIPHER_CTX_free(ctx);
  EVP_MD_CTX_free(md);
  ::close(in_fd);
  ::close(out_fd);
  if (!ok) {
    ::unlink(output_path.c_str());
  }
  return result;
}

Bytes oaep_sha256_decode(const Bytes& encoded_message, const Bytes& modulus) {
  constexpr size_t kHashLength = 32;
  const size_t k = modulus.size();
  if (k < 2 * kHashLength + 2) {
    throw CryptoError("RSA modulus is too small for OAEP-SHA256");
  }
  if (encoded_message.size() != k) {
    throw CryptoError("OAEP encoded message length does not match the modulus");
  }
  if (encoded_message[0] != 0x00) {
    throw CryptoError("OAEP encoded message has a non-zero leading byte");
  }

  Bytes masked_seed(encoded_message.begin() + 1,
                    encoded_message.begin() + 1 + kHashLength);
  Bytes masked_db(encoded_message.begin() + 1 + kHashLength,
                  encoded_message.end());
  if (masked_db.size() != k - kHashLength - 1) {
    throw CryptoError("OAEP masked DB length is invalid");
  }

  const Bytes seed_mask = mgf1_sha256(masked_db, kHashLength);
  Bytes seed = masked_seed;
  xor_in_place(&seed, seed_mask);

  const Bytes db_mask = mgf1_sha256(seed, k - kHashLength - 1);
  Bytes db = masked_db;
  xor_in_place(&db, db_mask);

  const Sha256Digest label_hash = sha256(nullptr, 0);
  if (!constant_time_equal(db.data(), label_hash.data(), kHashLength)) {
    throw CryptoError("OAEP label hash mismatch");
  }

  size_t index = kHashLength;
  while (index < db.size() && db[index] == 0x00) {
    ++index;
  }
  if (index >= db.size() || db[index] != 0x01) {
    throw CryptoError("OAEP padding is invalid");
  }
  return Bytes(db.begin() + static_cast<std::ptrdiff_t>(index + 1), db.end());
}

struct CertVerifier::Impl {
  X509_STORE* store = nullptr;
  bool check_time = true;

  ~Impl() {
    if (store != nullptr) {
      X509_STORE_free(store);
    }
  }
};

CertVerifier::CertVerifier(const std::string& ca_file,
                           const std::vector<Bytes>& extra_ca_certs,
                           bool check_time)
    : impl_(new Impl()) {
  impl_->check_time = check_time;
  impl_->store = X509_STORE_new();
  if (impl_->store == nullptr) {
    throw CryptoError("X509_STORE_new failed");
  }

  bool have_ca = false;
  if (!ca_file.empty()) {
    if (X509_STORE_load_locations(impl_->store, ca_file.c_str(), nullptr) != 1) {
      throw CryptoError("failed to load platform CA file " + ca_file + ": " +
                        openssl_errors());
    }
    have_ca = true;
  }

  for (const Bytes& cert_der : extra_ca_certs) {
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
    if (cert == nullptr) {
      throw CryptoError("failed to parse an exported CA certificate: " +
                        openssl_errors());
    }
    std::unique_ptr<X509, X509Deleter> cert_guard(cert);
    if (X509_STORE_add_cert(impl_->store, cert) != 1) {
      // A duplicate certificate is harmless; clear the error and continue.
      log_warn("X509_STORE_add_cert failed (possibly a duplicate): " +
               openssl_errors());
    } else {
      have_ca = true;
    }
  }

  if (!have_ca) {
    throw CryptoError("no platform CA certificate is available");
  }
}

CertVerifier::~CertVerifier() = default;

void CertVerifier::verify(const Bytes& leaf_der, const std::string& scheme,
                          const uint8_t* data, size_t size,
                          const uint8_t* signature,
                          size_t signature_size) const {
  const unsigned char* p = leaf_der.data();
  X509* leaf = d2i_X509(nullptr, &p, static_cast<long>(leaf_der.size()));
  if (leaf == nullptr) {
    throw CryptoError("failed to parse signer certificate: " + openssl_errors());
  }
  std::unique_ptr<X509, X509Deleter> leaf_guard(leaf);

  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  if (ctx == nullptr) {
    throw CryptoError("X509_STORE_CTX_new failed");
  }
  std::unique_ptr<X509_STORE_CTX, StoreCtxDeleter> ctx_guard(ctx);
  if (X509_STORE_CTX_init(ctx, impl_->store, leaf, nullptr) != 1) {
    throw CryptoError("X509_STORE_CTX_init failed");
  }
  if (!impl_->check_time) {
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);
  }
  // The configured platform CA is the trust anchor. It may itself have been
  // issued by a root that is not shipped in the bundle (the manifest bundle
  // only carries the signer leaf), so accept a chain that terminates at it.
  X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
  if (X509_verify_cert(ctx) != 1) {
    const int error = X509_STORE_CTX_get_error(ctx);
    throw CryptoError(std::string("signer certificate chain rejected: ") +
                      X509_verify_cert_error_string(error));
  }

  EVP_PKEY* public_key = X509_get_pubkey(leaf);
  if (public_key == nullptr) {
    throw CryptoError("failed to extract the signer public key");
  }
  std::unique_ptr<EVP_PKEY, PkeyDeleter> key_guard(public_key);
  if (EVP_PKEY_base_id(public_key) != EVP_PKEY_RSA) {
    throw CryptoError("signer certificate does not contain an RSA key");
  }
  const int bits = EVP_PKEY_bits(public_key);
  if (bits < 2048 || bits > 4096) {
    throw CryptoError("signer RSA key size is outside [2048, 4096] bits");
  }
  verify_with_pkey(public_key, scheme, data, size, signature, signature_size);
}

std::unique_ptr<IDeviceKey> make_software_device_key(const std::string& pem_path) {
  return std::unique_ptr<IDeviceKey>(new SoftwareDeviceKey(pem_path));
}

std::string rsa_public_key_pem(const Bytes& modulus, const Bytes& exponent) {
  if (modulus.empty() || exponent.empty()) {
    throw CryptoError("cannot serialize an empty RSA public key");
  }
  BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
  BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);
  if (n == nullptr || e == nullptr) {
    BN_free(n);
    BN_free(e);
    throw CryptoError("BN_bin2bn failed: " + openssl_errors());
  }
  RSA* rsa = RSA_new();
  if (rsa == nullptr) {
    BN_free(n);
    BN_free(e);
    throw CryptoError("RSA_new failed: " + openssl_errors());
  }
  if (RSA_set0_key(rsa, n, e, nullptr) != 1) {
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
    throw CryptoError("RSA_set0_key failed: " + openssl_errors());
  }
  // RSA_set0_key took ownership of n and e.
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == nullptr || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    throw CryptoError("EVP_PKEY_assign_RSA failed: " + openssl_errors());
  }
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == nullptr) {
    EVP_PKEY_free(pkey);
    throw CryptoError("BIO_new failed: " + openssl_errors());
  }
  if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    throw CryptoError("PEM_write_bio_PUBKEY failed: " + openssl_errors());
  }
  char* data = nullptr;
  const long length = BIO_get_mem_data(bio, &data);
  std::string pem = length > 0 ? std::string(data, static_cast<size_t>(length)) : "";
  BIO_free(bio);
  EVP_PKEY_free(pkey);
  if (pem.empty()) {
    throw CryptoError("PEM serialization produced an empty key");
  }
  return pem;
}

}  // namespace robot_ota
