// Production device key backed by the platform SE.
//
// This follows the integration pattern used by btgatt-server.c:
//   dlopen("/unitree/lib/libsesdk.so") -> dlsym(...) -> SE_OpenDevice ->
//   SE_OpenSession -> SE_* operations.
//
// The SE only performs the raw RSA private operation. OAEP-SHA256 decoding is
// done in software (oaep_sha256_decode), exactly as required by the protocol.

#include <dlfcn.h>
#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "robot_ota/crypto.h"
#include "robot_ota/errors.h"
#include "robot_ota/util.h"

namespace robot_ota {
namespace {

// Minimal ABI-compatible declarations from se_sdk.h. We deliberately do not
// include the vendor header so the project can build without it; the struct
// layout and function signatures must stay in sync with se_sdk.h.
using SE_HANDLE = void*;

struct SeRsaPublicKey {
  unsigned int bits;
  unsigned char m[256];
  unsigned char e[256];
};

using SeOpenDeviceFn = int (*)(SE_HANDLE*);
using SeOpenSessionFn = int (*)(SE_HANDLE, SE_HANDLE*);
using SeCloseSessionFn = int (*)(SE_HANDLE);
using SeCloseDeviceFn = int (*)(SE_HANDLE);
using SeExportSignPublicKeyRsaFn = int (*)(SE_HANDLE, int, SeRsaPublicKey*);
using SeInternalPrivateKeyOperationRsaFn =
    int (*)(SE_HANDLE, int, unsigned char*, unsigned int, unsigned char*,
            unsigned int*);
using SeExportCertificateFn = int (*)(SE_HANDLE, int, unsigned char*, int*);
// BLE entry points. The OTA server does not call them; they are resolved only
// because the platform uses them as the standard "SE is usable" contract.
using SeBleGenKeyCipherFn = int (*)(SE_HANDLE, unsigned char*, unsigned int*);
using SeBleGetKeyFn =
    int (*)(SE_HANDLE, unsigned char*, unsigned int, unsigned char*,
            unsigned int*);

constexpr int kSeCertRootCaRsa = 0x01;
constexpr int kSeCertCaRsa = 0x02;
constexpr size_t kSeRsaMaxLen = 256;
constexpr size_t kSeCertBuffer = 16384;

// Factory image marker. Products without the secure element do not ship this
// file, and must not attempt to use the SE key.
constexpr const char* kSecChipStatusPath =
    "/unitree/robot/basic/sec_chip_status";

bool path_exists(const std::string& path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0;
}

std::string se_error(int code) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%08x", static_cast<unsigned int>(code));
  return buffer;
}

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

Bytes trim_left_zeros(const unsigned char* data, size_t size) {
  size_t start = 0;
  while (start < size && data[start] == 0) {
    ++start;
  }
  return Bytes(data + start, data + size);
}

std::string rsa_public_key_spki_sha256(const Bytes& modulus,
                                       const Bytes& exponent) {
  RSA* rsa = RSA_new();
  if (rsa == nullptr) {
    throw CryptoError("RSA_new failed");
  }
  BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
  BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);
  if (n == nullptr || e == nullptr || RSA_set0_key(rsa, n, e, nullptr) != 1) {
    if (n != nullptr) {
      BN_free(n);
    }
    if (e != nullptr) {
      BN_free(e);
    }
    RSA_free(rsa);
    throw CryptoError("failed to build the RSA public key: " + openssl_errors());
  }
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == nullptr || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
    if (pkey != nullptr) {
      EVP_PKEY_free(pkey);
    }
    RSA_free(rsa);
    throw CryptoError("EVP_PKEY_assign_RSA failed: " + openssl_errors());
  }
  unsigned char* der = nullptr;
  const int length = i2d_PUBKEY(pkey, &der);
  EVP_PKEY_free(pkey);
  if (length <= 0) {
    throw CryptoError("i2d_PUBKEY failed: " + openssl_errors());
  }
  const Sha256Digest digest = sha256(der, static_cast<size_t>(length));
  OPENSSL_free(der);
  return to_hex(digest.data(), digest.size());
}

// SE_ExportCertificate returns DER in current SDK builds; accept PEM too in
// case a vendor build returns the PEM encoding.
Bytes normalize_certificate(const Bytes& raw) {
  const std::string text(reinterpret_cast<const char*>(raw.data()), raw.size());
  if (text.find("-----BEGIN") == std::string::npos) {
    return raw;
  }
  BIO* bio = BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size()));
  if (bio == nullptr) {
    throw CryptoError("BIO_new_mem_buf failed");
  }
  X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (cert == nullptr) {
    throw CryptoError("failed to parse a PEM certificate exported by the SE");
  }
  unsigned char* der = nullptr;
  const int length = i2d_X509(cert, &der);
  X509_free(cert);
  if (length <= 0) {
    throw CryptoError("i2d_X509 failed");
  }
  Bytes out(der, der + length);
  OPENSSL_free(der);
  return out;
}

class SeDeviceKey final : public IDeviceKey {
 public:
  explicit SeDeviceKey(const SeOptions& options) : options_(options) {
    // Same gating as the rest of the robot software: only products whose
    // factory image carries sec_chip_status may touch the SE.
    if (!path_exists(kSecChipStatusPath)) {
      throw CryptoError(std::string("非安全芯片产品，不可用：") +
                        kSecChipStatusPath + " 不存在");
    }

    handle_ = dlopen(options.lib_path.c_str(), RTLD_LAZY | RTLD_LOCAL);
    if (handle_ == nullptr) {
      const char* detail = dlerror();
      throw CryptoError("dlopen(" + options.lib_path + ") 失败: " +
                        (detail == nullptr ? "unknown error" : detail));
    }

    // Platform availability contract: these four symbols decide whether the
    // secure element is usable at all. The BLE pair is not called by OTA, but
    // is part of the same check used by the rest of the robot software.
    open_device_ =
        reinterpret_cast<SeOpenDeviceFn>(dlsym(handle_, "SE_OpenDevice"));
    open_session_ =
        reinterpret_cast<SeOpenSessionFn>(dlsym(handle_, "SE_OpenSession"));
    ble_gen_key_cipher_ = reinterpret_cast<SeBleGenKeyCipherFn>(
        dlsym(handle_, "SE_BLE_GenKeyCipher"));
    ble_get_key_ =
        reinterpret_cast<SeBleGetKeyFn>(dlsym(handle_, "SE_BLE_GetKey"));

    std::string missing;
    const auto note_missing = [&missing](const char* name, bool present) {
      if (!present) {
        if (!missing.empty()) {
          missing += ", ";
        }
        missing += name;
      }
    };
    note_missing("SE_OpenDevice", open_device_ != nullptr);
    note_missing("SE_OpenSession", open_session_ != nullptr);
    note_missing("SE_BLE_GenKeyCipher", ble_gen_key_cipher_ != nullptr);
    note_missing("SE_BLE_GetKey", ble_get_key_ != nullptr);
    if (!missing.empty()) {
      cleanup();
      throw CryptoError("libsesdk.so 缺少符号: " + missing +
                        "；已回退，安全芯片不可用");
    }

    log_info("成功加载 libsesdk.so,将使用安全芯片功能");

    // OTA-specific entry points. These are required in addition to the
    // platform availability check.
    close_session_ =
        reinterpret_cast<SeCloseSessionFn>(dlsym(handle_, "SE_CloseSession"));
    close_device_ =
        reinterpret_cast<SeCloseDeviceFn>(dlsym(handle_, "SE_CloseDevice"));
    export_public_ = reinterpret_cast<SeExportSignPublicKeyRsaFn>(
        dlsym(handle_, "SE_ExportSignPublicKey_RSA"));
    private_operation_ = reinterpret_cast<SeInternalPrivateKeyOperationRsaFn>(
        dlsym(handle_, "SE_InternalPrivateKeyOperation_RSA"));
    export_certificate_ = reinterpret_cast<SeExportCertificateFn>(
        dlsym(handle_, "SE_ExportCertificate"));

    missing.clear();
    note_missing("SE_CloseSession", close_session_ != nullptr);
    note_missing("SE_CloseDevice", close_device_ != nullptr);
    note_missing("SE_ExportSignPublicKey_RSA", export_public_ != nullptr);
    note_missing("SE_InternalPrivateKeyOperation_RSA",
                 private_operation_ != nullptr);
    if (!missing.empty()) {
      cleanup();
      throw CryptoError("libsesdk.so 缺少 OTA 所需符号: " + missing +
                        "；安全芯片不可用");
    }

    int rc = open_device_(&device_);
    if (rc != 0) {
      cleanup();
      throw CryptoError("SE_OpenDevice failed, rv=" + se_error(rc));
    }
    rc = open_session_(device_, &session_);
    if (rc != 0) {
      cleanup();
      throw CryptoError("SE_OpenSession failed, rv=" + se_error(rc));
    }

    SeRsaPublicKey public_key{};
    rc = export_public_(session_, options_.key_index, &public_key);
    if (rc != 0) {
      cleanup();
      throw CryptoError("SE_ExportSignPublicKey_RSA failed, rv=" + se_error(rc) +
                        " (key_index=" + std::to_string(options_.key_index) + ")");
    }

    size_t modulus_bytes = kSeRsaMaxLen;
    if (public_key.bits >= 1024 && public_key.bits <= 2048) {
      modulus_bytes = (static_cast<size_t>(public_key.bits) + 7) / 8;
    } else if (public_key.bits > 2048) {
      cleanup();
      throw CryptoError("SE RSA key is larger than 2048 bits, which is not supported");
    }
    Bytes raw_modulus = trim_left_zeros(public_key.m, kSeRsaMaxLen);
    if (raw_modulus.size() > modulus_bytes) {
      modulus_bytes = raw_modulus.size();
    }
    if (modulus_bytes < 256 || modulus_bytes > 512) {
      cleanup();
      throw CryptoError("SE RSA modulus size is outside [2048, 4096] bits");
    }
    modulus_.assign(modulus_bytes, 0);
    std::copy(raw_modulus.begin(), raw_modulus.end(),
              modulus_.begin() + static_cast<std::ptrdiff_t>(modulus_bytes -
                                                             raw_modulus.size()));
    exponent_ = trim_left_zeros(public_key.e, kSeRsaMaxLen);
    if (exponent_.empty()) {
      cleanup();
      throw CryptoError("SE returned an empty RSA public exponent");
    }
    if (exponent_.size() > 8) {
      cleanup();
      throw CryptoError("SE returned an unexpectedly large RSA public exponent");
    }
    spki_ = rsa_public_key_spki_sha256(modulus_, exponent_);
  }

  ~SeDeviceKey() override { cleanup(); }

  size_t modulus_bytes() const override { return modulus_.size(); }
  Bytes modulus() const override { return modulus_; }
  Bytes exponent() const override { return exponent_; }
  std::string spki_sha256() const override { return spki_; }

  Bytes raw_private(const Bytes& input) override {
    if (input.size() != modulus_.size()) {
      throw CryptoError("wrapped DEK length does not match the SE modulus");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    unsigned char output[512] = {0};
    unsigned int output_length = sizeof(output);
    const int rc = private_operation_(
        session_, options_.key_index, const_cast<unsigned char*>(input.data()),
        static_cast<unsigned int>(input.size()), output, &output_length);
    if (rc != 0) {
      throw CryptoError("SE_InternalPrivateKeyOperation_RSA failed, rv=" +
                        se_error(rc));
    }
    if (output_length != modulus_.size()) {
      throw CryptoError("SE returned an unexpected RSA output length");
    }
    return Bytes(output, output + output_length);
  }

  std::vector<Bytes> export_ca_certificates() {
    std::vector<Bytes> certs;
    if (export_certificate_ == nullptr) {
      log_warn("libsesdk.so has no SE_ExportCertificate; relying on plat_ca_file");
      return certs;
    }
    const int types[] = {kSeCertRootCaRsa, kSeCertCaRsa};
    for (int type : types) {
      unsigned char buffer[kSeCertBuffer] = {0};
      int length = static_cast<int>(sizeof(buffer));
      const int rc = export_certificate_(session_, type, buffer, &length);
      if (rc != 0 || length <= 0 ||
          static_cast<size_t>(length) > sizeof(buffer)) {
        log_warn("SE_ExportCertificate(type=" + std::to_string(type) +
                 ") failed, rv=" + se_error(rc));
        continue;
      }
      try {
        certs.push_back(normalize_certificate(
            Bytes(buffer, buffer + static_cast<size_t>(length))));
      } catch (const std::exception& e) {
        log_warn(std::string("failed to normalize SE certificate: ") + e.what());
      }
    }
    return certs;
  }

 private:
  void cleanup() {
    if (session_ != nullptr && close_session_ != nullptr) {
      close_session_(session_);
      session_ = nullptr;
    }
    if (device_ != nullptr && close_device_ != nullptr) {
      close_device_(device_);
      device_ = nullptr;
    }
    if (handle_ != nullptr) {
      dlclose(handle_);
      handle_ = nullptr;
    }
  }

  SeOptions options_;
  void* handle_ = nullptr;
  SE_HANDLE device_ = nullptr;
  SE_HANDLE session_ = nullptr;
  SeOpenDeviceFn open_device_ = nullptr;
  SeOpenSessionFn open_session_ = nullptr;
  SeCloseSessionFn close_session_ = nullptr;
  SeCloseDeviceFn close_device_ = nullptr;
  SeExportSignPublicKeyRsaFn export_public_ = nullptr;
  SeInternalPrivateKeyOperationRsaFn private_operation_ = nullptr;
  SeExportCertificateFn export_certificate_ = nullptr;
  // Resolved only for the platform availability check; OTA never calls them.
  SeBleGenKeyCipherFn ble_gen_key_cipher_ = nullptr;
  SeBleGetKeyFn ble_get_key_ = nullptr;
  Bytes modulus_;
  Bytes exponent_;
  std::string spki_;
  std::mutex mutex_;
};

}  // namespace

std::unique_ptr<IDeviceKey> make_se_device_key(
    const SeOptions& options, std::vector<Bytes>* exported_ca_certs) {
  auto key = std::make_unique<SeDeviceKey>(options);
  if (options.export_platform_ca) {
    const std::vector<Bytes> certs = key->export_ca_certificates();
    if (exported_ca_certs != nullptr) {
      exported_ca_certs->insert(exported_ca_certs->end(), certs.begin(), certs.end());
    }
  }
  return std::unique_ptr<IDeviceKey>(key.release());
}

}  // namespace robot_ota
