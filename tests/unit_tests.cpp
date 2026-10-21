#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <json/json.h>

#include "robot_ota/crypto.h"
#include "robot_ota/errors.h"
#include "robot_ota/jcs.h"
#include "robot_ota/manifest.h"
#include "robot_ota/util.h"

namespace {

int g_failures = 0;

void check(bool condition, const std::string& name) {
  if (!condition) {
    std::cerr << "FAIL: " << name << "\n";
    ++g_failures;
  }
}

void check_eq(const std::string& actual, const std::string& expected,
              const std::string& name) {
  if (actual != expected) {
    std::cerr << "FAIL: " << name << "\n  expected: [" << expected
              << "]\n  actual:   [" << actual << "]\n";
    ++g_failures;
  }
}

template <typename Fn>
void check_throws(Fn&& fn, const std::string& name) {
  try {
    fn();
  } catch (const std::exception&) {
    return;
  }
  std::cerr << "FAIL: expected an exception: " << name << "\n";
  ++g_failures;
}

std::string utf8_hex(const std::string& value) {
  return robot_ota::to_hex(
      reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

void test_jcs_object_ordering() {
  Json::Value value;
  value["b"] = 2;
  value["a"] = 1;
  check_eq(robot_ota::jcs_canonicalize(value), "{\"a\":1,\"b\":2}",
           "object keys are sorted");

  Json::Value order;
  order["\xE2\x82\xAC"] = "Euro Sign";
  order["\r"] = "Carriage Return";
  order["\xEF\xAC\xB3"] = "Hebrew Letter Dalet With Dagesh";
  order["1"] = "One";
  order["\xF0\x9F\x98\x80"] = "Emoji: Grinning Face";
  order["\xC2\x80"] = "Control";
  order["\xC3\xB6"] = "Latin Small Letter O With Diaeresis";

  const std::string expected =
      "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\xC2\x80\":\"Control\","
      "\"\xC3\xB6\":\"Latin Small Letter O With Diaeresis\","
      "\"\xE2\x82\xAC\":\"Euro Sign\",\"\xF0\x9F\x98\x80\":\"Emoji: Grinning Face\","
      "\"\xEF\xAC\xB3\":\"Hebrew Letter Dalet With Dagesh\"}";
  check_eq(robot_ota::jcs_canonicalize(order), expected,
           "keys are ordered by UTF-16 code units");
}

void test_jcs_scalars() {
  check_eq(robot_ota::jcs_canonicalize(Json::Value(42)), "42",
           "positive integer");
  check_eq(robot_ota::jcs_canonicalize(Json::Value(-7)), "-7",
           "negative integer");
  check_eq(robot_ota::jcs_canonicalize(
               Json::Value(static_cast<Json::UInt64>(18446744073709551615ULL))),
           "18446744073709551615", "uint64 integer");
  check_eq(robot_ota::jcs_canonicalize(Json::Value(true)), "true",
           "boolean true");
  check_eq(robot_ota::jcs_canonicalize(Json::Value(Json::nullValue)), "null",
           "null");

  check_throws([]() { robot_ota::jcs_canonicalize(Json::Value(1.5)); },
               "non-integral numbers are rejected");
  check_throws([]() { robot_ota::jcs_canonicalize(Json::Value(1e300)); },
               "large exponent numbers are rejected");
}

void test_jcs_strings() {
  std::string input = "q\"b\\";
  input.push_back('\n');
  input.push_back('\t');
  input.push_back('\b');
  input.push_back('\f');
  input.push_back('\r');
  input.push_back('\x00');
  input.push_back('\x1f');
  input += "\xC3\xB6";

  Json::Value value;
  value["s"] = input;
  const std::string expected =
      "{\"s\":\"q\\\"b\\\\\\n\\t\\b\\f\\r\\u0000\\u001f\xC3\xB6\"}";
  check_eq(robot_ota::jcs_canonicalize(value), expected,
           "minimal JSON escaping");

  // Invalid UTF-8 must be rejected, not silently replaced.
  std::string invalid("\xC3\x28", 2);
  check_throws([&]() {
    Json::Value bad;
    bad["s"] = invalid;
    robot_ota::jcs_canonicalize(bad);
  }, "invalid UTF-8 is rejected");
}

void test_base64() {
  const robot_ota::Bytes data = {'f', 'o', 'o'};
  check_eq(robot_ota::base64_encode(data), "Zm9v", "base64 encode");
  check_eq(robot_ota::base64_encode(robot_ota::Bytes{}), "",
           "base64 encode empty");

  const robot_ota::Bytes decoded = robot_ota::base64_decode_strict("Zm9vYmFy");
  check_eq(std::string(decoded.begin(), decoded.end()), "foobar",
           "base64 decode");

  const robot_ota::Bytes one_zero = robot_ota::base64_decode_strict("AA==");
  check(one_zero.size() == 1 && one_zero[0] == 0, "base64 decode one zero");

  check_throws([]() { robot_ota::base64_decode_strict("Zm9v\n"); },
               "base64 whitespace is rejected");
  check_throws([]() { robot_ota::base64_decode_strict("Zm9"); },
               "base64 bad length is rejected");
  check_throws([]() { robot_ota::base64_decode_strict("Zh=="); },
               "base64 non-canonical padding bits are rejected");
  check_throws([]() { robot_ota::base64_decode_strict("Zm9v=AAA"); },
               "base64 misplaced padding is rejected");
}

void test_sign_input() {
  const robot_ota::Bytes input =
      robot_ota::make_sign_input("PREFIX", "{\"a\":1}");
  const std::string expected = std::string("PREFIX") + '\0' + "{\"a\":1}";
  check_eq(std::string(input.begin(), input.end()), expected,
           "sign input is prefix || 0x00 || canonical");
}

Json::Value make_manifest() {
  Json::Value manifest;
  manifest["schema_version"] = 1;
  manifest["purpose"] = "ROBOT_OFFLINE_OTA";
  manifest["package_id"] = "123e4567-e89b-42d3-a456-426614174000";
  manifest["issued_at"] = "2026-10-21T00:00:00Z";

  manifest["target"]["robot_sn"] = "AS2_000001";
  manifest["target"]["recipient_spki_sha256"] = std::string(64, 'a');

  Json::Value& firmware = manifest["firmware"];
  firmware["artifact_id"] = "artifact-1";
  firmware["product_id"] = "AS2";
  firmware["hw_revision"] = "REV_A";
  firmware["version"] = "2.4.1";
  firmware["security_version"] = 5;
  firmware["plaintext_size"] = 3;
  firmware["plaintext_sha256"] = std::string(64, 'b');

  Json::Value& encryption = manifest["encryption"];
  encryption["content_alg"] = "AES-256-GCM";
  encryption["nonce_b64"] = robot_ota::base64_encode(
      robot_ota::Bytes(12, 0x11));
  encryption["tag_b64"] = robot_ota::base64_encode(
      robot_ota::Bytes(16, 0x22));
  encryption["aad_scheme"] = "NONE";
  encryption["key_wrap_alg"] = "RSA-OAEP-SHA256";
  encryption["wrapped_dek_b64"] = robot_ota::base64_encode(
      robot_ota::Bytes(256, 0x33));

  manifest["payload"]["ciphertext_size"] = 3;
  manifest["payload"]["ciphertext_sha256"] = std::string(64, 'c');
  return manifest;
}

void test_manifest() {
  const Json::Value root = make_manifest();
  robot_ota::Manifest manifest =
      robot_ota::parse_manifest(root, robot_ota::ManifestLimits{1024});
  check(manifest.schema_version == 1, "manifest schema version");
  check(manifest.security_version == 5, "manifest security version");
  check(manifest.nonce.size() == 12, "manifest nonce length");
  check(manifest.tag.size() == 16, "manifest tag length");
  check(manifest.wrapped_dek.size() == 256, "manifest wrapped DEK length");
  check(manifest.canonical_sha256.size() == 64, "manifest canonical hash");

  const std::string expected_canonical = robot_ota::jcs_canonicalize(root);
  check_eq(manifest.canonical, expected_canonical, "manifest canonical form");

  Json::Value extra = root;
  extra["unexpected"] = "field";
  check_throws([&]() {
    robot_ota::parse_manifest(extra, robot_ota::ManifestLimits{1024});
  }, "unknown manifest fields are rejected");

  Json::Value bad_size = root;
  bad_size["payload"]["ciphertext_size"] = 4;
  check_throws([&]() {
    robot_ota::parse_manifest(bad_size, robot_ota::ManifestLimits{1024});
  }, "ciphertext_size must equal plaintext_size");

  Json::Value too_large = root;
  too_large["firmware"]["plaintext_size"] = 2048;
  too_large["payload"]["ciphertext_size"] = 2048;
  check_throws([&]() {
    robot_ota::parse_manifest(too_large, robot_ota::ManifestLimits{1024});
  }, "plaintext above the device limit is rejected");
}

robot_ota::Bytes pkcs1_oaep_encrypt(const std::string& message,
                                   EVP_PKEY* key) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_PKEY_CTX_new failed");
  }
  robot_ota::Bytes out;
  try {
    if (EVP_PKEY_encrypt_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1) {
      throw std::runtime_error("failed to configure OAEP");
    }
    size_t length = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &length,
                         reinterpret_cast<const unsigned char*>(message.data()),
                         message.size()) != 1) {
      throw std::runtime_error("EVP_PKEY_encrypt size query failed");
    }
    out.resize(length);
    if (EVP_PKEY_encrypt(ctx, out.data(), &length,
                         reinterpret_cast<const unsigned char*>(message.data()),
                         message.size()) != 1) {
      throw std::runtime_error("EVP_PKEY_encrypt failed");
    }
    out.resize(length);
  } catch (...) {
    EVP_PKEY_CTX_free(ctx);
    throw;
  }
  EVP_PKEY_CTX_free(ctx);
  return out;
}

void test_oaep_decode() {
  BIGNUM* exponent = BN_new();
  RSA* rsa = RSA_new();
  check(exponent != nullptr && rsa != nullptr, "RSA allocation");
  if (exponent == nullptr || rsa == nullptr) {
    if (exponent != nullptr) {
      BN_free(exponent);
    }
    if (rsa != nullptr) {
      RSA_free(rsa);
    }
    return;
  }
  BN_set_word(exponent, RSA_F4);
  check(RSA_generate_key_ex(rsa, 2048, exponent, nullptr) == 1,
        "RSA key generation");

  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, rsa);
  check(pkey != nullptr, "EVP_PKEY allocation");

  const std::string message = "0123456789abcdef0123456789abcdef";
  const robot_ota::Bytes encrypted = pkcs1_oaep_encrypt(message, pkey);

  const int size = RSA_size(rsa);
  robot_ota::Bytes raw(static_cast<size_t>(size));
  const int raw_length =
      RSA_private_decrypt(size, encrypted.data(), raw.data(), rsa, RSA_NO_PADDING);
  check(raw_length == size, "raw private operation length");

  robot_ota::Bytes modulus(static_cast<size_t>(size));
  const BIGNUM* n = nullptr;
  RSA_get0_key(rsa, &n, nullptr, nullptr);
  BN_bn2binpad(n, modulus.data(), size);

  const robot_ota::Bytes decoded =
      robot_ota::oaep_sha256_decode(raw, modulus);
  check_eq(std::string(decoded.begin(), decoded.end()), message,
           "OAEP-SHA256 decode");

  robot_ota::Bytes corrupted = raw;
  corrupted[corrupted.size() - 1] ^= 0x01;
  check_throws([&]() { robot_ota::oaep_sha256_decode(corrupted, modulus); },
               "corrupted OAEP encoding is rejected");

  EVP_PKEY_free(pkey);
  RSA_free(rsa);
  BN_free(exponent);
}

void test_sha256() {
  check_eq(robot_ota::sha256_hex("abc"),
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "SHA-256 of abc");
  check_eq(utf8_hex(std::string("abc")), "616263", "hex helper");
}

}  // namespace

int main() {
  test_jcs_object_ordering();
  test_jcs_scalars();
  test_jcs_strings();
  test_base64();
  test_sign_input();
  test_manifest();
  test_oaep_decode();
  test_sha256();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all unit tests passed\n";
  return 0;
}
