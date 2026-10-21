#include "robot_ota/manifest.h"

#include <cctype>
#include <initializer_list>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>

#include "robot_ota/crypto.h"
#include "robot_ota/errors.h"
#include "robot_ota/jcs.h"

namespace robot_ota {
namespace {

[[noreturn]] void invalid(const std::string& message) {
  throw OtaError(400, "INVALID_MANIFEST", message);
}

bool is_ascii_token(const std::string& value, size_t max_length) {
  if (value.empty() || value.size() > max_length) {
    return false;
  }
  for (unsigned char c : value) {
    if (c < 0x21 || c > 0x7e) {
      return false;
    }
  }
  return true;
}

bool valid_robot_sn(const std::string& sn) {
  if (sn.empty() || sn.size() > 64) {
    return false;
  }
  for (size_t i = 0; i < sn.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(sn[i]);
    const bool alpha_num = std::isalnum(c) != 0;
    if (!alpha_num && c != '_' && c != '-' && c != '.' && c != ':') {
      return false;
    }
    if (i == 0 && !alpha_num) {
      return false;
    }
  }
  return true;
}

bool valid_uuid_v4(const std::string& value) {
  static const std::regex pattern(
      R"(^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$)");
  return std::regex_match(value, pattern);
}

bool valid_rfc3339_utc(const std::string& value) {
  static const std::regex pattern(
      R"(^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$)");
  return std::regex_match(value, pattern);
}

void require_keys(const Json::Value& object,
                  std::initializer_list<const char*> allowed,
                  const std::string& where) {
  if (!object.isObject()) {
    invalid(where + " must be an object");
  }
  std::set<std::string> seen;
  for (auto it = object.begin(); it != object.end(); ++it) {
    const std::string name(it.name());
    bool known = false;
    for (const char* candidate : allowed) {
      if (name == candidate) {
        known = true;
        break;
      }
    }
    if (!known) {
      invalid("unexpected field " + where + "." + name);
    }
    seen.insert(name);
  }
  for (const char* candidate : allowed) {
    if (seen.find(candidate) == seen.end()) {
      invalid("missing field " + where + "." + candidate);
    }
  }
}

std::string string_field(const Json::Value& object, const char* key,
                         const std::string& where) {
  const Json::Value& value = object[key];
  if (!value.isString()) {
    invalid(where + "." + key + " must be a string");
  }
  return value.asString();
}

uint64_t uint_field(const Json::Value& object, const char* key,
                    const std::string& where) {
  const Json::Value& value = object[key];
  switch (value.type()) {
    case Json::intValue: {
      const Json::Int64 v = value.asInt64();
      if (v < 0) {
        invalid(where + "." + key + " must be a non-negative integer");
      }
      return static_cast<uint64_t>(v);
    }
    case Json::uintValue:
      return value.asUInt64();
    default:
      invalid(where + "." + key + " must be a non-negative integer");
  }
}

std::string hex64_field(const Json::Value& object, const char* key,
                        const std::string& where) {
  const std::string value = string_field(object, key, where);
  if (!is_lower_hex(value, 64)) {
    invalid(where + "." + key + " must be 64 lowercase hex characters");
  }
  return value;
}

Bytes base64_field(const Json::Value& object, const char* key,
                   const std::string& where, size_t minimum,
                   size_t maximum) {
  const std::string text = string_field(object, key, where);
  if (text.size() > maximum * 2 + 16) {
    invalid(where + "." + key + " is too long");
  }
  Bytes decoded;
  try {
    decoded = base64_decode_strict(text);
  } catch (const std::exception& e) {
    invalid(where + "." + key + " is not strict base64: " + e.what());
  }
  if (decoded.size() < minimum || decoded.size() > maximum) {
    invalid(where + "." + key + " has an invalid decoded length");
  }
  return decoded;
}

}  // namespace

Manifest parse_manifest(const Json::Value& root, const ManifestLimits& limits) {
  require_keys(root,
               {"schema_version", "purpose", "package_id", "issued_at", "target",
                "firmware", "encryption", "payload"},
               "manifest");

  Manifest m;
  const uint64_t schema_version = uint_field(root, "schema_version", "manifest");
  if (schema_version != 1) {
    throw OtaError(400, "UNSUPPORTED_MANIFEST_VERSION",
                   "unsupported manifest schema_version");
  }
  m.schema_version = 1;

  m.purpose = string_field(root, "purpose", "manifest");
  if (m.purpose != "ROBOT_OFFLINE_OTA") {
    invalid("manifest.purpose must be ROBOT_OFFLINE_OTA");
  }

  m.package_id = string_field(root, "package_id", "manifest");
  if (!valid_uuid_v4(m.package_id)) {
    invalid("manifest.package_id must be a UUID v4");
  }

  m.issued_at = string_field(root, "issued_at", "manifest");
  if (!valid_rfc3339_utc(m.issued_at)) {
    invalid("manifest.issued_at must be an RFC3339 UTC timestamp");
  }

  const Json::Value& target = root["target"];
  require_keys(target, {"robot_sn", "recipient_spki_sha256"}, "manifest.target");
  m.robot_sn = string_field(target, "robot_sn", "manifest.target");
  if (!valid_robot_sn(m.robot_sn)) {
    invalid("manifest.target.robot_sn has an invalid format");
  }
  m.recipient_spki_sha256 =
      hex64_field(target, "recipient_spki_sha256", "manifest.target");

  const Json::Value& firmware = root["firmware"];
  require_keys(firmware,
               {"artifact_id", "product_id", "hw_revision", "version",
                "security_version", "plaintext_size", "plaintext_sha256"},
               "manifest.firmware");
  m.artifact_id = string_field(firmware, "artifact_id", "manifest.firmware");
  m.product_id = string_field(firmware, "product_id", "manifest.firmware");
  m.hw_revision = string_field(firmware, "hw_revision", "manifest.firmware");
  m.version = string_field(firmware, "version", "manifest.firmware");
  if (!is_ascii_token(m.artifact_id, 256) || !is_ascii_token(m.product_id, 128) ||
      !is_ascii_token(m.hw_revision, 128) || !is_ascii_token(m.version, 128)) {
    invalid("manifest.firmware contains an invalid identifier");
  }
  m.security_version = uint_field(firmware, "security_version", "manifest.firmware");
  m.plaintext_size = uint_field(firmware, "plaintext_size", "manifest.firmware");
  if (m.plaintext_size == 0 || m.plaintext_size > limits.max_plaintext_bytes) {
    invalid("manifest.firmware.plaintext_size is outside the device limit");
  }
  m.plaintext_sha256 =
      hex64_field(firmware, "plaintext_sha256", "manifest.firmware");

  const Json::Value& encryption = root["encryption"];
  require_keys(encryption,
               {"content_alg", "nonce_b64", "tag_b64", "aad_scheme",
                "key_wrap_alg", "wrapped_dek_b64"},
               "manifest.encryption");
  m.content_alg = string_field(encryption, "content_alg", "manifest.encryption");
  if (m.content_alg != "AES-256-GCM") {
    invalid("manifest.encryption.content_alg must be AES-256-GCM");
  }
  m.aad_scheme = string_field(encryption, "aad_scheme", "manifest.encryption");
  if (m.aad_scheme != "NONE") {
    invalid("manifest.encryption.aad_scheme must be NONE");
  }
  m.key_wrap_alg =
      string_field(encryption, "key_wrap_alg", "manifest.encryption");
  if (m.key_wrap_alg != "RSA-OAEP-SHA256") {
    invalid("manifest.encryption.key_wrap_alg must be RSA-OAEP-SHA256");
  }
  m.nonce_b64 = string_field(encryption, "nonce_b64", "manifest.encryption");
  m.tag_b64 = string_field(encryption, "tag_b64", "manifest.encryption");
  m.wrapped_dek_b64 =
      string_field(encryption, "wrapped_dek_b64", "manifest.encryption");
  m.nonce = base64_field(encryption, "nonce_b64", "manifest.encryption", 12, 12);
  m.tag = base64_field(encryption, "tag_b64", "manifest.encryption", 16, 16);
  m.wrapped_dek =
      base64_field(encryption, "wrapped_dek_b64", "manifest.encryption", 1, 1024);

  const Json::Value& payload = root["payload"];
  require_keys(payload, {"ciphertext_size", "ciphertext_sha256"},
               "manifest.payload");
  m.ciphertext_size = uint_field(payload, "ciphertext_size", "manifest.payload");
  if (m.ciphertext_size == 0 ||
      m.ciphertext_size > limits.max_plaintext_bytes) {
    invalid("manifest.payload.ciphertext_size is outside the device limit");
  }
  // AES-GCM ciphertext has the same length as the plaintext; the tag lives in
  // the manifest, not in the file.
  if (m.ciphertext_size != m.plaintext_size) {
    invalid("manifest ciphertext_size must equal plaintext_size");
  }
  m.ciphertext_sha256 =
      hex64_field(payload, "ciphertext_sha256", "manifest.payload");

  try {
    m.canonical = jcs_canonicalize(root);
  } catch (const std::exception& e) {
    invalid(std::string("manifest cannot be canonicalized: ") + e.what());
  }
  if (m.canonical.size() > 256 * 1024) {
    invalid("manifest is unreasonably large");
  }
  m.canonical_sha256 = sha256_hex(m.canonical);
  return m;
}

Bytes make_sign_input(const std::string& domain_prefix,
                      const std::string& canonical_manifest) {
  Bytes out;
  out.reserve(domain_prefix.size() + 1 + canonical_manifest.size());
  out.insert(out.end(), domain_prefix.begin(), domain_prefix.end());
  out.push_back(0x00);
  out.insert(out.end(), canonical_manifest.begin(), canonical_manifest.end());
  return out;
}

}  // namespace robot_ota
