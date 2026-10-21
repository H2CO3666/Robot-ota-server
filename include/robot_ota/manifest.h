#pragma once

#include <cstdint>
#include <string>

#include <json/json.h>

#include "robot_ota/util.h"

namespace robot_ota {

struct ManifestLimits {
  uint64_t max_plaintext_bytes = 0;
};

// Strictly parsed Manifest v1. Unknown, missing or wrongly typed fields are
// rejected. The struct keeps the canonical serialization because the signature
// covers exactly JCS(manifest).
struct Manifest {
  int schema_version = 0;
  std::string purpose;
  std::string package_id;
  std::string issued_at;

  std::string robot_sn;
  std::string recipient_spki_sha256;

  std::string artifact_id;
  std::string product_id;
  std::string hw_revision;
  std::string version;
  uint64_t security_version = 0;
  uint64_t plaintext_size = 0;
  std::string plaintext_sha256;

  std::string content_alg;
  std::string nonce_b64;
  std::string tag_b64;
  std::string aad_scheme;
  std::string key_wrap_alg;
  std::string wrapped_dek_b64;
  Bytes nonce;
  Bytes tag;
  Bytes wrapped_dek;

  uint64_t ciphertext_size = 0;
  std::string ciphertext_sha256;

  std::string canonical;
  std::string canonical_sha256;
};

Manifest parse_manifest(const Json::Value& root, const ManifestLimits& limits);

// prefix_bytes || 0x00 || JCS(manifest)
Bytes make_sign_input(const std::string& domain_prefix,
                      const std::string& canonical_manifest);

}  // namespace robot_ota
