#pragma once

#include <string>

#include <json/json.h>

namespace robot_ota {

// RFC 8785 (JCS) canonical JSON serialization.
//
// The manifest schema only uses integers and strings, so the floating point
// ECMAScript number formatting rules are deliberately not implemented; a
// non-integral number is rejected rather than canonicalized incorrectly.
std::string jcs_canonicalize(const Json::Value& value);

}  // namespace robot_ota
