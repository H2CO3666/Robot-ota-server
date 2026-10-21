#include "robot_ota/jcs.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace robot_ota {
namespace {

// Strict UTF-8 decoder. Rejects overlong forms, surrogates and out-of-range
// code points. Returns the decoded code points.
std::vector<uint32_t> decode_utf8(const std::string& text) {
  std::vector<uint32_t> out;
  out.reserve(text.size());
  size_t i = 0;
  while (i < text.size()) {
    const uint8_t c = static_cast<uint8_t>(text[i]);
    uint32_t cp = 0;
    size_t length = 0;
    if (c <= 0x7F) {
      cp = c;
      length = 1;
    } else if (c >= 0xC2 && c <= 0xDF) {
      cp = c & 0x1F;
      length = 2;
    } else if (c >= 0xE0 && c <= 0xEF) {
      cp = c & 0x0F;
      length = 3;
    } else if (c >= 0xF0 && c <= 0xF4) {
      cp = c & 0x07;
      length = 4;
    } else {
      throw std::runtime_error("JCS: invalid UTF-8 leading byte");
    }
    if (i + length > text.size()) {
      throw std::runtime_error("JCS: truncated UTF-8 sequence");
    }
    for (size_t j = 1; j < length; ++j) {
      const uint8_t next = static_cast<uint8_t>(text[i + j]);
      if ((next & 0xC0) != 0x80) {
        throw std::runtime_error("JCS: invalid UTF-8 continuation byte");
      }
      cp = (cp << 6) | (next & 0x3F);
    }
    // Reject overlong encodings and UTF-16 surrogates.
    if ((length == 2 && cp < 0x80) || (length == 3 && cp < 0x800) ||
        (length == 4 && cp < 0x10000) || (cp >= 0xD800 && cp <= 0xDFFF) ||
        cp > 0x10FFFF) {
      throw std::runtime_error("JCS: invalid UTF-8 code point");
    }
    out.push_back(cp);
    i += length;
  }
  return out;
}

std::u16string utf8_to_utf16(const std::string& text) {
  const std::vector<uint32_t> code_points = decode_utf8(text);
  std::u16string out;
  out.reserve(code_points.size());
  for (uint32_t cp : code_points) {
    if (cp <= 0xFFFF) {
      out.push_back(static_cast<char16_t>(cp));
    } else {
      cp -= 0x10000;
      out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
      out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
    }
  }
  return out;
}

void append_escaped_string(std::string& out, const std::string& text) {
  const std::vector<uint32_t> code_points = decode_utf8(text);
  static const char* kHex = "0123456789abcdef";
  out.push_back('"');
  for (uint32_t cp : code_points) {
    switch (cp) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\t':
        out += "\\t";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\r':
        out += "\\r";
        break;
      default:
        if (cp < 0x20) {
          out += "\\u00";
          out.push_back(kHex[(cp >> 4) & 0x0F]);
          out.push_back(kHex[cp & 0x0F]);
        } else {
          // JCS emits all remaining code points as literal UTF-8.
          if (cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
          } else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
          } else if (cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
          } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
          }
        }
        break;
    }
  }
  out.push_back('"');
}

void append_number(std::string& out, const Json::Value& value) {
  switch (value.type()) {
    case Json::intValue:
      out += std::to_string(value.asInt64());
      return;
    case Json::uintValue:
      out += std::to_string(value.asUInt64());
      return;
    case Json::realValue: {
      const double d = value.asDouble();
      if (!std::isfinite(d)) {
        throw std::runtime_error("JCS: non-finite number");
      }
      if (d == 0.0) {
        out += "0";
        return;
      }
      if (std::floor(d) == d && std::fabs(d) <= 9007199254740991.0) {
        out += std::to_string(static_cast<int64_t>(d));
        return;
      }
      throw std::runtime_error(
          "JCS: only integral numbers are supported by this implementation");
    }
    default:
      throw std::runtime_error("JCS: expected a number");
  }
}

void append_value(std::string& out, const Json::Value& value) {
  switch (value.type()) {
    case Json::nullValue:
      out += "null";
      return;
    case Json::booleanValue:
      out += value.asBool() ? "true" : "false";
      return;
    case Json::intValue:
    case Json::uintValue:
    case Json::realValue:
      append_number(out, value);
      return;
    case Json::stringValue:
      append_escaped_string(out, value.asString());
      return;
    case Json::arrayValue: {
      out.push_back('[');
      for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
        if (i != 0) {
          out.push_back(',');
        }
        append_value(out, value[i]);
      }
      out.push_back(']');
      return;
    }
    case Json::objectValue: {
      struct Member {
        std::u16string sort_key;
        std::string name;
        const Json::Value* value;
      };
      std::vector<Member> members;
      members.reserve(value.size());
      for (auto it = value.begin(); it != value.end(); ++it) {
        const std::string name(it.name());
        members.push_back(Member{utf8_to_utf16(name), name, &(*it)});
      }
      std::sort(members.begin(), members.end(),
                [](const Member& a, const Member& b) {
                  return a.sort_key < b.sort_key;
                });
      out.push_back('{');
      for (size_t i = 0; i < members.size(); ++i) {
        if (i != 0) {
          out.push_back(',');
        }
        append_escaped_string(out, members[i].name);
        out.push_back(':');
        append_value(out, *members[i].value);
      }
      out.push_back('}');
      return;
    }
    default:
      throw std::runtime_error("JCS: unsupported JSON value type");
  }
}

}  // namespace

std::string jcs_canonicalize(const Json::Value& value) {
  std::string out;
  out.reserve(1024);
  append_value(out, value);
  return out;
}

}  // namespace robot_ota
