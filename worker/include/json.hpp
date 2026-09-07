#pragma once
#include <cmath>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace gri {
// Small output-only JSON value. No untrusted JSON parser or runtime dependency.
class Json {
 public:
  std::string data = "null";
  Json() = default;
  Json(const char* value) : Json(std::string(value)) {}
  Json(const std::string& value) {
    std::ostringstream out; out << '"';
    for (unsigned char c : value) {
      if (c == '"' || c == '\\') out << '\\' << char(c);
      else if (c < 0x20) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c) << std::dec;
      else out << char(c);
    }
    out << '"'; data = out.str();
  }
  Json(bool value) : data(value ? "true" : "false") {}
  Json(double value) {
    if (!std::isfinite(value)) return;
    std::ostringstream out; out << std::setprecision(17) << value; data = out.str();
  }
  Json(int value) : data(std::to_string(value)) {}
  Json(unsigned value) : data(std::to_string(value)) {}
  Json(std::size_t value) : data(std::to_string(value)) {}
  static Json object(const std::map<std::string, Json>& values) {
    Json result; result.data = "{"; bool first = true;
    for (const auto& kv : values) {
      if (!first) result.data += ','; first = false;
      result.data += Json(kv.first).data + ':' + kv.second.data;
    }
    result.data += '}'; return result;
  }
  static Json array(const std::vector<Json>& values) {
    Json result; result.data = "["; bool first = true;
    for (const auto& value : values) {
      if (!first) result.data += ','; first = false; result.data += value.data;
    }
    result.data += ']'; return result;
  }
};
}  // namespace gri
