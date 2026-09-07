#pragma once
#include <string>

namespace gri {
// Eligibility for these portable CUDA/cuBLAS methods is not qualification of
// every product sharing the architecture, nor proof of a device's identity.
inline bool supported_architecture(int major, int minor) {
  return minor == 0 && (major == 9 || major == 12);
}
inline std::string architecture_family(int major, int minor) {
  if (!supported_architecture(major, minor)) return "unsupported";
  return major == 9 ? "hopper_sm90" : "blackwell_sm120";
}
inline std::string memory_technology(const std::string& reported_name) {
  if (reported_name.find("H100") != std::string::npos) return "HBM";
  if (reported_name.find("GeForce RTX 5080") != std::string::npos) return "GDDR7";
  return "unknown";
}
inline const char* memory_bandwidth_metric(int major) {
  // Preserve the original SM90 wire metric. The hbm_copy method ID also stays
  // stable, while Blackwell measurements have a technology-neutral metric.
  return major == 9 ? "hbm_effective_copy_bandwidth" : "device_memory_effective_copy_bandwidth";
}
}  // namespace gri
