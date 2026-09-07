#pragma once
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>

#ifdef __CUDACC__
#define GRI_HD __host__ __device__
#else
#define GRI_HD
#endif

namespace gri {
GRI_HD inline uint32_t mix32(uint32_t x) {
  x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15; x *= 0x846ca68bU; return x ^ (x >> 16);
}

// These functions operate only on supplied test-owned buffers. There is no
// physical-address inference: index means a logical offset in one allocation.
GRI_HD inline uint32_t pattern(std::size_t index, unsigned pass, uint32_t seed) {
  const uint32_t address = mix32(uint32_t(index) ^ mix32(uint32_t(index >> 32)) ^ seed);
  switch (pass % 8) {
    case 0: return 0;
    case 1: return 0xffffffffU;
    case 2: return address;
    case 3: return ~address;
    case 4: return 1U << (index % 32);
    case 5: return ~(1U << (index % 32));
    case 6: return (index & 1) ? 0xaaaaaaaaU : 0x55555555U;
    default: return mix32(address + uint32_t(index) + 0x9e3779b9U);
  }
}

struct Mismatch { std::size_t index; double expected; double observed; };

inline std::vector<Mismatch> check_words(const uint32_t* values, std::size_t count,
                                        std::size_t offset, unsigned pass, uint32_t seed,
                                        std::size_t max_examples = 8) {
  std::vector<Mismatch> result;
  for (std::size_t i = 0; i < count; ++i) {
    auto want = pattern(offset + i, pass, seed);
    if (values[i] != want && result.size() < max_examples)
      result.push_back({offset + i, double(want), double(values[i])});
  }
  return result;
}

// Small integers are exactly representable by FP32, BF16 and TF32. The CPU
// accumulator is int64_t. This checks a common exact-answer subset of the paths;
// it is not a general floating-point accuracy characterization.
GRI_HD inline float matrix_value(std::size_t index, uint32_t seed) {
  return float(int(mix32(uint32_t(index) ^ seed) % 7U) - 3);
}

inline double matrix_answer(int row, int column, int n, uint32_t seed) {
  int64_t sum = 0;
  for (int k = 0; k < n; ++k) {
    const int a = int(matrix_value(std::size_t(row) + std::size_t(k) * n, seed));
    const int b = int(matrix_value(std::size_t(k) + std::size_t(column) * n, seed ^ 0xa5a5a5a5U));
    sum += int64_t(a) * b;
  }
  return double(sum);
}

inline bool answer_matches(double expected, double observed, double tolerance = 0) {
  return std::isfinite(observed) && std::fabs(expected - observed) <= tolerance;
}

inline double median(std::vector<double> values) {
  if (values.empty()) return 0;
  std::sort(values.begin(), values.end());
  const auto n = values.size();
  return n % 2 ? values[n/2] : (values[n/2 - 1] + values[n/2])/2;
}
inline double mad(const std::vector<double>& values) {
  const auto mid = median(values);
  std::vector<double> deviations;
  for (auto value : values) deviations.push_back(std::fabs(value - mid));
  return median(deviations);
}

// Explicit little-endian word serialization makes this reproducible across CPU
// architectures. This is a non-cryptographic provenance checksum, not a signature.
inline uint64_t hash_word(uint64_t hash, uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    hash ^= (value >> shift) & 255U;
    hash *= 1099511628211ULL;
  }
  return hash;
}
inline std::string hash_string(uint64_t hash) {
  std::ostringstream result;
  result << std::hex << std::setw(16) << std::setfill('0') << hash;
  return result.str();
}
}  // namespace gri
