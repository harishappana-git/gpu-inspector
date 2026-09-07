#include "known_answer.hpp"
#include "json.hpp"
#include "device_support.hpp"
#include "numa_support.hpp"
#include <iostream>
#include <limits>
#include <cstring>
#include <stdexcept>

static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

int main() {
  try {
    require(gri::supported_architecture(9, 0), "Hopper support regressed");
    require(gri::supported_architecture(12, 0), "Blackwell support missing");
    require(!gri::supported_architecture(10, 0) && !gri::supported_architecture(12, 1), "untested architecture accepted");
    require(gri::architecture_family(12, 0) == "blackwell_sm120", "wrong architecture family");
    require(gri::memory_technology("NVIDIA GeForce RTX 5080") == "GDDR7", "RTX memory mislabeled");
    require(gri::memory_technology("NVIDIA H100 PCIe") == "HBM", "H100 memory label regressed");
    require(gri::memory_technology("different SM120 product") == "unknown", "memory technology invented");
    require(std::string(gri::memory_bandwidth_metric(12)) == "device_memory_effective_copy_bandwidth", "RTX bandwidth mislabeled HBM");
    const uint8_t e4m3_golden[] = {0xc4, 0xc0, 0xb8, 0x00, 0x38, 0x40, 0x44};
    for (int value = -3; value <= 3; ++value)
      require(gri::fp8_e4m3_small_integer(value) == e4m3_golden[value+3], "FP8 exact integer encoding regression");
    require(9 * 4096 < std::numeric_limits<int32_t>::max(), "INT8 known-answer accumulator overflow");
    require(gri::parse_cpu_list("0-2,7,9-10\n") == std::vector<int>({0,1,2,7,9,10}), "NUMA cpulist parser regression");
    for (const auto* invalid : {"", "2-1", "1,", "-1", "1024", "1;2", "0-99999999"}) {
      bool rejected=false;try{gri::parse_cpu_list(invalid);}catch(const std::invalid_argument&){rejected=true;}
      require(rejected,"malformed or unbounded NUMA CPU list accepted");
    }
    constexpr std::size_t count = 4099;
    std::vector<uint32_t> buffer(count);
    for (auto seed : {0U, 1U, 0xffffffffU}) {
      for (unsigned pass = 0; pass < 8; ++pass) {
        for (std::size_t i = 0; i < count; ++i) buffer[i] = gri::pattern(i + 93, pass, seed);
        require(gri::check_words(buffer.data(), count, 93, pass, seed).empty(), "clean pattern rejected");
        // Deliberate corruption is CPU-only synthetic evidence, never GPU evidence.
        buffer[107] ^= 1;
        auto wrong = gri::check_words(buffer.data(), count, 93, pass, seed);
        require(wrong.size() == 1 && wrong[0].index == 200, "synthetic corruption not located");
      }
    }
    constexpr int n = 7;
    for (std::size_t i = 0; i < 4096; ++i) {
      const float value = gri::matrix_value(i, 42);
      uint32_t bits = 0; std::memcpy(&bits, &value, sizeof(bits));
      require((bits & 0xffffU) == 0, "input is not exactly BF16 representable");
      require((bits & 0x1fffU) == 0, "input is not exactly TF32 representable");
    }
    for (int row = 0; row < n; ++row) for (int col = 0; col < n; ++col) {
      float independently_accumulated = 0;
      for (int k = 0; k < n; ++k)
        independently_accumulated += gri::matrix_value(row + k*n, 42) * gri::matrix_value(k + col*n, 42 ^ 0xa5a5a5a5U);
      const auto expected = gri::matrix_answer(row, col, n, 42);
      require(gri::answer_matches(expected, independently_accumulated), "matrix host paths disagree");
      require(!gri::answer_matches(expected, independently_accumulated + 1), "synthetic GEMM corruption missed");
      require(!gri::answer_matches(expected, std::numeric_limits<double>::quiet_NaN()), "NaN accepted");
      require(!gri::answer_matches(expected, std::numeric_limits<double>::infinity()), "infinity accepted");
    }
    // Independently derived dot product: [-1,0,1,1,-2,-3,-3] dot
    // [-3,-1,-2,3,-3,1,-1] = 10.
    require(gri::matrix_answer(0, 0, n, 42) == 10, "fixed known-answer regression");
    require(gri::median({1, 2, 9, 10}) == 5.5, "median wrong");
    require(gri::mad({1, 1, 2, 3, 100}) == 1, "MAD wrong");
    require(gri::hash_string(gri::hash_word(14695981039346656037ULL, 0)) == "4d25767f9dce13f5", "canonical checksum regression");
    require(gri::Json("a\n\"\\").data == "\"a\\u000a\\\"\\\\\"", "JSON escape wrong");
    require(gri::Json(std::numeric_limits<double>::quiet_NaN()).data == "null", "JSON emitted NaN");
    std::cout << "CPU known-answer and deliberate synthetic corruption checks passed. CUDA qualification not performed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
  }
}
