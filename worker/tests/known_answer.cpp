#include "known_answer.hpp"
#include "json.hpp"
#include <iostream>
#include <limits>
#include <cstring>
#include <stdexcept>

static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

int main() {
  try {
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
