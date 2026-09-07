#include <cuda_runtime.h>
#include <cuda_bf16.h>
#include <cublas_v2.h>
#include "json.hpp"
#include "known_answer.hpp"
#include "device_support.hpp"
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using gri::Json;
constexpr std::size_t MiB = 1024U * 1024U;
double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}
struct Failure : std::exception {
  std::string status, code; int native_code;
  Failure(std::string s, std::string c, int n = 0) : status(std::move(s)), code(std::move(c)), native_code(n) {}
};
void cuda_check(cudaError_t code, const char* operation) {
  if (code != cudaSuccess) {
    std::string status = "test_error";
    if (code == cudaErrorNoDevice || code == cudaErrorInsufficientDriver || code == cudaErrorInvalidDeviceFunction || code == cudaErrorNoKernelImageForDevice)
      status = "unsupported";
    if (code == cudaErrorMemoryAllocation) status = "blocked";
    throw Failure(status, operation, int(code));
  }
}
void blas_check(cublasStatus_t code, const char* operation) {
  if (code != CUBLAS_STATUS_SUCCESS)
    throw Failure(code == CUBLAS_STATUS_NOT_SUPPORTED ? "unsupported" : "test_error", operation, int(code));
}
struct Args {
  std::string device, method, tier = "quick";
  unsigned budget_ms = 5000, memory_mib = 256, seed = 1;
};
bool uuid_valid(const std::string& uuid) {
  if (uuid.size() != 40 || uuid.substr(0, 4) != "GPU-") return false;
  for (std::size_t i = 4; i < uuid.size(); ++i) {
    if (i == 12 || i == 17 || i == 22 || i == 27) { if (uuid[i] != '-') return false; }
    else if (!((uuid[i] >= '0' && uuid[i] <= '9') || (uuid[i] >= 'a' && uuid[i] <= 'f'))) return false;
  }
  return true;
}
unsigned unsigned_arg(const std::string& value) {
  if (value.empty() || value.size() > 10 || value.find_first_not_of("0123456789") != std::string::npos)
    throw Failure("blocked", "invalid_numeric_argument");
  auto number = std::stoull(value);
  if (number > 0xffffffffULL) throw Failure("blocked", "numeric_argument_out_of_range");
  return unsigned(number);
}
Args parse(int argc, char** argv) {
  Args args;
  std::set<std::string> seen;
  for (int i = 1; i < argc; i += 2) {
    if (i + 1 >= argc) throw Failure("blocked", "argument_value_missing");
    std::string key(argv[i]), value(argv[i+1]);
    if (!seen.insert(key).second) throw Failure("blocked", "duplicate_argument");
    if (key == "--device") args.device = value;
    else if (key == "--method") args.method = value;
    else if (key == "--tier") args.tier = value;
    else if (key == "--budget-ms") args.budget_ms = unsigned_arg(value);
    else if (key == "--memory-mib") args.memory_mib = unsigned_arg(value);
    else if (key == "--seed") args.seed = unsigned_arg(value);
    else throw Failure("blocked", "unknown_argument");
  }
  if (!uuid_valid(args.device)) throw Failure("blocked", "full_physical_gpu_uuid_required");
  if (args.tier != "quick" && args.tier != "standard") throw Failure("blocked", "invalid_tier");
  const std::set<std::string> methods = {"memory_integrity", "fp32_gemm", "bf16_gemm", "tf32_gemm", "hbm_copy", "h2d", "d2h", "working_set", "dispatch_latency"};
  if (!methods.count(args.method)) throw Failure("unsupported", "unknown_method");
  if (args.budget_ms < 100 || args.budget_ms > 300000 || args.memory_mib < 1 || args.memory_mib > 8192)
    throw Failure("blocked", "budget_or_memory_cap_out_of_range");
  return args;
}
std::string uuid_string(const cudaUUID_t& uuid) {
  static const char* digits = "0123456789abcdef";
  std::string text = "GPU-";
  for (int i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) text += '-';
    const auto c = static_cast<unsigned char>(uuid.bytes[i]);
    text += digits[c >> 4]; text += digits[c & 15];
  }
  return text;
}
struct DeviceBuffer {
  void* data = nullptr;
  explicit DeviceBuffer(std::size_t bytes) { cuda_check(cudaMalloc(&data, bytes), "cudaMalloc"); }
  ~DeviceBuffer() { if (data) cudaFree(data); }
  DeviceBuffer(const DeviceBuffer&) = delete;
  DeviceBuffer& operator=(const DeviceBuffer&) = delete;
};
struct PinnedBuffer {
  void* data = nullptr;
  explicit PinnedBuffer(std::size_t bytes) { cuda_check(cudaMallocHost(&data, bytes), "cudaMallocHost"); }
  ~PinnedBuffer() { if (data) cudaFreeHost(data); }
};
struct Blas {
  cublasHandle_t handle = nullptr;
  Blas() { blas_check(cublasCreate(&handle), "cublasCreate"); }
  ~Blas() { if (handle) cublasDestroy(handle); }
};
struct Events {
  cudaEvent_t start = nullptr, stop = nullptr;
  Events() {
    cuda_check(cudaEventCreate(&start), "cudaEventCreate");
    auto error = cudaEventCreate(&stop);
    if (error != cudaSuccess) { cudaEventDestroy(start); start = nullptr; cuda_check(error, "cudaEventCreate"); }
  }
  ~Events() { if (start) cudaEventDestroy(start); if (stop) cudaEventDestroy(stop); }
};
struct Result {
  Args args;
  std::string status = "ok", metric_name, unit;
  Clock::time_point start = Clock::now();
  double cold_start_ms = 0, warmup_ms = 0;
  std::vector<double> samples, event_samples, wall_samples, verified_offsets;
  std::map<std::string, Json> conditions, coverage;
  std::vector<Json> errors, mismatches, limitations;
  std::size_t checked_values = 0, mismatch_count = 0;
  unsigned confirmation_count = 0;
  bool correctness_checked = false;

  void budget(double reserve_ms = 25) const {
    if (elapsed_ms(start) + reserve_ms >= args.budget_ms)
      throw Failure("budget_exhausted", "worker_budget_exhausted");
  }
  void add_sample(double value, double event_ms, double wall_ms) {
    if (!std::isfinite(value) || value < 0 || !std::isfinite(event_ms) || event_ms <= 0 || event_ms > wall_ms + 2.0)
      throw Failure("test_error", "invalid_or_inconsistent_timing");
    samples.push_back(value); event_samples.push_back(event_ms); wall_samples.push_back(wall_ms);
    verified_offsets.push_back(elapsed_ms(start));
  }
  void verify(const std::vector<gri::Mismatch>& wrong, std::size_t checked) {
    checked_values += checked;
    correctness_checked = true;
    if (!wrong.empty()) {
      mismatch_count += wrong.size();
      for (const auto& mismatch : wrong) if (mismatches.size() < 8)
        mismatches.push_back(Json::object({{"logical_index", mismatch.index}, {"expected", mismatch.expected}, {"observed", mismatch.observed},
          {"observed_class", std::isnan(mismatch.observed) ? "nan" : (std::isinf(mismatch.observed) ? (mismatch.observed < 0 ? "negative_infinity" : "positive_infinity") : "finite")}}));
      // No retry load after first wrong output. The scanner may arrange a separate
      // bounded investigation; one observation is not a reproduced device fault.
      throw Failure("mismatch", "checked_output_mismatch");
    }
  }
  Json json() const {
    std::vector<Json> s, e, w, offsets;
    for (double value : samples) s.emplace_back(value);
    for (double value : event_samples) e.emplace_back(value);
    for (double value : wall_samples) w.emplace_back(value);
    for (double value : verified_offsets) offsets.emplace_back(value);
    Json metric;
    if (!samples.empty() && status == "ok") metric = Json::object({{"name", metric_name}, {"value", gri::median(samples)}, {"unit", unit}});
    return Json::object({
      {"schema_version", "1.0.0"}, {"worker_version", "0.1.0-dev"}, {"method_version", "1.0.0"},
      {"device_uuid", args.device}, {"method", args.method}, {"status", status}, {"metric", metric},
      {"samples", Json::array(s)}, {"sample_count", samples.size()},
      {"timings", Json::object({{"cold_start_ms", cold_start_ms}, {"warmup_ms", warmup_ms},
        {"wall_ms", elapsed_ms(start)}, {"event_samples_ms", Json::array(e)}, {"wall_samples_ms", Json::array(w)},
        {"sample_verified_offsets_ms", Json::array(offsets)}})},
      {"spread", Json::object({{"median", samples.empty() ? Json() : Json(gri::median(samples))},
        {"mad", samples.empty() ? Json() : Json(gri::mad(samples))}, {"independent_allocations", 1}})},
      {"conditions", Json::object(conditions)}, {"coverage", Json::object(coverage)},
      {"correctness", Json::object({{"checked", correctness_checked}, {"checked_values", checked_values},
        {"mismatch_count_lower_bound", mismatch_count}, {"mismatch_count", mismatch_count}, {"count_is_lower_bound", mismatch_count > 0},
        {"confirmation_count", confirmation_count}, {"reproducible", false}, {"synthetic", false}, {"mismatch_examples", Json::array(mismatches)}})},
      {"errors", Json::array(errors)}, {"limitations", Json::array(limitations)}});
  }
};

template<class Operation> std::pair<double, double> measure(Operation operation) {
  Events events;
  cuda_check(cudaDeviceSynchronize(), "pre_timing_synchronize");
  auto host = Clock::now();
  cuda_check(cudaEventRecord(events.start), "cudaEventRecord");
  operation();
  cuda_check(cudaGetLastError(), "kernel_launch_status");
  cuda_check(cudaEventRecord(events.stop), "cudaEventRecord");
  cuda_check(cudaEventSynchronize(events.stop), "cudaEventSynchronize");
  const auto wall = elapsed_ms(host);
  float device = 0;
  cuda_check(cudaEventElapsedTime(&device, events.start, events.stop), "cudaEventElapsedTime");
  return {double(device), wall};
}

__global__ void fill_pattern(uint32_t* data, std::size_t words, unsigned pass, uint32_t seed) {
  for (std::size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < words; i += std::size_t(blockDim.x) * gridDim.x)
    data[i] = gri::pattern(i, pass, seed);
}
__global__ void copy_words(const uint32_t* input, uint32_t* output, std::size_t words, unsigned stride) {
  // Stride is a permutation in each power-of-two tile, preserving all bytes.
  constexpr std::size_t tile = 1024;
  for (std::size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < words; i += std::size_t(blockDim.x) * gridDim.x) {
    const auto base = (i / tile) * tile;
    const auto permuted = base + ((i % tile) * stride) % tile;
    if (permuted < words) output[permuted] = input[permuted];
  }
}
__global__ void dispatch_increment(uint32_t* counter) { if (threadIdx.x == 0 && blockIdx.x == 0) atomicAdd(counter, 1U); }
template<class T> __global__ void fill_matrix(T* output, std::size_t count, uint32_t seed) {
  for (std::size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < count; i += std::size_t(blockDim.x) * gridDim.x)
    output[i] = T(gri::matrix_value(i, seed));
}

void verify_device_words(Result& result, const void* data, std::size_t bytes, unsigned pass) {
  const std::size_t chunk_words = MiB / sizeof(uint32_t);
  std::vector<uint32_t> host(std::min(bytes / sizeof(uint32_t), chunk_words));
  uint64_t hash = 14695981039346656037ULL;
  for (std::size_t offset = 0; offset < bytes / sizeof(uint32_t); offset += host.size()) {
    result.budget();
    const auto count = std::min(host.size(), bytes / sizeof(uint32_t) - offset);
    cuda_check(cudaMemcpy(host.data(), static_cast<const uint32_t*>(data) + offset, count * sizeof(uint32_t), cudaMemcpyDeviceToHost), "verification_readback");
    result.verify(gri::check_words(host.data(), count, offset, pass, result.args.seed), count);
    for (std::size_t i = 0; i < count; ++i) hash = gri::hash_word(hash, host[i]);
  }
  result.coverage["last_verified_readback_fnv1a64"] = gri::hash_string(hash);
  result.coverage["last_verified_readback_bytes"] = bytes;
  result.coverage["last_verified_readback_pattern_pass"] = pass;
}

void memory_integrity(Result& result, std::size_t allowance) {
  const auto bytes = allowance - allowance % sizeof(uint32_t);
  DeviceBuffer device(bytes);
  const unsigned passes = result.args.tier == "standard" ? 8 : 3;
  result.conditions["pattern_generator"] = "gri-pattern-v1";
  result.conditions["requested_passes"] = passes;
  result.conditions["patterns"] = result.args.tier == "standard" ? "zero,ones,address,complement,walking-one,walking-zero,alternating,mixed" : "zero,ones,address";
  result.coverage["allocated_bytes"] = bytes;
  result.coverage["unique_logical_bytes_verified"] = 0;
  result.coverage["completed_passes"] = 0;
  result.coverage["physical_memory_coverage"] = "unknown";
  result.metric_name = "pattern_fill_bandwidth"; result.unit = "GB/s";
  result.limitations.emplace_back("Pattern fill speed is not a device-memory bandwidth benchmark; integrity checks cover owned logical bytes only.");
  for (unsigned pass = 0; pass < passes; ++pass) {
    result.budget();
    const auto timing = measure([&] { fill_pattern<<<256, 256>>>(static_cast<uint32_t*>(device.data), bytes/4, pass, result.args.seed); });
    verify_device_words(result, device.data, bytes, pass);
    result.add_sample(double(bytes) / (timing.first * 1e6), timing.first, timing.second);
    result.coverage["unique_logical_bytes_verified"] = bytes;
    result.coverage["completed_passes"] = pass + 1;
    result.coverage["total_verified_bytes"] = bytes * (pass + 1);
  }
}

void gemm(Result& result, std::size_t allowance) {
  const bool bf16 = result.args.method == "bf16_gemm", tf32 = result.args.method == "tf32_gemm";
  const char* tf32_override = std::getenv("NVIDIA_TF32_OVERRIDE");
  result.conditions["tf32_override"] = tf32_override && std::string(tf32_override) == "0" ? "disabled" : "not_disabled";
  if (tf32 && tf32_override && std::string(tf32_override) == "0") throw Failure("unsupported", "tf32_disabled_by_environment");
  int n = result.args.tier == "standard" ? 4096 : 2048;
  const std::size_t per_element = bf16 ? 8 : 12;
  while (std::size_t(n) * n * per_element > allowance && n > 256) n /= 2;
  if (std::size_t(n) * n * per_element > allowance) throw Failure("blocked", "insufficient_gemm_headroom");
  const auto elements = std::size_t(n) * n;
  DeviceBuffer a(elements * (bf16 ? 2 : 4)), b(elements * (bf16 ? 2 : 4)), c(elements * 4);
  Blas blas;
  blas_check(cublasSetAtomicsMode(blas.handle, CUBLAS_ATOMICS_NOT_ALLOWED), "cublasSetAtomicsMode");
  const auto math_mode = (!bf16 && !tf32) ? CUBLAS_PEDANTIC_MATH :
    static_cast<cublasMath_t>(CUBLAS_DEFAULT_MATH | CUBLAS_MATH_DISALLOW_REDUCED_PRECISION_REDUCTION);
  blas_check(cublasSetMathMode(blas.handle, math_mode), "cublasSetMathMode");
  int library_version = 0;
  blas_check(cublasGetVersion(blas.handle, &library_version), "cublasGetVersion");
  if (bf16) {
    fill_matrix<<<256,256>>>(static_cast<__nv_bfloat16*>(a.data), elements, result.args.seed);
    fill_matrix<<<256,256>>>(static_cast<__nv_bfloat16*>(b.data), elements, result.args.seed ^ 0xa5a5a5a5U);
  } else {
    fill_matrix<<<256,256>>>(static_cast<float*>(a.data), elements, result.args.seed);
    fill_matrix<<<256,256>>>(static_cast<float*>(b.data), elements, result.args.seed ^ 0xa5a5a5a5U);
  }
  cuda_check(cudaGetLastError(), "gemm_input_initialization");
  const auto compute = bf16 ? CUBLAS_COMPUTE_32F : (tf32 ? CUBLAS_COMPUTE_32F_FAST_TF32 : CUBLAS_COMPUTE_32F_PEDANTIC);
  const auto input_type = bf16 ? CUDA_R_16BF : CUDA_R_32F;
  const float alpha = 1, beta = 0;
  auto operation = [&] {
    blas_check(cublasGemmEx(blas.handle, CUBLAS_OP_N, CUBLAS_OP_N, n, n, n, &alpha,
      a.data, input_type, n, b.data, input_type, n, &beta, c.data, CUDA_R_32F, n,
      compute, CUBLAS_GEMM_DEFAULT), "cublasGemmEx");
  };
  result.conditions["m"] = n; result.conditions["n"] = n; result.conditions["k"] = n;
  result.conditions["batch_count"] = 1; result.conditions["operations_per_gemm"] = double(2) * n*n*n;
  result.conditions["input_type"] = bf16 ? "bf16" : "fp32";
  result.conditions["accumulator_type"] = "fp32"; result.conditions["output_type"] = "fp32";
  result.conditions["compute_mode"] = bf16 ? "CUBLAS_COMPUTE_32F" : (tf32 ? "CUBLAS_COMPUTE_32F_FAST_TF32" : "CUBLAS_COMPUTE_32F_PEDANTIC");
  result.conditions["math_mode"] = (!bf16 && !tf32) ? "CUBLAS_PEDANTIC_MATH" : "CUBLAS_DEFAULT_MATH|CUBLAS_MATH_DISALLOW_REDUCED_PRECISION_REDUCTION";
  result.conditions["algorithm"] = "CUBLAS_GEMM_DEFAULT"; result.conditions["cublas_version"] = library_version;
  result.conditions["layout"] = "column_major"; result.conditions["dense"] = true;
  result.conditions["input_generator"] = "gri-matrix-v1_integer_-3_to_3";
  uint64_t input_hash = 14695981039346656037ULL;
  for (auto seed : {result.args.seed, result.args.seed ^ 0xa5a5a5a5U}) {
    for (std::size_t i = 0; i < elements; ++i) {
      float value = gri::matrix_value(i, seed);
      uint32_t bits = 0; std::memcpy(&bits, &value, sizeof(bits));
      input_hash = gri::hash_word(input_hash, bits);
    }
    result.budget(100);
  }
  result.conditions["input_logical_values_fnv1a64"] = gri::hash_string(input_hash);
  result.conditions["input_hash_serialization"] = "A then B, column-major, logical FP32 values, little-endian; non-cryptographic";
  result.conditions["input_a_seed"] = result.args.seed; result.conditions["input_b_seed"] = result.args.seed ^ 0xa5a5a5a5U;
  result.conditions["absolute_tolerance"] = 0; result.conditions["warmup_gemms"] = 2;
  result.conditions["timed_gemms_per_sample"] = 8;
  result.conditions["validation_granularity"] = "final output after each batch of 8 identical-input GEMMs";
  result.coverage["allocated_bytes"] = elements * per_element;
  result.coverage["output_elements"] = elements;
  result.coverage["checked_output_positions_per_sample"] = 128;
  result.coverage["nonfinite_output_positions_checked_per_sample"] = elements;
  result.limitations.emplace_back("Host int64 known answers check 128 seeded output positions per sample; every output is checked for NaN/Inf. Integer inputs do not characterize general FP precision.");
  result.limitations.emplace_back("cuBLAS default algorithm is library-selected; references must match the recorded library version and math mode. Tensor-core instruction use is not independently traced.");
  result.limitations.emplace_back("Intermediate outputs overwritten within a timed batch are not checked individually.");
  result.metric_name = bf16 ? "bf16_dense_gemm" : (tf32 ? "tf32_dense_gemm" : "fp32_dense_gemm"); result.unit = "TFLOP/s";
  auto warmup = Clock::now(); operation(); operation(); cuda_check(cudaDeviceSynchronize(), "gemm_warmup"); result.warmup_ms = elapsed_ms(warmup);
  std::vector<float> host(elements);
  const unsigned repetitions = result.args.tier == "standard" ? 64 : 8;
  for (unsigned repetition = 0; repetition < repetitions; ++repetition) {
    result.budget(100);
    // Poison every output before each measured batch; beta=0 must overwrite it.
    cuda_check(cudaMemset(c.data, 0xff, elements*4), "gemm_output_poison");
    const auto timing = measure([&] { for (int iteration = 0; iteration < 8; ++iteration) operation(); });
    cuda_check(cudaMemcpy(host.data(), c.data, elements*4, cudaMemcpyDeviceToHost), "gemm_readback");
    std::vector<gri::Mismatch> wrong;
    for (std::size_t i = 0; i < elements; ++i)
      if (!std::isfinite(host[i]) && wrong.size() < 8)
        wrong.push_back({i, gri::matrix_answer(int(i % n), int(i / n), n, result.args.seed), host[i]});
    for (unsigned sample = 0; sample < 128; ++sample) {
      const auto position = sample == 0 ? 0 : (sample == 1 ? elements - 1 : gri::mix32(result.args.seed + repetition*128 + sample) % elements);
      const int row = int(position % n), column = int(position / n);
      const auto expected = gri::matrix_answer(row, column, n, result.args.seed);
      if (!gri::answer_matches(expected, host[position]) && wrong.size() < 8)
        wrong.push_back({position, expected, host[position]});
    }
    result.verify(wrong, 128);
    result.add_sample((2.0*n*n*n*8) / (timing.first*1e9), timing.first, timing.second);
  }
}

void bandwidth(Result& result, std::size_t allowance, std::size_t l2_bytes, int architecture_major) {
  const bool sweep = result.args.method == "working_set";
  std::size_t bytes = allowance / 2;
  bytes -= bytes % (1024 * sizeof(uint32_t));
  if (!l2_bytes) throw Failure("unsupported", "l2_size_unavailable_for_memory_bandwidth_method");
  // Each of the two buffers is at least twice L2; combined working set >=4x L2.
  if (bytes < 2 * l2_bytes) throw Failure("blocked", "memory_cap_too_small_to_exceed_l2");
  DeviceBuffer source(bytes), destination(bytes);
  fill_pattern<<<256,256>>>(static_cast<uint32_t*>(source.data), bytes/4, 2, result.args.seed);
  cuda_check(cudaGetLastError(), "bandwidth_input_initialization");
  cuda_check(cudaDeviceSynchronize(), "bandwidth_input_synchronize");
  result.conditions["l2_bytes"] = l2_bytes; result.conditions["buffer_bytes"] = bytes;
  result.conditions["traffic_accounting"] = "source bytes read + destination bytes written (2 * buffer_bytes)";
  result.conditions["copy_method"] = "gri-copy-kernel-v1";
  result.conditions["warmup_copies"] = 2; result.conditions["timed_copies_per_sample"] = 8;
  result.conditions["validation_granularity"] = "final content after each batch of 8 identical-input copies";
  result.coverage["allocated_bytes"] = 2 * bytes;
  result.coverage["physical_memory_coverage"] = "unknown";
  result.metric_name = sweep ? "working_set_copy" : gri::memory_bandwidth_metric(architecture_major); result.unit = "GB/s";
  result.conditions["memory_bandwidth_method_id"] = "hbm_copy is the legacy ID for architecture-specific device-memory copy";
  std::vector<std::size_t> sizes = sweep ? std::vector<std::size_t>{std::min(bytes, std::max(std::size_t(4096), l2_bytes/4/4096*4096)), bytes} : std::vector<std::size_t>{bytes};
  std::vector<Json> windows;
  const unsigned repetitions = result.args.tier == "standard" ? 12 : 5;
  for (auto size : sizes) for (unsigned stride : (sweep ? std::vector<unsigned>{1, 17} : std::vector<unsigned>{1})) {
    auto operation = [&] { copy_words<<<256,256>>>(static_cast<const uint32_t*>(source.data), static_cast<uint32_t*>(destination.data), size/4, stride); };
    auto warm = Clock::now(); operation(); operation(); cuda_check(cudaDeviceSynchronize(), "copy_warmup"); result.warmup_ms += elapsed_ms(warm);
    for (unsigned repetition = 0; repetition < repetitions; ++repetition) {
      result.budget(50);
      cuda_check(cudaMemset(destination.data, 0, size), "copy_destination_clear");
      const auto timing = measure([&] { for (int iteration = 0; iteration < 8; ++iteration) operation(); });
      verify_device_words(result, destination.data, size, 2);
      const auto value = (2.0 * size * 8) / (timing.first * 1e6);
      result.add_sample(value, timing.first, timing.second);
      windows.push_back(Json::object({{"sample_index", result.samples.size()-1}, {"bytes", size}, {"stride_words", stride}, {"value_gb_s", value}, {"working_set_exceeds_l2", size > l2_bytes}}));
      result.coverage["windows"] = Json::array(windows);
    }
  }
  result.coverage["windows"] = Json::array(windows);
  if (sweep) {
    result.conditions["mixed_working_sets"] = true;
    result.limitations.emplace_back("Working-set samples have different sizes/strides; the aggregate median is descriptive only and ineligible for device-memory reference scoring.");
  }
}

void transfer(Result& result, std::size_t allowance) {
  const bool h2d = result.args.method == "h2d";
  const auto bytes = std::min(allowance, (result.args.tier == "standard" ? 256U : 64U) * MiB) / 4 * 4;
  DeviceBuffer device(bytes); PinnedBuffer host(bytes);
  auto* words = static_cast<uint32_t*>(host.data);
  if (h2d) {
    for (std::size_t i = 0; i < bytes/4; ++i) words[i] = gri::pattern(i, 2, result.args.seed);
  } else {
    fill_pattern<<<256,256>>>(static_cast<uint32_t*>(device.data), bytes/4, 2, result.args.seed);
    cuda_check(cudaGetLastError(), "d2h_input_initialization");
  }
  uint64_t input_hash = 14695981039346656037ULL;
  for (std::size_t i = 0; i < bytes/4; ++i) input_hash = gri::hash_word(input_hash, gri::pattern(i, 2, result.args.seed));
  result.conditions["expected_input_fnv1a64"] = gri::hash_string(input_hash);
  result.conditions["checksum_serialization"] = "little-endian uint32 words; non-cryptographic";
  auto operation = [&] {
    cuda_check(cudaMemcpyAsync(h2d ? device.data : host.data, h2d ? host.data : device.data, bytes,
      h2d ? cudaMemcpyHostToDevice : cudaMemcpyDeviceToHost), "cudaMemcpyAsync");
  };
  result.conditions["direction"] = h2d ? "H2D" : "D2H";
  result.conditions["copy_method"] = "cudaMemcpyAsync_pinned_default_stream";
  result.conditions["host_memory"] = "cudaMallocHost_page_locked";
  result.conditions["host_placement"] = "first_touch_by_worker; NUMA binding not controlled";
  result.conditions["transfer_bytes"] = bytes;
  result.conditions["traffic_accounting"] = "one direction payload bytes";
  result.conditions["warmup_transfers"] = 2; result.conditions["timed_transfers_per_sample"] = 4;
  result.conditions["validation_granularity"] = "final content after each batch of 4 identical-input transfers";
  result.coverage["allocated_device_bytes"] = bytes; result.coverage["pinned_host_bytes"] = bytes;
  result.metric_name = h2d ? "pinned_h2d" : "pinned_d2h"; result.unit = "GB/s";
  auto warm = Clock::now(); operation(); operation(); cuda_check(cudaDeviceSynchronize(), "transfer_warmup"); result.warmup_ms = elapsed_ms(warm);
  const unsigned repetitions = result.args.tier == "standard" ? 20 : 5;
  for (unsigned repetition = 0; repetition < repetitions; ++repetition) {
    result.budget(50);
    if (h2d) cuda_check(cudaMemset(device.data, 0, bytes), "transfer_destination_clear");
    else std::memset(host.data, 0, bytes);
    const auto timing = measure([&] { for (int i = 0; i < 4; ++i) operation(); });
    if (h2d) verify_device_words(result, device.data, bytes, 2);
    else result.verify(gri::check_words(words, bytes/4, 0, 2, result.args.seed), bytes/4);
    result.add_sample(double(bytes*4) / (timing.first*1e6), timing.first, timing.second);
  }
}

void dispatch_latency(Result& result) {
  DeviceBuffer counter(sizeof(uint32_t));
  cuda_check(cudaMemset(counter.data, 0, 4), "dispatch_counter_clear");
  auto operation = [&] { dispatch_increment<<<1,1>>>(static_cast<uint32_t*>(counter.data)); };
  auto warm = Clock::now(); operation(); cuda_check(cudaDeviceSynchronize(), "dispatch_warmup"); result.warmup_ms = elapsed_ms(warm);
  result.conditions["operation"] = "single_thread_atomic_increment";
  result.conditions["synchronization"] = "CUDA event synchronize after every launch";
  result.conditions["warmup_launches"] = 1;
  result.metric_name = "synchronized_dispatch_wall_latency"; result.unit = "us";
  result.limitations.emplace_back("Per-launch wall latency includes event recording and synchronization; it is not pure hardware launch latency or proof of time-sharing.");
  for (unsigned repetition = 0; repetition < 128; ++repetition) {
    result.budget();
    const auto timing = measure(operation);
    uint32_t value = 0; cuda_check(cudaMemcpy(&value, counter.data, 4, cudaMemcpyDeviceToHost), "dispatch_readback");
    std::vector<gri::Mismatch> wrong;
    if (value != repetition + 2) wrong.push_back({0, double(repetition+2), double(value)});
    result.verify(wrong, 1);
    result.add_sample(timing.second * 1000, timing.first, timing.second);
  }
}

void run(Result& result) {
  const char* visible = std::getenv("CUDA_VISIBLE_DEVICES");
  // Refuse to broaden or reinterpret a caller-provided selection. The parent
  // collector must first map its resource and set the exact UUID in child env.
  if (visible && std::string(visible) != result.args.device)
    throw Failure("blocked", "cuda_visible_devices_must_equal_selected_uuid");
#ifdef _WIN32
  if (_putenv_s("CUDA_VISIBLE_DEVICES", result.args.device.c_str()) != 0)
#else
  if (setenv("CUDA_VISIBLE_DEVICES", result.args.device.c_str(), 1) != 0)
#endif
    throw Failure("blocked", "cannot_restrict_cuda_visibility");
  int count = 0; cuda_check(cudaGetDeviceCount(&count), "cudaGetDeviceCount");
  if (count != 1) throw Failure("blocked", "selected_resource_not_unique");
  cudaDeviceProp properties{};
  cuda_check(cudaGetDeviceProperties(&properties, 0), "cudaGetDeviceProperties");
  if (uuid_string(properties.uuid) != result.args.device) throw Failure("blocked", "selected_uuid_changed");
  if (!gri::supported_architecture(properties.major, properties.minor))
    throw Failure("unsupported", "architecture_not_supported_by_worker");
  int runtime_version = 0, driver_version = 0;
  cuda_check(cudaRuntimeGetVersion(&runtime_version), "cudaRuntimeGetVersion");
  cuda_check(cudaDriverGetVersion(&driver_version), "cudaDriverGetVersion");
  if (properties.major == 12 && runtime_version < 12080)
    throw Failure("unsupported", "sm120_requires_cuda_runtime_12_8_or_later");
  cuda_check(cudaSetDevice(0), "cudaSetDevice");
  cuda_check(cudaFree(nullptr), "cuda_context_initialize");
  cudaDeviceProp rechecked{};
  cuda_check(cudaGetDeviceProperties(&rechecked, 0), "recheck_device_properties");
  if (uuid_string(rechecked.uuid) != result.args.device) throw Failure("blocked", "selected_uuid_changed");
  std::size_t free_bytes = 0, total_bytes = 0;
  cuda_check(cudaMemGetInfo(&free_bytes, &total_bytes), "cudaMemGetInfo");
  const std::size_t reserve = std::max(std::size_t(512)*MiB, total_bytes/10);
  if (free_bytes <= reserve + MiB) throw Failure("blocked", "insufficient_free_memory_reserve");
  const auto allowance = std::min(std::size_t(result.args.memory_mib)*MiB, free_bytes-reserve);
  result.conditions = {{"seed", result.args.seed}, {"tier", result.args.tier}, {"budget_ms", result.args.budget_ms},
    {"memory_cap_bytes", std::size_t(result.args.memory_mib)*MiB}, {"device_memory_free_bytes_before", free_bytes},
    {"device_memory_total_bytes", total_bytes}, {"device_memory_reserve_bytes", reserve}, {"allocation_allowance_bytes", allowance},
    {"scope", "one_selected_visible_full_gpu"}, {"selected_uuid_rechecked", true}, {"visible_device_count", count},
    {"runtime_version", runtime_version}, {"cuda_driver_api_version", driver_version},
    {"compute_capability", std::to_string(properties.major) + "." + std::to_string(properties.minor)},
    {"architecture_family", gri::architecture_family(properties.major, properties.minor)},
    {"device_name", properties.name}, {"device_memory_technology", gri::memory_technology(properties.name)},
    {"memory_technology_source", "reported product name; CUDA runtime does not independently expose memory technology"},
    {"kernel_execution_timeout_enabled", properties.kernelExecTimeoutEnabled != 0},
    {"device_sm_count", properties.multiProcessorCount}, {"device_l2_bytes", properties.l2CacheSize},
    {"device_warp_size", properties.warpSize}, {"device_max_threads_per_block", properties.maxThreadsPerBlock},
    {"worker_qualification", "pending_real_gpu_acceptance"}, {"sample_independence", "correlated_repetitions_on_one_allocation"}};
  result.cold_start_ms = elapsed_ms(result.start);
#ifdef _WIN32
  result.conditions["worker_os"] = "windows";
  result.conditions["windows_driver_model"] = properties.tccDriver ? "TCC" : "WDDM";
  result.limitations.emplace_back("Windows WDDM scheduling and display workloads can affect timing and available memory; no driver timeout settings are changed. Compare only matching OS/driver-model references.");
#else
  result.conditions["worker_os"] = "linux";
#endif
  result.limitations.emplace_back("Development worker: no real-GPU numerical, sanitizer, timing-budget or isolation qualification is asserted by this build.");
  result.limitations.emplace_back("The parent scanner enforces ownership, idle/safety telemetry and a hard process timeout. A blocked driver wait may outlive userspace cancellation.");
  result.budget(100);
  if (result.args.method == "memory_integrity") memory_integrity(result, allowance);
  else if (result.args.method == "fp32_gemm" || result.args.method == "bf16_gemm" || result.args.method == "tf32_gemm") gemm(result, allowance);
  else if (result.args.method == "hbm_copy" || result.args.method == "working_set") bandwidth(result, allowance, properties.l2CacheSize > 0 ? std::size_t(properties.l2CacheSize) : 0, properties.major);
  else if (result.args.method == "h2d" || result.args.method == "d2h") transfer(result, allowance);
  else if (result.args.method == "dispatch_latency") dispatch_latency(result);
}
}  // namespace

int main(int argc, char** argv) {
  Result result;
  try {
    result.args = parse(argc, argv);
    run(result);
  } catch (const Failure& error) {
    result.status = error.status;
    result.errors.push_back(Json::object({{"code", error.code}, {"native_code", error.native_code}}));
  } catch (const std::bad_alloc&) {
    result.status = "blocked"; result.errors.push_back(Json::object({{"code", "host_allocation_failed"}}));
  } catch (...) {
    result.status = "test_error"; result.errors.push_back(Json::object({{"code", "unexpected_worker_exception"}}));
  }
  std::cout << result.json().data << '\n';
  return result.status == "ok" ? 0 : 2;
}
