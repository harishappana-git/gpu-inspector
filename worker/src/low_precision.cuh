// Included within the worker's private namespace after shared CUDA helpers.
struct LtHandle {
  cublasLtHandle_t handle = nullptr;
  LtHandle() { blas_check(cublasLtCreate(&handle), "cublasLtCreate"); }
  ~LtHandle() { if (handle) cublasLtDestroy(handle); }
};
struct LtDescriptor {
  cublasLtMatmulDesc_t value = nullptr;
  LtDescriptor() { blas_check(cublasLtMatmulDescCreate(&value, CUBLAS_COMPUTE_32F, CUDA_R_32F), "cublasLtMatmulDescCreate"); }
  ~LtDescriptor() { if (value) cublasLtMatmulDescDestroy(value); }
};
struct LtLayout {
  cublasLtMatrixLayout_t value = nullptr;
  LtLayout(cudaDataType_t type, int n) { blas_check(cublasLtMatrixLayoutCreate(&value, type, n, n, n), "cublasLtMatrixLayoutCreate"); }
  ~LtLayout() { if (value) cublasLtMatrixLayoutDestroy(value); }
};
struct LtPreference {
  cublasLtMatmulPreference_t value = nullptr;
  LtPreference() { blas_check(cublasLtMatmulPreferenceCreate(&value), "cublasLtMatmulPreferenceCreate"); }
  ~LtPreference() { if (value) cublasLtMatmulPreferenceDestroy(value); }
};

__global__ void fill_low_precision(uint8_t* output, std::size_t count, int n, uint32_t seed, bool fp8, bool transpose) {
  for (std::size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < count; i += std::size_t(blockDim.x) * gridDim.x) {
    const auto logical = transpose ? i / n + (i % n) * n : i;
    const int value = int(gri::matrix_value(logical, seed));
    output[i] = fp8 ? gri::fp8_e4m3_small_integer(value) : uint8_t(int8_t(value));
  }
}

void low_precision_gemm(Result& result, std::size_t allowance) {
  const bool fp8 = result.args.method == "fp8_gemm";
  const std::size_t workspace_bytes = fp8 ? std::min(std::size_t(result.args.tier == "standard" ? 32 : 4)*MiB, allowance/8) : 0;
  int n = result.args.tier == "standard" ? 4096 : 2048;
  while (std::size_t(n)*n*6 + workspace_bytes + 8 > allowance && n > 256) n /= 2;
  if (std::size_t(n)*n*6 + workspace_bytes + 8 > allowance)
    throw Failure("blocked", "insufficient_low_precision_gemm_headroom");
  const auto elements = std::size_t(n)*n;
  DeviceBuffer a(elements), b(elements), c(elements*4);
  // FP8 uses the documented TN column-major storage. The A initializer writes
  // the transpose of the canonical logical A; host known answers still use A*B.
  fill_low_precision<<<256,256>>>(static_cast<uint8_t*>(a.data), elements, n, result.args.seed, fp8, fp8);
  fill_low_precision<<<256,256>>>(static_cast<uint8_t*>(b.data), elements, n, result.args.seed ^ 0xa5a5a5a5U, fp8, false);
  cuda_check(cudaGetLastError(), "low_precision_input_initialization");
  result.conditions["m"] = n; result.conditions["n"] = n; result.conditions["k"] = n;
  result.conditions["batch_count"] = 1; result.conditions["operations_per_gemm"] = 2.0*n*n*n;
  result.conditions["input_type"] = fp8 ? "fp8_e4m3" : "int8";
  result.conditions["accumulator_type"] = fp8 ? "fp32" : "int32";
  result.conditions["output_type"] = fp8 ? "fp32" : "int32";
  result.conditions["compute_mode"] = fp8 ? "CUBLAS_COMPUTE_32F" : "CUBLAS_COMPUTE_32I_PEDANTIC";
  result.conditions["math_mode"] = fp8 ? "CUBLASLT_FP8_FAST_ACCUM_DISABLED" : "CUBLAS_PEDANTIC_MATH";
  result.conditions["layout"] = "column_major"; result.conditions["operation_a"] = fp8 ? "transpose_physical_A" : "none";
  result.conditions["operation_b"] = "none"; result.conditions["dense"] = true;
  result.conditions["input_generator"] = "gri-matrix-v1_integer_-3_to_3";
  result.conditions["input_a_seed"] = result.args.seed; result.conditions["input_b_seed"] = result.args.seed ^ 0xa5a5a5a5U;
  result.conditions["input_a_scale"] = 1.0; result.conditions["input_b_scale"] = 1.0;
  result.conditions["input_a_zero_point"] = 0; result.conditions["input_b_zero_point"] = 0;
  result.conditions["scaling_mode"] = fp8 ? "tensorwide_fp32_scalar" : "exact_integer_unit_scale";
  result.conditions["alpha"] = 1; result.conditions["beta"] = 0; result.conditions["absolute_tolerance"] = 0;
  result.conditions["workspace_bytes"] = workspace_bytes;
  result.conditions["warmup_gemms"] = 2; result.conditions["timed_gemms_per_sample"] = 8;
  result.conditions["validation_granularity"] = "final output after each batch of 8 identical-input GEMMs";
  result.conditions["output_absolute_bound"] = 9*n;
  result.coverage["allocated_bytes"] = elements*6 + workspace_bytes + (fp8 ? 8 : 0);
  result.coverage["output_elements"] = elements;
  result.coverage["checked_output_positions_per_sample"] = 128;
  result.coverage["range_checked_output_positions_per_sample"] = elements;
  result.coverage["nonfinite_output_positions_checked_per_sample"] = fp8 ? elements : 0;
  uint64_t input_hash = 14695981039346656037ULL;
  for (auto seed : {result.args.seed, result.args.seed ^ 0xa5a5a5a5U}) {
    for (std::size_t i=0; i<elements; ++i) {
      float value = gri::matrix_value(i,seed); uint32_t bits=0; std::memcpy(&bits,&value,4);
      input_hash = gri::hash_word(input_hash,bits);
    }
    result.budget(100);
  }
  result.conditions["input_logical_values_fnv1a64"] = gri::hash_string(input_hash);
  result.conditions["input_hash_serialization"] = "canonical logical A then B, column-major FP32 integers, little-endian; independent of physical transpose/encoding; non-cryptographic";
  result.metric_name = fp8 ? "fp8_dense_gemm" : "int8_dense_gemm";
  result.unit = fp8 ? "TFLOP/s" : "TOP/s";
  result.limitations.emplace_back("Exact small-integer inputs exercise the declared FP8/INT8 path but do not characterize general quantization accuracy, arbitrary scale calibration or tensor instruction selection.");
  result.limitations.emplace_back("128 independent host int64 dot products per sample; every final output is checked against its finite/range bound. Intermediate overwritten GEMM results are not independently checked.");

  std::function<void()> operation;
  std::unique_ptr<Blas> blas;
  std::unique_ptr<LtHandle> lt;
  std::unique_ptr<LtDescriptor> descriptor;
  std::unique_ptr<LtLayout> ab_layout, cd_layout;
  std::unique_ptr<LtPreference> preference;
  std::unique_ptr<DeviceBuffer> workspace, scales;
  cublasLtMatmulHeuristicResult_t heuristic{};
  const float alpha_float=1, beta_float=0;
  const int32_t alpha_integer=1, beta_integer=0;
  if (fp8) {
    lt.reset(new LtHandle); descriptor.reset(new LtDescriptor);
    ab_layout.reset(new LtLayout(CUDA_R_8F_E4M3,n)); cd_layout.reset(new LtLayout(CUDA_R_32F,n));
    preference.reset(new LtPreference); workspace.reset(new DeviceBuffer(workspace_bytes)); scales.reset(new DeviceBuffer(8));
    const float host_scales[2]={1,1}; cuda_check(cudaMemcpy(scales->data,host_scales,8,cudaMemcpyHostToDevice),"fp8_scale_initialize");
    auto transpose=CUBLAS_OP_T, normal=CUBLAS_OP_N;
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_TRANSA,&transpose,sizeof(transpose)),"fp8_transpose_a");
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_TRANSB,&normal,sizeof(normal)),"fp8_transpose_b");
    void* scale_a=scales->data; void* scale_b=static_cast<float*>(scales->data)+1;
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_A_SCALE_POINTER,&scale_a,sizeof(scale_a)),"fp8_scale_a");
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_B_SCALE_POINTER,&scale_b,sizeof(scale_b)),"fp8_scale_b");
    int8_t fast_accum=0;
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_FAST_ACCUM,&fast_accum,sizeof(fast_accum)),"fp8_fast_accum_disable");
#if CUDART_VERSION >= 12080
    auto scale_mode=CUBLASLT_MATMUL_MATRIX_SCALE_SCALAR_32F;
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_A_SCALE_MODE,&scale_mode,sizeof(scale_mode)),"fp8_scalar_scale_a");
    blas_check(cublasLtMatmulDescSetAttribute(descriptor->value,CUBLASLT_MATMUL_DESC_B_SCALE_MODE,&scale_mode,sizeof(scale_mode)),"fp8_scalar_scale_b");
#endif
    blas_check(cublasLtMatmulPreferenceSetAttribute(preference->value,CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,&workspace_bytes,sizeof(workspace_bytes)),"fp8_workspace_limit");
    int count=0;
    blas_check(cublasLtMatmulAlgoGetHeuristic(lt->handle,descriptor->value,ab_layout->value,ab_layout->value,cd_layout->value,cd_layout->value,preference->value,1,&heuristic,&count),"fp8_algorithm_heuristic");
    if (count!=1 || heuristic.state!=CUBLAS_STATUS_SUCCESS || heuristic.workspaceSize>workspace_bytes) throw Failure("unsupported","fp8_supported_algorithm_unavailable");
    result.conditions["algorithm"]="cublasLtMatmulAlgoGetHeuristic_first_supported";
    result.conditions["cublas_version"]=cublasLtGetVersion();
    int algorithm_id=0; std::size_t written=0;
    blas_check(cublasLtMatmulAlgoConfigGetAttribute(&heuristic.algo,CUBLASLT_ALGO_CONFIG_ID,&algorithm_id,sizeof(algorithm_id),&written),"fp8_algorithm_id");
    result.conditions["algorithm_id"]=algorithm_id;
    operation=[&] { blas_check(cublasLtMatmul(lt->handle,descriptor->value,&alpha_float,a.data,ab_layout->value,b.data,ab_layout->value,&beta_float,c.data,cd_layout->value,c.data,cd_layout->value,&heuristic.algo,workspace->data,workspace_bytes,nullptr),"cublasLtMatmul_fp8"); };
  } else {
    blas.reset(new Blas);
    blas_check(cublasSetAtomicsMode(blas->handle,CUBLAS_ATOMICS_NOT_ALLOWED),"int8_atomics_disable");
    blas_check(cublasSetMathMode(blas->handle,CUBLAS_PEDANTIC_MATH),"int8_pedantic_math");
    int version=0;blas_check(cublasGetVersion(blas->handle,&version),"cublasGetVersion");result.conditions["cublas_version"]=version;
    result.conditions["algorithm"]="CUBLAS_GEMM_DEFAULT";
    operation=[&] { blas_check(cublasGemmEx(blas->handle,CUBLAS_OP_N,CUBLAS_OP_N,n,n,n,&alpha_integer,a.data,CUDA_R_8I,n,b.data,CUDA_R_8I,n,&beta_integer,c.data,CUDA_R_32I,n,CUBLAS_COMPUTE_32I_PEDANTIC,CUBLAS_GEMM_DEFAULT),"cublasGemmEx_int8"); };
  }
  auto warm=Clock::now();operation();operation();cuda_check(cudaDeviceSynchronize(),"low_precision_warmup");result.warmup_ms=elapsed_ms(warm);
  std::vector<uint32_t> host(elements);
  const unsigned repetitions=result.args.tier=="standard"?64:8;
  for (unsigned repetition=0;repetition<repetitions;++repetition) {
    result.budget(100);
    cuda_check(cudaMemset(c.data,0x7f,elements*4),"low_precision_output_poison");
    const auto timing=measure([&]{for(int i=0;i<8;++i)operation();});
    cuda_check(cudaMemcpy(host.data(),c.data,elements*4,cudaMemcpyDeviceToHost),"low_precision_readback");
    auto observed=[&](std::size_t i) -> double { if(fp8){float v;std::memcpy(&v,&host[i],4);return v;}int32_t v;std::memcpy(&v,&host[i],4);return v; };
    std::vector<gri::Mismatch> wrong;
    for(std::size_t i=0;i<elements;++i) { const auto value=observed(i);if((!std::isfinite(value)||std::fabs(value)>9*n)&&wrong.size()<8)wrong.push_back({i,gri::matrix_answer(int(i%n),int(i/n),n,result.args.seed),value}); }
    for(unsigned sample=0;sample<128;++sample) {
      const auto position=sample==0?0:(sample==1?elements-1:gri::mix32(result.args.seed+repetition*128+sample)%elements);
      const auto expected=gri::matrix_answer(int(position%n),int(position/n),n,result.args.seed);
      if(!gri::answer_matches(expected,observed(position))&&wrong.size()<8)wrong.push_back({position,expected,observed(position)});
    }
    result.verify(wrong,128);result.add_sample((2.0*n*n*n*8)/(timing.first*1e9),timing.first,timing.second);
  }
}
