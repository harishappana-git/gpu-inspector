package worker

import "errors"

func (r Result) validateLowPrecision() error {
	c := r.Conditions
	input, output, compute, mode, algorithm, scaling, transpose := "int8", "int32", "CUBLAS_COMPUTE_32I_PEDANTIC", "CUBLAS_PEDANTIC_MATH", "CUBLAS_GEMM_DEFAULT", "exact_integer_unit_scale", "none"
	if r.Method == "fp8_gemm" {
		input, output, compute, mode, algorithm, scaling, transpose = "fp8_e4m3", "fp32", "CUBLAS_COMPUTE_32F", "CUBLASLT_FP8_FAST_ACCUM_DISABLED", "cublasLtMatmulAlgoGetHeuristic_first_supported", "tensorwide_fp32_scalar", "transpose_physical_A"
	}
	m, ok := number(c["m"])
	if !ok || (m != 256 && m != 512 && m != 1024 && m != 2048 && m != 4096) || !equalNumber(c["n"], m) || !equalNumber(c["k"], m) || c["input_type"] != input || c["output_type"] != output || c["accumulator_type"] != output || c["compute_mode"] != compute || c["math_mode"] != mode || c["algorithm"] != algorithm || c["layout"] != "column_major" || c["operation_a"] != transpose || c["operation_b"] != "none" || c["dense"] != true || !equalNumber(c["operations_per_gemm"], 2*m*m*m) {
		return errors.New("low-precision format, shape, layout or arithmetic contract mismatch")
	}
	if c["scaling_mode"] != scaling || !equalNumber(c["input_a_scale"], 1) || !equalNumber(c["input_b_scale"], 1) || !equalNumber(c["input_a_zero_point"], 0) || !equalNumber(c["input_b_zero_point"], 0) || !equalNumber(c["alpha"], 1) || !equalNumber(c["beta"], 0) || !equalNumber(c["absolute_tolerance"], 0) || !equalNumber(c["output_absolute_bound"], 9*m) {
		return errors.New("low-precision scaling or exact known-answer contract mismatch")
	}
	count := 8
	if c["tier"] == "standard" {
		count = 64
	}
	if r.SampleCount != count || !equalNumber(r.Coverage["checked_output_positions_per_sample"], 128) || !equalNumber(r.Coverage["output_elements"], m*m) || !equalNumber(r.Coverage["range_checked_output_positions_per_sample"], m*m) || r.Correctness.CheckedValues != uint64(count*128) {
		return errors.New("low-precision checked output coverage is incomplete")
	}
	capBytes, _ := number(c["memory_cap_bytes"])
	allocated, aOK := number(r.Coverage["allocated_bytes"])
	workspace, wOK := number(c["workspace_bytes"])
	workspaceCap := float64(4 << 20)
	if c["tier"] == "standard" {
		workspaceCap = 32 << 20
	}
	expectedAllocated := 6*m*m + workspace
	if r.Method == "fp8_gemm" {
		expectedAllocated += 8
	}
	if !aOK || !wOK || allocated > capBytes || allocated != expectedAllocated || workspace > workspaceCap || (r.Method == "int8_gemm" && workspace != 0) {
		return errors.New("low-precision allocation exceeds bounds")
	}
	if r.Method == "fp8_gemm" && (!equalNumber(r.Coverage["nonfinite_output_positions_checked_per_sample"], m*m) || workspace <= 0) {
		return errors.New("FP8 finite validation or workspace missing")
	}
	return nil
}
