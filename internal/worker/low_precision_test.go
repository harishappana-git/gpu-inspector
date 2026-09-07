package worker

import "testing"

func lowPrecisionFixture(method string) Result {
	r := protocolFixture("fp32_gemm", "quick")
	r.Method = method
	for len(r.Samples) < 8 {
		r.Samples = append(r.Samples, r.Samples[0])
		r.Timings.EventSamples = append(r.Timings.EventSamples, 1)
		r.Timings.WallSamples = append(r.Timings.WallSamples, 1.1)
		r.Timings.SampleVerifiedOffsets = append(r.Timings.SampleVerifiedOffsets, 20+float64(len(r.Samples))*5)
	}
	r.SampleCount = 8
	for key, value := range map[string]any{"input_type": "int8", "output_type": "int32", "accumulator_type": "int32", "compute_mode": "CUBLAS_COMPUTE_32I_PEDANTIC", "math_mode": "CUBLAS_PEDANTIC_MATH", "layout": "column_major", "operation_a": "none", "operation_b": "none", "input_a_scale": 1, "input_b_scale": 1, "input_a_zero_point": 0, "input_b_zero_point": 0, "scaling_mode": "exact_integer_unit_scale", "alpha": 1, "beta": 0, "absolute_tolerance": 0, "output_absolute_bound": 9 * 2048, "workspace_bytes": 0} {
		r.Conditions[key] = value
	}
	r.Coverage = map[string]any{"allocated_bytes": float64(6 * 2048 * 2048), "output_elements": 2048 * 2048, "checked_output_positions_per_sample": 128, "range_checked_output_positions_per_sample": 2048 * 2048, "nonfinite_output_positions_checked_per_sample": 0}
	if method == "fp8_gemm" {
		for key, value := range map[string]any{"input_type": "fp8_e4m3", "output_type": "fp32", "accumulator_type": "fp32", "compute_mode": "CUBLAS_COMPUTE_32F", "math_mode": "CUBLASLT_FP8_FAST_ACCUM_DISABLED", "algorithm": "cublasLtMatmulAlgoGetHeuristic_first_supported", "scaling_mode": "tensorwide_fp32_scalar", "operation_a": "transpose_physical_A", "workspace_bytes": 4 << 20} {
			r.Conditions[key] = value
		}
		r.Coverage["allocated_bytes"] = 6*2048*2048 + (4 << 20) + 8
		r.Coverage["nonfinite_output_positions_checked_per_sample"] = 2048 * 2048
	}
	updateSummary(&r)
	return r
}

func TestLowPrecisionContracts(t *testing.T) {
	for _, method := range []string{"fp8_gemm", "int8_gemm"} {
		t.Run(method, func(t *testing.T) {
			r := lowPrecisionFixture(method)
			if _, err := parsed(t, r); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"input_a_scale", "input_b_scale", "input_a_zero_point", "absolute_tolerance"} {
				r = lowPrecisionFixture(method)
				r.Conditions[key] = 2
				if _, err := parsed(t, r); err == nil {
					t.Fatalf("altered %s accepted", key)
				}
			}
			r = lowPrecisionFixture(method)
			r.Correctness.CheckedValues = 1
			if _, err := parsed(t, r); err == nil {
				t.Fatal("insufficient exact checks accepted")
			}
			r = lowPrecisionFixture(method)
			r.Conditions["accumulator_type"] = "fp16"
			if _, err := parsed(t, r); err == nil {
				t.Fatal("wrong accumulator accepted")
			}
		})
	}
	r := lowPrecisionFixture("fp8_gemm")
	r.Conditions["operation_a"] = "none"
	if _, err := parsed(t, r); err == nil {
		t.Fatal("unsupported FP8 layout accepted")
	}
	r = lowPrecisionFixture("int8_gemm")
	r.Metric.Unit = "TFLOP/s"
	if _, err := parsed(t, r); err == nil {
		t.Fatal("integer operations labeled FLOPs")
	}
}
