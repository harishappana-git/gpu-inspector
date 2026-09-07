package worker

import (
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestOptionalUnavailableMethodRetainsScopeWithoutInventingExecution(t *testing.T) {
	for _, method := range []string{"fp8_gemm", "int8_gemm", "numa_transfer"} {
		for _, status := range []string{"unsupported", "blocked"} {
			t.Run(method+"/"+status, func(t *testing.T) {
				r := Result{Status: status, WorkerVersion: "1.0.0", Errors: []map[string]any{{"code": "path_unavailable"}}}
				b := Binary{Qualified: true}
				observations, stop := b.observations(Request{Method: method}, model.Observation{MethodID: method}, r, time.Millisecond)
				if stop || len(observations) != 2 {
					t.Fatalf("unexpected unavailable projection: stop=%v observations=%+v", stop, observations)
				}
				for _, observation := range observations {
					if observation.CheckID != MethodChecks[method][0] || observation.Status == model.Pass {
						t.Fatalf("optional absence projected into measured core scope: %+v", observation)
					}
				}
				if observations[1].MethodID != method+".validation" || observations[1].Value == nil {
					t.Fatal("unavailable method diagnostics were discarded")
				}
			})
		}
	}
}

func TestOptionalFailureOrPartialExecutionIsNeverHidden(t *testing.T) {
	for name, mutate := range map[string]func(*Result){
		"mismatch":       func(r *Result) { r.Status = "mismatch" },
		"tool error":     func(r *Result) { r.Status = "test_error" },
		"timeout":        func(r *Result) { r.Status = "budget_exhausted" },
		"checked":        func(r *Result) { r.Correctness.Checked = true },
		"checked values": func(r *Result) { r.Correctness.CheckedValues = 1 },
		"partial sample": func(r *Result) { r.SampleCount = 1; r.Samples = []float64{1} },
		"identity loss":  func(r *Result) { r.Errors = []map[string]any{{"code": "selected_uuid_changed"}} },
	} {
		t.Run(name, func(t *testing.T) {
			r := Result{Status: "unsupported", WorkerVersion: "1.0.0"}
			mutate(&r)
			if optionalMethodUnperformed("fp8_gemm", r) {
				t.Fatal("partial or failed optional execution treated as absent")
			}
			b := Binary{Qualified: true}
			observations, _ := b.observations(Request{Method: "fp8_gemm"}, model.Observation{}, r, time.Millisecond)
			found := map[string]bool{}
			for _, observation := range observations {
				found[observation.CheckID] = true
			}
			for _, check := range []string{"B09", "C12", "A04", "H02", "B12"} {
				if !found[check] {
					t.Fatalf("lost partial/failure evidence for %s", check)
				}
			}
		})
	}
	if optionalMethodUnperformed("bf16_gemm", Result{Status: "unsupported"}) {
		t.Fatal("core method contract changed")
	}
}
