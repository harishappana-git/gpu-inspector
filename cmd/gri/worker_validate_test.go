package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/worker"
)

const workerValidationUUID = "GPU-00000000-0000-0000-0000-000000000001"

// Synthetic retained JSON only; this fixture never launches a CUDA worker or
// instruments a process. Its admitted status must not imply sanitizer success.
func workerValidationFixture(status string) worker.Result {
	r := worker.Result{SchemaVersion: model.SchemaVersion, WorkerVersion: model.ToolVersion, MethodVersion: model.MethodVersion, DeviceUUID: workerValidationUUID, Method: "h2d", Status: status, Timings: worker.Timings{WallMS: 100}, Limitations: []string{"Synthetic CLI fixture; not GPU or sanitizer evidence."}}
	r.Spread.IndependentAllocations = 1
	if status != "ok" {
		r.Errors = []map[string]any{{"code": "synthetic_unavailable"}}
		if status == "mismatch" {
			r.Correctness = worker.Correctness{Checked: true, CheckedValues: 1, MismatchCount: 1, MismatchLowerBound: 1, CountIsLowerBound: true, Examples: []map[string]any{{"logical_index": 0, "expected": 1, "observed": 2}}}
		}
		return r
	}
	value, zero := float64(64<<20)*4/1e6, 0.0
	r.Conditions = map[string]any{"seed": 42, "tier": "quick", "budget_ms": 1000, "memory_cap_bytes": 256 << 20, "scope": "one_selected_visible_full_gpu", "selected_uuid_rechecked": true, "visible_device_count": 1, "worker_qualification": "pending_real_gpu_acceptance", "direction": "H2D", "copy_method": "cudaMemcpyAsync_pinned_default_stream", "host_memory": "cudaMallocHost_page_locked", "transfer_bytes": 64 << 20, "timed_transfers_per_sample": 4}
	r.Metric = &worker.Metric{Name: "pinned_h2d", Value: value, Unit: "GB/s"}
	r.Samples = []float64{value}
	r.SampleCount = 1
	r.Timings.EventSamples = []float64{1}
	r.Timings.WallSamples = []float64{1.1}
	r.Timings.SampleVerifiedOffsets = []float64{20}
	r.Spread.Median = &value
	r.Spread.MAD = &zero
	r.Correctness = worker.Correctness{Checked: true, CheckedValues: 1024}
	return r
}
func workerValidationInput(t *testing.T, r worker.Result) (string, []byte) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic-worker.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, data
}
func workerValidationArgs(input string) []string {
	return []string{"worker-validate", "--input", input, "--device", workerValidationUUID, "--method", "h2d", "--elapsed-ms", "1000", "--budget-ms", "1000", "--memory-mib", "256", "--seed", "42", "--tier", "quick"}
}

func TestWorkerValidateCommandAdmitsDataWithoutChangingUnavailableStatus(t *testing.T) {
	for _, status := range []string{"ok", "unsupported", "blocked", "test_error", "budget_exhausted", "mismatch"} {
		t.Run(status, func(t *testing.T) {
			path, original := workerValidationInput(t, workerValidationFixture(status))
			code, stdout, stderr := invoke(t, workerValidationArgs(path)...)
			if code != 0 {
				t.Fatalf("valid retained output rejected: %d %s", code, stderr)
			}
			var got worker.Result
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatal(err)
			}
			if got.Status != status || got.DeviceUUID != workerValidationUUID || len(got.Limitations) != 1 {
				t.Fatal("protocol status or provenance changed")
			}
			if status != "ok" && got.Metric != nil {
				t.Fatal("unavailable retained result acquired a metric")
			}
			if status == "ok" && got.Conditions["worker_qualification"] != "pending_real_gpu_acceptance" {
				t.Fatal("protocol admission acquired qualification")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("validation changed input evidence")
			}
		})
	}
}

func TestWorkerValidateCommandRejectsRequestBoundsBeforeOpeningInput(t *testing.T) {
	for _, tc := range []struct{ flag, value string }{
		{"--device", "0"}, {"--device", "GPU-prefix"}, {"--method", "arbitrary-plugin"}, {"--elapsed-ms", "NaN"}, {"--elapsed-ms", "Inf"}, {"--elapsed-ms", "0"}, {"--elapsed-ms", "-1"}, {"--elapsed-ms", "3600000.01"},
		{"--memory-mib", "0"}, {"--memory-mib", "8193"}, {"--seed", "4294967296"}, {"--seed", "-1"}, {"--budget-ms", "99"}, {"--budget-ms", "300001"}, {"--tier", "deep"},
	} {
		t.Run(tc.flag+"="+tc.value, func(t *testing.T) {
			args := append(workerValidationArgs("must-not-open-missing.json"), tc.flag, tc.value)
			code, stdout, stderr := invoke(t, args...)
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("invalid request admitted: %d %s %s", code, stdout, stderr)
			}
			if strings.Contains(stderr, "must-not-open-missing.json") {
				t.Fatal("invalid request opened the input before validating arguments")
			}
		})
	}
}

func TestWorkerValidateCommandRejectsWrongInvocationAndMalformedData(t *testing.T) {
	path, _ := workerValidationInput(t, workerValidationFixture("ok"))
	for _, mismatch := range []struct{ flag, value string }{{"--seed", "43"}, {"--memory-mib", "512"}, {"--budget-ms", "1001"}, {"--tier", "standard"}, {"--method", "d2h"}, {"--device", "GPU-11111111-2222-3333-4444-555555555555"}, {"--elapsed-ms", "50"}} {
		code, stdout, _ := invoke(t, append(workerValidationArgs(path), mismatch.flag, mismatch.value)...)
		if code != 1 || stdout != "" {
			t.Fatalf("different invocation produced admitted output: %s %s", mismatch.flag, mismatch.value)
		}
	}
	for _, data := range [][]byte{[]byte(`{"status":"ok"}`), []byte("{}\n{}"), bytes.Repeat([]byte("x"), (2<<20)+1)} {
		input := filepath.Join(t.TempDir(), "malformed.json")
		if err := os.WriteFile(input, data, 0600); err != nil {
			t.Fatal(err)
		}
		code, stdout, _ := invoke(t, workerValidationArgs(input)...)
		if code != 1 || stdout != "" {
			t.Fatal("malformed or oversized JSON was admitted")
		}
	}
	code, stdout, _ := invoke(t, workerValidationArgs(t.TempDir())...)
	if code != 1 || stdout != "" {
		t.Fatal("directory admitted as a retained worker document")
	}
}
