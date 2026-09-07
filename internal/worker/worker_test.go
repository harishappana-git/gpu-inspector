package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
)

const testUUID = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

// All values in these protocol fixtures are synthetic test data. They exercise
// parser/translation behavior only and never serve as GPU performance evidence.
func protocolFixture(method, tier string) Result {
	r := Result{SchemaVersion: model.SchemaVersion, WorkerVersion: model.ToolVersion, MethodVersion: model.MethodVersion, DeviceUUID: testUUID, Method: method, Status: "ok", Conditions: map[string]any{"seed": float64(42), "tier": tier, "budget_ms": float64(1000), "memory_cap_bytes": float64(256 << 20), "scope": "one_selected_visible_full_gpu", "selected_uuid_rechecked": true, "visible_device_count": float64(1), "worker_qualification": "pending_real_gpu_acceptance", "cuda_driver_api_version": float64(12080)}, Coverage: map[string]any{}, Correctness: Correctness{Checked: true, CheckedValues: 1024}, Errors: []map[string]any{}, Limitations: []string{"Synthetic protocol fixture, not GPU evidence."}}
	r.Timings = Timings{ColdStartMS: 10, WarmupMS: 1, WallMS: 100}
	r.Spread.IndependentAllocations = 1
	count := 5
	traffic := float64(64<<20) * 4
	denominator := 1e6
	switch method {
	case "memory_integrity":
		count = 3
		if tier == "standard" {
			count = 8
		}
		r.Coverage = map[string]any{"allocated_bytes": float64(256 << 20), "unique_logical_bytes_verified": float64(256 << 20), "completed_passes": float64(count), "total_verified_bytes": float64(256<<20) * float64(count)}
		traffic = float64(256 << 20)
	case "h2d", "d2h":
		direction := "H2D"
		if method == "d2h" {
			direction = "D2H"
		}
		r.Conditions["direction"] = direction
		r.Conditions["copy_method"] = "cudaMemcpyAsync_pinned_default_stream"
		r.Conditions["host_memory"] = "cudaMallocHost_page_locked"
		r.Conditions["transfer_bytes"] = float64(64 << 20)
		r.Conditions["timed_transfers_per_sample"] = float64(4)
	case "hbm_copy":
		r.Conditions["l2_bytes"] = float64(50 << 20)
		r.Conditions["buffer_bytes"] = float64(128 << 20)
		r.Conditions["copy_method"] = "gri-copy-kernel-v1"
		r.Conditions["timed_copies_per_sample"] = float64(8)
		traffic = 2 * float64(128<<20) * 8
	case "working_set":
		r.Conditions["l2_bytes"] = float64(50 << 20)
		r.Conditions["timed_copies_per_sample"] = float64(8)
		r.Conditions["mixed_working_sets"] = true
		traffic = 2 * float64(128<<20) * 8
	case "fp32_gemm", "bf16_gemm", "tf32_gemm":
		input, compute, mode := "fp32", "CUBLAS_COMPUTE_32F_PEDANTIC", "CUBLAS_PEDANTIC_MATH"
		if method == "bf16_gemm" {
			input = "bf16"
			compute = "CUBLAS_COMPUTE_32F"
		}
		if method == "tf32_gemm" {
			compute = "CUBLAS_COMPUTE_32F_FAST_TF32"
		}
		if method != "fp32_gemm" {
			mode = "CUBLAS_DEFAULT_MATH|CUBLAS_MATH_DISALLOW_REDUCED_PRECISION_REDUCTION"
		}
		for k, v := range map[string]any{"m": float64(2048), "n": float64(2048), "k": float64(2048), "input_type": input, "accumulator_type": "fp32", "output_type": "fp32", "compute_mode": compute, "math_mode": mode, "algorithm": "CUBLAS_GEMM_DEFAULT", "dense": true, "operations_per_gemm": float64(2) * 2048 * 2048 * 2048, "timed_gemms_per_sample": float64(8)} {
			r.Conditions[k] = v
		}
		traffic = float64(2) * 2048 * 2048 * 2048 * 8
		denominator = 1e9
	}
	for i := 0; i < count; i++ {
		event := 1 + float64(i)/10
		r.Timings.EventSamples = append(r.Timings.EventSamples, event)
		r.Timings.WallSamples = append(r.Timings.WallSamples, event+0.1)
		r.Timings.SampleVerifiedOffsets = append(r.Timings.SampleVerifiedOffsets, 20+float64(i)*5)
		value := traffic / (event * denominator)
		if method == "dispatch_latency" {
			value = (event + 0.1) * 1000
		}
		r.Samples = append(r.Samples, value)
	}
	r.SampleCount = count
	if method == "working_set" {
		windows := []any{}
		for i, value := range r.Samples {
			windows = append(windows, map[string]any{"sample_index": float64(i), "bytes": float64(128 << 20), "stride_words": float64(1), "value_gb_s": value, "working_set_exceeds_l2": true})
		}
		r.Coverage["windows"] = windows
	}
	updateSummary(&r)
	return r
}
func updateSummary(r *Result) {
	mid, spread := median(r.Samples), mad(r.Samples)
	r.Spread.Median = &mid
	r.Spread.MAD = &spread
	contract := metricContracts[r.Method]
	r.Metric = &Metric{Name: contract[0], Unit: contract[1], Value: mid}
}
func parsed(t *testing.T, r Result) (Result, error) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return Parse(data, testUUID, r.Method, time.Second)
}
func request(method, tier string) Request {
	return Request{Device: model.Device{UUID: testUUID, DriverVersion: "580.65", SKU: "H100 PCIe 80GB", MIGMode: "disabled", VirtualizationMode: "none"}, Method: method, Tier: tier, Budget: time.Second, MemoryMiB: 256, Seed: 42}
}

func TestNativeProtocolMethods(t *testing.T) {
	for _, method := range []string{"memory_integrity", "fp32_gemm", "bf16_gemm", "tf32_gemm", "hbm_copy", "h2d", "d2h", "working_set", "dispatch_latency"} {
		t.Run(method, func(t *testing.T) {
			r, err := parsed(t, protocolFixture(method, "quick"))
			if err != nil {
				t.Fatal(err)
			}
			if err = r.validateRequest(request(method, "quick")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestProtocolRejectsFalseSuccess(t *testing.T) {
	tests := map[string]func(*Result){
		"wrong uuid":                       func(r *Result) { r.DeviceUUID = "GPU-bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee" },
		"synthetic":                        func(r *Result) { r.Correctness.Synthetic = true },
		"unchecked":                        func(r *Result) { r.Correctness.Checked = false },
		"zero checked values":              func(r *Result) { r.Correctness.CheckedValues = 0 },
		"wrong direction":                  func(r *Result) { r.Conditions["direction"] = "D2H" },
		"pageable transfer":                func(r *Result) { r.Conditions["host_memory"] = "malloc" },
		"wrong units":                      func(r *Result) { r.Metric.Unit = "TB/s" },
		"wrong metric":                     func(r *Result) { r.Metric.Name = "hbm_effective_copy_bandwidth" },
		"wrong median":                     func(r *Result) { r.Metric.Value++ },
		"wrong MAD":                        func(r *Result) { v := 99.0; r.Spread.MAD = &v },
		"wrong summary":                    func(r *Result) { v := 99.0; r.Spread.Median = &v },
		"unrecorded repetition":            func(r *Result) { r.SampleCount++ },
		"missing timeline":                 func(r *Result) { r.Timings.SampleVerifiedOffsets = nil },
		"backwards timeline":               func(r *Result) { r.Timings.SampleVerifiedOffsets[1] = 0 },
		"event beyond wall":                func(r *Result) { r.Timings.EventSamples[0] = 99 },
		"event zero":                       func(r *Result) { r.Timings.EventSamples[0] = 0 },
		"independent allocations invented": func(r *Result) { r.Spread.IndependentAllocations = 5 },
		"reproduced fault invented":        func(r *Result) { r.Correctness.Reproducible = true; r.Correctness.ConfirmationCount = 1 },
		"whole host scope":                 func(r *Result) { r.Conditions["scope"] = "all GPUs" },
		"unrechecked target":               func(r *Result) { r.Conditions["selected_uuid_rechecked"] = false },
		"multiple devices":                 func(r *Result) { r.Conditions["visible_device_count"] = float64(2) },
		"out of range seed":                func(r *Result) { r.Conditions["seed"] = float64(math.MaxUint32) + 1 },
		"claimed qualification":            func(r *Result) { r.Conditions["worker_qualification"] = "qualified" },
		"inconsistent arithmetic":          func(r *Result) { r.Conditions["transfer_bytes"] = float64(32 << 20) },
		"different timed method":           func(r *Result) { r.Conditions["timed_transfers_per_sample"] = float64(8) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := protocolFixture("h2d", "quick")
			mutate(&r)
			if _, err := parsed(t, r); err == nil {
				t.Fatal("invalid success accepted")
			}
		})
	}
}
func TestMethodSpecificBoundaries(t *testing.T) {
	r := protocolFixture("hbm_copy", "quick")
	r.Conditions["buffer_bytes"] = float64(16 << 20)
	if _, err := parsed(t, r); err == nil {
		t.Fatal("cache-sized HBM benchmark accepted")
	}
	r = protocolFixture("fp32_gemm", "quick")
	r.Conditions["compute_mode"] = "CUBLAS_COMPUTE_32F_FAST_TF32"
	if _, err := parsed(t, r); err == nil {
		t.Fatal("TF32 as FP32 accepted")
	}
	r = protocolFixture("memory_integrity", "standard")
	r.Coverage["completed_passes"] = float64(3)
	if _, err := parsed(t, r); err == nil {
		t.Fatal("incomplete Standard coverage accepted")
	}
}
func TestEchoRejectsDifferentInvocation(t *testing.T) {
	for _, key := range []string{"seed", "budget_ms", "memory_cap_bytes"} {
		r := protocolFixture("h2d", "quick")
		r.Conditions[key] = float64(17)
		if err := r.validateRequest(request("h2d", "quick")); err == nil {
			t.Fatalf("wrong %s echo accepted", key)
		}
	}
	r := protocolFixture("h2d", "standard")
	if err := r.validateRequest(request("h2d", "quick")); err == nil {
		t.Fatal("wrong tier accepted")
	}
}
func TestMismatchNullNonfiniteEvidence(t *testing.T) {
	r := protocolFixture("h2d", "quick")
	r.Status = "mismatch"
	r.Metric = nil
	r.Correctness.MismatchCount = 1
	r.Correctness.MismatchLowerBound = 1
	r.Correctness.CountIsLowerBound = true
	r.Correctness.Examples = []map[string]any{{"logical_index": 0, "expected": 10, "observed": nil, "observed_class": "nan"}}
	r.Errors = []map[string]any{{"code": "checked_output_mismatch", "native_code": 0}}
	if _, err := parsed(t, r); err != nil {
		t.Fatal(err)
	}
}
func TestRawNonfiniteAndTrailingDataRejected(t *testing.T) {
	r := protocolFixture("h2d", "quick")
	data, _ := json.Marshal(r)
	bad := strings.Replace(string(data), `"wall_ms":100`, `"wall_ms":NaN`, 1)
	if _, err := Parse([]byte(bad), testUUID, "h2d", time.Second); err == nil {
		t.Fatal("NaN accepted")
	}
	if _, err := Parse(append(data, []byte("\n{}")...), testUUID, "h2d", time.Second); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestDevelopmentWorkerCannotAcquireQualificationBySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "worker")
	bytes := []byte("synthetic signed bytes, not an executable GPU measurement")
	if err = os.WriteFile(path, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	manifest := Manifest{Kind: "gri-worker", Version: model.ToolVersion, MethodVersion: model.MethodVersion, Platform: runtime.GOOS + "-" + runtime.GOARCH, File: "worker", SHA256: hex.EncodeToString(sum[:]), Qualified: true, QualificationEvidence: []string{"synthetic test assertion"}}
	payload, _ := json.Marshal(manifest)
	envelope, err := bundle.Sign(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "manifest.json")
	if err = os.WriteFile(mp, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path, mp, pub, false); err == nil {
		t.Fatal("dev worker bypassed explicit acceptance flag")
	}
	b, err := Load(path, mp, pub, true)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := b.Path
	defer b.Close()
	if b.Qualified {
		t.Fatal("signature turned development source into qualified method")
	}
	if err = os.WriteFile(path, []byte("changed later"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(snapshot)
	if err != nil || string(got) != string(bytes) {
		t.Fatal("verified snapshot changed with original")
	}
}
func TestTranslationRetainsCoverageDriverAndQualification(t *testing.T) {
	r, err := parsed(t, protocolFixture("memory_integrity", "standard"))
	if err != nil {
		t.Fatal(err)
	}
	q := request("memory_integrity", "standard")
	out, stop := (&Binary{Qualified: true}).observations(q, model.Observation{MethodID: q.Method, SourceKind: "measured"}, r, time.Second)
	if stop {
		t.Fatal("valid method stopped scan")
	}
	seen := map[string]model.Observation{}
	for _, o := range out {
		seen[o.CheckID] = o
	}
	if seen["B07"].Status != model.Pass || seen["B08"].Status != model.Pass {
		t.Fatal("checked standard logical coverage missing")
	}
	if seen["H03"].Status != model.NotTested {
		t.Fatal("unqualified method not gated")
	}
	c := seen["B07"].Conditions
	if c["driver_version"] != "580.65" || c["cuda_driver_api_version"] != json.Number("12080") || c["worker_qualified"] != false {
		t.Fatalf("driver/qualification provenance overwritten: %#v", c)
	}
}
func TestIdentityFailureStopsActiveScheduling(t *testing.T) {
	r := protocolFixture("h2d", "quick")
	r.Status = "blocked"
	r.Metric = nil
	r.Errors = []map[string]any{{"code": "selected_uuid_changed"}}
	_, stop := (&Binary{}).observations(request("h2d", "quick"), model.Observation{}, r, time.Second)
	if !stop {
		t.Fatal("changed target did not stop scan")
	}
	r.Errors = []map[string]any{{"code": "insufficient_free_memory_reserve"}}
	_, stop = (&Binary{}).observations(request("h2d", "quick"), model.Observation{}, r, time.Second)
	if stop {
		t.Fatal("headroom skip misclassified as identity failure")
	}
}
func TestInvalidSeedNeverLaunchesWorker(t *testing.T) {
	q := request("h2d", "quick")
	q.Seed = math.MaxUint32 + 1
	out, stop := (&Binary{Path: "/must-not-execute"}).Run(context.Background(), q)
	if !stop || len(out) == 0 || out[0].Status != model.ToolError || !strings.Contains(out[0].Message, "uint32") {
		t.Fatal("invalid request not rejected before process launch")
	}
}
func TestRepeatedWindowsRespectMeaningAndDuration(t *testing.T) {
	r := protocolFixture("fp32_gemm", "standard")
	r.Samples = nil
	r.Timings.SampleVerifiedOffsets = nil
	r.Timings.EventSamples = nil
	for i := 0; i < 16; i++ {
		r.Samples = append(r.Samples, 10+float64(i)/10)
		r.Timings.SampleVerifiedOffsets = append(r.Timings.SampleVerifiedOffsets, float64(i)*250)
		r.Timings.EventSamples = append(r.Timings.EventSamples, 100)
	}
	out := repeatObservations(model.Observation{}, r)
	if len(out) != 5 || out[0].CheckID != "J01" || out[1].CheckID != "C10" || out[2].CheckID != "J02" || out[3].CheckID != "C09" || out[4].CheckID != "J03" {
		t.Fatal("adequate disjoint windows not retained")
	}
	r.Timings.EventSamples[0] = 0
	for i := 1; i < len(r.Timings.EventSamples); i++ {
		r.Timings.EventSamples[i] = 1
	}
	if len(repeatObservations(model.Observation{}, r)) != 3 {
		t.Fatal("host checking gaps labeled sustained GPU work")
	}
	for i := range r.Timings.EventSamples {
		r.Timings.EventSamples[i] = 100
	}
	for i := range r.Timings.SampleVerifiedOffsets {
		r.Timings.SampleVerifiedOffsets[i] = float64(i)
	}
	if len(repeatObservations(model.Observation{}, r)) != 3 {
		t.Fatal("short burst labeled sustained curve")
	}
	r.Method = "working_set"
	if len(repeatObservations(model.Observation{}, r)) != 1 {
		t.Fatal("mixed working sets pooled as repeatability")
	}
}

func TestRunProtocolFixtureWithSanitizedEnvironment(t *testing.T) {
	r := protocolFixture("h2d", "quick")
	r.Conditions["budget_ms"] = float64(5000)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := nativeProtocolFixture(t, data)
	t.Setenv("NVIDIA_TF32_OVERRIDE", "0")
	t.Setenv("LD_PRELOAD", "must-not-be-inherited")
	q := request("h2d", "quick")
	q.Budget = 5 * time.Second
	out, stop := (&Binary{Path: path}).Run(context.Background(), q)
	if stop || len(out) == 0 || out[0].Status != model.Pass {
		t.Fatalf("checked synthetic transport fixture rejected: %#v", out)
	}
	for _, o := range out {
		if o.CheckID == "H03" && o.Status == model.NotTested {
			return
		}
	}
	t.Fatal("development transport fixture lost its qualification gate")
}
