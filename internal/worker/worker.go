// Package worker validates signed executables and distrusts malformed, stale,
// wrong-device, or numerically unchecked worker results.
package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/secureexec"
)

type Manifest struct {
	Kind                  string   `json:"kind"`
	Version               string   `json:"version"`
	MethodVersion         string   `json:"method_version"`
	Platform              string   `json:"platform"`
	File                  string   `json:"file"`
	SHA256                string   `json:"sha256"`
	Qualified             bool     `json:"qualified"`
	QualificationEvidence []string `json:"qualification_evidence"`
}
type Binary struct {
	Path         string
	Digest       string
	Qualified    bool
	temporaryDir string
}

func (b *Binary) Close() error {
	if b == nil || b.temporaryDir == "" {
		return nil
	}
	return os.RemoveAll(b.temporaryDir)
}
func Load(path, manifestPath string, key ed25519.PublicKey, allowUnqualified bool) (*Binary, error) {
	data, err := bundle.ReadLimited(manifestPath, bundle.MaxDocumentBytes)
	if err != nil {
		return nil, err
	}
	payload, err := bundle.Verify(data, key)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err = bundle.Decode(payload, &m); err != nil {
		return nil, err
	}
	if m.Kind != "gri-worker" || m.Version != model.ToolVersion || m.MethodVersion != model.MethodVersion || m.Platform != "linux-amd64" || m.File != filepath.Base(path) || m.File == "." || len(m.SHA256) != 64 {
		return nil, errors.New("worker manifest version, platform or filename mismatch")
	}
	if m.Qualified && len(m.QualificationEvidence) == 0 {
		return nil, errors.New("worker qualification requires evidence references")
	}
	// A signature authenticates bytes and an assertion. It cannot qualify this
	// development method, whose own source explicitly records acceptance pending.
	qualified := m.Qualified && !strings.Contains(m.Version, "-dev")
	if !qualified && !allowUnqualified {
		return nil, errors.New("worker is unqualified; acceptance testing requires explicit --allow-unqualified-worker")
	}
	binary, err := bundle.ReadLimited(path, 128<<20)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(binary)
	digest := hex.EncodeToString(hash[:])
	if digest != m.SHA256 {
		return nil, errors.New("worker executable digest mismatch")
	}
	// Execute exactly verified bytes. Adjacent/$ORIGIN libraries are deliberately
	// not copied; a compatible system CUDA/cuBLAS loader configuration is required.
	tmp, err := os.MkdirTemp("", "gri-worker-")
	if err != nil {
		return nil, err
	}
	snapshot := filepath.Join(tmp, "gri-cuda-worker")
	if err = bundle.WriteNew(snapshot, binary, 0700); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	return &Binary{Path: snapshot, Digest: digest, Qualified: qualified, temporaryDir: tmp}, nil
}

type Metric struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}
type Timings struct {
	ColdStartMS           float64   `json:"cold_start_ms"`
	WarmupMS              float64   `json:"warmup_ms"`
	WallMS                float64   `json:"wall_ms"`
	EventSamples          []float64 `json:"event_samples_ms"`
	WallSamples           []float64 `json:"wall_samples_ms"`
	SampleVerifiedOffsets []float64 `json:"sample_verified_offsets_ms"`
}
type Correctness struct {
	Checked            bool             `json:"checked"`
	CheckedValues      uint64           `json:"checked_values"`
	MismatchCount      uint64           `json:"mismatch_count"`
	MismatchLowerBound uint64           `json:"mismatch_count_lower_bound"`
	CountIsLowerBound  bool             `json:"count_is_lower_bound"`
	ConfirmationCount  int              `json:"confirmation_count"`
	Reproducible       bool             `json:"reproducible"`
	Synthetic          bool             `json:"synthetic"`
	Examples           []map[string]any `json:"mismatch_examples"`
}
type Result struct {
	SchemaVersion string    `json:"schema_version"`
	WorkerVersion string    `json:"worker_version"`
	MethodVersion string    `json:"method_version"`
	DeviceUUID    string    `json:"device_uuid"`
	Method        string    `json:"method"`
	Status        string    `json:"status"`
	Metric        *Metric   `json:"metric"`
	Samples       []float64 `json:"samples"`
	SampleCount   int       `json:"sample_count"`
	Timings       Timings   `json:"timings"`
	Spread        struct {
		Median                 *float64 `json:"median"`
		MAD                    *float64 `json:"mad"`
		IndependentAllocations int      `json:"independent_allocations"`
	} `json:"spread"`
	Conditions  map[string]any   `json:"conditions"`
	Coverage    map[string]any   `json:"coverage"`
	Correctness Correctness      `json:"correctness"`
	Errors      []map[string]any `json:"errors"`
	Limitations []string         `json:"limitations"`
}

var MethodChecks = map[string][]string{
	"memory_integrity": {"B07", "A05"}, "fp32_gemm": {"C01", "B09"}, "bf16_gemm": {"C02", "B09"}, "tf32_gemm": {"C03", "B09"}, "hbm_copy": {"C05"}, "h2d": {"C07"}, "d2h": {"C07"}, "working_set": {"C06"}, "dispatch_latency": {"C08"},
}
var metricContracts = map[string][2]string{
	"memory_integrity": {"pattern_fill_bandwidth", "GB/s"}, "fp32_gemm": {"fp32_dense_gemm", "TFLOP/s"}, "bf16_gemm": {"bf16_dense_gemm", "TFLOP/s"}, "tf32_gemm": {"tf32_dense_gemm", "TFLOP/s"}, "hbm_copy": {"hbm_effective_copy_bandwidth", "GB/s"}, "h2d": {"pinned_h2d", "GB/s"}, "d2h": {"pinned_d2h", "GB/s"}, "working_set": {"working_set_copy", "GB/s"}, "dispatch_latency": {"synchronized_dispatch_wall_latency", "us"},
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 }
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil && finite(f)
	case float64:
		return n, finite(n)
	case int:
		return float64(n), n >= 0
	case uint64:
		return float64(n), true
	case uint32:
		return float64(n), true
	}
	return 0, false
}
func equalNumber(v any, want float64) bool { got, ok := number(v); return ok && got == want }
func closeNumber(a, b float64) bool {
	return finite(a) && finite(b) && math.Abs(a-b) <= 1e-9*math.Max(1, math.Max(a, b))
}
func median(samples []float64) float64 {
	values := append([]float64(nil), samples...)
	sort.Float64s(values)
	n := len(values)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return values[n/2]
	}
	return values[n/2-1]/2 + values[n/2]/2
}
func mad(samples []float64) float64 {
	mid := median(samples)
	d := make([]float64, len(samples))
	for i, v := range samples {
		d[i] = math.Abs(v - mid)
	}
	return median(d)
}
func Parse(data []byte, device, method string, elapsed time.Duration) (Result, error) {
	var r Result
	if err := bundle.Decode(data, &r); err != nil {
		return r, err
	}
	return r, r.Validate(device, method, elapsed)
}
func (r Result) Validate(device, method string, elapsed time.Duration) error {
	if r.SchemaVersion != model.SchemaVersion || r.WorkerVersion != model.ToolVersion || r.MethodVersion != model.MethodVersion || r.DeviceUUID != device || r.Method != method {
		return errors.New("worker schema, version, method or selected UUID mismatch")
	}
	contract, ok := metricContracts[r.Method]
	if !ok {
		return errors.New("unknown worker method")
	}
	if r.Correctness.Synthetic {
		return errors.New("synthetic worker output cannot enter a live scan")
	}
	switch r.Status {
	case "ok", "unsupported", "blocked", "test_error", "mismatch", "budget_exhausted":
	default:
		return errors.New("unknown worker status")
	}
	if !finite(r.Timings.WallMS) || !finite(r.Timings.ColdStartMS) || !finite(r.Timings.WarmupMS) || r.Timings.WallMS > float64(elapsed.Microseconds())/1000+5 || r.Timings.ColdStartMS+r.Timings.WarmupMS > r.Timings.WallMS+2 {
		return errors.New("worker wall timing is inconsistent")
	}
	if r.SampleCount < 0 || r.SampleCount > 1024 || r.SampleCount != len(r.Samples) || len(r.Timings.EventSamples) != len(r.Samples) || len(r.Timings.WallSamples) != len(r.Samples) || len(r.Timings.SampleVerifiedOffsets) != len(r.Samples) {
		return errors.New("worker sample counts disagree")
	}
	sumWall, lastOffset := 0.0, 0.0
	for i, v := range r.Samples {
		offset := r.Timings.SampleVerifiedOffsets[i]
		if !finite(v) || !finite(r.Timings.EventSamples[i]) || !finite(r.Timings.WallSamples[i]) || r.Timings.EventSamples[i] <= 0 || r.Timings.EventSamples[i] > r.Timings.WallSamples[i]+2 || !finite(offset) || offset < lastOffset || offset > r.Timings.WallMS+2 {
			return errors.New("invalid worker sample timing")
		}
		sumWall += r.Timings.WallSamples[i]
		lastOffset = offset
	}
	if sumWall > r.Timings.WallMS+2 {
		return errors.New("sample wall intervals exceed worker lifetime")
	}
	if r.Spread.IndependentAllocations != 1 {
		return errors.New("worker repetitions cannot represent independent allocations")
	}
	if len(r.Samples) > 0 {
		if r.Spread.Median == nil || r.Spread.MAD == nil || !closeNumber(*r.Spread.Median, median(r.Samples)) || !closeNumber(*r.Spread.MAD, mad(r.Samples)) {
			return errors.New("worker median or MAD disagrees with retained samples")
		}
	} else if r.Spread.Median != nil || r.Spread.MAD != nil {
		return errors.New("empty samples expose spread statistics")
	}
	if r.Correctness.ConfirmationCount != 0 || r.Correctness.Reproducible {
		return errors.New("method version 1 does not independently confirm a device fault")
	}
	if len(r.Correctness.Examples) > 8 {
		return errors.New("mismatch evidence exceeds bounded example limit")
	}
	if r.Status == "ok" {
		if !r.Correctness.Checked || r.Correctness.CheckedValues == 0 || r.Correctness.MismatchCount != 0 || r.Correctness.MismatchLowerBound != 0 || r.Correctness.CountIsLowerBound || len(r.Correctness.Examples) > 0 || len(r.Errors) > 0 {
			return errors.New("successful worker result lacks checked correct output")
		}
		if r.Metric == nil || r.SampleCount == 0 || !finite(r.Metric.Value) || r.Metric.Value <= 0 || r.Metric.Name != contract[0] || r.Metric.Unit != contract[1] || !closeNumber(r.Metric.Value, median(r.Samples)) || r.Conditions == nil {
			return errors.New("successful worker metric is incomplete or violates its method contract")
		}
		if err := r.validateConditions(); err != nil {
			return err
		}
		if err := r.validateArithmetic(); err != nil {
			return err
		}
	}
	if r.Status == "mismatch" && (!r.Correctness.Checked || r.Correctness.MismatchCount == 0 || r.Correctness.MismatchLowerBound != r.Correctness.MismatchCount || !r.Correctness.CountIsLowerBound || len(r.Correctness.Examples) == 0) {
		return errors.New("mismatch without bounded mismatch evidence")
	}
	if r.Status != "mismatch" && (r.Correctness.MismatchCount > 0 || r.Correctness.MismatchLowerBound > 0 || len(r.Correctness.Examples) > 0) {
		return errors.New("worker mismatch evidence conflicts with its status")
	}
	if r.Status != "ok" && r.Metric != nil {
		return errors.New("failed worker exposes eligible metric")
	}
	return nil
}

func (r Result) validateArithmetic() error {
	for i, value := range r.Samples {
		var expected float64
		switch r.Method {
		case "memory_integrity":
			bytes, _ := number(r.Coverage["allocated_bytes"])
			expected = bytes / (r.Timings.EventSamples[i] * 1e6)
		case "fp32_gemm", "bf16_gemm", "tf32_gemm":
			operations, _ := number(r.Conditions["operations_per_gemm"])
			if !equalNumber(r.Conditions["timed_gemms_per_sample"], 8) {
				return errors.New("GEMM timed iteration count mismatch")
			}
			expected = operations * 8 / (r.Timings.EventSamples[i] * 1e9)
		case "hbm_copy":
			bytes, _ := number(r.Conditions["buffer_bytes"])
			if !equalNumber(r.Conditions["timed_copies_per_sample"], 8) {
				return errors.New("HBM timed copy count mismatch")
			}
			expected = 2 * bytes * 8 / (r.Timings.EventSamples[i] * 1e6)
		case "h2d", "d2h":
			bytes, ok := number(r.Conditions["transfer_bytes"])
			if !ok || bytes <= 0 || bytes > 256*(1<<20) || !equalNumber(r.Conditions["timed_transfers_per_sample"], 4) {
				return errors.New("transfer size or iteration count mismatch")
			}
			expected = bytes * 4 / (r.Timings.EventSamples[i] * 1e6)
		case "dispatch_latency":
			expected = r.Timings.WallSamples[i] * 1000
		case "working_set":
			// Detailed sizes/strides remain separately retained and cannot enter
			// an HBM score. Validate each sample's explicit window arithmetic.
			windows, ok := r.Coverage["windows"].([]any)
			if !ok || len(windows) != len(r.Samples) {
				return errors.New("working-set sample windows missing")
			}
			window, ok := windows[i].(map[string]any)
			if !ok || !equalNumber(window["sample_index"], float64(i)) {
				return errors.New("working-set sample window index mismatch")
			}
			bytes, ok := number(window["bytes"])
			stride, strideOK := number(window["stride_words"])
			l2, l2OK := number(r.Conditions["l2_bytes"])
			capBytes, _ := number(r.Conditions["memory_cap_bytes"])
			if !ok || bytes <= 0 || 2*bytes > capBytes || !strideOK || (stride != 1 && stride != 17) || !l2OK || l2 <= 0 || window["working_set_exceeds_l2"] != (bytes > l2) || !equalNumber(window["value_gb_s"], value) || !equalNumber(r.Conditions["timed_copies_per_sample"], 8) {
				return errors.New("working-set window size or copy count missing")
			}
			expected = 2 * bytes * 8 / (r.Timings.EventSamples[i] * 1e6)
		}
		if expected <= 0 || !closeNumber(value, expected) {
			return errors.New("worker metric disagrees with timed bytes or operations")
		}
	}
	return nil
}

func (r Result) validateConditions() error {
	c := r.Conditions
	tier, _ := c["tier"].(string)
	if (tier != "quick" && tier != "standard") || c["scope"] != "one_selected_visible_full_gpu" || c["selected_uuid_rechecked"] != true || !equalNumber(c["visible_device_count"], 1) {
		return errors.New("successful worker lacks the guarded selected-device scope")
	}
	seed, seedOK := number(c["seed"])
	budget, budgetOK := number(c["budget_ms"])
	capBytes, capOK := number(c["memory_cap_bytes"])
	if !seedOK || seed > math.MaxUint32 || seed != math.Trunc(seed) || !budgetOK || budget < 100 || budget > 300000 || !capOK || capBytes < (1<<20) || capBytes > (8192<<20) {
		return errors.New("invalid echoed worker limits")
	}
	if c["worker_qualification"] != "pending_real_gpu_acceptance" {
		return errors.New("development method has an unrecognized qualification assertion")
	}
	if r.Method == "memory_integrity" {
		passes := 3.0
		if tier == "standard" {
			passes = 8
		}
		unique, uOK := number(r.Coverage["unique_logical_bytes_verified"])
		allocated, aOK := number(r.Coverage["allocated_bytes"])
		if !uOK || !aOK || unique <= 0 || unique != allocated || allocated > capBytes || !equalNumber(r.Coverage["completed_passes"], passes) || !equalNumber(r.Coverage["total_verified_bytes"], unique*passes) || r.SampleCount != int(passes) {
			return errors.New("successful integrity method lacks complete logical coverage")
		}
	}
	if r.Method == "h2d" || r.Method == "d2h" {
		direction := "H2D"
		if r.Method == "d2h" {
			direction = "D2H"
		}
		if c["direction"] != direction || c["copy_method"] != "cudaMemcpyAsync_pinned_default_stream" || c["host_memory"] != "cudaMallocHost_page_locked" {
			return errors.New("transfer direction or pinned copy method mismatch")
		}
	}
	if r.Method == "hbm_copy" {
		l2, lOK := number(c["l2_bytes"])
		bytes, bOK := number(c["buffer_bytes"])
		if !lOK || !bOK || l2 <= 0 || bytes < 2*l2 || 2*bytes > capBytes || c["copy_method"] != "gri-copy-kernel-v1" {
			return errors.New("HBM copy does not establish an above-cache working set")
		}
	}
	if strings.HasSuffix(r.Method, "_gemm") {
		expectedInput, expectedCompute, expectedMath := "fp32", "CUBLAS_COMPUTE_32F_PEDANTIC", "CUBLAS_PEDANTIC_MATH"
		if r.Method == "bf16_gemm" {
			expectedInput = "bf16"
			expectedCompute = "CUBLAS_COMPUTE_32F"
		}
		if r.Method == "tf32_gemm" {
			expectedCompute = "CUBLAS_COMPUTE_32F_FAST_TF32"
		}
		if r.Method != "fp32_gemm" {
			expectedMath = "CUBLAS_DEFAULT_MATH|CUBLAS_MATH_DISALLOW_REDUCED_PRECISION_REDUCTION"
		}
		m, mOK := number(c["m"])
		n, nOK := number(c["n"])
		k, kOK := number(c["k"])
		if !mOK || !nOK || !kOK || m < 256 || m > 4096 || m != n || n != k || c["input_type"] != expectedInput || c["accumulator_type"] != "fp32" || c["output_type"] != "fp32" || c["compute_mode"] != expectedCompute || c["math_mode"] != expectedMath || c["algorithm"] != "CUBLAS_GEMM_DEFAULT" || c["dense"] != true || !equalNumber(c["operations_per_gemm"], 2*m*n*k) {
			return errors.New("GEMM numeric format, shape or dense operation contract mismatch")
		}
	}
	return nil
}

type Request struct {
	Device       model.Device
	Method, Tier string
	Budget       time.Duration
	MemoryMiB    int
	Seed         uint64
}

func (r Result) validateRequest(q Request) error {
	// An initialization failure may have no method conditions. Successful measured
	// output must echo the exact invocation, including the recorded seed and cap.
	if r.Status != "ok" {
		return nil
	}
	if r.Conditions["tier"] != q.Tier || !equalNumber(r.Conditions["seed"], float64(q.Seed)) || !equalNumber(r.Conditions["memory_cap_bytes"], float64(q.MemoryMiB)*(1<<20)) || !equalNumber(r.Conditions["budget_ms"], float64(q.Budget.Milliseconds())) {
		return errors.New("worker result does not echo the scheduled seed, tier or limits")
	}
	return nil
}
func identityFailure(r Result) bool {
	for _, e := range r.Errors {
		switch e["code"] {
		case "selected_uuid_changed", "selected_resource_not_unique", "cuda_visible_devices_must_equal_selected_uuid", "cannot_restrict_cuda_visibility", "full_physical_gpu_uuid_required":
			return true
		}
	}
	return false
}
func (b *Binary) Run(ctx context.Context, q Request) ([]model.Observation, bool) {
	start := time.Now()
	base := model.Observation{ResourceID: q.Device.UUID, MethodID: q.Method, Version: model.MethodVersion, StartUTC: start.UTC(), SourceKind: "measured", Visibility: "selected CUDA device; host/driver mediated", Scope: "test-owned allocations on one selected GPU", Conditions: map[string]any{"seed": q.Seed, "tier": q.Tier}}
	fail := func(status model.Status, message string) ([]model.Observation, bool) {
		base.Status = status
		base.Message = message
		base.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		var out []model.Observation
		for _, id := range MethodChecks[q.Method] {
			o := base
			o.CheckID = id
			out = append(out, o)
		}
		loss := base
		loss.CheckID = "B12"
		out = append(out, loss)
		return out, true
	}
	if _, ok := MethodChecks[q.Method]; !ok {
		return fail(model.Unsupported, "Unknown worker method")
	}
	if q.Seed > math.MaxUint32 || q.MemoryMiB < 1 || q.MemoryMiB > 8192 || (q.Tier != "quick" && q.Tier != "standard") {
		return fail(model.ToolError, "Invalid worker request: seed must be uint32, tier quick/standard, and memory cap 1–8192 MiB")
	}
	budget := q.Budget
	if budget < 100*time.Millisecond {
		return fail(model.TimeBudgetExhausted, "Insufficient remaining worker budget")
	}
	if budget > 300000*time.Millisecond {
		return fail(model.ToolError, "Worker request exceeds the supported 300-second method cap")
	}
	call, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	args := []string{"--device", q.Device.UUID, "--method", q.Method, "--budget-ms", strconv.FormatInt(budget.Milliseconds(), 10), "--memory-mib", strconv.Itoa(q.MemoryMiB), "--seed", strconv.FormatUint(q.Seed, 10), "--tier", q.Tier}
	process := secureexec.Run(call, b.Path, args, map[string]string{"CUDA_VISIBLE_DEVICES": q.Device.UUID, "NVIDIA_VISIBLE_DEVICES": q.Device.UUID}, 2<<20)
	if call.Err() != nil {
		return fail(model.TimeBudgetExhausted, "Worker deadline/cancellation ended this test; device failure is not established")
	}
	if process.Truncated {
		return fail(model.ToolError, "Worker output exceeded the bounded protocol limit")
	}
	r, err := Parse(process.Stdout, q.Device.UUID, q.Method, process.Duration)
	if err != nil {
		return fail(model.ToolError, "Worker output rejected: "+err.Error())
	}
	if err = r.validateRequest(q); err != nil {
		return fail(model.ToolError, "Worker invocation echo rejected: "+err.Error())
	}
	if process.ExitCode != 0 && r.Status == "ok" {
		return fail(model.ToolError, "Worker exited unsuccessfully despite reporting success")
	}
	return b.observations(q, base, r, process.Duration)
}
func (b *Binary) observations(q Request, base model.Observation, r Result, duration time.Duration) ([]model.Observation, bool) {
	base.DurationMS = float64(duration.Microseconds()) / 1000
	base.SampleCount = r.SampleCount
	base.Spread = r.Spread.MAD
	base.Conditions = r.Conditions
	if base.Conditions == nil {
		base.Conditions = map[string]any{}
	}
	// Preserve the CUDA API integer separately from the host NVML driver string.
	if v, ok := base.Conditions["driver_version"]; ok {
		base.Conditions["cuda_driver_api_version"] = v
	}
	base.Conditions["driver_version"] = q.Device.DriverVersion
	base.Conditions["sku"] = q.Device.SKU
	base.Conditions["mig_mode"] = q.Device.MIGMode
	base.Conditions["virtualization_mode"] = q.Device.VirtualizationMode
	qualified := b.Qualified && !strings.Contains(r.WorkerVersion, "-dev") && r.Conditions["worker_qualification"] != "pending_real_gpu_acceptance"
	base.Conditions["worker_qualified"] = qualified
	base.Status = map[string]model.Status{"ok": model.Pass, "unsupported": model.Unsupported, "blocked": model.NotTested, "test_error": model.ToolError, "mismatch": model.Fail, "budget_exhausted": model.TimeBudgetExhausted}[r.Status]
	base.Message = fmt.Sprintf("%s: %s; %d checked values; %d observed mismatches (lower bound=%t); reproducible=%t", q.Method, r.Status, r.Correctness.CheckedValues, r.Correctness.MismatchCount, r.Correctness.CountIsLowerBound, r.Correctness.Reproducible)
	if r.Metric != nil {
		base.Value = r.Metric.Value
		base.Unit = r.Metric.Unit
	}
	var out []model.Observation
	for _, id := range MethodChecks[q.Method] {
		o := base
		o.CheckID = id
		out = append(out, o)
	}
	if q.Tier == "standard" && q.Method == "memory_integrity" && r.Status == "ok" && equalNumber(r.Coverage["completed_passes"], 8) {
		o := base
		o.CheckID = "B08"
		o.MethodID = "memory_integrity.standard_coverage"
		o.Value = r.Coverage
		o.Unit = ""
		o.Message = "Eight checked patterns across the recorded test-owned logical allocation; no physical-chip or complete-VRAM coverage claim."
		out = append(out, o)
	}
	detail := base
	detail.CheckID = "C12"
	detail.MethodID = q.Method + ".validation"
	detail.Value = map[string]any{"timings": r.Timings, "coverage": r.Coverage, "correctness": r.Correctness, "samples": r.Samples, "errors": r.Errors, "limitations": r.Limitations}
	detail.Unit = ""
	out = append(out, detail)
	for _, id := range []string{"A04", "H02", "B12"} {
		o := base
		o.CheckID = id
		o.MethodID = q.Method + ".execution"
		o.Unit = ""
		o.Value = map[string]any{"checked": r.Correctness.Checked, "checked_values": r.Correctness.CheckedValues}
		out = append(out, o)
	}
	if !qualified {
		o := base
		o.CheckID = "H03"
		o.MethodID = "worker.qualification"
		o.Status = model.NotTested
		o.Value = nil
		o.Unit = ""
		o.Message = "Development worker executed for acceptance testing; architecture, dependencies and real-GPU method qualification remain pending. Metrics are ineligible for calibrated assessment."
		out = append(out, o)
	}
	if r.Status == "ok" {
		out = append(out, runtimeObservations(base)...)
	}
	if q.Tier == "standard" && r.Status == "ok" {
		out = append(out, repeatObservations(base, r)...)
	}
	if identityFailure(r) {
		o := base
		o.CheckID = "A07"
		o.MethodID = "guard.worker_identity"
		o.Status = model.NotTested
		o.Value = nil
		o.Unit = ""
		o.Message = "Worker could not maintain unambiguous selected-resource identity; active testing stopped."
		out = append(out, o)
	}
	return out, r.Status == "mismatch" || r.Status == "test_error" || r.Status == "budget_exhausted" || identityFailure(r)
}

func runtimeObservations(base model.Observation) []model.Observation {
	attributes := base
	attributes.CheckID = "A03"
	attributes.MethodID = "cuda.runtime_attributes"
	attributes.SourceKind = "reported"
	attributes.Unit = ""
	attributes.Value = map[string]any{}
	attributes.Status = model.Pass
	attributes.Message = "Selected runtime-reported compute capability, SM/cache and execution attributes; not an independent die-authenticity certificate."
	for _, key := range []string{"compute_capability", "device_sm_count", "device_l2_bytes", "device_warp_size", "device_max_threads_per_block"} {
		value, present := base.Conditions[key]
		if !present || (key != "compute_capability" && !positiveNumber(value)) {
			attributes.Status = model.NotTested
			attributes.Message = "One or more selected CUDA runtime attributes were unavailable; exact internal topology remains unverified."
		}
		if present {
			attributes.Value.(map[string]any)[key] = value
		}
	}
	libraries := base
	libraries.CheckID = "H01"
	libraries.MethodID = "cuda.loaded_versions"
	libraries.SourceKind = "reported"
	libraries.Unit = ""
	libraries.Value = map[string]any{}
	libraries.Message = "Versions returned by the loaded CUDA runtime and driver API; driver API support is distinct from an installed toolkit."
	for _, key := range []string{"runtime_version", "cuda_driver_api_version", "driver_version", "cublas_version"} {
		if value, present := base.Conditions[key]; present {
			libraries.Value.(map[string]any)[key] = value
		}
	}
	if !positiveNumber(base.Conditions["runtime_version"]) || !positiveNumber(base.Conditions["cuda_driver_api_version"]) {
		libraries.Status = model.NotTested
		libraries.Message = "Loaded CUDA runtime/driver version evidence is incomplete."
	}
	return []model.Observation{attributes, libraries}
}

func positiveNumber(value any) bool { n, ok := number(value); return ok && n > 0 }

func repeatObservations(base model.Observation, r Result) []model.Observation {
	if len(r.Samples) < 8 {
		return nil
	}
	activeMS := 0.0
	for _, elapsed := range r.Timings.EventSamples {
		activeMS += elapsed
	}
	stability := base
	stability.CheckID = "J01"
	stability.MethodID = r.Method + ".observed_interval"
	stability.Unit = ""
	stability.Value = map[string]any{"event_timed_operation_ms": activeMS, "worker_interval_ms": r.Timings.WallMS, "checked_values": r.Correctness.CheckedValues, "sample_count": len(r.Samples), "mismatch_count": r.Correctness.MismatchCount}
	stability.Message = "No checked-output failure observed in these completed samples. Event-timed active operations and the worker interval including setup/checking gaps are recorded separately; no future-life prediction."
	out := []model.Observation{stability}
	// Mixed-size/stride samples and differing integrity patterns cannot be pooled
	// as repeated measurements of one performance condition.
	if r.Method == "working_set" || r.Method == "memory_integrity" {
		return out
	}
	values := map[string]any{"samples": r.Samples, "median": median(r.Samples), "mad": mad(r.Samples), "independent_allocations": 1, "sample_verified_offsets_ms": r.Timings.SampleVerifiedOffsets}
	o := base
	o.CheckID = "C10"
	o.MethodID = r.Method + ".repeatability"
	o.Value = values
	o.Unit = ""
	o.Message = "Repeated identical-method samples with median/MAD; correlated observations from one allocation, with all samples retained. No independent fleet or future-reliability inference."
	out = append(out, o)
	sorted := append([]float64(nil), r.Samples...)
	sort.Float64s(sorted)
	variability := o
	variability.CheckID = "J02"
	variability.MethodID = r.Method + ".observed_variability"
	variability.Value = map[string]any{"minimum": sorted[0], "maximum": sorted[len(sorted)-1], "median": median(r.Samples), "mad": mad(r.Samples), "unit": base.Unit, "samples": r.Samples}
	variability.Message = "Observed spread across repeated identical-method windows; every sample is retained. Root cause, co-tenant interference and a healthy variability threshold are not established."
	out = append(out, variability)
	// These timestamps include checking gaps; define disjoint index windows and
	// retain the actual observation interval. No heat-soak or noise-cause claim.
	if !strings.HasSuffix(r.Method, "_gemm") || len(r.Samples) < 16 || activeMS < 1000 || len(r.Timings.SampleVerifiedOffsets) != len(r.Samples) {
		return out
	}
	n := len(r.Samples) / 4
	early := r.Samples[:n]
	late := r.Samples[len(r.Samples)-n:]
	earlyEnd := r.Timings.SampleVerifiedOffsets[n-1]
	lateStart := r.Timings.SampleVerifiedOffsets[len(r.Samples)-n]
	if lateStart-earlyEnd < 1000 {
		return out
	}
	curve := base
	curve.CheckID = "C09"
	curve.MethodID = r.Method + ".early_late_windows"
	curve.Unit = ""
	curve.Value = map[string]any{"early_samples": early, "late_samples": late, "early_median": median(early), "late_median": median(late), "early_end_ms": earlyEnd, "late_start_ms": lateStart, "observation_end_ms": r.Timings.SampleVerifiedOffsets[len(r.Samples)-1], "event_timed_operation_ms": activeMS, "median_ratio_late_to_early": median(late) / median(early)}
	curve.Message = "Disjoint early/late checked GEMM windows during this interval; validation gaps separate samples. Power/thermal causes and multi-day stability are not established."
	out = append(out, curve)
	stages := curve
	stages.CheckID = "J03"
	stages.MethodID = r.Method + ".warmup_and_later_windows"
	stages.Value = map[string]any{"cold_start_ms": r.Timings.ColdStartMS, "warmup_ms": r.Timings.WarmupMS, "later_windows": curve.Value}
	stages.Message = "Cold initialization and method warm-up are recorded separately from disjoint early/late checked windows. Any measured later change is limited to this interval; heat-soak failure and thermal cause are not established."
	return append(out, stages)
}
