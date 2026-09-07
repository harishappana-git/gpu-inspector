package reference

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
)

// These packs, prices and measurements are synthetic unit-test fixtures. Their
// qualified=true field exercises validation logic only; no GPU or healthy
// population was measured and no fixture is a distributable reference pack.
var fixtureTime = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func referenceFixture() (*Pack, model.Report, model.Observation) {
	conditions := map[string]any{
		"input_type": "bf16", "accumulator_type": "fp32", "output_type": "fp32",
		"math_mode":    "CUBLAS_DEFAULT_MATH|CUBLAS_MATH_DISALLOW_REDUCED_PRECISION_REDUCTION",
		"compute_mode": "CUBLAS_COMPUTE_32F", "m": float64(2048), "n": float64(2048), "k": float64(2048),
		"algorithm": "CUBLAS_GEMM_DEFAULT", "runtime_version": float64(12080), "cublas_version": float64(120803),
		"seed": float64(42), "power_limit_w": float64(350), "host_class": "synthetic-host-class", "scope": "one_selected_visible_full_gpu",
	}
	o := model.Observation{ID: "synthetic-observation-only", MethodID: "bf16_gemm", Version: model.MethodVersion, ResourceID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Status: model.Pass, Value: 100.0, Unit: "TFLOP/s", Conditions: conditions, SourceKind: "synthetic", Message: "Synthetic protocol fixture; not a measurement."}
	p := &Pack{Kind: "gri-reference", ID: "synthetic-reference-test-only", Version: "fixture-1", SKU: "h100-pcie-80gb", MIGMode: "disabled", VirtualizationMode: "none", DriverVersion: "580.65", MethodVersion: model.MethodVersion, WorkerDigest: strings.Repeat("a", 64), Qualified: true, IndependentAllocations: 5, IndependentHosts: 2, AcquiredAt: fixtureTime.Add(-24 * time.Hour), ValidUntil: fixtureTime.Add(24 * time.Hour), Approval: "synthetic test assertion only", Provenance: []string{"synthetic-allocation-1", "synthetic-allocation-2", "synthetic-allocation-3", "synthetic-allocation-4", "synthetic-allocation-5"}, Metrics: []Metric{{Method: "bf16_gemm", Unit: "TFLOP/s", ConditionsHash: ConditionsHash(conditions), HealthyLow: 80, HealthyHigh: 110, HealthyReference: 100, HigherIsBetter: true}}}
	report := model.Report{SchemaVersion: model.SchemaVersion, ToolVersion: model.ToolVersion, MethodVersion: model.MethodVersion, WorkerDigest: p.WorkerDigest, FinishedUTC: fixtureTime, Synthetic: true, Device: &model.Device{UUID: o.ResourceID, SKU: p.SKU, MIGMode: p.MIGMode, VirtualizationMode: p.VirtualizationMode, DriverVersion: p.DriverVersion}}
	return p, report, o
}

func TestSyntheticFixtureExactStructureMatches(t *testing.T) {
	p, r, o := referenceFixture()
	if err := p.Validate(fixtureTime); err != nil {
		t.Fatal(err)
	}
	if err := p.Match(r); err != nil {
		t.Fatal(err)
	}
	m, err := p.Metric(o)
	if err != nil || m.Method != o.MethodID {
		t.Fatalf("exact synthetic structure did not match: %v", err)
	}
	if !r.Synthetic || o.SourceKind != "synthetic" {
		t.Fatal("fixture lost synthetic provenance")
	}
}
func TestReferenceRejectsUnqualifiedOrInsufficientAcquisition(t *testing.T) {
	tests := map[string]func(*Pack){
		"unqualified":                           func(p *Pack) { p.Qualified = false },
		"missing kind":                          func(p *Pack) { p.Kind = "" },
		"missing version":                       func(p *Pack) { p.Version = "" },
		"missing ID":                            func(p *Pack) { p.ID = "" },
		"four allocations":                      func(p *Pack) { p.IndependentAllocations = 4 },
		"one host":                              func(p *Pack) { p.IndependentHosts = 1 },
		"too little provenance":                 func(p *Pack) { p.Provenance = p.Provenance[:4] },
		"duplicated provenance":                 func(p *Pack) { p.Provenance[4] = p.Provenance[0] },
		"empty provenance":                      func(p *Pack) { p.Provenance[0] = "" },
		"missing approval":                      func(p *Pack) { p.Approval = "" },
		"missing SKU":                           func(p *Pack) { p.SKU = "" },
		"missing MIG scope":                     func(p *Pack) { p.MIGMode = "" },
		"missing virtualization":                func(p *Pack) { p.VirtualizationMode = "" },
		"missing driver":                        func(p *Pack) { p.DriverVersion = "" },
		"wrong method version":                  func(p *Pack) { p.MethodVersion = "future-method" },
		"incomplete worker digest":              func(p *Pack) { p.WorkerDigest = "abc" },
		"nonhex worker digest":                  func(p *Pack) { p.WorkerDigest = strings.Repeat("z", 64) },
		"provenance below declared allocations": func(p *Pack) { p.IndependentAllocations = 6 },
		"more hosts than allocations":           func(p *Pack) { p.IndependentHosts = 6 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, _, _ := referenceFixture()
			change(p)
			if err := p.Validate(fixtureTime); err == nil {
				t.Fatal("ineligible acquisition accepted")
			}
		})
	}
}
func TestReferenceRejectsInvalidOrExpiredDates(t *testing.T) {
	tests := map[string]func(*Pack){
		"expired":                   func(p *Pack) { p.ValidUntil = fixtureTime.Add(-time.Second) },
		"expires exactly now":       func(p *Pack) { p.ValidUntil = fixtureTime },
		"future acquisition":        func(p *Pack) { p.AcquiredAt = fixtureTime.Add(time.Second) },
		"zero acquisition":          func(p *Pack) { p.AcquiredAt = time.Time{} },
		"zero expiry":               func(p *Pack) { p.ValidUntil = time.Time{} },
		"expiry before acquisition": func(p *Pack) { p.ValidUntil = p.AcquiredAt.Add(-time.Second) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, r, _ := referenceFixture()
			change(p)
			if err := p.Validate(fixtureTime); err == nil {
				t.Fatal("invalid date accepted")
			}
			if err := p.Match(r); err == nil {
				t.Fatal("report matching skipped freshness validation")
			}
		})
	}
}
func TestReferenceRejectsWrongSKUAndAllocationMode(t *testing.T) {
	tests := map[string]func(*model.Report){
		"SXM instead of PCIe":      func(r *model.Report) { r.Device.SKU = "h100-sxm-80gb" },
		"NVL instead of PCIe":      func(r *model.Report) { r.Device.SKU = "h100-nvl-94gb" },
		"different memory variant": func(r *model.Report) { r.Device.SKU = "h100-pcie-40gb" },
		"MIG enabled":              func(r *model.Report) { r.Device.MIGMode = "enabled" },
		"unknown MIG":              func(r *model.Report) { r.Device.MIGMode = "unknown" },
		"vGPU":                     func(r *model.Report) { r.Device.VirtualizationMode = "vgpu" },
		"different driver":         func(r *model.Report) { r.Device.DriverVersion = "581.00" },
		"different worker":         func(r *model.Report) { r.WorkerDigest = strings.Repeat("b", 64) },
		"different method":         func(r *model.Report) { r.MethodVersion = "2.0.0" },
		"missing selected device":  func(r *model.Report) { r.Device = nil },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, r, _ := referenceFixture()
			change(&r)
			if err := p.Match(r); err == nil {
				t.Fatal("reference leaked across exact allocation scope")
			}
		})
	}
}
func TestReferenceRejectsDifferentNumericalMethodConditions(t *testing.T) {
	tests := map[string]func(*model.Observation){
		"FP16 operands":             func(o *model.Observation) { o.Conditions["input_type"] = "fp16" },
		"FP16 accumulation":         func(o *model.Observation) { o.Conditions["accumulator_type"] = "fp16" },
		"TF32 compute":              func(o *model.Observation) { o.Conditions["compute_mode"] = "CUBLAS_COMPUTE_32F_FAST_TF32" },
		"pedantic math":             func(o *model.Observation) { o.Conditions["math_mode"] = "CUBLAS_PEDANTIC_MATH" },
		"different shape":           func(o *model.Observation) { o.Conditions["k"] = float64(4096) },
		"different algorithm":       func(o *model.Observation) { o.Conditions["algorithm"] = "different" },
		"different cuBLAS":          func(o *model.Observation) { o.Conditions["cublas_version"] = float64(130001) },
		"different runtime":         func(o *model.Observation) { o.Conditions["runtime_version"] = float64(13000) },
		"different power limit":     func(o *model.Observation) { o.Conditions["power_limit_w"] = float64(250) },
		"unknown power":             func(o *model.Observation) { delete(o.Conditions, "power_limit_w") },
		"unknown host class":        func(o *model.Observation) { delete(o.Conditions, "host_class") },
		"different host class":      func(o *model.Observation) { o.Conditions["host_class"] = "synthetic-other-class" },
		"different execution scope": func(o *model.Observation) { o.Conditions["scope"] = "MIG instance" },
		"wrong units":               func(o *model.Observation) { o.Unit = "GB/s" },
		"wrong version":             func(o *model.Observation) { o.Version = "2.0.0" },
		"unknown method":            func(o *model.Observation) { o.MethodID = "fp8_gemm" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, _, o := referenceFixture()
			change(&o)
			if _, err := p.Metric(o); err == nil {
				t.Fatal("incomparable numeric conditions accepted")
			}
		})
	}
}
func TestReferenceSeparatesTransferDirectionAndCopyMethod(t *testing.T) {
	for _, change := range []string{"direction", "method", "host_memory", "copy_method", "transfer_bytes", "traffic_accounting"} {
		t.Run(change, func(t *testing.T) {
			p, _, o := referenceFixture()
			o.MethodID = "h2d"
			o.Unit = "GB/s"
			o.Conditions = map[string]any{"direction": "H2D", "host_memory": "cudaMallocHost_page_locked", "copy_method": "cudaMemcpyAsync_pinned_default_stream", "transfer_bytes": float64(64 << 20), "traffic_accounting": "one direction payload bytes"}
			p.Metrics = []Metric{{Method: o.MethodID, Unit: o.Unit, ConditionsHash: ConditionsHash(o.Conditions), HealthyLow: 20, HealthyHigh: 25, HealthyReference: 24, HigherIsBetter: true}}
			if _, err := p.Metric(o); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "direction":
				o.Conditions["direction"] = "D2H"
			case "method":
				o.MethodID = "d2h"
			case "host_memory":
				o.Conditions["host_memory"] = "pageable"
			case "copy_method":
				o.Conditions["copy_method"] = "cudaMemcpy_sync"
			case "transfer_bytes":
				o.Conditions["transfer_bytes"] = float64(256 << 20)
			case "traffic_accounting":
				o.Conditions["traffic_accounting"] = "reads plus writes"
			}
			if _, err := p.Metric(o); err == nil {
				t.Fatal("incomparable transfer reference accepted")
			}
		})
	}
}
func TestReferenceRejectsInvalidEnvelopesAndMetrics(t *testing.T) {
	tests := map[string]func(*Pack){
		"duplicate method":           func(p *Pack) { p.Metrics = append(p.Metrics, p.Metrics[0]) },
		"empty method":               func(p *Pack) { p.Metrics[0].Method = "" },
		"empty unit":                 func(p *Pack) { p.Metrics[0].Unit = "" },
		"incomplete conditions hash": func(p *Pack) { p.Metrics[0].ConditionsHash = "abc" },
		"nonhex conditions hash":     func(p *Pack) { p.Metrics[0].ConditionsHash = strings.Repeat("g", 64) },
		"no metrics":                 func(p *Pack) { p.Metrics = nil },
		"negative bound":             func(p *Pack) { p.Metrics[0].HealthyLow = -1 },
		"zero reference":             func(p *Pack) { p.Metrics[0].HealthyReference = 0 },
		"NaN reference":              func(p *Pack) { p.Metrics[0].HealthyReference = math.NaN() },
		"infinite upper":             func(p *Pack) { p.Metrics[0].HealthyHigh = math.Inf(1) },
		"reference below lower":      func(p *Pack) { p.Metrics[0].HealthyReference = 70 },
		"reference above upper":      func(p *Pack) { p.Metrics[0].HealthyReference = 120 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, _, _ := referenceFixture()
			change(p)
			if err := p.Validate(fixtureTime); err == nil {
				t.Fatal("invalid metric accepted")
			}
		})
	}
}
func writeEnvelope(t *testing.T, payload []byte, key ed25519.PrivateKey) string {
	t.Helper()
	signed, err := bundle.Sign(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic-reference.json")
	if err = os.WriteFile(path, signed, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestSignedReferenceLoadAndTamperRejection(t *testing.T) {
	p, _, _ := referenceFixture()
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writeEnvelope(t, payload, priv)
	loaded, err := Load(path, pub, fixtureTime)
	if err != nil || loaded.ID != p.ID {
		t.Fatalf("signed synthetic fixture rejected: %v", err)
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = Load(path, wrong, fixtureTime); err == nil {
		t.Fatal("wrong signing key accepted")
	}
	data, _ := os.ReadFile(path)
	var env bundle.Envelope
	if err = json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.StdEncoding.EncodeToString(append(payload, ' '))
	changed, _ := json.Marshal(env)
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path, pub, fixtureTime); err == nil {
		t.Fatal("changed signed payload accepted")
	}
}
func TestSignedPayloadStillRequiresSchemaAndAcquisitionValidation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tests := map[string]func(*Pack) []byte{
		"unqualified":          func(p *Pack) []byte { p.Qualified = false; b, _ := json.Marshal(p); return b },
		"expired":              func(p *Pack) []byte { p.ValidUntil = fixtureTime.Add(-time.Second); b, _ := json.Marshal(p); return b },
		"future acquired":      func(p *Pack) []byte { p.AcquiredAt = fixtureTime.Add(time.Hour); b, _ := json.Marshal(p); return b },
		"duplicate provenance": func(p *Pack) []byte { p.Provenance[1] = p.Provenance[0]; b, _ := json.Marshal(p); return b },
		"unknown field": func(p *Pack) []byte {
			b, _ := json.Marshal(p)
			return append(b[:len(b)-1], []byte(`,"unrecognized_qualification_override":true}`)...)
		},
		"trailing object": func(p *Pack) []byte { b, _ := json.Marshal(p); return append(b, []byte("\n{}")...) },
		"duplicate qualification member": func(p *Pack) []byte {
			b, _ := json.Marshal(p)
			return append(b[:len(b)-1], []byte(`,"qualified":true}`)...)
		},
		"nested duplicate method member": func(p *Pack) []byte {
			b, _ := json.Marshal(p)
			return []byte(strings.Replace(string(b), `"method":"bf16_gemm"`, `"method":"bf16_gemm","method":"bf16_gemm"`, 1))
		},
	}
	for name, makePayload := range tests {
		t.Run(name, func(t *testing.T) {
			p, _, _ := referenceFixture()
			path := writeEnvelope(t, makePayload(p), priv)
			if _, err := Load(path, pub, fixtureTime); err == nil {
				t.Fatal("signature bypassed reference content validation")
			}
		})
	}
}
func TestConditionsHashStableForMapOrderAndExactForObservedKey(t *testing.T) {
	a := map[string]any{"math_mode": "pedantic", "shape": float64(2048)}
	b := map[string]any{"shape": float64(2048), "math_mode": "pedantic"}
	if ConditionsHash(a) != ConditionsHash(b) {
		t.Fatal("map insertion order changed exact key")
	}
	b["shape"] = float64(4096)
	if ConditionsHash(a) == ConditionsHash(b) {
		t.Fatal("shape change omitted from exact key")
	}
}

func TestConditionsHashFailsClosedOnUnserializableValues(t *testing.T) {
	for name, value := range map[string]any{"NaN": math.NaN(), "infinity": math.Inf(1), "function": func() {}, "channel": make(chan int)} {
		t.Run(name, func(t *testing.T) {
			p, _, o := referenceFixture()
			o.Conditions = map[string]any{"invalid": value}
			hash := ConditionsHash(o.Conditions)
			if hash != "" {
				t.Fatalf("serialization failure became a valid-looking hash: %s", hash)
			}
			p.Metrics[0].ConditionsHash = ""
			if _, err := p.Metric(o); err == nil {
				t.Fatal("empty error hashes matched as an eligible method")
			}
		})
	}
	p, _, o := referenceFixture()
	p.Metrics[0].ConditionsHash = ""
	if _, err := p.Metric(o); err == nil {
		t.Fatal("empty reference hash accepted for valid conditions")
	}
}
func TestCurrentConditionsKeyRemainsConservative(t *testing.T) {
	p, _, o := referenceFixture()
	// This records current behavior rather than claiming that a differing free
	// memory snapshot is a hardware problem. A future comparability-key redesign
	// needs its own method version and qualification policy.
	for _, key := range []string{"device_memory_free_bytes_before", "budget_ms", "seed"} {
		p, _, o = referenceFixture()
		o.Conditions[key] = float64(123)
		if _, err := p.Metric(o); err == nil {
			t.Fatalf("current key silently dropped %s to obtain a match", key)
		}
	}
}
