package rules

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/catalog"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/reference"
)

// This is simulated evidence for testing admission rules. No fixture or test
// pack in this file represents a measured healthy rental or release calibration.
func reviewQualifiedEvidence() (model.Report, reference.Pack) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := model.Report{SchemaVersion: model.SchemaVersion, ScanID: "rules-review", ToolVersion: model.ToolVersion, MethodVersion: model.MethodVersion, Tier: "quick", Profile: "general", StartedUTC: now.Add(-time.Minute), FinishedUTC: now, WorkerDigest: strings.Repeat("a", 64), Device: &model.Device{UUID: "GPU-review", SKU: "h100-pcie-80gb", MIGMode: "disabled", VirtualizationMode: "none", DriverVersion: "555.42"}}
	p := reference.Pack{Kind: "gri-reference", ID: "SIMULATED-ADMISSION-TEST", Version: "1", SKU: r.Device.SKU, MIGMode: r.Device.MIGMode, VirtualizationMode: r.Device.VirtualizationMode, DriverVersion: r.Device.DriverVersion, MethodVersion: r.MethodVersion, WorkerDigest: r.WorkerDigest, Qualified: true, IndependentAllocations: 5, IndependentHosts: 2, Approval: "fixture only", Provenance: []string{"simulated-1", "simulated-2", "simulated-3", "simulated-4", "simulated-5"}, AcquiredAt: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	add := func(check, method string, value any, unit string) {
		r.Observations = append(r.Observations, model.Observation{ID: fmt.Sprintf("review-%d", len(r.Observations)), CheckID: check, ResourceID: r.Device.UUID, MethodID: method, Version: model.MethodVersion, Status: model.Pass, SourceKind: "measured", StartUTC: r.StartedUTC, DurationMS: 1000, SampleCount: 5, Value: value, Unit: unit, Conditions: map[string]any{"test": "simulated-admission"}})
	}
	for _, c := range catalog.All() {
		if !catalog.InTier(c, r.Tier) || !catalog.Mandatory(c.ID, r.Tier) {
			continue
		}
		switch c.ID {
		case "C01", "C02", "C05", "C07", "B09":
			continue
		case "A01", "A02", "A06", "A07", "A08":
			add(c.ID, "guard."+c.ID, true, "")
		case "B03":
			add(c.ID, "delta.ecc-uncorrectable", 0, "errors")
		default:
			add(c.ID, "scheduler."+c.ID, true, "")
		}
	}
	for i, method := range []string{"fp32_gemm", "bf16_gemm", "hbm_copy", "h2d", "d2h"} {
		check := map[string]string{"fp32_gemm": "C01", "bf16_gemm": "C02", "hbm_copy": "C05", "h2d": "C07", "d2h": "C07"}[method]
		add(check, method, 73.137+float64(i)*0.423, "fixture-units")
		p.Metrics = append(p.Metrics, reference.Metric{Method: method, Unit: "fixture-units", ConditionsHash: reference.ConditionsHash(r.Observations[len(r.Observations)-1].Conditions), HealthyLow: 70, HealthyHigh: 110, HealthyReference: 100, HigherIsBetter: true})
		if method == "fp32_gemm" || method == "bf16_gemm" {
			add("B09", method, 73.137+float64(i)*0.423, "fixture-units")
		}
	}
	return r, p
}

func TestReviewRequiredMissingAlwaysWithholdsScore(t *testing.T) {
	for _, status := range []model.Status{model.NotTested, model.Unsupported, model.PermissionDenied, model.DependencyMissing, model.TimeBudgetExhausted, model.Contaminated, model.ToolError} {
		t.Run(string(status), func(t *testing.T) {
			r, p := reviewQualifiedEvidence()
			for i := range r.Observations {
				if r.Observations[i].CheckID == "A07" {
					r.Observations[i].Status = status
				}
			}
			Evaluate(&r, &p)
			if r.Score != nil || r.Verdict != model.Inconclusive {
				t.Fatalf("required missing check admitted: %s score %v", r.Verdict, r.Score)
			}
		})
	}
}

func TestReviewRawInventoryCannotSatisfyCorrectness(t *testing.T) {
	r, p := reviewQualifiedEvidence()
	for i := range r.Observations {
		if r.Observations[i].CheckID == "B07" {
			r.Observations[i].SourceKind = "vendor-telemetry"
			r.Observations[i].MethodID = "nvml.memory.total"
		}
	}
	Evaluate(&r, &p)
	if r.Score != nil || r.Verdict != model.Inconclusive {
		t.Fatal("inventory-only memory reading satisfied correctness")
	}
}

func TestReviewHistoricalErrorsAndDisclosedConfigurationDoNotBlock(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	for i, field := range []string{"ecc_uncorrected_total", "row_remap_corrected", "row_remap_uncorrected", "retired_pages_uncorrected", "power_limit", "pcie_current_generation"} {
		r.Observations = append(r.Observations, model.Observation{ID: fmt.Sprintf("historical-%d", i), CheckID: "B04", ResourceID: r.Device.UUID, MethodID: "nvml.field", Version: model.MethodVersion, Status: model.Pass, Value: uint64(123), Conditions: map[string]any{"field": field}})
	}
	Evaluate(&r, nil)
	if len(r.Blockers) > 0 || r.Verdict == model.DoNotStart {
		t.Fatalf("historical/context evidence became a blocker: %v", r.Blockers)
	}
}

func TestReviewCurrentMaintenanceStateRemainsBlocker(t *testing.T) {
	for _, field := range []string{"row_remap_failure", "row_remap_pending", "retirement_pending"} {
		t.Run(field, func(t *testing.T) {
			r, _ := reviewQualifiedEvidence()
			r.Observations = append(r.Observations, model.Observation{ID: "active-state", CheckID: "B04", ResourceID: r.Device.UUID, MethodID: "nvml.field", Version: model.MethodVersion, Status: model.Pass, Value: uint64(1), Conditions: map[string]any{"field": field}})
			Evaluate(&r, nil)
			if r.Verdict != model.DoNotStart || len(r.Blockers) == 0 {
				t.Fatal("active maintenance condition suppressed")
			}
		})
	}
}

func TestReviewRequiredNotApplicableCannotBypassGate(t *testing.T) {
	r, p := reviewQualifiedEvidence()
	for i := range r.Observations {
		if r.Observations[i].CheckID == "A07" {
			r.Observations[i].Status = model.NotApplicable
		}
	}
	Evaluate(&r, &p)
	if r.Score != nil || r.Verdict != model.Inconclusive {
		t.Fatalf("required target mapping N/A bypassed gate: %s score %v", r.Verdict, r.Score)
	}
}

func TestReviewNumericInputRejectsAllNonfiniteRepresentations(t *testing.T) {
	for _, value := range []any{float64(math.NaN()), float64(math.Inf(1)), float32(math.NaN()), float32(math.Inf(-1))} {
		if _, ok := Number(value); ok {
			t.Errorf("accepted nonfinite %T numeric input", value)
		}
	}
}

func TestReviewDeterministicScoreIndependentOfMapIteration(t *testing.T) {
	var first uint64
	for i := 0; i < 200; i++ {
		r, p := reviewQualifiedEvidence()
		Evaluate(&r, &p)
		if r.Score == nil {
			t.Fatal("simulated admission fixture must reach score before testing determinism")
		}
		bits := math.Float64bits(*r.Score)
		if i == 0 {
			first = bits
		} else if bits != first {
			t.Fatalf("identical evidence produced non-deterministic score bits: %x versus %x", first, bits)
		}
	}
}

func TestReviewPerformanceObservationMustBelongToSelectedGPU(t *testing.T) {
	r, p := reviewQualifiedEvidence()
	for i := range r.Observations {
		if r.Observations[i].MethodID == "hbm_copy" {
			r.Observations[i].ResourceID = "GPU-unselected"
		}
	}
	Evaluate(&r, &p)
	if r.Score != nil || r.Verdict != model.Inconclusive {
		t.Fatal("another GPU's performance entered selected-device score")
	}
}

func TestReviewCorrectnessObservationMustBelongToSelectedGPUAndInterval(t *testing.T) {
	for _, condition := range []string{"wrong-device", "stale"} {
		r, p := reviewQualifiedEvidence()
		for i := range r.Observations {
			if r.Observations[i].CheckID == "B07" {
				if condition == "wrong-device" {
					r.Observations[i].ResourceID = "GPU-unselected"
				} else {
					r.Observations[i].StartUTC = r.StartedUTC.Add(-time.Hour)
				}
			}
		}
		Evaluate(&r, &p)
		if r.Score != nil || r.Verdict != model.Inconclusive {
			t.Fatal("unscoped correctness evidence satisfied required gate")
		}
	}
}

func TestReviewReportCanRetainEarlyUncalibratedFailure(t *testing.T) {
	r := model.Report{SchemaVersion: model.SchemaVersion, ScanID: "early-failure", Tier: "quick"}
	Evaluate(&r, nil)
	for _, f := range r.Findings {
		if len(f.EvidenceRefs) == 0 {
			t.Fatalf("finding %s cannot be rendered because it has no evidence", f.ID)
		}
	}
}

func TestReviewNoDeclaredExpectationHasNarrowNotApplicableException(t *testing.T) {
	for _, expected := range []string{"", "h100-pcie-80gb"} {
		r, p := reviewQualifiedEvidence()
		r.ExpectedSKU = expected
		for i := range r.Observations {
			if r.Observations[i].CheckID == "A01" {
				r.Observations[i].Status = model.NotApplicable
				r.Observations[i].MethodID = "guard.expectation"
			}
		}
		Evaluate(&r, &p)
		if expected == "" && r.Score == nil {
			t.Fatal("absent user expectation prevented otherwise qualified scope")
		}
		if expected != "" && r.Score != nil {
			t.Fatal("declared expectation was waived as not applicable")
		}
	}
}

func TestReviewMixedMethodSamplesCannotBeCherryPicked(t *testing.T) {
	for _, condition := range []string{"identical-projection", "conflicting-value", "contaminated-projection", "wrong-check", "new-window"} {
		t.Run(condition, func(t *testing.T) {
			r, p := reviewQualifiedEvidence()
			var duplicate model.Observation
			for _, o := range r.Observations {
				if o.CheckID == "C01" {
					duplicate = o
					break
				}
			}
			duplicate.ID = "additional-method-observation"
			switch condition {
			case "conflicting-value":
				duplicate.Value = 10.0
			case "contaminated-projection":
				duplicate.CheckID = "B09"
				duplicate.Status = model.Contaminated
			case "wrong-check":
				duplicate.CheckID = "A03"
			case "new-window":
				duplicate.StartUTC = duplicate.StartUTC.Add(time.Second)
			}
			r.Observations = append(r.Observations, duplicate)
			Evaluate(&r, &p)
			if condition == "identical-projection" && r.Score == nil {
				t.Fatal("identical projected result was rejected")
			}
			if condition != "identical-projection" && r.Score != nil {
				t.Fatal("mixed/invalid method observations were cherry-picked")
			}
		})
	}
}

func TestReviewWorkerQualificationAndMeasuredIntervalAreMandatory(t *testing.T) {
	for _, condition := range []string{"unqualified-worker", "missing-samples", "stale-observation", "future-observation", "invalid-duration", "wrong-unit", "wrong-version"} {
		t.Run(condition, func(t *testing.T) {
			r, p := reviewQualifiedEvidence()
			for i := range r.Observations {
				o := &r.Observations[i]
				if o.MethodID != "hbm_copy" {
					continue
				}
				switch condition {
				case "unqualified-worker":
					o.Conditions["worker_qualified"] = false
					for j := range p.Metrics {
						if p.Metrics[j].Method == o.MethodID {
							p.Metrics[j].ConditionsHash = reference.ConditionsHash(o.Conditions)
						}
					}
				case "missing-samples":
					o.SampleCount = 0
				case "stale-observation":
					o.StartUTC = r.StartedUTC.Add(-time.Second)
				case "future-observation":
					o.StartUTC = r.FinishedUTC.Add(time.Second)
				case "invalid-duration":
					o.DurationMS = math.NaN()
				case "wrong-unit":
					o.Unit = "unmatched-unit"
				case "wrong-version":
					o.Version = "future-method"
				}
			}
			Evaluate(&r, &p)
			if r.Score != nil || r.PerformanceJudgment == "CALIBRATED" {
				t.Fatal("invalid worker evidence entered calibration")
			}
		})
	}
}

func TestReviewUnknownECCStateDoesNotMeanDisabled(t *testing.T) {
	for _, value := range []any{"unknown", "unsupported", 2, nil} {
		r, _ := reviewQualifiedEvidence()
		r.Observations = append(r.Observations, model.Observation{ID: "unknown-ecc", CheckID: "B01", ResourceID: r.Device.UUID, MethodID: "nvml.ecc_current", Version: model.MethodVersion, Status: model.Pass, Value: value, Conditions: map[string]any{"field": "ecc_current"}})
		Evaluate(&r, nil)
		for _, f := range r.Findings {
			if f.ID == "ecc-disabled" {
				t.Fatalf("unknown state %v became disabled", value)
			}
		}
	}
}

func TestReviewCoverageCountsMandatoryChecksAndAncillaryFailureIsScoped(t *testing.T) {
	r, p := reviewQualifiedEvidence()
	r.Observations = append(r.Observations, model.Observation{ID: "ancillary-failure", CheckID: "D04", MethodID: "nvml.temperature", Version: model.MethodVersion, Status: model.Fail, Message: "Ancillary sensor observation failed"})
	Evaluate(&r, &p)
	if len(r.Blockers) > 0 || r.Verdict == model.DoNotStart {
		t.Fatal("ancillary sensor failure escalated to mandatory blocker")
	}
	mandatory := 0
	for _, c := range r.Checks {
		if c.Required {
			mandatory++
		}
	}
	if r.Coverage.Required != mandatory {
		t.Fatal("required coverage denominator includes ancillary checks")
	}
}

func TestReviewUncalibratedFindingUsesExplicitReferenceEvidence(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	r.Observations = append(r.Observations, model.Observation{ID: "reference-absence", CheckID: "A09", MethodID: "reference.qualification", Version: model.MethodVersion, Status: model.NotTested, Message: "No qualified reference supplied"})
	Evaluate(&r, nil)
	found := false
	for _, f := range r.Findings {
		if f.ID == "reference-required" {
			found = true
			if len(f.EvidenceRefs) != 1 || f.EvidenceRefs[0] != "reference-absence" {
				t.Fatal("reference finding links unrelated identity observation")
			}
		}
	}
	if !found {
		t.Fatal("explicit missing reference evidence was not explained")
	}
}

func TestReviewOptionalPathChecksRequireExplicitAdapterOptIn(t *testing.T) {
	for _, condition := range []string{"enabled", "disabled", "missing-opt-in", "string-opt-in", "wrong-method", "wrong-tier"} {
		t.Run(condition, func(t *testing.T) {
			r, _ := reviewQualifiedEvidence()
			r.Tier = "standard"
			o := model.Observation{ID: "optional-disk", CheckID: "F03", MethodID: "pathcheck.disk.sequential", Version: model.MethodVersion, Status: model.Pass, Conditions: map[string]any{"opt_in": true}, Message: "Bounded selected workspace operation"}
			switch condition {
			case "disabled":
				o.Conditions["opt_in"] = false
			case "missing-opt-in":
				o.Conditions = nil
			case "string-opt-in":
				o.Conditions["opt_in"] = "true"
			case "wrong-method":
				o.MethodID = "unbounded-disk-test"
			case "wrong-tier":
				r.Tier = "quick"
			}
			r.Observations = append(r.Observations, o)
			Evaluate(&r, nil)
			for _, c := range r.Checks {
				if c.CheckID == "F03" {
					if condition == "enabled" {
						if c.Status != model.Pass || len(c.EvidenceRefs) != 1 || c.Required {
							t.Fatal("opted-in bounded check was not scoped correctly")
						}
					} else if c.Status != model.NotApplicable {
						t.Fatal("unselected/unqualified optional method was admitted")
					}
				}
			}
		})
	}
}

func TestReviewAllBoundedPathResultsAndMissingStatesStayVisible(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	r.Tier = "standard"
	expect := map[string]model.Status{"F03": model.Pass, "F05": model.Warning, "F06": model.Warning, "F07": model.Fail, "G02": model.Pass, "G03": model.TimeBudgetExhausted, "G04": model.NotTested}
	methods := map[string]string{"F03": "pathcheck.disk.sequential", "F05": "pathcheck.disk.latency", "F06": "pathcheck.disk.cache_context", "F07": "pathcheck.disk.integrity", "G02": "pathcheck.https.reachability", "G03": "pathcheck.https.download", "G04": "pathcheck.https.estimate"}
	for id, status := range expect {
		r.Observations = append(r.Observations, model.Observation{ID: "optional-" + id, CheckID: id, MethodID: methods[id], Version: model.MethodVersion, Status: status, Conditions: map[string]any{"opt_in": true}, Message: "Explicit adapter result"})
	}
	Evaluate(&r, nil)
	for _, c := range r.Checks {
		if status, ok := expect[c.CheckID]; ok {
			if c.Status != status || len(c.EvidenceRefs) != 1 || c.Required {
				t.Errorf("%s lost actual optional result: %s", c.CheckID, c.Status)
			}
		}
	}
	missing := map[string]bool{}
	for _, id := range r.MissingChecks {
		missing[id] = true
	}
	if !missing["G03"] || !missing["G04"] {
		t.Fatal("opted-in unavailable checks vanished from missing coverage")
	}
}

func TestReviewOptionalHelperFailureAndDeclaredPriceCostAreAdmitted(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	r.Tier = "standard"
	r.Price = &model.Price{PerHour: 1, Currency: "USD"}
	r.Observations = append(r.Observations,
		model.Observation{ID: "helper-timeout", CheckID: "F03", MethodID: "path.helper", Version: model.MethodVersion, Status: model.TimeBudgetExhausted, Conditions: map[string]any{"opt_in": true}},
		model.Observation{ID: "scan-cost", CheckID: "M04", MethodID: "measured.scan-cost", Version: model.MethodVersion, Status: model.Pass, Value: 0.01, Conditions: map[string]any{"opt_in": true}},
		model.Observation{ID: "future-poison", CheckID: "G05", MethodID: "pathcheck.https.upload", Version: model.MethodVersion, Status: model.Pass, Conditions: map[string]any{"opt_in": true}},
	)
	Evaluate(&r, nil)
	for _, c := range r.Checks {
		switch c.CheckID {
		case "F03":
			if c.Status != model.TimeBudgetExhausted {
				t.Fatal("helper failure was hidden")
			}
		case "M04":
			if c.Status != model.Pass || c.Required {
				t.Fatal("declared price scan cost not admitted")
			}
		case "G05":
			if c.Status != model.NotApplicable {
				t.Fatal("future method was admitted")
			}
		}
	}
	r.Price = nil
	Evaluate(&r, nil)
	for _, c := range r.Checks {
		if c.CheckID == "M04" && c.Status != model.NotApplicable {
			t.Fatal("cost observation without declared price was admitted")
		}
	}
}

func TestReviewRawVBIOSVersionDoesNotEstablishOEMConsistency(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	r.Tier = "standard"
	r.Observations = append(r.Observations, model.Observation{ID: "reported-vbios", CheckID: "A10", MethodID: "nvml.vbios", Version: model.MethodVersion, Status: model.Pass, Value: "96.00.fixture", SourceKind: "reported", Conditions: map[string]any{"field": "vbios_version"}})
	Evaluate(&r, nil)
	for _, c := range r.Checks {
		if c.CheckID == "A10" {
			if c.Status != model.NotTested || len(c.EvidenceRefs) != 1 || !strings.Contains(c.Reason, "qualified signed") {
				t.Fatal("raw VBIOS metadata became an OEM-consistency pass")
			}
			return
		}
	}
	t.Fatal("A10 missing from report")
}

func appendMemoryFailure(r *model.Report, resource string, start time.Time) []string {
	refs := []string{}
	for _, projection := range []struct{ check, method string }{{"B07", "memory_integrity"}, {"A05", "memory_integrity"}, {"A04", "memory_integrity.execution"}, {"H02", "memory_integrity.execution"}, {"B12", "memory_integrity.execution"}, {"C12", "memory_integrity.validation"}} {
		id := fmt.Sprintf("failure-%d-%s", start.UnixNano(), projection.check)
		refs = append(refs, id)
		r.Observations = append(r.Observations, model.Observation{ID: id, CheckID: projection.check, ResourceID: resource, MethodID: projection.method, Version: model.MethodVersion, Status: model.Fail, SourceKind: "measured", StartUTC: start, DurationMS: 1000, SampleCount: 1, Message: "memory_integrity: mismatch; 1 observed mismatch; reproducible=false"})
	}
	return refs
}

func TestReviewOneFailedWorkerInvocationProducesOneConcern(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	refs := appendMemoryFailure(&r, r.Device.UUID, r.StartedUTC.Add(time.Second))
	Evaluate(&r, nil)
	if r.Verdict != model.DoNotStart || len(r.Blockers) != 1 {
		t.Fatalf("one invocation became %d blockers", len(r.Blockers))
	}
	var finding *model.Finding
	for i := range r.Findings {
		if r.Findings[i].Severity == "BLOCKER" {
			finding = &r.Findings[i]
		}
	}
	if finding == nil || finding.CheckID != "B07" || len(finding.EvidenceRefs) != len(refs) {
		t.Fatal("primary correctness concern or projected evidence was lost")
	}
	blockerHighlights := 0
	for _, h := range r.Highlights {
		if h.Severity == "BLOCKER" {
			blockerHighlights++
		}
	}
	if blockerHighlights != 1 || len(r.Highlights) > 5 || r.Highlights[0].FindingID != finding.ID {
		t.Fatal("duplicate projection highlights obscure primary concern")
	}
	if !strings.Contains(finding.Interpretation, "device/context loss") || !strings.Contains(finding.Interpretation, "not established") {
		t.Fatal("numerical mismatch implies context/device loss")
	}
	for _, c := range r.Checks {
		switch c.CheckID {
		case "B07", "A05", "A04", "H02", "B12":
			if c.Status != model.Fail {
				t.Fatalf("grouping changed coverage row %s", c.CheckID)
			}
		}
	}
	first := finding.ID
	for i, j := 0, len(r.Observations)-1; i < j; i, j = i+1, j-1 {
		r.Observations[i], r.Observations[j] = r.Observations[j], r.Observations[i]
	}
	Evaluate(&r, nil)
	if len(r.Blockers) != 1 || r.Blockers[0] != first {
		t.Fatal("group identity depends on observation order")
	}
}

func TestReviewIndependentFailedInvocationsRemainSeparate(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	appendMemoryFailure(&r, r.Device.UUID, r.StartedUTC.Add(time.Second))
	appendMemoryFailure(&r, r.Device.UUID, r.StartedUTC.Add(3*time.Second))
	Evaluate(&r, nil)
	if len(r.Blockers) != 2 {
		t.Fatalf("independent failures became %d blockers", len(r.Blockers))
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if f.Severity == "BLOCKER" {
			if len(f.EvidenceRefs) != 6 {
				t.Fatal("independent invocation evidence merged")
			}
			for _, id := range f.EvidenceRefs {
				if seen[id] {
					t.Fatal("invocation groups overlap")
				}
				seen[id] = true
			}
		}
	}
}

func TestReviewForeignOrStaleFailureCannotAccuseSelectedGPU(t *testing.T) {
	for _, kind := range []string{"foreign", "stale"} {
		r, _ := reviewQualifiedEvidence()
		resource := r.Device.UUID
		start := r.StartedUTC.Add(time.Second)
		if kind == "foreign" {
			resource = "GPU-unselected"
		} else {
			start = r.StartedUTC.Add(-time.Hour)
		}
		appendMemoryFailure(&r, resource, start)
		Evaluate(&r, nil)
		if len(r.Blockers) != 0 || r.Verdict != model.Inconclusive {
			t.Fatal("unscoped worker failure accused selected GPU")
		}
		for _, c := range r.Checks {
			if c.CheckID == "B07" && c.Status != model.Contaminated {
				t.Fatal("unscoped failure was not contaminated")
			}
		}
	}
}

func TestReviewForeignRawMaintenanceFlagsDoNotAccuseSelectedGPU(t *testing.T) {
	for _, resource := range []string{"", "GPU-unselected"} {
		r, _ := reviewQualifiedEvidence()
		for _, field := range []string{"row_remap_failure", "row_remap_pending", "retirement_pending"} {
			r.Observations = append(r.Observations, model.Observation{ID: "foreign-" + field, CheckID: "B04", ResourceID: resource, MethodID: "nvml.field", Version: model.MethodVersion, Status: model.Pass, Value: 1, Conditions: map[string]any{"field": field}})
		}
		Evaluate(&r, nil)
		if len(r.Blockers) != 0 || r.Verdict == model.DoNotStart {
			t.Fatal("foreign or missing-subject maintenance state accused selected GPU")
		}
	}
}
