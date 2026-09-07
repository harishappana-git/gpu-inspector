package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

// Synthetic rule inputs exercise decisions, not hardware or vendor qualification.
func singleNodeReport() model.Report {
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	return model.Report{Tier: "standard", Profile: "general", StartedUTC: start, FinishedUTC: start.Add(time.Minute), Device: &model.Device{UUID: "GPU-synthetic-rules", SKU: "h100-pcie-80gb"}}
}
func singleNodeObservation(r model.Report, id, check, method string, status model.Status) model.Observation {
	return model.Observation{ID: id, CheckID: check, MethodID: method, Version: "synthetic-fixture-only", ResourceID: r.Device.UUID, StartUTC: r.StartedUTC.Add(time.Second), DurationMS: 10, SampleCount: 1, Status: status, SourceKind: "measured", Value: 1.0, Message: "Synthetic integration fixture; not a hardware measurement."}
}
func singleNodeCheck(t *testing.T, r model.Report, id string) model.CheckResult {
	t.Helper()
	for _, c := range r.Checks {
		if c.CheckID == id {
			return c
		}
	}
	t.Fatalf("missing catalog check %s", id)
	return model.CheckResult{}
}

func TestSingleNodeLowPrecisionRequiresBothCheckedFormats(t *testing.T) {
	for _, tc := range []struct {
		name     string
		methods  []string
		statuses []model.Status
		want     model.Status
	}{
		{"INT8 only", []string{"int8_gemm"}, []model.Status{model.Pass}, model.NotTested},
		{"FP8 only", []string{"fp8_gemm"}, []model.Status{model.Pass}, model.NotTested},
		{"repeated INT8", []string{"int8_gemm", "int8_gemm"}, []model.Status{model.Pass, model.Pass}, model.NotTested},
		{"architecture only", []string{"nvml.compute_capability"}, []model.Status{model.Pass}, model.NotTested},
		{"both checked", []string{"int8_gemm", "fp8_gemm"}, []model.Status{model.Pass, model.Pass}, model.Pass},
		{"FP8 unsupported", []string{"int8_gemm", "fp8_gemm"}, []model.Status{model.Pass, model.Unsupported}, model.Unsupported},
		{"FP8 failure", []string{"int8_gemm", "fp8_gemm"}, []model.Status{model.Pass, model.Fail}, model.Fail},
		{"FP8 contaminated", []string{"int8_gemm", "fp8_gemm"}, []model.Status{model.Pass, model.Contaminated}, model.Contaminated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := singleNodeReport()
			for i, method := range tc.methods {
				o := singleNodeObservation(r, fmt.Sprintf("synthetic-%d", i), "C04", method, tc.statuses[i])
				if strings.HasPrefix(method, "nvml.") {
					o.SourceKind = "reported"
				}
				r.Observations = append(r.Observations, o)
			}
			Evaluate(&r, nil)
			if c := singleNodeCheck(t, r, "C04"); c.Status != tc.want {
				t.Fatalf("format coverage overstated: %+v", c)
			}
			if r.Score != nil || r.PerformanceJudgment != "UNCALIBRATED" {
				t.Fatal("new-method presence invented calibration")
			}
		})
	}
}

func TestSingleNodeNewMethodsRequireSelectedDeviceAndScanInterval(t *testing.T) {
	for _, method := range []string{"int8_gemm", "fp8_gemm", "numa_transfer"} {
		for _, defect := range []string{"wrong UUID", "missing timestamp", "outside interval"} {
			t.Run(method+"/"+defect, func(t *testing.T) {
				r := singleNodeReport()
				check := "C04"
				if method == "numa_transfer" {
					check = "D10"
				}
				o := singleNodeObservation(r, "synthetic-invalid", check, method, model.Pass)
				switch defect {
				case "wrong UUID":
					o.ResourceID = "GPU-unselected"
				case "missing timestamp":
					o.StartUTC = time.Time{}
				case "outside interval":
					o.StartUTC = r.FinishedUTC
				}
				r.Observations = []model.Observation{o}
				Evaluate(&r, nil)
				if c := singleNodeCheck(t, r, check); c.Status != model.Contaminated {
					t.Fatalf("unscoped active result admitted: %+v", c)
				}
				if r.Score != nil || r.Verdict != model.Inconclusive {
					t.Fatal("invalid method scope invented a health result")
				}
			})
		}
	}
}

func TestSingleNodeNUMAPlacementContextIsNotTransferMeasurement(t *testing.T) {
	r := singleNodeReport()
	for i, method := range []string{"h2d.host_numa_context", "host.numa_topology", "nvidia-smi.topology"} {
		o := singleNodeObservation(r, fmt.Sprintf("synthetic-placement-%d", i), "D10", method, model.Pass)
		o.SourceKind = "reported"
		o.Value = map[string]any{"gpu_numa_node": 0, "host_numa_node": 0, "measurement_performed": false}
		r.Observations = append(r.Observations, o)
	}
	Evaluate(&r, nil)
	if c := singleNodeCheck(t, r, "D10"); c.Status != model.NotTested {
		t.Fatalf("host placement became measured NUMA path: %+v", c)
	}
	r.Observations = append(r.Observations, singleNodeObservation(r, "synthetic-numa", "D10", "numa_transfer", model.Pass))
	Evaluate(&r, nil)
	if c := singleNodeCheck(t, r, "D10"); c.Status != model.Pass || len(c.EvidenceRefs) != 1 || c.EvidenceRefs[0] != "synthetic-numa" {
		t.Fatalf("checked NUMA method was lost among host context: %+v", c)
	}
	if r.Score != nil || r.Verdict != model.Inconclusive {
		t.Fatal("NUMA test completion invented qualified health")
	}
}

func TestSingleNodeRawFirmwareAndDriverMetadataNeverPassAdvisoryChecks(t *testing.T) {
	r := singleNodeReport()
	for _, raw := range []struct{ check, method, field, value string }{{"A10", "nvml.vbios", "vbios", "SYNTHETIC-UNRECOGNIZED"}, {"A10", "nvml.part_number", "part_number", "SYNTHETIC-BOARD"}, {"H04", "nvml.driver_version", "driver_version", "100.01"}} {
		o := singleNodeObservation(r, raw.method, raw.check, raw.method, model.Pass)
		o.SourceKind, o.Value, o.Conditions = "reported", raw.value, map[string]any{"field": raw.field}
		r.Observations = append(r.Observations, o)
	}
	Evaluate(&r, nil)
	for _, id := range []string{"A10", "H04"} {
		if c := singleNodeCheck(t, r, id); c.Status != model.NotTested {
			t.Fatalf("raw metadata became signed reference/advisory conclusion: %+v", c)
		}
	}
	if r.Score != nil || len(r.Blockers) != 0 || r.Verdict != model.Inconclusive {
		t.Fatal("unknown firmware or old driver implied hardware modification/failure")
	}
}

func TestSingleNodeNewMethodNumericalFailuresGroupExactInvocation(t *testing.T) {
	r := singleNodeReport()
	expected := map[string][]string{}
	for n, method := range []string{"int8_gemm", "fp8_gemm", "numa_transfer", "fp8_gemm"} {
		check := "C04"
		if method == "numa_transfer" {
			check = "D10"
		}
		for _, projection := range []struct{ check, method string }{{check, method}, {"C12", method + ".validation"}, {"A04", method + ".execution"}, {"H02", method + ".execution"}} {
			id := fmt.Sprintf("synthetic-failure-%d-%s", n, projection.check)
			o := singleNodeObservation(r, id, projection.check, projection.method, model.Fail)
			o.StartUTC = r.StartedUTC.Add(time.Duration(n+1) * time.Second)
			o.Message = method + ": synthetic numerical mismatch, not execution failure."
			r.Observations = append(r.Observations, o)
			expected[fmt.Sprint(n)] = append(expected[fmt.Sprint(n)], id)
		}
	}
	Evaluate(&r, nil)
	groups, grouped := workerFailures(r)
	if len(groups) != 4 || len(grouped) != 16 || len(r.Blockers) != 4 || r.Verdict != model.DoNotStart {
		t.Fatalf("projection grouping changed: groups=%d refs=%d blockers=%d verdict=%s", len(groups), len(grouped), len(r.Blockers), r.Verdict)
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if f.ActionID != "investigate-correctness" {
			continue
		}
		if f.CheckID != "C04" && f.CheckID != "D10" {
			t.Fatalf("failure misclassified as separate infrastructure issue: %+v", f)
		}
		if len(f.EvidenceRefs) != 4 || f.CauseStrength != "Not established" || !strings.Contains(f.Interpretation, "numerical mismatch") {
			t.Fatalf("failure event lost limits or projections: %+v", f)
		}
		invocations := 0
		for _, refs := range expected {
			matched := 0
			for _, wanted := range refs {
				for _, actual := range f.EvidenceRefs {
					if actual == wanted {
						matched++
					}
				}
			}
			if matched == 4 {
				invocations++
			}
		}
		if invocations != 1 {
			t.Fatal("failure finding merged projections from different worker invocations")
		}
		for _, id := range f.EvidenceRefs {
			if seen[id] {
				t.Fatal("one failure projection counted twice")
			}
			seen[id] = true
		}
	}
	if len(seen) != 16 {
		t.Fatal("new-method failure evidence was not linked to findings")
	}
}

func TestSingleNodeUnselectedFailureCannotBecomeNumericalBlocker(t *testing.T) {
	r := singleNodeReport()
	for i, method := range []string{"int8_gemm", "fp8_gemm", "numa_transfer"} {
		o := singleNodeObservation(r, fmt.Sprintf("synthetic-unselected-%d", i), "C12", method+".validation", model.Fail)
		o.ResourceID = "GPU-unselected"
		r.Observations = append(r.Observations, o)
	}
	Evaluate(&r, nil)
	groups, _ := workerFailures(r)
	if len(groups) != 0 || len(r.Blockers) != 0 || r.Verdict != model.Inconclusive {
		t.Fatal("another GPU's failure became a selected-device numerical blocker")
	}
}
