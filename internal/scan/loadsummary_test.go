package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/worker"
)

// All inputs below are synthetic fixtures. They exercise evidence arithmetic
// and status gates; they are not GPU measurements or worker qualification.
func loadFixtureRun(method string, count int) model.Observation {
	samples, events, walls, offsets := []float64{}, []float64{}, []float64{}, []float64{}
	for i := 0; i < count; i++ {
		samples = append(samples, 100-float64(i))
		events = append(events, 100)
		walls = append(walls, 150)
		offsets = append(offsets, float64(i+1)*1000)
	}
	return model.Observation{ID: "fixture-" + method, CheckID: "C12", ResourceID: guardGPU, MethodID: method + ".validation", Version: model.MethodVersion, StartUTC: guardTime.Add(time.Second), DurationMS: float64(count)*1000 + 1000, Status: model.Pass, SampleCount: count, SourceKind: "fixture", Scope: "test-owned allocations on one selected GPU", Conditions: map[string]any{"fixture": true, "tier": "standard", "selected_uuid_rechecked": true, "scope": "one_selected_visible_full_gpu", "worker_qualified": false}, Value: map[string]any{"samples": samples, "timings": worker.Timings{WallMS: float64(count)*1000 + 900, EventSamples: events, WallSamples: walls, SampleVerifiedOffsets: offsets}, "correctness": worker.Correctness{Checked: true, CheckedValues: uint64(9007199254740993)}, "errors": []map[string]any{}}}
}
func loadFixtureEvidence(epochKnown bool) []model.Observation {
	pre, post := guardSnapshot(guardTime), guardSnapshot(guardTime.Add(30*time.Second))
	for _, observations := range [][]model.Observation{pre, post} {
		for i := range observations {
			observations[i].SourceKind = "fixture"
			observations[i].Conditions["fixture"] = true
			observations[i].Unit = "errors"
			if epochKnown {
				observations[i].Conditions["counter_epoch_id"] = "fixture-epoch-1"
			}
		}
	}
	out := append(append([]model.Observation{}, pre...), post...)
	for i, o := range Deltas(pre, post) {
		o.ID = fmt.Sprintf("fixture-delta-%d", i)
		out = append(out, o)
	}
	return append(out, loadFixtureRun("fp32_gemm", 16))
}
func loadFixtureChangeDelta(observations []model.Observation, check string, difference uint64) {
	for i := range observations {
		o := &observations[i]
		if o.CheckID == check && strings.HasPrefix(o.MethodID, "delta.") {
			o.Value = map[string]any{"before": uint64(0), "after": difference, "conditional_delta": difference}
			o.Status = model.Warning
			if check == "B03" {
				o.Status = model.Fail
			}
			for j := range observations {
				if observations[j].ID == o.EvidenceRefs[1] {
					observations[j].Value = difference
				}
			}
			return
		}
	}
}
func assertLoadRefs(t *testing.T, outputs, inputs []model.Observation) {
	t.Helper()
	if _, err := json.Marshal(outputs); err != nil {
		t.Fatalf("summary cannot be journaled: %v", err)
	}
	ids := map[string]int{}
	for _, o := range inputs {
		if o.ID != "" {
			ids[o.ID]++
		}
	}
	for _, o := range outputs {
		seen := map[string]bool{}
		for _, ref := range o.EvidenceRefs {
			if ref == "" || ids[ref] != 1 || seen[ref] {
				t.Fatalf("invalid, duplicate or absent reference %q in %s", ref, o.CheckID)
			}
			seen[ref] = true
		}
	}
}
func TestLoadSummaryRequiresCheckedRepeatedWorkAndKnownEpoch(t *testing.T) {
	d := guardDevice()
	for _, known := range []bool{false, true} {
		inputs := loadFixtureEvidence(known)
		out := loadSummary("standard", &d, inputs)
		got := guardFind(t, out, "B10")
		want := model.NotTested
		if known {
			want = model.Pass
		}
		if got.Status != want {
			t.Fatalf("known epoch %t: got %s: %s", known, got.Status, got.Message)
		}
		if got.StartUTC != guardTime.Add(time.Second) || got.DurationMS != 17000 || got.ResourceID != guardGPU || got.SourceKind != "fixture" {
			t.Fatalf("lost exact fixture scope/time: %+v", got)
		}
		methods := got.Value.(map[string]any)["completed_methods"].([]map[string]any)
		if len(methods) != 1 || methods[0]["checked_values"] != uint64(9007199254740993) || methods[0]["event_timed_operation_ms"] != float64(1600) {
			t.Fatalf("lost exact checked count or active-operation time: %+v", methods)
		}
		assertLoadRefs(t, out, inputs)
		if len(got.EvidenceRefs) != 7 {
			t.Fatalf("expected validation, two deltas and four raw counters, got %v", got.EvidenceRefs)
		}
		if !strings.Contains(got.Message, "interval") {
			t.Fatal("summary omitted observation interval boundary")
		}
	}
	if got := loadSummary("quick", &d, loadFixtureEvidence(true)); len(got) != 0 {
		t.Fatal("Standard-only load assessment emitted in Quick")
	}
}
func TestLoadSummaryPreservesExactEvidenceAfterJSONDecode(t *testing.T) {
	inputs := loadFixtureEvidence(true)
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []model.Observation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	d := guardDevice()
	out := loadSummary("standard", &d, decoded)
	got := guardFind(t, out, "B10")
	if got.Status != model.Pass || got.Value.(map[string]any)["completed_methods"].([]map[string]any)[0]["checked_values"] != uint64(9007199254740993) {
		t.Fatalf("JSON-decoded exact counter/scope evidence lost: %+v", got)
	}
	assertLoadRefs(t, out, decoded)
}
func TestLoadSummaryNeverPassesMissingOrIncomparableEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func([]model.Observation) []model.Observation
		want   model.Status
	}{
		{"no_operations", func(xs []model.Observation) []model.Observation { return xs[:len(xs)-1] }, model.NotTested},
		{"few_samples", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-1] = loadFixtureRun("fp32_gemm", 7)
			return xs
		}, model.NotTested},
		{"worker_deadline", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-1].Status = model.TimeBudgetExhausted
			return xs
		}, model.NotTested},
		{"dependency", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-1].Status = model.DependencyMissing
			return xs
		}, model.NotTested},
		{"synthetic_worker", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-1].Value.(map[string]any)["correctness"] = worker.Correctness{Checked: true, CheckedValues: 10, Synthetic: true}
			return xs
		}, model.NotTested},
		{"unchecked", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-1].Value.(map[string]any)["correctness"] = worker.Correctness{Checked: false, CheckedValues: 10}
			return xs
		}, model.NotTested},
		{"duplicate_validation", func(xs []model.Observation) []model.Observation {
			extra := xs[len(xs)-1]
			extra.ID += "-duplicate"
			return append(xs, extra)
		}, model.NotTested},
		{"missing_validation_id", func(xs []model.Observation) []model.Observation { xs[len(xs)-1].ID = ""; return xs }, model.NotTested},
		{"counter_interval_does_not_enclose_work", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-1].StartUTC = guardTime.Add(29 * time.Second)
			return xs
		}, model.NotTested},
		{"unrelated_device", func(xs []model.Observation) []model.Observation { xs[len(xs)-1].ResourceID = guardPeer; return xs }, model.NotTested},
		{"nonfinite_time", func(xs []model.Observation) []model.Observation { xs[len(xs)-1].DurationMS = math.NaN(); return xs }, model.NotTested},
		{"bad_delta_ref", func(xs []model.Observation) []model.Observation {
			for i := range xs {
				if xs[i].CheckID == "B03" {
					xs[i].EvidenceRefs = []string{"", "nonexistent"}
				}
			}
			return xs
		}, model.NotTested},
		{"duplicate_delta", func(xs []model.Observation) []model.Observation {
			for _, o := range xs {
				if o.CheckID == "B03" {
					o.ID += "-duplicate"
					return append(xs, o)
				}
			}
			return xs
		}, model.NotTested},
		{"denied_counter", func(xs []model.Observation) []model.Observation {
			for i := range xs {
				if xs[i].CheckID == "B03" {
					xs[i].Status = model.PermissionDenied
				}
			}
			return xs
		}, model.NotTested},
		{"counter_reset", func(xs []model.Observation) []model.Observation {
			for i := range xs {
				if xs[i].CheckID == "B03" {
					xs[i].Status = model.Contaminated
					xs[i].Value = nil
				}
			}
			return xs
		}, model.Contaminated},
		{"identity_changed", func(xs []model.Observation) []model.Observation {
			return append(xs, model.Observation{ID: "fixture-loss", CheckID: "A07", MethodID: "guard.recheck", ResourceID: guardGPU, Status: model.Contaminated})
		}, model.Contaminated},
	}
	d := guardDevice()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := tc.change(loadFixtureEvidence(true))
			out := loadSummary("standard", &d, inputs)
			got := guardFind(t, out, "B10")
			if got.Status != tc.want {
				t.Fatalf("got %s, want %s: %s", got.Status, tc.want, got.Message)
			}
			assertLoadRefs(t, out, inputs)
		})
	}
	if got := guardFind(t, loadSummary("standard", nil, loadFixtureEvidence(true)), "B10"); got.Status != model.NotTested {
		t.Fatal("nil selected target passed")
	}
}
func TestLoadSummaryObservedErrorsPreventReadinessWithoutDefectClaim(t *testing.T) {
	d := guardDevice()
	for _, check := range []string{"B02", "B03", "C12"} {
		inputs := loadFixtureEvidence(false)
		if check != "C12" {
			loadFixtureChangeDelta(inputs, check, 1)
		} else {
			o := &inputs[len(inputs)-1]
			o.Status = model.Fail
			o.Value.(map[string]any)["correctness"] = worker.Correctness{Checked: true, CheckedValues: 100, MismatchCount: 1}
		}
		out := loadSummary("standard", &d, inputs)
		got := guardFind(t, out, "B10")
		if got.Status != model.Fail || !strings.Contains(got.Message, "physical cause remain unresolved") {
			t.Fatalf("%s error not a scoped stop: %+v", check, got)
		}
		if got.StartUTC != guardTime.Add(time.Second) || got.DurationMS != 17000 {
			t.Fatal("failed operation lost its recorded interval")
		}
		assertLoadRefs(t, out, inputs)
	}
}
func loadFixtureTelemetry() []model.Observation {
	var observations []model.Observation
	// Relative to parent launch: early [1102,4000] ms, late [12102,16000] ms.
	for _, spec := range []struct {
		field, unit string
		early, late float64
	}{{"power_draw_w", "W", 200, 250}, {"temperature_gpu_c", "C", 50, 60}} {
		for i, at := range []int{2000, 3000, 13000, 14000} {
			value := spec.early
			if i >= 2 {
				value = spec.late
			}
			o := guardRaw(spec.field, guardGPU, value, guardTime.Add(time.Second+time.Duration(at)*time.Millisecond))
			o.ID = fmt.Sprintf("fixture-%s-%d", spec.field, i)
			o.DurationMS = 10
			o.Unit = spec.unit
			o.MethodID = "nvml.telemetry"
			o.Version = "1.0.0"
			o.SourceKind = "fixture"
			o.Conditions["telemetry"] = true
			o.Conditions["fixture"] = true
			observations = append(observations, o)
		}
	}
	return observations
}
func TestLoadTrendsAlignComparableWindowsWithTimingUncertainty(t *testing.T) {
	d := guardDevice()
	inputs := append(loadFixtureEvidence(false), loadFixtureTelemetry()...)
	out := loadSummary("standard", &d, inputs)
	if guardFind(t, out, "B10").Status != model.NotTested {
		t.Fatal("observed trend erased unknown ECC epoch")
	}
	for _, check := range []string{"D02", "D06"} {
		o := guardFind(t, out, check)
		if o.Status != model.Pass || o.SampleCount != 1 || len(o.EvidenceRefs) != 5 {
			t.Fatalf("%s comparable windows unavailable: %+v", check, o)
		}
		window := o.Value.(map[string]any)["same_method_windows"].([]map[string]any)[0]
		if window["parent_worker_origin_uncertainty_ms"] != float64(102) || window["early_performance_median"] != float64(98) || window["late_performance_median"] != float64(86.5) {
			t.Fatalf("wrong window association: %+v", window)
		}
		if !strings.Contains(o.Message, "sensor sampling latency remains unknown") || !strings.Contains(o.Message, "not a quantified power-cap penalty") {
			t.Fatal("trend lacks timing/cause boundary")
		}
	}
	assertLoadRefs(t, out, inputs)
}
func TestLoadTrendsRefuseSparseMixedOrInvalidWindows(t *testing.T) {
	cases := []struct {
		name   string
		change func([]model.Observation) []model.Observation
	}{
		{"no_telemetry", func(xs []model.Observation) []model.Observation { return xs[:len(xs)-8] }},
		{"one_each_window", func(xs []model.Observation) []model.Observation {
			n := len(xs)
			xs[n-8].Conditions["telemetry"] = false
			xs[n-6].Conditions["telemetry"] = false
			return xs
		}},
		{"denied", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-8].Status = model.PermissionDenied
			return xs
		}},
		{"mixed_backend", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-8].MethodID = "nvidia-smi.telemetry"
			return xs
		}},
		{"duplicate_timestamp", func(xs []model.Observation) []model.Observation {
			xs[len(xs)-8].StartUTC = xs[len(xs)-7].StartUTC
			return xs
		}},
		{"unknown_sensor_units", func(xs []model.Observation) []model.Observation { xs[len(xs)-8].Unit = "mW"; return xs }},
		{"straddles_window_end", func(xs []model.Observation) []model.Observation { xs[len(xs)-8].DurationMS = 2500; return xs }},
		{"launch_uncertainty", func(xs []model.Observation) []model.Observation {
			for i := range xs {
				if xs[i].CheckID == "C12" {
					xs[i].DurationMS += 4000
				}
			}
			return xs
		}},
		{"mixed_integrity_patterns", func(xs []model.Observation) []model.Observation {
			for i := range xs {
				if xs[i].CheckID == "C12" {
					xs[i].MethodID = "memory_integrity.validation"
				}
			}
			return xs
		}},
		{"identity_changed", func(xs []model.Observation) []model.Observation {
			return append(xs, model.Observation{ID: "fixture-loss", ResourceID: guardGPU, CheckID: "A07", MethodID: "guard.identity", Status: model.Contaminated})
		}},
	}
	d := guardDevice()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := tc.change(append(loadFixtureEvidence(true), loadFixtureTelemetry()...))
			out := loadSummary("standard", &d, inputs)
			if got := guardFind(t, out, "D02"); got.Status != model.NotTested {
				t.Fatalf("unsupported correlation passed: %+v", got)
			}
			assertLoadRefs(t, out, inputs)
		})
	}
}
