package scan

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

// These summaries consume retained evidence only. They launch no work and do
// not turn short observations into a lifetime or physical-cause prediction.
func loadSummary(tier string, device *model.Device, observations []model.Observation) []model.Observation {
	if tier != "standard" {
		return nil
	}
	resource := "selected-gpu"
	if device != nil && fullGPUUUID.MatchString(device.UUID) {
		resource = device.UUID
	}
	base := model.Observation{ResourceID: resource, Version: model.MethodVersion, SourceKind: "interpreted", Status: model.NotTested, Scope: "recorded checked work and counter interval on one selected GPU", Visibility: "selected allocation; host/driver mediated", Conditions: map[string]any{"derived": true, "tier": tier, "minimum_completed_samples_per_method": 8, "future_reliability": "not inferred"}}
	ids := map[string]model.Observation{}
	counts := map[string]int{}
	for _, o := range observations {
		if o.ID != "" {
			ids[o.ID] = o
			counts[o.ID]++
		}
		if o.ResourceID == resource && (o.SourceKind == "fixture" || o.Conditions["fixture"] == true) {
			base.SourceKind = "fixture"
			base.Conditions["fixture"] = true
		}
	}
	uniqueID := func(id string) bool { return id != "" && counts[id] == 1 }
	refs := []string{}
	addRef := func(id string) {
		if uniqueID(id) {
			for _, existing := range refs {
				if existing == id {
					return
				}
			}
			refs = append(refs, id)
		}
	}
	var runs []loadRun
	var performed []map[string]any
	var attempts []map[string]any
	var start, end time.Time
	failed, contaminated, incomplete := false, false, false
	seenMethods := map[string]bool{}
	for _, o := range observations {
		if o.ResourceID != resource {
			continue
		}
		if o.CheckID == "A07" && strings.HasPrefix(o.MethodID, "guard.") && o.Status != model.Pass {
			contaminated = true
			addRef(o.ID)
		}
		method := strings.TrimSuffix(o.MethodID, ".validation")
		if o.CheckID != "C12" || method == o.MethodID || !loadMethod(method) {
			continue
		}
		addRef(o.ID)
		if seenMethods[method] || !uniqueID(o.ID) {
			incomplete = true
		}
		seenMethods[method] = true
		var detail loadDetail
		data, err := json.Marshal(o.Value)
		if err != nil || json.Unmarshal(data, &detail) != nil {
			incomplete = true
			continue
		}
		attempt := map[string]any{"method_id": method, "status": o.Status, "checked": detail.Correctness.Checked, "checked_values": detail.Correctness.CheckedValues, "observed_mismatches": detail.Correctness.MismatchCount, "completed_sample_count": len(detail.Samples), "parent_start_utc": o.StartUTC}
		if loadFinite(o.DurationMS) && o.DurationMS >= 0 {
			attempt["parent_interval_ms"] = o.DurationMS
		}
		if uniqueID(o.ID) {
			attempt["validation_ref"] = o.ID
		}
		attempts = append(attempts, attempt)
		if !o.StartUTC.IsZero() && loadFinite(o.DurationMS) && o.DurationMS > 0 && o.DurationMS <= 301000 {
			if start.IsZero() || o.StartUTC.Before(start) {
				start = o.StartUTC
			}
			if loadEnd(o).After(end) {
				end = loadEnd(o)
			}
		}
		if o.Status == model.Fail || detail.Correctness.MismatchCount > 0 {
			failed = true
		}
		if o.Status == model.Contaminated {
			contaminated = true
		}
		if !uniqueID(o.ID) || !loadComplete(o, detail) {
			incomplete = true
			continue
		}
		run := loadRun{o, detail, method}
		runs = append(runs, run)
		performed = append(performed, map[string]any{"method_id": method, "validation_ref": o.ID, "checked_values": detail.Correctness.CheckedValues, "completed_sample_count": len(detail.Samples), "parent_start_utc": o.StartUTC, "parent_end_utc": loadEnd(o), "worker_interval_ms": detail.Timings.WallMS, "event_timed_operation_ms": loadSum(detail.Timings.EventSamples), "sample_verified_offsets_ms": detail.Timings.VerifiedOffsets, "worker_qualified": o.Conditions["worker_qualified"]})
	}
	base.StartUTC = start
	if !start.IsZero() {
		base.DurationMS = float64(end.Sub(start)) / float64(time.Millisecond)
	}
	base.CheckID, base.MethodID = "B10", "load.errors_across_checked_operations"
	base.SampleCount = len(runs)
	intervals := []map[string]any{}
	eligible := len(runs) > 0 && !incomplete && resource != "selected-gpu"
	for _, check := range []string{"B02", "B03"} {
		method := "delta.ecc_corrected_volatile"
		if check == "B03" {
			method = "delta.ecc_uncorrected_volatile"
		}
		var matches []model.Observation
		for _, o := range observations {
			if o.ResourceID == resource && o.CheckID == check && o.MethodID == method {
				matches = append(matches, o)
				addRef(o.ID)
				for _, id := range o.EvidenceRefs {
					addRef(id)
				}
				interval := map[string]any{"check_id": check, "status": o.Status, "start_utc": o.StartUTC, "interval_ms": o.DurationMS, "values": o.Value, "counter_epoch": o.Conditions["counter_epoch"]}
				if uniqueID(o.ID) {
					interval["delta_ref"] = o.ID
				}
				intervals = append(intervals, interval)
			}
		}
		if len(matches) != 1 {
			eligible = false
			continue
		}
		o := matches[0]
		valid := uniqueID(o.ID) && loadDeltaReferences(o, ids, counts)
		v, mapOK := o.Value.(map[string]any)
		delta, deltaOK := counter(v["conditional_delta"])
		if valid && mapOK && deltaOK && delta > 0 && (o.Status == model.Fail || o.Status == model.Warning || o.Status == model.NotTested || o.Status == model.Pass) {
			failed = true
		}
		if o.Status == model.Contaminated {
			contaminated = true
		}
		if !valid || !mapOK || !deltaOK || delta != 0 || o.Status != model.Pass || o.Conditions["counter_epoch"] != "verified equal exposed identifiers" || start.IsZero() || o.StartUTC.After(start) || loadEnd(o).Before(end) {
			eligible = false
		}
	}
	base.Value = map[string]any{"attempted_methods": attempts, "completed_methods": performed, "gpu_error_intervals": intervals, "completed_method_count": len(runs), "parent_interval_includes": "worker launch, initialization, operations, validation and inter-method gaps; active operation time is listed separately"}
	base.EvidenceRefs = refs
	base.Conditions["continuity_contaminated"] = contaminated
	base.Message = "Repeated-load error assessment is incomplete: completed checked work, both comparable ECC boundaries enclosing the work interval, and known unchanged counter epochs are required. Performed work and conditional differences are retained; no absent counter is zero."
	if eligible {
		base.Status = model.Pass
		base.Message = "Recorded repeated checked operations completed without an output mismatch, and both ECC counters have eligible zero differences across the enclosing interval and exposed unchanged epochs. This observation applies only to the recorded logical allocations and interval; future reliability and physical cause are not inferred."
	}
	if contaminated {
		base.Status = model.Contaminated
		base.Message = "Selected identity or counter continuity is contaminated. Completed operations remain recorded, but no stable zero-error load interval is established."
	}
	if failed {
		base.Status = model.Fail
		base.Message = "A checked-output failure or positive conditional GPU error-counter difference was observed for the selected scope. Do not treat this interval as ready; stop and investigate. Counter-epoch uncertainty, attribution to the probe, and physical cause remain unresolved."
	}
	return append([]model.Observation{base}, loadTrends(base, runs, observations, uniqueID)...)
}

type loadDetail struct {
	Samples []float64 `json:"samples"`
	Timings struct {
		WallMS          float64   `json:"wall_ms"`
		EventSamples    []float64 `json:"event_samples_ms"`
		WallSamples     []float64 `json:"wall_samples_ms"`
		VerifiedOffsets []float64 `json:"sample_verified_offsets_ms"`
	} `json:"timings"`
	Correctness struct {
		Checked       bool   `json:"checked"`
		CheckedValues uint64 `json:"checked_values"`
		MismatchCount uint64 `json:"mismatch_count"`
		Synthetic     bool   `json:"synthetic"`
	} `json:"correctness"`
	Errors []map[string]any `json:"errors"`
}
type loadRun struct {
	observation model.Observation
	detail      loadDetail
	method      string
}

func loadMethod(method string) bool {
	switch method {
	case "memory_integrity", "fp32_gemm", "bf16_gemm", "tf32_gemm", "fp8_gemm", "int8_gemm", "hbm_copy", "h2d", "d2h", "working_set", "dispatch_latency":
		return true
	}
	return false
}
func loadEnd(o model.Observation) time.Time {
	return o.StartUTC.Add(time.Duration(o.DurationMS * float64(time.Millisecond)))
}
func loadSum(xs []float64) float64 {
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum
}
func loadFinite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }
func loadComplete(o model.Observation, d loadDetail) bool {
	n := len(d.Samples)
	if o.Status != model.Pass || o.StartUTC.IsZero() || !loadFinite(o.DurationMS) || o.DurationMS <= 0 || o.DurationMS > 301000 || !loadFinite(d.Timings.WallMS) || d.Timings.WallMS <= 0 || d.Timings.WallMS > o.DurationMS+2 || n < 8 || n != o.SampleCount || len(d.Timings.EventSamples) != n || len(d.Timings.WallSamples) != n || len(d.Timings.VerifiedOffsets) != n || !d.Correctness.Checked || d.Correctness.CheckedValues == 0 || d.Correctness.MismatchCount != 0 || d.Correctness.Synthetic || len(d.Errors) > 0 || o.Conditions["tier"] != "standard" || o.Conditions["selected_uuid_rechecked"] != true || o.Conditions["scope"] != "one_selected_visible_full_gpu" {
		return false
	}
	previous := 0.0
	for i, sample := range d.Samples {
		event, wall, offset := d.Timings.EventSamples[i], d.Timings.WallSamples[i], d.Timings.VerifiedOffsets[i]
		if !loadFinite(sample) || sample <= 0 || !loadFinite(event) || event <= 0 || !loadFinite(wall) || wall <= 0 || event > wall+2 || !loadFinite(offset) || offset <= previous || offset > d.Timings.WallMS+2 {
			return false
		}
		previous = offset
	}
	return loadSum(d.Timings.WallSamples) <= d.Timings.WallMS+2
}
func loadDeltaReferences(o model.Observation, ids map[string]model.Observation, counts map[string]int) bool {
	if len(o.EvidenceRefs) != 2 || o.EvidenceRefs[0] == o.EvidenceRefs[1] || !loadFinite(o.DurationMS) || o.DurationMS <= 0 || o.StartUTC.IsZero() {
		return false
	}
	a, b := ids[o.EvidenceRefs[0]], ids[o.EvidenceRefs[1]]
	if counts[a.ID] != 1 || counts[b.ID] != 1 || a.Status != model.Pass || b.Status != model.Pass || a.ResourceID != o.ResourceID || b.ResourceID != o.ResourceID || scalarField(a) != strings.TrimPrefix(o.MethodID, "delta.") || scalarField(b) != scalarField(a) || a.Unit != b.Unit || a.Scope != b.Scope || a.StartUTC != o.StartUTC || !b.StartUTC.After(a.StartUTC) || b.StartUTC != loadEnd(o) {
		return false
	}
	av, aOK := counter(a.Value)
	bv, bOK := counter(b.Value)
	values, ok := o.Value.(map[string]any)
	before, beforeOK := counter(values["before"])
	after, afterOK := counter(values["after"])
	delta, deltaOK := counter(values["conditional_delta"])
	return ok && aOK && bOK && beforeOK && afterOK && deltaOK && bv >= av && before == av && after == bv && delta == bv-av
}

// A telemetry point must fit the whole uncertainty-adjusted interval between
// checked completions. These windows include checking gaps, not just kernels.
func loadTrends(base model.Observation, runs []loadRun, observations []model.Observation, uniqueID func(string) bool) []model.Observation {
	var out []model.Observation
	for _, spec := range []struct{ check, field, unit string }{{"D02", "power_draw_w", "W"}, {"D06", "temperature_gpu_c", "C"}} {
		o := base
		o.CheckID, o.MethodID = spec.check, "load."+spec.field+"_performance_windows"
		o.Status, o.Value, o.EvidenceRefs, o.SampleCount = model.NotTested, nil, nil, 0
		o.Message = "Insufficient comparable checked-method windows with at least two eligible timestamped telemetry observations per window; no power/performance or cooling trend is inferred."
		o.Conditions = map[string]any{"derived": true, "tier": "standard", "minimum_telemetry_samples_per_window": 2, "window_scope": "between checked completions, including validation gaps", "cause": "not established"}
		if base.SourceKind == "fixture" {
			o.Conditions["fixture"] = true
		}
		var windows []map[string]any
		methodCounts := map[string]int{}
		for _, run := range runs {
			methodCounts[run.method]++
		}
		for _, run := range runs {
			if base.Conditions["continuity_contaminated"] == true || methodCounts[run.method] != 1 {
				continue
			}
			n := len(run.detail.Samples) / 4
			if !strings.HasSuffix(run.method, "_gemm") || n < 4 || !uniqueID(run.observation.ID) || loadSum(run.detail.Timings.EventSamples) < 1000 {
				continue
			}
			offsets := run.detail.Timings.VerifiedOffsets
			// Parent/child start alignment is not instrumented. Exclude all
			// possible launch/exit overhead plus the timing-contract allowance.
			uncertainty := math.Max(0, run.observation.DurationMS-run.detail.Timings.WallMS) + 2
			bounds := [][2]float64{{offsets[0] + uncertainty, offsets[n-1]}, {offsets[len(offsets)-n-1] + uncertainty, offsets[len(offsets)-1]}}
			if bounds[0][1] <= bounds[0][0] || bounds[1][0]-bounds[0][1] < 1000 || bounds[1][1] <= bounds[1][0] {
				continue
			}
			points := [2][]float64{}
			refs := []string{run.observation.ID}
			seenTimes := [2]map[time.Time]bool{{}, {}}
			key, invalid := "", false
			for _, sample := range observations {
				if sample.ResourceID != base.ResourceID || scalarField(sample) != spec.field || sample.Conditions["telemetry"] != true {
					continue
				}
				relative := float64(sample.StartUTC.Sub(run.observation.StartUTC)) / float64(time.Millisecond)
				for index, bound := range bounds {
					if relative < bound[0] || relative+sample.DurationMS > bound[1] {
						continue
					}
					value, valid := number(sample.Value)
					if !uniqueID(sample.ID) || sample.Status != model.Pass || sample.StartUTC.IsZero() || !loadFinite(sample.DurationMS) || sample.DurationMS < 0 || sample.Unit != spec.unit || !valid || value < 0 || seenTimes[index][sample.StartUTC] {
						invalid = true
						continue
					}
					currentKey := sample.MethodID + "|" + sample.Version + "|" + sample.SourceKind + "|" + sample.Unit + "|" + sample.Scope
					if key != "" && key != currentKey {
						invalid = true
						continue
					}
					key = currentKey
					seenTimes[index][sample.StartUTC] = true
					points[index] = append(points[index], value)
					refs = append(refs, sample.ID)
				}
			}
			if invalid || len(points[0]) < 2 || len(points[1]) < 2 {
				continue
			}
			early, late := run.detail.Samples[1:n], run.detail.Samples[len(run.detail.Samples)-n:]
			windows = append(windows, map[string]any{"method_id": run.method, "validation_ref": run.observation.ID, "parent_start_utc": run.observation.StartUTC, "parent_worker_origin_uncertainty_ms": uncertainty, "early_guaranteed_window_ms": bounds[0], "late_guaranteed_window_ms": bounds[1], "early_performance_samples": early, "late_performance_samples": late, "early_performance_median": loadMedian(early), "late_performance_median": loadMedian(late), "late_to_early_performance_ratio": loadMedian(late) / loadMedian(early), "telemetry_unit": spec.unit, "early_telemetry_samples": points[0], "late_telemetry_samples": points[1], "early_telemetry_median": loadMedian(points[0]), "late_telemetry_median": loadMedian(points[1]), "worker_qualified": run.observation.Conditions["worker_qualified"]})
			for _, ref := range refs {
				present := false
				for _, existing := range o.EvidenceRefs {
					present = present || existing == ref
				}
				if !present {
					o.EvidenceRefs = append(o.EvidenceRefs, ref)
				}
			}
		}
		if len(windows) > 0 {
			o.Status, o.SampleCount, o.Value = model.Pass, len(windows), map[string]any{"same_method_windows": windows}
			o.Message = "Observed telemetry and performance changes are aligned within disjoint windows of the same checked method, excluding parent/worker timing-origin uncertainty. Windows include validation gaps and sensor sampling latency remains unknown. This is a conditional short-interval association, not a quantified power-cap penalty, cooling diagnosis, healthy-performance threshold, or stability guarantee."
		}
		out = append(out, o)
	}
	return out
}
func loadMedian(xs []float64) float64 {
	values := append([]float64(nil), xs...)
	sort.Float64s(values)
	n := len(values)
	if n%2 == 0 {
		return (values[n/2-1] + values[n/2]) / 2
	}
	return values[n/2]
}
