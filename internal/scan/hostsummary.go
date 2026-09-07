package scan

import (
	"encoding/json"
	"github.com/harishappana/gpu-inspector/internal/model"
	"math"
	"strings"
	"time"
)

func clockEvidence(start, end time.Time) model.Observation {
	return clockObservation(start.UTC(), end.UTC(), end.Sub(start))
}

func clockObservation(startUTC, endUTC time.Time, monotonic time.Duration) model.Observation {
	difference := math.Abs(endUTC.Sub(startUTC).Seconds()-monotonic.Seconds()) * 1000
	o := baseObservation("J05", "clock.wall-monotonic", model.Pass, "Recorded wall/monotonic interval consistency. Absolute UTC synchronization and clock error relative to other hosts are unverified.")
	o.StartUTC = startUTC
	o.DurationMS = float64(monotonic.Microseconds()) / 1000
	o.SourceKind = "measured"
	o.ResourceID = "process-host"
	o.Scope = "inspector process clock interval"
	o.SampleCount = 2
	o.Value = map[string]any{"wall_elapsed_seconds": endUTC.Sub(startUTC).Seconds(), "monotonic_elapsed_seconds": monotonic.Seconds(), "absolute_difference_ms": difference, "utc_synchronization_verified": false, "utc_uncertainty_seconds": nil}
	o.Conditions = map[string]any{"wall_step_warning_policy_ms": 50, "policy_is_engineering_convention": true, "clock_reconfigured": false}
	if monotonic < 0 || endUTC.Before(startUTC) || difference > 50 {
		o.Status = model.Warning
		o.Message = "Wall and monotonic intervals differ beyond the recorded 50 ms engineering policy; UTC event correlation is uncertain. No time settings were changed."
	}
	return o
}

func hostSummary(pre, post, all []model.Observation) []model.Observation {
	out := []model.Observation{containerReadiness(all), stealInterval(pre, post)}
	return out
}

func containerReadiness(all []model.Observation) model.Observation {
	o := baseObservation("H07", "host.container-resources", model.NotTested, "Container/runtime resource setup is only partly visible; missing shared memory, process limits, PID scope or checked device access remains explicit.")
	o.ResourceID = "process-host"
	o.SourceKind = "interpreted"
	o.Scope = "visible process/container resources; no runtime changes"
	values := map[string]any{}
	seen := map[string]bool{}
	for _, sample := range all {
		name := scalarField(sample)
		if sample.ResourceID == "process-host" && (name == "shared_memory_capacity" || name == "process_limits" || name == "cgroup_pids") {
			values[name] = map[string]any{"status": sample.Status, "value": sample.Value}
			seen[name] = sample.Status == model.Pass
			if sample.ID != "" {
				o.EvidenceRefs = append(o.EvidenceRefs, sample.ID)
			}
		}
		if sample.CheckID == "A04" && sample.SourceKind == "measured" && sample.Status == model.Pass {
			seen["checked_device_access"] = true
			values["checked_device_access"] = true
			if sample.ID != "" {
				o.EvidenceRefs = append(o.EvidenceRefs, sample.ID)
			}
		}
	}
	o.Value = values
	if seen["shared_memory_capacity"] && seen["process_limits"] && seen["cgroup_pids"] && seen["checked_device_access"] {
		o.Status = model.Pass
		o.Message = "Recorded visible shared-memory, process/PID limits and checked probe device access. Application requirements remain untested; no generic DataLoader-failure, framework-compatibility or isolation promise."
	}
	return o
}

func asCounterMap(v any) (map[string]uint64, bool) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var raw map[string]any
	if err = decoder.Decode(&raw); err != nil {
		return nil, false
	}
	out := map[string]uint64{}
	for key, value := range raw {
		n, ok := counter(value)
		if !ok {
			return nil, false
		}
		out[key] = n
	}
	return out, len(out) > 0
}

func stealInterval(pre, post []model.Observation) model.Observation {
	o := baseObservation("E03", "delta.cpu_steal", model.NotTested, "A comparable pair of CPU accounting snapshots is required; no unavailable value becomes zero.")
	o.ResourceID = "process-host"
	o.SourceKind = "reported"
	o.Scope = "kernel/hypervisor-reported aggregate CPU accounting, not process CPU entitlement"
	a, okA := passField(pre, "process-host", "cpu_time_counters")
	b, okB := passField(post, "process-host", "cpu_time_counters")
	if a.ID != "" {
		o.EvidenceRefs = append(o.EvidenceRefs, a.ID)
	}
	if b.ID != "" {
		o.EvidenceRefs = append(o.EvidenceRefs, b.ID)
	}
	if !okA || !okB || !b.StartUTC.After(a.StartUTC) {
		return o
	}
	before, okA := asCounterMap(a.Value)
	after, okB := asCounterMap(b.Value)
	if !okA || !okB {
		return o
	}
	deltas := map[string]uint64{}
	total := uint64(0)
	for _, key := range []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"} {
		av, aok := before[key]
		bv, bok := after[key]
		if !aok || !bok || bv < av {
			o.Status = model.Contaminated
			o.Message = "CPU accounting reset, changed shape or decreased; a steal rate is not eligible."
			return o
		}
		delta := bv - av
		if math.MaxUint64-total < delta {
			o.Status = model.ToolError
			o.Message = "CPU accounting delta exceeds the representable method range."
			return o
		}
		total += delta
		deltas[key] = delta
	}
	o.StartUTC = a.StartUTC
	o.DurationMS = b.StartUTC.Sub(a.StartUTC).Seconds() * 1000
	o.SampleCount = 2
	o.Value = map[string]any{"counter_deltas": deltas, "total_accounted_delta": total, "reported_steal_percent": nil}
	if total == 0 {
		o.Message = "No aggregate CPU accounting progress was observed; a percentage is undefined."
		return o
	}
	o.Value.(map[string]any)["reported_steal_percent"] = 100 * float64(deltas["steal"]) / float64(total)
	o.Status = model.Pass
	o.Message = "Reported steal fraction during the observed accounting interval; hidden resets and hypervisor policy remain uncertain, and this does not prove oversubscription or the job's effective CPU entitlement."
	o.Conditions = map[string]any{"counter_epoch": "unverified", "guest_counters_excluded_from_denominator": "guest time is already included in user/nice", "claim": "reported interval accounting only"}
	return o
}
