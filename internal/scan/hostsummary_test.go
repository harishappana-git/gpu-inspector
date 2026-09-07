package scan

import (
	"github.com/harishappana/gpu-inspector/internal/model"
	"testing"
	"time"
)

func TestClockEvidenceDisclosesUTCUncertaintyAndClockStep(t *testing.T) {
	start := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	if o := clockObservation(start, start.Add(time.Second), time.Second); o.Status != model.Pass || o.Value.(map[string]any)["utc_synchronization_verified"] != false {
		t.Fatal(o)
	}
	if o := clockObservation(start, start.Add(2*time.Second), time.Second); o.Status != model.Warning {
		t.Fatal("wall step was hidden", o)
	}
}

func cpuAccounting(t time.Time, id string, steal, idle uint64) model.Observation {
	return model.Observation{ID: id, ResourceID: "process-host", Status: model.Pass, StartUTC: t, Conditions: map[string]any{"field": "cpu_time_counters"}, Value: map[string]uint64{"user": 0, "nice": 0, "system": 0, "idle": idle, "iowait": 0, "irq": 0, "softirq": 0, "steal": steal}}
}

func TestStealIntervalPreservesLargeCountersAndRejectsReset(t *testing.T) {
	start := time.Now()
	before := cpuAccounting(start, "a", 9007199254740993, 100)
	after := cpuAccounting(start.Add(time.Second), "b", 9007199254740994, 103)
	o := stealInterval([]model.Observation{before}, []model.Observation{after})
	if o.Status != model.Pass || o.Value.(map[string]any)["reported_steal_percent"] != float64(25) {
		t.Fatal(o)
	}
	if len(o.EvidenceRefs) != 2 {
		t.Fatal("missing boundary references")
	}
	after.Value.(map[string]uint64)["steal"] = 0
	if o = stealInterval([]model.Observation{before}, []model.Observation{after}); o.Status != model.Contaminated {
		t.Fatal("reset became a rate")
	}
	if o = stealInterval(nil, []model.Observation{after}); o.Status != model.NotTested {
		t.Fatal("missing boundary became zero")
	}
}

func TestContainerContextDoesNotPromiseApplicationReadiness(t *testing.T) {
	all := []model.Observation{}
	for _, name := range []string{"shared_memory_capacity", "process_limits", "cgroup_pids"} {
		all = append(all, model.Observation{ID: name, ResourceID: "process-host", Status: model.Pass, Conditions: map[string]any{"field": name}, Value: map[string]any{"synthetic_fixture": true}})
	}
	if o := containerReadiness(all); o.Status != model.NotTested {
		t.Fatal("device accessibility not checked")
	}
	all = append(all, model.Observation{ID: "fixture-execution", CheckID: "A04", Status: model.Pass, SourceKind: "measured"})
	if o := containerReadiness(all); o.Status != model.Pass || len(o.EvidenceRefs) != 4 {
		t.Fatal(o)
	}
}
