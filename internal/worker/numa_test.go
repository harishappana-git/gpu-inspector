package worker

import (
	"github.com/harishappana/gpu-inspector/internal/model"
	"testing"
)

func numaFixture() Result {
	r := protocolFixture("h2d", "quick")
	r.Method = "numa_transfer"
	for len(r.Samples) < 10 {
		r.Samples = append(r.Samples, r.Samples[0])
		r.Timings.EventSamples = append(r.Timings.EventSamples, 1)
		r.Timings.WallSamples = append(r.Timings.WallSamples, 1.1)
		r.Timings.SampleVerifiedOffsets = append(r.Timings.SampleVerifiedOffsets, 20+float64(len(r.Samples))*5)
	}
	r.SampleCount = 10
	r.Correctness.CheckedValues = 10 * (64 << 20) / 4
	for key, value := range map[string]any{"worker_os": "linux", "copy_method": "cudaMemcpyAsync_registered_owned_pages", "host_memory": "mmap_private_anonymous_cudaHostRegister", "numa_cpu_core": 2, "numa_local_node": 0, "numa_remote_node": 1, "numa_page_bytes": 4096, "numa_policy": "MPOL_BIND_owned_anonymous_pages", "numa_placement_query": "move_pages_query_only_all_pages_before_and_after_each_sample", "numa_cpu_affinity_controlled": true, "numa_placement_verified": true, "mixed_numa_placements": true, "numa_node_order": "local_then_remote"} {
		r.Conditions[key] = value
	}
	windows := []any{}
	for i, value := range r.Samples {
		node := 1
		if i < 5 {
			node = 0
		}
		windows = append(windows, map[string]any{"sample_index": i, "node": node, "local": node == 0, "cpu": 2, "bytes": 64 << 20, "value_gb_s": value, "pages_verified_before": 16384, "pages_verified_after": 16384, "placement_verified": true})
	}
	lMedian, rMedian := median(r.Samples[:5]), median(r.Samples[5:])
	r.Coverage = map[string]any{"windows": windows, "allocated_device_bytes": 64 << 20, "peak_pinned_host_bytes": 64 << 20, "host_bytes_per_placement": 64 << 20, "local_median_gb_s": lMedian, "remote_median_gb_s": rMedian, "local_over_remote_ratio": lMedian / rMedian}
	updateSummary(&r)
	return r
}

func TestNUMARequiresBothVerifiedPlacements(t *testing.T) {
	if _, err := parsed(t, numaFixture()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Result){
		"Windows claim":         func(r *Result) { r.Conditions["worker_os"] = "windows" },
		"same node":             func(r *Result) { r.Conditions["numa_remote_node"] = 0 },
		"no placement proof":    func(r *Result) { r.Conditions["numa_placement_verified"] = false },
		"no CPU control":        func(r *Result) { r.Conditions["numa_cpu_affinity_controlled"] = false },
		"page proof incomplete": func(r *Result) { r.Coverage["windows"].([]any)[0].(map[string]any)["pages_verified_after"] = 0 },
		"second node omitted":   func(r *Result) { r.Coverage["windows"] = r.Coverage["windows"].([]any)[:5] },
		"contents unchecked":    func(r *Result) { r.Correctness.CheckedValues = 1 },
		"invented ratio":        func(r *Result) { r.Coverage["local_over_remote_ratio"] = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			r := numaFixture()
			mutate(&r)
			if _, err := parsed(t, r); err == nil {
				t.Fatal("unsupported NUMA success accepted")
			}
		})
	}
	if len(repeatObservations(model.Observation{}, numaFixture())) != 1 {
		t.Fatal("different NUMA placements pooled as repeatability")
	}
}
