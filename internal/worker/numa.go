package worker

import (
	"errors"
	"math"
)

func (r Result) validateNUMA() error {
	c := r.Conditions
	local, lOK := number(c["numa_local_node"])
	remote, rOK := number(c["numa_remote_node"])
	cpu, cOK := number(c["numa_cpu_core"])
	bytes, bOK := number(c["transfer_bytes"])
	page, pOK := number(c["numa_page_bytes"])
	capBytes, _ := number(c["memory_cap_bytes"])
	transferCap := float64(64 << 20)
	if c["tier"] == "standard" {
		transferCap = 256 << 20
	}
	if !lOK || !rOK || !cOK || local == remote || local >= 1024 || remote >= 1024 || cpu >= 1024 || local != math.Trunc(local) || remote != math.Trunc(remote) || cpu != math.Trunc(cpu) || !bOK || !pOK || page < 4096 || page > 1<<20 || page != math.Trunc(page) || uint64(page)&(uint64(page)-1) != 0 || bytes != math.Trunc(bytes) || bytes < page || bytes > transferCap || bytes > capBytes || math.Mod(bytes, page) != 0 {
		return errors.New("NUMA node, CPU, page or transfer limits are invalid")
	}
	if c["worker_os"] != "linux" || c["direction"] != "H2D" || c["copy_method"] != "cudaMemcpyAsync_registered_owned_pages" || c["host_memory"] != "mmap_private_anonymous_cudaHostRegister" || c["numa_policy"] != "MPOL_BIND_owned_anonymous_pages" || c["numa_placement_query"] != "move_pages_query_only_all_pages_before_and_after_each_sample" || c["numa_cpu_affinity_controlled"] != true || c["numa_placement_verified"] != true || c["mixed_numa_placements"] != true || c["numa_node_order"] != "local_then_remote" {
		return errors.New("NUMA comparison lacks controlled and verified placement")
	}
	perNode := 5
	if c["tier"] == "standard" {
		perNode = 10
	}
	windows, ok := r.Coverage["windows"].([]any)
	if !ok || r.SampleCount != 2*perNode || len(windows) != r.SampleCount || r.Correctness.CheckedValues != uint64(bytes/4)*uint64(r.SampleCount) || !equalNumber(r.Coverage["allocated_device_bytes"], bytes) || !equalNumber(r.Coverage["peak_pinned_host_bytes"], bytes) || !equalNumber(r.Coverage["host_bytes_per_placement"], bytes) {
		return errors.New("NUMA comparison coverage is incomplete")
	}
	localSamples, remoteSamples := []float64{}, []float64{}
	for i, item := range windows {
		w, ok := item.(map[string]any)
		if !ok {
			return errors.New("NUMA sample window missing")
		}
		node := remote
		if i < perNode {
			node = local
		}
		if !equalNumber(w["sample_index"], float64(i)) || !equalNumber(w["node"], node) || w["local"] != (node == local) || !equalNumber(w["cpu"], cpu) || !equalNumber(w["bytes"], bytes) || !equalNumber(w["value_gb_s"], r.Samples[i]) || !equalNumber(w["pages_verified_before"], bytes/page) || !equalNumber(w["pages_verified_after"], bytes/page) || w["placement_verified"] != true {
			return errors.New("NUMA sample placement or content evidence is incomplete")
		}
		if node == local {
			localSamples = append(localSamples, r.Samples[i])
		} else {
			remoteSamples = append(remoteSamples, r.Samples[i])
		}
	}
	lMedian, rMedian := median(localSamples), median(remoteSamples)
	if rMedian <= 0 || !equalNumber(r.Coverage["local_median_gb_s"], lMedian) || !equalNumber(r.Coverage["remote_median_gb_s"], rMedian) || !equalNumber(r.Coverage["local_over_remote_ratio"], lMedian/rMedian) {
		return errors.New("NUMA node comparison does not match retained samples")
	}
	return nil
}
