//go:build windows

package collect

import (
	"context"
	"math/bits"
	"net"
	"runtime"
	"time"
	"unsafe"

	"github.com/harishappana/gpu-inspector/internal/model"
	"golang.org/x/sys/windows"
)

type winMemoryStatus struct {
	Length, Load                                                                                         uint32
	TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual uint64
}

func winHostObs(check, name string, f field, start time.Time) model.Observation {
	o := observation(check, "windows."+name, "process-host", f, start)
	o.Conditions = map[string]any{"field": name, "temporal_scope": "single snapshot; counters may predate scan", "hierarchy_scope": "Windows API visibility; nested job limits and hidden host constraints may remain"}
	return o
}

func platformHost(ctx context.Context, opts Options, start time.Time) []model.Observation {
	out := []model.Observation{}
	add := func(check, name string, f field) {
		if ctx.Err() != nil {
			f = absent(model.TimeBudgetExhausted, "Windows host collection cancelled.")
		}
		out = append(out, winHostObs(check, name, f, start))
	}
	if ctx.Err() != nil {
		add("E01", "collector", absent(model.TimeBudgetExhausted, "Windows host collection cancelled."))
		return out
	}
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	version := windows.RtlGetVersion()
	add("H01", "os_context", present(map[string]any{"os": "windows", "architecture": runtime.GOARCH, "major": version.MajorVersion, "minor": version.MinorVersion, "build": version.BuildNumber}, ""))
	var processMask, systemMask uintptr
	rc, _, _ := kernel.NewProc("GetProcessAffinityMask").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&processMask)), uintptr(unsafe.Pointer(&systemMask)))
	if rc != 0 && processMask != 0 {
		add("E01", "cpu_affinity_count", field{Status: model.Pass, Value: bits.OnesCount64(uint64(processMask)), Unit: "CPUs", Message: "GetProcessAffinityMask count in the caller's processor group; processor groups, CPU sets and job CPU-rate limits may impose additional constraints."})
	} else {
		add("E01", "cpu_affinity_count", absent(model.Unsupported, "A single Windows processor-group affinity mask is unavailable; no aggregate entitlement inferred."))
	}
	add("E01", "logical_cpu_context", field{Status: model.Pass, Value: map[string]any{"system_active_logical_processors": windows.GetActiveProcessorCount(0xffff), "runtime_visible_logical_processors": runtime.NumCPU()}, Message: "Reported logical processor context; counts do not establish sustained CPU entitlement or physical core count."})
	var memory winMemoryStatus
	memory.Length = uint32(unsafe.Sizeof(memory))
	rc, _, _ = kernel.NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&memory)))
	if rc != 0 && memory.TotalPhys > 0 && memory.AvailPhys <= memory.TotalPhys {
		add("E05", "host_memory_context", field{Status: model.Pass, Value: map[string]uint64{"MemTotal": memory.TotalPhys, "MemAvailable": memory.AvailPhys, "CommitLimitForProcess": memory.TotalPageFile, "CommitAvailableForProcess": memory.AvailPageFile, "VirtualAddressTotal": memory.TotalVirtual, "VirtualAddressAvailable": memory.AvailVirtual}, Unit: "bytes", Message: "Windows physical memory and calling helper commit/address-space context; values are volatile and do not certify the worker's maximum allocatable memory. Commit limits include RAM and pagefile, not pagefile size alone."})
	} else {
		add("E05", "host_memory_context", absent(model.ToolError, "GlobalMemoryStatusEx did not provide valid memory capacity."))
	}
	var idle, kernelTime, user windows.Filetime
	rc, _, _ = kernel.NewProc("GetSystemTimes").Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernelTime)), uintptr(unsafe.Pointer(&user)))
	if rc != 0 {
		value := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
		add("E03", "cpu_time_counters", field{Status: model.Pass, Value: map[string]uint64{"idle": value(idle), "kernel_including_idle": value(kernelTime), "user": value(user)}, Unit: "100 ns ticks", Message: "Cumulative Windows system CPU times; on systems with more than 64 processors these are limited to the caller's primary group. Windows does not expose Linux steal/iowait counters here."})
	} else {
		add("E03", "cpu_time_counters", absent(model.ToolError, "GetSystemTimes failed."))
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		milliseconds, _, _ := kernel.NewProc("GetTickCount64").Call()
		add("J04", "history_visibility", field{Status: model.Warning, Value: map[string]any{"host_uptime_seconds": float64(milliseconds) / 1000, "oldest_accessible_gpu_event_utc": nil, "gpu_reset_epoch": nil, "complete_event_history": false}, Message: "Host-reported uptime only; GPU reset epoch and historical device events are not established."})
	} else {
		add("J04", "history_visibility", absent(model.Unsupported, "64-bit Windows uptime adapter is unavailable in this build."))
	}
	var node uint32
	rc, _, _ = kernel.NewProc("GetNumaHighestNodeNumber").Call(uintptr(unsafe.Pointer(&node)))
	if rc != 0 {
		add("E10", "numa_context", field{Status: model.Pass, Value: map[string]any{"highest_node_number": node}, Message: "Highest reported Windows NUMA node number; this is not a node count or process memory placement guarantee."})
	} else {
		add("E10", "numa_context", absent(model.Unsupported, "Windows NUMA topology API unavailable."))
	}
	for _, spec := range []struct{ check, name, message string }{
		{"E01", "cgroup_hierarchy", "Linux cgroups do not apply to native Windows. Windows nested job CPU/memory limits are not completely enumerated by this helper."},
		{"E02", "cgroup_cpu_stat", "Linux cgroup throttling counters are unavailable on Windows."},
		{"E06", "cgroup_memory_events", "Linux cgroup OOM/reclaim counters are unavailable on Windows; no zero OOM event count is inferred."},
		{"E07", "swap_counters", "This Windows adapter does not collect interval paging I/O counters."},
		{"E07", "pressure_cpu", "Linux PSI CPU pressure is unavailable on Windows."},
		{"E07", "pressure_memory", "Linux PSI memory pressure is unavailable on Windows."},
		{"E07", "pressure_io", "Linux PSI I/O pressure is unavailable on Windows."},
		{"E08", "shared_memory_capacity", "Windows shared sections use system commitment; a Linux /dev/shm filesystem capacity does not apply."},
		{"E09", "process_limits", "POSIX rlimits do not apply to Windows; inherited and nested job limits are not fully established by this isolated helper."},
		{"I03", "process_security_context", "Linux capabilities, seccomp and NoNewPrivs do not apply to Windows; full token and sandbox rights are not enumerated."},
		{"A11", "cgroup_namespace_context", "Linux cgroup namespaces do not apply to native Windows."},
	} {
		add(spec.check, spec.name, absent(model.Unsupported, spec.message))
	}
	if ctx.Err() == nil {
		out = append(out, capacityObservations(opts, start)...)
		out = append(out, windowsMountContext(opts.Workspace, start))
	}
	interfaces, err := net.Interfaces()
	if err == nil {
		up, nonloop := 0, 0
		var mtu []int
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			nonloop++
			if iface.Flags&net.FlagUp != 0 {
				up++
				if len(mtu) < 64 {
					mtu = append(mtu, iface.MTU)
				}
			}
		}
		add("G01", "network_interface_context", field{Status: model.Pass, Value: map[string]any{"nonloopback_interfaces": nonloop, "up_nonloopback_interfaces": up, "up_interface_mtu": mtu, "external_requests": 0, "reachability": "not tested"}, Message: "Read-only Windows interface count/MTU context; interface names, addresses and MACs are omitted. Route, DNS, connectivity and throughput are not tested."})
	} else {
		add("G01", "network_interface_context", absent(model.ToolError, "Windows interface metadata could not be read."))
	}
	add("I09", "trust_boundary", field{Status: model.Warning, Value: "host/driver mediated; externally verified attestation not performed", Message: "Local Windows APIs and the GPU driver cannot certify a hostile kernel/hypervisor or guarantee workload confidentiality."})
	return out
}
