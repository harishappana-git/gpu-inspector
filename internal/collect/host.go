package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

type hostReader struct {
	ctx       context.Context
	proc, sys string
}

func (r hostReader) read(path string) (string, model.Status) {
	if r.ctx.Err() != nil {
		return "", model.TimeBudgetExhausted
	}
	f, e := os.Open(path)
	if e != nil {
		if errors.Is(e, os.ErrPermission) {
			return "", model.PermissionDenied
		}
		if errors.Is(e, os.ErrNotExist) {
			return "", model.Unsupported
		}
		return "", model.ToolError
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return "", model.ToolError
	}
	return strings.TrimSpace(string(b)), model.Pass
}
func (r hostReader) procFile(name string) (string, model.Status) {
	return r.read(filepath.Join(r.proc, name))
}
func hostObs(check, field string, f field, start time.Time) model.Observation {
	o := observation(check, "linux."+field, "process-host", f, start)
	o.Conditions = map[string]any{"field": field, "temporal_scope": "single snapshot; counters may predate scan", "hierarchy_scope": "only visible ancestors; hidden ancestor limits may remain"}
	return o
}
func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		p := strings.SplitN(line, ":", 2)
		if len(p) == 2 {
			m[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return m
}
func uintValue(s string) (uint64, bool) {
	v, e := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return v, e == nil
}
func counterMap(s string, allowed []string) (map[string]uint64, bool) {
	m := map[string]uint64{}
	allow := map[string]bool{}
	for _, k := range allowed {
		allow[k] = true
	}
	for _, line := range strings.Split(s, "\n") {
		p := strings.Fields(line)
		if len(p) == 2 && allow[p[0]] {
			v, ok := uintValue(p[1])
			if !ok {
				return nil, false
			}
			m[p[0]] = v
		}
	}
	return m, len(m) > 0
}

func Host(ctx context.Context, opts Options) []model.Observation {
	if runtime.GOOS != "linux" || opts.ProcRoot != "" || opts.SysRoot != "" {
		return hostDirect(ctx, opts)
	}
	start := time.Now()
	exe, err := os.Executable()
	if err != nil {
		return []model.Observation{hostObs("E01", "collector", absent(model.ToolError, "Cannot locate isolated OS helper."), start)}
	}
	b, status := run(ctx, exe, []string{"__collect-host", opts.Workspace}, timeout(opts), 1<<20)
	if status != model.Pass {
		return []model.Observation{hostObs("E01", "collector", absent(status, "Isolated OS collector unavailable or incomplete."), start)}
	}
	var out []model.Observation
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&out) != nil {
		return []model.Observation{hostObs("E01", "collector", absent(model.ToolError, "Invalid isolated OS collector response."), start)}
	}
	for _, o := range out {
		if !o.Status.Valid() {
			return []model.Observation{hostObs("E01", "collector", absent(model.ToolError, "Invalid isolated OS observation status."), start)}
		}
	}
	return out
}
func hostDirect(ctx context.Context, opts Options) []model.Observation {
	start := time.Now()
	if runtime.GOOS != "linux" && opts.ProcRoot == "" {
		return []model.Observation{hostObs("E01", "platform", absent(model.Unsupported, "Linux proc/sys/cgroup collectors are unavailable on this operating system."), start)}
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.SysRoot == "" {
		opts.SysRoot = "/sys"
	}
	r := hostReader{ctx, opts.ProcRoot, opts.SysRoot}
	out := []model.Observation{}
	out = append(out, historyObservations(r, start)...)
	add := func(check, name string, f field) { out = append(out, hostObs(check, name, f, start)) }
	status, ss := r.procFile("self/status")
	values := parseKV(status)
	for _, spec := range []struct{ key, name, check string }{{"Cpus_allowed_list", "cpus_allowed_list", "E01"}, {"Mems_allowed_list", "numa_memory_nodes_allowed", "E10"}, {"CapEff", "capabilities_effective", "I03"}, {"NoNewPrivs", "no_new_privileges", "I03"}, {"Seccomp", "seccomp_mode", "I03"}} {
		f := absent(ss, "Allowlisted process status field unavailable.")
		if ss == model.Pass {
			v, ok := values[spec.key]
			if !ok {
				f.Status = model.Unsupported
			} else {
				f = present(v, "")
			}
		}
		add(spec.check, spec.name, f)
	}
	if ss == model.Pass {
		if n, e := cpuCount(values["Cpus_allowed_list"]); e == nil {
			add("E01", "cpu_affinity_count", present(n, "CPUs"))
		}
	}
	limits, ls := r.procFile("self/limits")
	limitValues := map[string]any{}
	if ls == model.Pass {
		for _, line := range strings.Split(limits, "\n") {
			for _, key := range []string{"Max locked memory", "Max processes", "Max open files", "Max address space"} {
				if strings.HasPrefix(line, key+" ") {
					p := strings.Fields(strings.TrimPrefix(line, key))
					if len(p) >= 2 {
						limitValues[key] = map[string]string{"soft": p[0], "hard": p[1]}
					}
				}
			}
		}
		if len(limitValues) == 0 {
			ls = model.ToolError
		}
	}
	add("E09", "process_limits", field{Status: ls, Value: limitValues, Message: "Reported current process limits; a specific worker's allocation still requires a checked operation."})
	mem, ms := r.procFile("meminfo")
	mk := parseKV(mem)
	memValues := map[string]uint64{}
	if ms == model.Pass {
		for _, key := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
			p := strings.Fields(mk[key])
			if len(p) == 2 && p[1] == "kB" {
				if v, ok := uintValue(p[0]); ok {
					memValues[key] = v * 1024
				}
			}
		}
		if len(memValues) == 0 {
			ms = model.ToolError
		}
	}
	add("E05", "host_memory_context", field{Status: ms, Value: memValues, Unit: "bytes", Message: "Host-reported context can exceed the process cgroup entitlement; it is not the job-visible limit."})
	vm, vs := r.procFile("vmstat")
	vmap, ok := counterMap(vm, []string{"pswpin", "pswpout"})
	if vs == model.Pass && !ok {
		vs = model.ToolError
	}
	add("E07", "swap_counters", field{Status: vs, Value: vmap, Unit: "pages", Message: "Cumulative reported swap counters; interval deltas require continuity."})
	stat, sts := r.procFile("stat")
	cpu := map[string]uint64{}
	if sts == model.Pass {
		for _, line := range strings.Split(stat, "\n") {
			p := strings.Fields(line)
			if len(p) >= 9 && p[0] == "cpu" {
				for i, key := range []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"} {
					v, ok := uintValue(p[i+1])
					if !ok {
						sts = model.ToolError
						break
					}
					cpu[key] = v
				}
				break
			}
		}
		if len(cpu) == 0 {
			sts = model.Unsupported
		}
	}
	add("E03", "cpu_time_counters", field{Status: sts, Value: cpu, Unit: "USER_HZ", Message: "Hypervisor/kernel-reported CPU accounting; single snapshots do not measure steal rate or prove host oversubscription."})
	for _, name := range []string{"cpu", "memory", "io"} {
		raw, s := r.procFile("pressure/" + name)
		pressure, ok := parsePressure(raw)
		if s == model.Pass && !ok {
			s = model.ToolError
		}
		add("E07", "pressure_"+name, field{Status: s, Value: pressure, Message: "Kernel PSI averages and cumulative stall microseconds; resource pressure is a symptom, not attribution."})
	}
	cg, cs := r.procFile("self/cgroup")
	mi, mis := r.procFile("self/mountinfo")
	if cs == model.Pass && mis == model.Pass {
		mounts := resolveCgroups(cg, mi)
		if len(mounts) == 0 {
			add("E01", "cgroup_hierarchy", absent(model.Unsupported, "No resolvable cgroup mount for this process; effective limits remain unknown."))
		} else {
			out = append(out, collectCgroups(r, mounts, start)...)
		}
	} else {
		s := cs
		if cs == model.Pass {
			s = mis
		}
		add("E01", "cgroup_hierarchy", absent(s, "Current process cgroup hierarchy cannot be resolved; no host-root limit is substituted."))
	}
	// Only expose whether a known control socket is mounted. Do not connect,
	// enumerate contents, read endpoint credentials, or exercise capabilities.
	sockets := map[string]bool{}
	if mis == model.Pass {
		for _, line := range strings.Split(mi, "\n") {
			p := strings.Fields(line)
			if len(p) > 5 {
				path := unescapeMount(p[4])
				for _, known := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock"} {
					if path == known {
						sockets[known] = true
					}
				}
			}
		}
	}
	add("I03", "mounted_control_socket_indicators", field{Status: mis, Value: sockets, Message: "Known socket mount indicators only; absence does not establish isolation and no socket is contacted."})
	for _, key := range []string{"product_name", "sys_vendor"} {
		v, s := r.read(filepath.Join(r.sys, "class/dmi/id", key))
		if len(v) > 256 {
			s = model.ToolError
			v = ""
		}
		add("A11", "dmi_"+key, field{Status: s, Value: valueIf(s, v), Message: "Allowlisted DMI context; VM/container isolation and physical host authenticity are not established."})
	}
	add("A11", "cgroup_namespace_context", field{Status: cs, Value: map[string]any{"current_hierarchy_readable": cs == model.Pass}, Message: "Only the current process hierarchy is inspected; namespace root and hidden host ancestors may constrain visibility."})
	out = append(out, capacityObservations(opts, start)...)
	out = append(out, mountContext(opts.Workspace, mi, mis, start))
	out = append(out, networkContext(r, start)...)
	add("I09", "trust_boundary", field{Status: model.Warning, Value: "host/driver mediated; externally verified attestation not performed", Message: "A local process cannot certify a hostile kernel/hypervisor or protect workload secrets from it; use independently verified attestation when required."})
	return out
}

func valueIf(s model.Status, v any) any {
	if s == model.Pass {
		return v
	}
	return nil
}
func cpuCount(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty CPU list")
	}
	ranges := [][2]int{}
	for _, token := range strings.Split(s, ",") {
		p := strings.Split(token, "-")
		if len(p) > 2 {
			return 0, fmt.Errorf("invalid CPU list")
		}
		a, e := strconv.Atoi(p[0])
		if e != nil || a < 0 {
			return 0, fmt.Errorf("invalid CPU")
		}
		b := a
		if len(p) == 2 {
			b, e = strconv.Atoi(p[1])
			if e != nil || b < a {
				return 0, fmt.Errorf("invalid CPU range")
			}
		}
		if b > 1048576 {
			return 0, fmt.Errorf("CPU list too large")
		}
		ranges = append(ranges, [2]int{a, b})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	n := 0
	last := -1
	for _, r := range ranges {
		if r[0] <= last {
			return 0, fmt.Errorf("overlapping CPU list")
		}
		n += r[1] - r[0] + 1
		last = r[1]
	}
	return n, nil
}
func parsePressure(s string) (map[string]map[string]float64, bool) {
	out := map[string]map[string]float64{}
	for _, line := range strings.Split(s, "\n") {
		p := strings.Fields(line)
		if len(p) != 5 || (p[0] != "some" && p[0] != "full") {
			return nil, false
		}
		m := map[string]float64{}
		for _, x := range p[1:] {
			kv := strings.SplitN(x, "=", 2)
			if len(kv) != 2 {
				return nil, false
			}
			if kv[0] != "avg10" && kv[0] != "avg60" && kv[0] != "avg300" && kv[0] != "total" {
				return nil, false
			}
			v, e := strconv.ParseFloat(kv[1], 64)
			if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				return nil, false
			}
			m[kv[0]] = v
		}
		if len(m) != 4 {
			return nil, false
		}
		out[p[0]] = m
	}
	return out, len(out) > 0
}

type cgroupMount struct {
	Version                   int
	Controllers               map[string]bool
	Root, Current, Mountpoint string
	HiddenAncestors           bool
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}
func cleanAbsolute(s string) (string, bool) {
	if !strings.HasPrefix(s, "/") {
		return "", false
	}
	p := filepath.Clean(s)
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return "", false
		}
	}
	return p, true
}
func resolveCgroups(cg, mountinfo string) []cgroupMount {
	type member struct {
		controllers map[string]bool
		path        string
		v2          bool
	}
	members := []member{}
	for _, line := range strings.Split(cg, "\n") {
		p := strings.SplitN(line, ":", 3)
		if len(p) != 3 {
			continue
		}
		path, ok := cleanAbsolute(p[2])
		if !ok {
			continue
		}
		m := member{controllers: map[string]bool{}, path: path, v2: p[0] == "0" && p[1] == ""}
		for _, c := range strings.Split(p[1], ",") {
			m.controllers[c] = true
		}
		members = append(members, m)
	}
	out := []cgroupMount{}
	for _, line := range strings.Split(mountinfo, "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		p, q := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(p) < 6 || len(q) < 3 || (q[0] != "cgroup" && q[0] != "cgroup2") {
			continue
		}
		root, ok := cleanAbsolute(unescapeMount(p[3]))
		if !ok {
			continue
		}
		mount, ok := cleanAbsolute(unescapeMount(p[4]))
		if !ok {
			continue
		}
		controllers := map[string]bool{}
		for _, c := range strings.Split(q[2], ",") {
			controllers[c] = true
		}
		for _, m := range members {
			v2 := q[0] == "cgroup2"
			if v2 != m.v2 {
				continue
			}
			if !v2 {
				match := false
				for c := range m.controllers {
					if controllers[c] {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			rel := ""
			if m.path == root {
				rel = "."
			} else if strings.HasPrefix(m.path, strings.TrimSuffix(root, "/")+"/") {
				rel = strings.TrimPrefix(m.path, strings.TrimSuffix(root, "/")+"/")
			} else if m.path == "/" && root != "/" {
				rel = "."
			} else {
				continue
			}
			current := filepath.Join(mount, rel)
			if current != mount && !strings.HasPrefix(current, mount+"/") {
				continue
			}
			version := 1
			if v2 {
				version = 2
			}
			out = append(out, cgroupMount{version, controllers, root, current, mount, root != "/"})
			break
		}
	}
	return out
}
func ancestors(m cgroupMount) []string {
	out := []string{}
	p := m.Current
	for len(out) < 128 {
		out = append(out, p)
		if p == m.Mountpoint {
			break
		}
		next := filepath.Dir(p)
		if next == p || (!strings.HasPrefix(next, m.Mountpoint+"/") && next != m.Mountpoint) {
			break
		}
		p = next
	}
	return out
}
func collectCgroups(r hostReader, mounts []cgroupMount, start time.Time) []model.Observation {
	out := []model.Observation{}
	add := func(check, name string, f field) { out = append(out, hostObs(check, name, f, start)) }
	versions := map[int]bool{}
	hidden := false
	for _, m := range mounts {
		versions[m.Version] = true
		hidden = hidden || m.HiddenAncestors
		paths := ancestors(m)
		if len(paths) >= 128 {
			hidden = true
		}
		if m.Version == 2 || m.Controllers["cpu"] {
			minQuota := math.Inf(1)
			complete := true
			queried := 0
			readStatus := model.Unsupported
			for _, p := range paths {
				if m.Version == 2 {
					v, s := r.read(filepath.Join(p, "cpu.max"))
					if s != model.Pass {
						if p != m.Mountpoint {
							complete = false
							readStatus = s
						}
						continue
					}
					q, finite, ok := parseCPUMax(v)
					if !ok {
						complete = false
						readStatus = model.ToolError
						continue
					}
					queried++
					if finite && q < minQuota {
						minQuota = q
					}
				} else {
					q, qs := r.read(filepath.Join(p, "cpu.cfs_quota_us"))
					per, ps := r.read(filepath.Join(p, "cpu.cfs_period_us"))
					if qs != model.Pass || ps != model.Pass {
						complete = false
						readStatus = qs
						if qs == model.Pass {
							readStatus = ps
						}
						continue
					}
					qq, e := strconv.ParseInt(q, 10, 64)
					pp, ok := uintValue(per)
					if e != nil || !ok || pp == 0 || qq == 0 || qq < -1 {
						complete = false
						readStatus = model.ToolError
						continue
					}
					queried++
					if qq > 0 && float64(qq)/float64(pp) < minQuota {
						minQuota = float64(qq) / float64(pp)
					}
				}
			}
			f := field{Status: model.Pass, Value: map[string]any{"visible_ancestors_checked": queried, "visible_hierarchy_complete": complete, "hidden_ancestors_possible": true}, Message: "Minimum CPU quota across readable visible ancestors; unknown host ancestors can impose tighter limits."}
			if !math.IsInf(minQuota, 1) {
				f.Value.(map[string]any)["quota_cpu_equivalent"] = minQuota
			} else {
				f.Value.(map[string]any)["finite_quota_observed"] = false
			}
			if queried == 0 {
				f.Status = readStatus
			}
			if !complete && queried > 0 {
				f.Status = model.Warning
			}
			add("E01", "cgroup_cpu_entitlement", f)
			v, s := r.read(filepath.Join(m.Current, "cpu.stat"))
			allowed := []string{"usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec", "throttled_time", "nr_bursts", "burst_usec"}
			vals, ok := counterMap(v, allowed)
			if s == model.Pass && !ok {
				s = model.ToolError
			}
			add("E02", "cgroup_cpu_stat", field{Status: s, Value: valueIf(s, vals), Message: "Current cgroup cumulative CPU/throttling counters; historical totals are not scan deltas."})
		}
		if m.Version == 2 || m.Controllers["cpuset"] {
			name := "cpuset.cpus.effective"
			if m.Version == 1 {
				name = "cpuset.effective_cpus"
			}
			v, s := r.read(filepath.Join(m.Current, name))
			if s != model.Pass && m.Version == 1 {
				v, s = r.read(filepath.Join(m.Current, "cpuset.cpus"))
			}
			f := field{Status: s, Message: "Effective cpuset within visible hierarchy; affinity can impose additional restrictions."}
			if s == model.Pass {
				n, e := cpuCount(v)
				if e != nil {
					f.Status = model.ToolError
				} else {
					f.Value = map[string]any{"cpu_list": v, "count": n}
				}
			}
			add("E01", "cgroup_cpuset", f)
		}
		if m.Version == 2 || m.Controllers["memory"] {
			name := "memory.max"
			current := "memory.current"
			if m.Version == 1 {
				name = "memory.limit_in_bytes"
				current = "memory.usage_in_bytes"
			}
			var minLimit uint64 = math.MaxUint64
			queried := 0
			complete := true
			missing := model.Unsupported
			for _, p := range paths {
				v, s := r.read(filepath.Join(p, name))
				if s != model.Pass {
					if p != m.Mountpoint {
						complete = false
						missing = s
					}
					continue
				}
				queried++
				if v == "max" {
					continue
				}
				n, ok := uintValue(v)
				if !ok {
					complete = false
					missing = model.ToolError
					continue
				}
				if m.Version == 1 && n >= (1<<60) {
					continue
				}
				if n < minLimit {
					minLimit = n
				}
			}
			usage, us := r.read(filepath.Join(m.Current, current))
			u, uok := uintValue(usage)
			if us == model.Pass && !uok {
				us = model.ToolError
			}
			data := map[string]any{"visible_ancestors_checked": queried, "visible_hierarchy_complete": complete, "hidden_ancestors_possible": true}
			if minLimit != math.MaxUint64 {
				data["visible_limit_bytes"] = minLimit
			}
			if us == model.Pass {
				data["current_usage_bytes"] = u
			}
			if minLimit != math.MaxUint64 && us == model.Pass {
				var head uint64
				if minLimit > u {
					head = minLimit - u
				}
				data["ceiling_minus_current_group_usage_bytes"] = head
			}
			f := field{Status: model.Pass, Value: data, Unit: "bytes", Message: "Visible hierarchy ceiling and current-group usage; siblings and hidden ancestor usage can reduce real headroom further."}
			if queried == 0 {
				f.Status = missing
			}
			if (!complete || us != model.Pass) && queried > 0 {
				f.Status = model.Warning
			}
			add("E05", "cgroup_memory", f)
			if m.Version == 2 {
				v, s := r.read(filepath.Join(m.Current, "memory.events"))
				vals, ok := counterMap(v, []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"})
				if s == model.Pass && !ok {
					s = model.ToolError
				}
				add("E06", "cgroup_memory_events", field{Status: s, Value: valueIf(s, vals), Message: "Cumulative memory events for the current cgroup and descendants; OOM/reclaim events may predate this scan."})
			} else {
				v, s := r.read(filepath.Join(m.Current, "memory.failcnt"))
				n, ok := uintValue(v)
				if s == model.Pass && !ok {
					s = model.ToolError
				}
				add("E06", "cgroup_memory_failcnt", field{Status: s, Value: valueIf(s, n), Message: "Cgroup v1 limit-hit count is not a count of OOM kills or a scan delta."})
			}
		}
		if m.Version == 2 || m.Controllers["pids"] {
			vals := map[string]any{}
			sfinal := model.Pass
			for _, name := range []string{"pids.max", "pids.current"} {
				v, s := r.read(filepath.Join(m.Current, name))
				if s != model.Pass {
					sfinal = s
					continue
				}
				if v == "max" {
					vals[name] = "max"
				} else if n, ok := uintValue(v); ok {
					vals[name] = n
				} else {
					sfinal = model.ToolError
				}
			}
			add("E09", "cgroup_pids", field{Status: sfinal, Value: vals, Message: "Current-group PID ceiling and use; visible ancestor limits can be tighter."})
		}
	}
	versionList := []int{}
	for v := range versions {
		versionList = append(versionList, v)
	}
	sort.Ints(versionList)
	add("E01", "cgroup_hierarchy", field{Status: model.Pass, Value: map[string]any{"versions": versionList, "mount_count": len(mounts), "mount_hides_ancestors": hidden, "host_hierarchy_completeness": "unknown"}, Message: "Resolved current process cgroup via mountinfo and membership; private cgroup paths are omitted from exported evidence."})
	return out
}
func parseCPUMax(s string) (quota float64, finite, ok bool) {
	p := strings.Fields(s)
	if len(p) != 2 {
		return 0, false, false
	}
	period, yes := uintValue(p[1])
	if !yes || period == 0 {
		return 0, false, false
	}
	if p[0] == "max" {
		return 0, false, true
	}
	q, yes := uintValue(p[0])
	if !yes || q == 0 {
		return 0, false, false
	}
	return float64(q) / float64(period), true, true
}

// mountContext exports no source path, UUID, hostname, or mount credential.
func mountContext(workspace, mountinfo string, status model.Status, start time.Time) model.Observation {
	if status != model.Pass {
		return hostObs("F02", "workspace_mount_context", absent(status, "Mount context unavailable; persistence remains undeclared."), start)
	}
	if workspace == "" {
		workspace = "."
	}
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return hostObs("F02", "workspace_mount_context", absent(model.ToolError, "Workspace cannot be resolved."), start)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	longest := -1
	var value map[string]any
	for _, line := range strings.Split(mountinfo, "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		p, q := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(p) < 6 || len(q) < 3 {
			continue
		}
		mount, ok := cleanAbsolute(unescapeMount(p[4]))
		if !ok {
			continue
		}
		if absolute != mount && !strings.HasPrefix(absolute, strings.TrimSuffix(mount, "/")+"/") {
			continue
		}
		if len(mount) <= longest {
			continue
		}
		longest = len(mount)
		flags := []string{}
		for _, flag := range strings.Split(p[5], ",") {
			switch flag {
			case "ro", "rw", "noexec", "nosuid", "nodev":
				flags = append(flags, flag)
			}
		}
		value = map[string]any{"filesystem_type": q[0], "mount_flags": flags, "persistence": "unknown; requires provider or user declaration", "quota": "not established by statfs"}
	}
	if value == nil {
		return hostObs("F02", "workspace_mount_context", absent(model.Unsupported, "Workspace mount not resolvable in visible mountinfo; persistence unknown."), start)
	}
	return hostObs("F02", "workspace_mount_context", field{Status: model.Pass, Value: value, Message: "Exposed mount context only; a local filesystem type does not establish persistence after rental stop/deletion."}, start)
}

func networkContext(r hostReader, start time.Time) []model.Observation {
	raw, s := r.procFile("net/route")
	data := map[string]any{"scope": "visible IPv4 route context only", "reachability": "not tested", "external_requests": 0}
	interfaces := []string{}
	if s == model.Pass {
		seen := map[string]bool{}
		routeCount := 0
		for _, line := range strings.Split(raw, "\n") {
			p := strings.Fields(line)
			if len(p) < 8 || p[0] == "Iface" {
				continue
			}
			routeCount++
			if p[1] == "00000000" && p[7] == "00000000" && safeInterface(p[0]) && !seen[p[0]] {
				interfaces = append(interfaces, p[0])
				seen[p[0]] = true
			}
		}
		data["route_count"] = routeCount
		data["default_route_count"] = len(interfaces)
	}
	details := []map[string]any{}
	for i, name := range interfaces {
		if i >= 16 {
			break
		}
		item := map[string]any{"interface_alias": fmt.Sprintf("default-route-%d", i+1)}
		for _, key := range []string{"operstate", "mtu", "speed", "duplex"} {
			v, status := r.read(filepath.Join(r.sys, "class/net", name, key))
			if len(v) > 128 {
				status = model.ToolError
			}
			if status == model.Pass {
				item[key] = v
			} else {
				item[key+"_status"] = status
			}
		}
		details = append(details, item)
	}
	data["interfaces"] = details
	return []model.Observation{hostObs("G01", "network_route_context", field{Status: s, Value: valueIf(s, data), Message: "Read-only route/interface context; addresses and MACs omitted, no DNS, connection, neighbor scan, or traffic test performed."}, start)}
}
func safeInterface(s string) bool {
	if len(s) == 0 || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}
