package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestMain(m *testing.M) {
	if HandleInternalCommand(os.Args[1:]) {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMissingSMIFieldsAreNeverZero(t *testing.T) {
	spec := fieldSpec{Name: "memory_total_bytes", Unit: "bytes"}
	for _, raw := range []string{"N/A", "[Not Supported]", "", "NaN", "+Inf", "-1", "unknown error"} {
		f := parseSMIField(raw, spec)
		if f.Status == model.Pass || f.Value != nil {
			t.Fatalf("%q became measured value: %+v", raw, f)
		}
	}
	f := parseSMIField("0", fieldSpec{Unit: "errors"})
	if f.Status != model.Pass || f.Value != uint64(0) {
		t.Fatalf("observed zero was lost: %+v", f)
	}
	f = parseSMIField("81920", spec)
	if f.Value != uint64(81920)*1024*1024 {
		t.Fatalf("wrong MiB conversion: %+v", f)
	}
	f = parseSMIField("[Insufficient Permissions]", spec)
	if f.Status != model.PermissionDenied {
		t.Fatalf("wrong denied state: %+v", f)
	}
}
func TestObservationDropsUnavailablePayload(t *testing.T) {
	o := observation("B01", "fixture", "gpu", field{Status: model.Unsupported, Value: 0}, time.Now())
	if o.Value != nil {
		t.Fatal("unavailable value retained as a numeric zero")
	}
}

func TestVisibilityDoesNotGuessCUDAOrdinals(t *testing.T) {
	ds := []model.Device{{Index: 0, UUID: "GPU-aaaa"}, {Index: 1, UUID: "GPU-bbbb"}}
	lookup := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	out, s, _ := filterVisibility(ds, lookup(map[string]string{"CUDA_VISIBLE_DEVICES": "0"}), nil, model.DependencyMissing)
	if len(out) != 0 || s != model.Contaminated {
		t.Fatal("guessed NVML index from a CUDA ordinal")
	}
	out, s, _ = filterVisibility(ds, lookup(map[string]string{"CUDA_VISIBLE_DEVICES": "0"}), []string{"GPU-bbbb"}, model.Pass)
	if s != model.Pass || len(out) != 1 || out[0].UUID != "GPU-bbbb" {
		t.Fatalf("CUDA UUID mapping ignored: %+v %s", out, s)
	}
	out, s, _ = filterVisibility(ds, lookup(map[string]string{"CUDA_VISIBLE_DEVICES": "GPU-bb", "NVIDIA_VISIBLE_DEVICES": "1"}), nil, model.Unsupported)
	if s != model.Pass || len(out) != 1 || out[0].UUID != "GPU-bbbb" {
		t.Fatal("intersection/prefix selection failed")
	}
	out, s, _ = filterVisibility(ds, lookup(map[string]string{"CUDA_VISIBLE_DEVICES": "MIG-abcd"}), nil, model.Pass)
	if len(out) != 0 || s != model.Unsupported {
		t.Fatal("substituted a physical parent for a MIG resource")
	}
	out, s, _ = filterVisibility(ds, lookup(map[string]string{"CUDA_VISIBLE_DEVICES": ""}), nil, model.Pass)
	if len(out) != 0 || s != model.Pass {
		t.Fatal("empty visibility mask should hide all devices")
	}
	out, s, _ = filterVisibility(ds, lookup(map[string]string{"CUDA_VISIBLE_DEVICES": "GPU-"}), nil, model.Pass)
	if len(out) != 0 || s != model.Contaminated {
		t.Fatal("ambiguous prefix permitted")
	}
}

func TestCollectorRunBoundsAndPrivacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process fixture")
	}
	t.Setenv("GRI_FIXTURE_SECRET", "sensitive-value")
	t.Setenv("LD_PRELOAD", "injected-loader")
	t.Setenv("CUDA_VISIBLE_DEVICES", "GPU-aaaa")
	b, s := run(context.Background(), "/usr/bin/env", nil, time.Second, 4096)
	if s != model.Pass || strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "LD_PRELOAD") || !strings.Contains(string(b), "CUDA_VISIBLE_DEVICES=GPU-aaaa") {
		t.Fatalf("allowlist failure: %s %q", s, b)
	}
	start := time.Now()
	_, s = run(context.Background(), "/bin/sh", []string{"-c", "sleep 10"}, 40*time.Millisecond, 1024)
	if s != model.TimeBudgetExhausted || time.Since(start) > 2*time.Second {
		t.Fatalf("process group did not cancel: %s", s)
	}
	_, s = run(context.Background(), "/bin/sh", []string{"-c", "while :; do printf 'overflow'; done"}, time.Second, 64)
	if s != model.ToolError {
		t.Fatalf("output overflow not rejected: %s", s)
	}
	_, s = run(context.Background(), "gri-certainly-nonexistent-command", nil, time.Second, 1024)
	if s != model.DependencyMissing {
		t.Fatalf("dependency status lost: %s", s)
	}
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}
func findField(t *testing.T, obs []model.Observation, key string) model.Observation {
	t.Helper()
	for _, o := range obs {
		if o.Conditions["field"] == key {
			return o
		}
	}
	t.Fatalf("missing field %s", key)
	return model.Observation{}
}

func TestCgroupCurrentHierarchyAndAncestorLimits(t *testing.T) {
	base := t.TempDir()
	mount := filepath.Join(base, "cg")
	current := filepath.Join(mount, "tenant-secret/job")
	for path, data := range map[string]string{
		filepath.Join(mount, "cpu.max"): "max 100000", filepath.Join(mount, "memory.max"): "max",
		filepath.Join(mount, "tenant-secret/cpu.max"): "150000 100000", filepath.Join(mount, "tenant-secret/memory.max"): "4096",
		filepath.Join(current, "cpu.max"): "400000 100000", filepath.Join(current, "cpu.stat"): "nr_periods 10\nnr_throttled 3\nthrottled_usec 123",
		filepath.Join(current, "cpuset.cpus.effective"): "2-5", filepath.Join(current, "memory.max"): "8192", filepath.Join(current, "memory.current"): "1024",
		filepath.Join(current, "memory.events"): "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0", filepath.Join(current, "pids.max"): "max", filepath.Join(current, "pids.current"): "5",
	} {
		writeFixture(t, path, data)
	}
	mi := "22 1 0:28 / " + mount + " rw - cgroup2 cgroup rw"
	mounts := resolveCgroups("0::/tenant-secret/job", mi)
	if len(mounts) != 1 || mounts[0].Current != current {
		t.Fatalf("wrong membership mapping: %+v", mounts)
	}
	obs := collectCgroups(hostReader{ctx: context.Background()}, mounts, time.Now())
	cpu := findField(t, obs, "cgroup_cpu_entitlement").Value.(map[string]any)
	if cpu["quota_cpu_equivalent"] != 1.5 {
		t.Fatalf("ignored tighter ancestor: %+v", cpu)
	}
	mem := findField(t, obs, "cgroup_memory").Value.(map[string]any)
	if mem["visible_limit_bytes"] != uint64(4096) || mem["ceiling_minus_current_group_usage_bytes"] != uint64(3072) {
		t.Fatalf("wrong visible memory ceiling: %+v", mem)
	}
	data, _ := json.Marshal(obs)
	if strings.Contains(string(data), "tenant-secret") {
		t.Fatal("private cgroup path exported")
	}
	if findField(t, obs, "cgroup_memory_events").Status != model.Pass {
		t.Fatal("zero OOM totals must remain observed zero")
	}
}

func TestCgroupMountResolutionAndTraversal(t *testing.T) {
	mounts := resolveCgroups("0::/", `22 1 0:28 /hidden/tenant /sys/fs/cgroup rw - cgroup2 cgroup rw`)
	if len(mounts) != 1 || mounts[0].Current != "/sys/fs/cgroup" || !mounts[0].HiddenAncestors {
		t.Fatalf("namespace root not resolved: %+v", mounts)
	}
	mounts = resolveCgroups("2:cpu,cpuacct:/docker/task", `23 1 0:29 /docker /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct`)
	if len(mounts) != 1 || mounts[0].Current != "/sys/fs/cgroup/cpu/task" || mounts[0].Version != 1 {
		t.Fatalf("v1 mapping failed: %+v", mounts)
	}
	mounts = resolveCgroups("0::/../../etc", `22 1 0:28 / /sys/fs/cgroup rw - cgroup2 cgroup rw`)
	if len(mounts) != 0 {
		t.Fatal("traversal escaped allowlisted hierarchy")
	}
}

func TestHostAllowlistNeverExportsNamesSecretsOrRawMountOptions(t *testing.T) {
	base := t.TempDir()
	proc := filepath.Join(base, "proc")
	sys := filepath.Join(base, "sys")
	writeFixture(t, filepath.Join(proc, "self/status"), "Name:\tPRIVATE-PROCESS\nCpus_allowed_list:\t0-3\nMems_allowed_list:\t0\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nUid:\tSECRET-UID\n")
	writeFixture(t, filepath.Join(proc, "self/limits"), "Max locked memory         65536                65536                bytes\nMax processes             1024                 1024                 processes\n")
	writeFixture(t, filepath.Join(proc, "self/mountinfo"), "1 0 0:1 / / rw,nosuid - overlay PRIVATE-HOST rw,password=PRIVATE-PASSWORD\n")
	writeFixture(t, filepath.Join(proc, "self/cgroup"), "0::/PRIVATE-TENANT")
	writeFixture(t, filepath.Join(proc, "meminfo"), "MemTotal: 8192 kB\nMemAvailable: 4096 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB")
	writeFixture(t, filepath.Join(proc, "vmstat"), "pswpin 0\npswpout 0")
	writeFixture(t, filepath.Join(proc, "stat"), "cpu 1 2 3 4 5 6 7 8")
	writeFixture(t, filepath.Join(proc, "net/route"), "Iface Destination Gateway Flags RefCnt Use Metric Mask\nPRIVATE-NET 00000000 AABBCCDD 0003 0 0 100 00000000")
	obs := Host(context.Background(), Options{ProcRoot: proc, SysRoot: sys, Workspace: base})
	data, _ := json.Marshal(obs)
	for _, private := range []string{"PRIVATE-PROCESS", "SECRET-UID", "PRIVATE-PASSWORD", "PRIVATE-HOST", "PRIVATE-TENANT", "PRIVATE-NET", "AABBCCDD"} {
		if strings.Contains(string(data), private) {
			t.Fatalf("private data exported: %s", private)
		}
	}
	for _, o := range obs {
		if !o.Status.Valid() {
			t.Fatalf("invalid status: %+v", o)
		}
	}
}

func TestCPUAndPressureParsersRejectMalformedData(t *testing.T) {
	n, e := cpuCount("0-2,5,8-9")
	if e != nil || n != 6 {
		t.Fatal("valid affinity rejected")
	}
	for _, s := range []string{"", "3-1", "0-2,2-3", "-1", "99999999"} {
		if _, e := cpuCount(s); e == nil {
			t.Fatalf("malformed list accepted: %q", s)
		}
	}
	if _, _, ok := parseCPUMax("1000 0"); ok {
		t.Fatal("zero period accepted")
	}
	if _, _, ok := parseCPUMax("-1 100000"); ok {
		t.Fatal("v1 sentinel accepted as v2 quota")
	}
	if _, ok := parsePressure("some avg10=NaN avg60=0 avg300=0 total=0"); ok {
		t.Fatal("NaN pressure accepted")
	}
	if _, ok := parsePressure("some avg10=0.01 avg60=0 avg300=0 total=100"); !ok {
		t.Fatal("valid pressure rejected")
	}
}

func TestCancelledHostReportsMissingCoverage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	obs := Host(ctx, Options{ProcRoot: t.TempDir(), SysRoot: t.TempDir()})
	if findField(t, obs, "cpus_allowed_list").Status != model.TimeBudgetExhausted {
		t.Fatal("cancelled read falsely completed")
	}
}

func TestIdentityMismatchContaminatesWholeSnapshot(t *testing.T) {
	obs := []model.Observation{
		{Status: model.Pass, Value: "GPU-other", Conditions: map[string]any{"field": "uuid"}},
		{Status: model.Pass, Value: float64(40), Conditions: map[string]any{"field": "temperature_gpu_c"}},
		{Status: model.Unsupported, Conditions: map[string]any{"field": "temperature_memory_c"}},
	}
	out := enforceSnapshotIdentity(obs, "GPU-selected")
	if out[0].Status != model.Contaminated || out[1].Status != model.Contaminated || out[2].Status != model.Unsupported {
		t.Fatalf("wrong target data remained trusted: %+v", out)
	}
}

func TestNativeDecodeRetainsExactCounterBeyondFloat64Precision(t *testing.T) {
	input := []byte(`{"status":"PASS","fields":{"ecc_uncorrected_volatile":{"status":"PASS","value":9007199254740993,"unit":"errors"}}}`)
	result, err := decodeNativeResult(input)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := result.Fields["ecc_uncorrected_volatile"].Value.(json.Number)
	if !ok || string(value) != "9007199254740993" {
		t.Fatalf("native counter was rounded before journaling: %#v", result.Fields)
	}
	encoded, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(encoded), "9007199254740993") {
		t.Fatal("native round-trip lost exact counter")
	}
	if _, err := decodeNativeResult(append(input, []byte(" {}")...)); err == nil {
		t.Fatal("trailing helper JSON accepted")
	}
}
func TestSMIExactUnsignedCountersAndMemoryConversion(t *testing.T) {
	for _, unit := range []string{"errors", "events", "rows", "pages", "processes"} {
		f := parseSMIField("9007199254740993", fieldSpec{Unit: unit})
		if f.Status != model.Pass || f.Value != uint64(9007199254740993) {
			t.Fatalf("%s counter rounded: %#v", unit, f)
		}
	}
	f := parseSMIField("18446744073709551615", fieldSpec{Unit: "errors"})
	if f.Value != ^uint64(0) {
		t.Fatalf("uint64 maximum not preserved: %#v", f)
	}
	f = parseSMIField("1.5", fieldSpec{Unit: "bytes"})
	if f.Status != model.Pass || f.Value != uint64(1572864) {
		t.Fatalf("exact decimal MiB conversion failed: %#v", f)
	}
	for _, raw := range []string{"18446744073709551616", "1.1", "-1", "NaN", "1e20"} {
		f := parseSMIField(raw, fieldSpec{Unit: "errors"})
		if f.Status == model.Pass {
			t.Fatalf("invalid exact counter accepted: %s", raw)
		}
	}
	for _, raw := range []string{"18446744073709551615", "0.1", "1e9999999999999999"} {
		f := parseSMIField(raw, fieldSpec{Unit: "bytes"})
		if f.Status == model.Pass {
			t.Fatalf("overflow/fractional-byte/unbounded-exponent memory accepted: %s", raw)
		}
	}
}
