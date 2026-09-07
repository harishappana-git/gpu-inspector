package scan

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

const guardGPU = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const guardPeer = "GPU-11111111-2222-3333-4444-555555555555"

var guardTime = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func guardDevice() model.Device {
	return model.Device{UUID: guardGPU, PCIAddress: "00000000:01:00.0", Index: 0, Name: "NVIDIA H100 PCIe", SKU: "h100-pcie-80gb", MemoryBytes: 80 << 30, MIGMode: "disabled", VirtualizationMode: "none", DriverVersion: "fixture-driver"}
}
func guardRaw(field, resource string, value any, at time.Time) model.Observation {
	return model.Observation{ID: resource + "-" + field + "-" + at.Format(time.RFC3339Nano), ResourceID: resource, Status: model.Pass, Value: value, StartUTC: at, SourceKind: "reported", Scope: resource, Conditions: map[string]any{"field": field}}
}
func guardSnapshot(at time.Time) []model.Observation {
	return []model.Observation{guardRaw("uuid", guardGPU, guardGPU, at), guardRaw("ecc_corrected_volatile", guardGPU, uint64(0), at), guardRaw("ecc_uncorrected_volatile", guardGPU, uint64(0), at), guardRaw("pcie_replay_count", guardGPU, uint64(0), at)}
}
func guardFind(t *testing.T, obs []model.Observation, id string) model.Observation {
	t.Helper()
	for _, o := range obs {
		if o.CheckID == id {
			return o
		}
	}
	t.Fatalf("check %s missing", id)
	return model.Observation{}
}
func setGuardField(obs []model.Observation, name string, v any) {
	for i := range obs {
		if scalarField(obs[i]) == name {
			obs[i].Value = v
		}
	}
}

func TestSelectRequiresUniqueFullUUIDAndPCI(t *testing.T) {
	d := guardDevice()
	peer := d
	peer.UUID = guardPeer
	peer.Index = 1
	peer.PCIAddress = "0000:02:00.0"
	if got, e := Select([]model.Device{d}, ""); e != nil || got.UUID != guardGPU {
		t.Fatal("single permitted target not selected")
	}
	if got, e := Select([]model.Device{d, peer}, guardPeer); e != nil || got.UUID != guardPeer {
		t.Fatal("explicit full UUID not selected")
	}
	for _, target := range []string{"", "0", "GPU-aaaa", "MIG-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"} {
		if _, e := Select([]model.Device{d, peer}, target); e == nil {
			t.Fatalf("ambiguous/numeric/partition selection accepted: %q", target)
		}
	}
	duplicate := peer
	duplicate.PCIAddress = "0000:01:00.0"
	if _, e := Select([]model.Device{d, duplicate}, guardGPU); e == nil {
		t.Fatal("same PCI under alternate formatting accepted")
	}
	duplicate = peer
	duplicate.UUID = strings.ToUpper(strings.TrimPrefix(guardGPU, "GPU-"))
	duplicate.UUID = "GPU-" + duplicate.UUID
	if _, e := Select([]model.Device{d, duplicate}, guardGPU); e == nil {
		t.Fatal("case-insensitive duplicate UUID accepted")
	}
	d.PCIAddress = ""
	if _, e := Select([]model.Device{d}, ""); e == nil {
		t.Fatal("missing PCI identity accepted")
	}
}
func TestNormalizeDoesNotApplyPCIePackToOtherVariants(t *testing.T) {
	for _, test := range []struct {
		name   string
		memory uint64
		want   string
	}{{"NVIDIA H100 PCIe", 80 << 30, "h100-pcie-80gb"}, {"NVIDIA H100-SXM5-80GB", 80 << 30, "h100-sxm-80gb"}, {"NVIDIA H100 NVL", 94 << 30, "h100-nvl-94gb"}, {"NVIDIA H100 80GB HBM3", 80 << 30, "unknown"}, {"NVIDIA H100 PCIe", 10 << 30, "unknown"}, {"NVIDIA A100 PCIe", 80 << 30, "unknown"}, {"H100 PCIe SXM", 80 << 30, "unknown"}} {
		d := guardDevice()
		pre := []model.Observation{guardRaw("name", guardGPU, test.name, guardTime), guardRaw("memory_total_bytes", guardGPU, test.memory, guardTime), guardRaw("mig_current", guardGPU, float64(0), guardTime), guardRaw("virtualization_mode", guardGPU, json.Number("1"), guardTime)}
		got := NormalizeDevice(d, pre)
		if got.SKU != test.want || got.MIGMode != "disabled" || got.VirtualizationMode != "passthrough" {
			t.Fatalf("wrong normalization for %q: %+v", test.name, got)
		}
	}
	d := NormalizeDevice(guardDevice(), []model.Observation{guardRaw("name", guardPeer, "H100 NVL", guardTime)})
	if d.Name != "NVIDIA H100 PCIe" {
		t.Fatal("peer observation changed selected identity")
	}
}
func TestGuardExpectationsAndChangedPCI(t *testing.T) {
	d := guardDevice()
	obs := GuardObservations(&d, "", []model.Device{d}, nil)
	if o := guardFind(t, obs, "A01"); o.Status != model.NotApplicable || o.MethodID != "guard.expectation" {
		t.Fatal("missing declaration not explicitly inapplicable")
	}
	if o := guardFind(t, GuardObservations(&d, "H100", []model.Device{d}, nil), "A01"); o.Status != model.Pass {
		t.Fatal("family expectation did not match")
	}
	if o := guardFind(t, GuardObservations(&d, "H100 80GB", []model.Device{d}, nil), "A01"); o.Status != model.Pass {
		t.Fatal("family and memory expectation incorrectly required a form-factor declaration")
	}
	if o := guardFind(t, GuardObservations(&d, "H100 SXM 80GB", []model.Device{d}, nil), "A01"); o.Status != model.Fail {
		t.Fatal("exact variant mismatch not caught")
	}
	inventory := d
	d.PCIAddress = "0000:03:00.0"
	if o := guardFind(t, GuardObservations(&d, "", []model.Device{inventory}, nil), "A07"); o.Status != model.Contaminated {
		t.Fatal("UUID-matching changed PCI remained trusted")
	}
	d = guardDevice()
	d.Name = "H100 SXM"
	if o := guardFind(t, GuardObservations(&d, "", []model.Device{d}, nil), "A02"); o.Status == model.Pass {
		t.Fatal("stale PCIe SKU survived SXM name")
	}
	if o := guardFind(t, GuardObservations(nil, "H100", nil, errors.New("no selection")), "A07"); o.Status == model.Pass {
		t.Fatal("nil selected device passed")
	}
}
func TestGuardAllocationModeRemainsConservative(t *testing.T) {
	d := guardDevice()
	for _, mode := range []string{"enabled", "unknown", "unsupported"} {
		d.MIGMode = mode
		if guardFind(t, GuardObservations(&d, "", []model.Device{d}, nil), "A06").Status != model.Unsupported {
			t.Fatalf("MIG mode accepted: %s", mode)
		}
	}
	d.MIGMode = "disabled"
	for _, mode := range []string{"vgpu", "host-vgpu", "unknown"} {
		d.VirtualizationMode = mode
		if guardFind(t, GuardObservations(&d, "", []model.Device{d}, nil), "A06").Status != model.Unsupported {
			t.Fatalf("unqualified virtualization accepted: %s", mode)
		}
	}
}

func TestIdleUsesSupportedSelectedSignals(t *testing.T) {
	pre := guardSnapshot(guardTime)
	if ok, _ := Idle(pre); ok {
		t.Fatal("missing idle signals passed")
	}
	pre = append(pre, guardRaw("utilization_gpu_percent", guardGPU, 0.0, guardTime))
	if ok, _ := Idle(pre); !ok {
		t.Fatal("reported quiet supported utilization did not pass policy")
	}
	pre = append(pre, guardRaw("compute_process_count", guardGPU, uint64(1), guardTime))
	if ok, _ := Idle(pre); ok {
		t.Fatal("visible compute process ignored")
	}
	pre[len(pre)-1].ResourceID = guardPeer
	if ok, _ := Idle(pre); !ok {
		t.Fatal("peer process incorrectly blocked selected device")
	}
	setGuardField(pre, "utilization_gpu_percent", 11.0)
	if ok, _ := Idle(pre); ok {
		t.Fatal("busy utilization accepted")
	}
}
func TestSafetyScopesHistoricalErrorsAndThermalThresholds(t *testing.T) {
	pre := guardSnapshot(guardTime)
	sample := guardSnapshot(guardTime.Add(time.Second))
	setGuardField(pre, "ecc_uncorrected_volatile", uint64(100))
	setGuardField(sample, "ecc_uncorrected_volatile", uint64(100))
	sample = append(sample, guardRaw("temperature_gpu_c", guardGPU, 90.0, guardTime.Add(time.Second)), guardRaw("power_draw_w", guardGPU, 1.0, guardTime.Add(time.Second)))
	if stop, _ := Safety(pre, sample, 0); stop {
		t.Fatal("historical error total or generic hot/low power became a defect")
	}
	pre = append(pre, guardRaw("temperature_slowdown_c", guardGPU, 95.0, guardTime))
	if stop, _ := Safety(pre, sample, 80); !stop {
		t.Fatal("configured ceiling ignored")
	}
	if stop, _ := Safety(pre, sample, 100); stop {
		t.Fatal("below device threshold stopped")
	}
	setGuardField(sample, "temperature_gpu_c", 96.0)
	if stop, _ := Safety(pre, sample, 100); !stop {
		t.Fatal("device slowdown threshold ignored")
	}
	setGuardField(sample, "temperature_gpu_c", 40.0)
	setGuardField(sample, "ecc_uncorrected_volatile", uint64(101))
	if stop, reason := Safety(pre, sample, 0); !stop || !strings.Contains(reason, "conditional") {
		t.Fatal("new uncorrected count did not stop with epoch caveat")
	}
	setGuardField(sample, "ecc_uncorrected_volatile", uint64(100))
	sample = append(sample, guardRaw("row_remap_failure", guardPeer, true, guardTime.Add(time.Second)))
	if stop, _ := Safety(pre, sample, 0); stop {
		t.Fatal("peer maintenance event contaminated target")
	}
	sample[len(sample)-1].ResourceID = guardGPU
	if stop, _ := Safety(pre, sample, 0); !stop {
		t.Fatal("target maintenance state ignored")
	}
}
func TestSafetyRejectsIdentityAndInvalidTemperaturePolicy(t *testing.T) {
	pre := guardSnapshot(guardTime)
	sample := guardSnapshot(guardTime.Add(time.Second))
	sample[0].Status = model.Contaminated
	if stop, _ := Safety(pre, sample, 0); !stop {
		t.Fatal("contaminated identity accepted")
	}
	sample = guardSnapshot(guardTime.Add(time.Second))
	if stop, _ := Safety(pre, sample, math.NaN()); !stop {
		t.Fatal("NaN policy accepted")
	}
}

func TestCounterDeltasPreserveUnknownEpochAndReferences(t *testing.T) {
	pre, post := guardSnapshot(guardTime), guardSnapshot(guardTime.Add(time.Second))
	delta := guardFind(t, Deltas(pre, post), "B03")
	if delta.Status != model.NotTested || delta.Value.(map[string]any)["conditional_delta"] != uint64(0) || len(delta.EvidenceRefs) != 2 {
		t.Fatalf("unknown epoch became zero-error pass or lost evidence: %+v", delta)
	}
	setGuardField(post, "ecc_uncorrected_volatile", uint64(2))
	delta = guardFind(t, Deltas(pre, post), "B03")
	if delta.Status != model.Fail || !strings.Contains(delta.Message, "physical cause is unproven") {
		t.Fatalf("positive uncorrected gate improperly scoped: %+v", delta)
	}
	setGuardField(pre, "ecc_uncorrected_volatile", uint64(10))
	delta = guardFind(t, Deltas(pre, post), "B03")
	if delta.Status != model.Contaminated || delta.Value != nil {
		t.Fatal("counter reset converted to improvement/zero")
	}
}
func TestExposedEpochAndScopeDiscontinuities(t *testing.T) {
	pre, post := guardSnapshot(guardTime), guardSnapshot(guardTime.Add(time.Second))
	for _, obs := range [][]model.Observation{pre, post} {
		for i := range obs {
			obs[i].Conditions["counter_epoch_id"] = "same-fixture-epoch"
		}
	}
	if o := guardFind(t, Deltas(pre, post), "B03"); o.Status != model.Pass {
		t.Fatalf("explicit stable epoch did not permit zero delta: %+v", o)
	}
	post[2].Conditions["counter_epoch_id"] = "new-fixture-epoch"
	if o := guardFind(t, Deltas(pre, post), "B03"); o.Status != model.Contaminated {
		t.Fatal("observed epoch transition ignored")
	}
	post = guardSnapshot(guardTime.Add(time.Second))
	post[0].Value = guardPeer
	if guardFind(t, Deltas(pre, post), "B03").Status != model.Contaminated {
		t.Fatal("changed target applied to earlier counter")
	}
}
func TestCounterPrecisionAndMissingKeysNeverInventZero(t *testing.T) {
	pre, post := guardSnapshot(guardTime), guardSnapshot(guardTime.Add(time.Second))
	setGuardField(post, "ecc_uncorrected_volatile", float64(9007199254740992))
	if guardFind(t, Deltas(pre, post), "B03").Status != model.NotTested {
		t.Fatal("imprecise float accepted as exact counter")
	}
	pre = append(pre, guardRaw("cgroup_memory_events", "process-host", map[string]uint64{"oom": 0, "oom_kill": 0}, guardTime))
	post = append(post, guardRaw("cgroup_memory_events", "process-host", map[string]uint64{"oom": 0}, guardTime.Add(time.Second)))
	if guardFind(t, Deltas(pre, post), "E06").Status != model.Contaminated {
		t.Fatal("missing map key silently became zero")
	}
}
func TestCPUUsageIncreaseIsNotQuotaThrottling(t *testing.T) {
	pre, post := guardSnapshot(guardTime), guardSnapshot(guardTime.Add(time.Second))
	before := guardRaw("cgroup_cpu_stat", "process-host", map[string]uint64{"usage_usec": 100, "nr_periods": 1, "nr_throttled": 0}, guardTime)
	after := guardRaw("cgroup_cpu_stat", "process-host", map[string]uint64{"usage_usec": 200, "nr_periods": 2, "nr_throttled": 0}, guardTime.Add(time.Second))
	before.Conditions["counter_epoch_id"] = "fixture"
	after.Conditions["counter_epoch_id"] = "fixture"
	pre = append(pre, before)
	post = append(post, after)
	if o := guardFind(t, Deltas(pre, post), "E02"); o.Status != model.Pass {
		t.Fatalf("normal usage became throttling warning: %+v", o)
	}
}

func TestSafetyCannotEnforceConfiguredCeilingWithoutTrustedSensor(t *testing.T) {
	pre := guardSnapshot(guardTime)
	for _, status := range []model.Status{model.Unsupported, model.PermissionDenied, model.Contaminated, model.ToolError} {
		sample := guardSnapshot(guardTime.Add(time.Second))
		temp := guardRaw("temperature_gpu_c", guardGPU, 40.0, guardTime.Add(time.Second))
		temp.Status = status
		sample = append(sample, temp)
		if stop, reason := Safety(pre, sample, 80); !stop || !strings.Contains(reason, "cannot be enforced") {
			t.Fatalf("untrusted %s sensor did not stop configured policy: %v %s", status, stop, reason)
		}
	}
	sample := guardSnapshot(guardTime.Add(time.Second))
	if stop, reason := Safety(pre, sample, 80); !stop || !strings.Contains(reason, "cannot be enforced") {
		t.Fatal("absent sensor allowed an unenforceable explicit ceiling")
	}
	sample = append(sample, guardRaw("temperature_gpu_c", guardPeer, 30.0, guardTime.Add(time.Second)))
	if stop, _ := Safety(pre, sample, 80); !stop {
		t.Fatal("peer temperature was used to enforce selected-device policy")
	}
	sample[len(sample)-1].ResourceID = guardGPU
	sample[len(sample)-1].Value = math.NaN()
	if stop, _ := Safety(pre, sample, 80); !stop {
		t.Fatal("invalid sensor allowed configured ceiling")
	}
}

func TestCurrentUnavailableModeDoesNotRetainStaleDiscoveryPass(t *testing.T) {
	d := guardDevice()
	mig := guardRaw("mig_current", guardGPU, nil, guardTime)
	mig.Status = model.Unsupported
	virt := guardRaw("virtualization_mode", guardGPU, nil, guardTime)
	virt.Status = model.PermissionDenied
	normalized := NormalizeDevice(d, []model.Observation{mig, virt})
	if normalized.MIGMode != "unsupported" || normalized.VirtualizationMode != "unknown" {
		t.Fatalf("stale discovery mode stayed qualified after current query gap: %+v", normalized)
	}
}

func TestAbsentGPUIsCoverageGapNotIdentityContamination(t *testing.T) {
	observations := GuardObservations(nil, "", nil, errors.New("no permitted GPU is visible"))
	if o := guardFind(t, observations, "A07"); o.Status != model.NotTested {
		t.Fatalf("absence became identity-change concern: %+v", o)
	}
	pre := []model.Observation{guardRaw("cgroup_cpu_stat", "process-host", map[string]uint64{"nr_throttled": 0}, guardTime)}
	post := []model.Observation{guardRaw("cgroup_cpu_stat", "process-host", map[string]uint64{"nr_throttled": 0}, guardTime.Add(time.Second))}
	for _, o := range Deltas(pre, post) {
		if o.CheckID == "B02" || o.CheckID == "B03" || o.CheckID == "D09" {
			t.Fatalf("host-only scan fabricated GPU identity contamination: %+v", o)
		}
	}
	gpuPre := guardSnapshot(guardTime)
	lost := Deltas(gpuPre, post)
	if o := guardFind(t, lost, "B03"); o.Status != model.Contaminated {
		t.Fatal("actual loss of previously observed GPU identity was suppressed")
	}
}
