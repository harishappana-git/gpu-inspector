package scan

import (
	"testing"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestRTX5080IdentityAndModeAreSpecific(t *testing.T) {
	d := guardDevice()
	d.Name, d.MemoryBytes, d.MIGMode = "NVIDIA GeForce RTX 5080", 16303<<20, "unsupported"
	d = NormalizeDevice(d, nil)
	if d.SKU != "rtx-5080-16gb" || !fullDeviceMode(d) {
		t.Fatalf("RTX5080 not admitted: %+v", d)
	}
	for _, mutate := range []func(*model.Device){
		func(d *model.Device) { d.Name = "NVIDIA GeForce RTX 5080 Laptop GPU" },
		func(d *model.Device) { d.MemoryBytes = 8 << 30 },
		func(d *model.Device) { d.MIGMode = "unknown" },
		func(d *model.Device) { d.MIGMode = "enabled" },
		func(d *model.Device) { d.VirtualizationMode = "vgpu" },
	} {
		candidate := d
		mutate(&candidate)
		if fullDeviceMode(candidate) {
			t.Fatalf("ambiguous/partitioned mode admitted: %+v", candidate)
		}
	}
	h100 := guardDevice()
	h100.MIGMode = "unsupported"
	if fullDeviceMode(h100) {
		t.Fatal("RTX exception leaked to H100")
	}
}

func TestBusyOptInDoesNotRelaxIdentityOrMissingActivity(t *testing.T) {
	pre := append(guardSnapshot(guardTime), guardRaw("compute_process_count", guardGPU, uint64(3), guardTime))
	if idle, _ := Idle(pre); idle {
		t.Fatal("busy device reported idle")
	}
	if !busyOverrideEligible(pre) {
		t.Fatal("visible busy device cannot be explicitly tested")
	}
	if busyOverrideEligible(pre[1:]) {
		t.Fatal("consent bypassed absent UUID")
	}
	if busyOverrideEligible(guardSnapshot(guardTime)) {
		t.Fatal("consent bypassed absent activity evidence")
	}
	pre[0].Status = model.Contaminated
	if busyOverrideEligible(pre) {
		t.Fatal("consent bypassed contaminated identity")
	}
}

func TestBusyResultsRetainCorrectnessAndRejectPerformance(t *testing.T) {
	obs := []model.Observation{
		{MethodID: "fp32_gemm", Status: model.Pass, Value: 1.5},
		{MethodID: "fp32_gemm.validation", Status: model.Pass},
		{MethodID: "fp32_gemm", Status: model.Fail},
	}
	markBusyResults(obs, "fp32_gemm")
	if obs[0].Status != model.Contaminated || obs[0].Value != 1.5 {
		t.Fatal("busy performance not retained as contaminated")
	}
	if obs[1].Status != model.Pass || obs[2].Status != model.Fail {
		t.Fatal("busy consent changed correctness/failure")
	}
	for _, o := range obs {
		if o.Conditions["busy_gpu_opt_in"] != true {
			t.Fatal("busy consent missing from method conditions")
		}
	}
}
