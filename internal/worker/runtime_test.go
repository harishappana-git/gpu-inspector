package worker

import (
	"encoding/json"
	"github.com/harishappana/gpu-inspector/internal/model"
	"testing"
)

func TestRuntimeContextRequiresActualAttributesAndLoadedVersions(t *testing.T) {
	base := model.Observation{Status: model.Pass, Conditions: map[string]any{"compute_capability": "9.0", "device_sm_count": json.Number("114"), "device_l2_bytes": json.Number("52428800"), "device_warp_size": 32, "device_max_threads_per_block": 1024, "runtime_version": 12080, "cuda_driver_api_version": 13000, "driver_version": "synthetic-NVML-version"}}
	observations := runtimeObservations(base)
	if observations[0].Status != model.Pass || observations[1].Status != model.Pass {
		t.Fatal("complete synthetic metadata was not retained")
	}
	versions := observations[1].Value.(map[string]any)
	if versions["cuda_driver_api_version"] != 13000 || versions["driver_version"] != "synthetic-NVML-version" {
		t.Fatal("driver API and management versions were conflated")
	}
	delete(base.Conditions, "device_sm_count")
	delete(base.Conditions, "runtime_version")
	observations = runtimeObservations(base)
	if observations[0].Status != model.NotTested || observations[1].Status != model.NotTested {
		t.Fatal("missing metadata became complete capability evidence")
	}
}
