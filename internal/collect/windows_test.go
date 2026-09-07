//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/harishappana/gpu-inspector/internal/model"
	"golang.org/x/sys/windows"
)

func TestWindowsCollectorUsesTrustedSystemPaths(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "nvidia-smi.exe"), "untrusted fixture")
	t.Setenv("PATH", dir)
	t.Setenv("SystemRoot", dir)
	t.Setenv("ProgramFiles", dir)
	found := trustedCollectorBinary("nvidia-smi")
	if found != "" && (strings.HasPrefix(found, dir) || !filepath.IsAbs(found)) {
		t.Fatalf("untrusted executable chosen: %s", found)
	}
	for _, name := range []string{"../nvidia-smi", ".\\nvidia-smi.exe", "powershell", "cmd.exe"} {
		if trustedCollectorBinary(name) != "" {
			t.Fatalf("nonallowlisted tool accepted: %s", name)
		}
	}
	env := strings.Join(collectorEnvironment(), "\n")
	if strings.Contains(env, dir) {
		t.Fatalf("untrusted system environment forwarded: %s", env)
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil || !strings.Contains(env, "SystemRoot="+root) {
		t.Fatal("required actual Windows root missing")
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || !strings.Contains(env, "ProgramFiles="+programFiles) {
		t.Fatal("required OS-resolved NVIDIA ProgramFiles context missing")
	}
}

func TestWindowsHostCollectorReturnsNativeContext(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "PRIVATE-WORKSPACE-FIXTURE")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	obs := Host(context.Background(), Options{Workspace: workspace, Timeout: 5 * time.Second})
	for _, name := range []string{"os_context", "logical_cpu_context", "host_memory_context", "cpu_time_counters", "workspace_capacity", "workspace_mount_context", "network_interface_context"} {
		o := findField(t, obs, name)
		if o.Status != model.Pass || o.Value == nil || !strings.HasPrefix(o.MethodID, "windows.") {
			t.Fatalf("native context missing: %+v", o)
		}
	}
	for _, name := range []string{"cgroup_hierarchy", "cgroup_cpu_stat", "cgroup_memory_events", "pressure_cpu", "pressure_memory", "pressure_io", "shared_memory_capacity"} {
		o := findField(t, obs, name)
		if o.Status != model.Unsupported || o.Value != nil {
			t.Fatalf("Linux-only field falsely measured: %+v", o)
		}
	}
	mem := findField(t, obs, "host_memory_context").Value.(map[string]any)
	if total, ok := mem["MemTotal"].(json.Number); !ok || total == "0" {
		t.Fatalf("physical memory unavailable: %#v", mem)
	}
	encoded, _ := json.Marshal(obs)
	if strings.Contains(string(encoded), filepath.Base(workspace)) {
		t.Fatal("private workspace path exported")
	}
}

func TestWindowsHostCancellationAndMissingWorkspace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	obs := Host(ctx, Options{})
	if len(obs) != 1 || obs[0].Status != model.TimeBudgetExhausted || obs[0].Value != nil {
		t.Fatalf("cancelled Windows collection falsely passed: %+v", obs)
	}
	obs = capacityObservations(Options{Workspace: filepath.Join(t.TempDir(), "does-not-exist")}, time.Now())
	if len(obs) != 1 || obs[0].Status == model.Pass || obs[0].Value != nil {
		t.Fatalf("missing workspace capacity measured: %+v", obs)
	}
}

func TestWindowsPublicABIStructSizes(t *testing.T) {
	if unsafe.Sizeof(winNVMemory{}) != 24 || unsafe.Sizeof(winNVPCI{}) != 68 || unsafe.Sizeof(winNVUtilization{}) != 8 || unsafe.Sizeof(winMemoryStatus{}) != 64 {
		t.Fatal("Windows NVML/OS struct layout does not match the documented public ABI")
	}
}

func TestWindowsNVIDIAReadOnlyIntegration(t *testing.T) {
	if os.Getenv("GRI_WINDOWS_GPU_TEST") != "1" {
		t.Skip("set GRI_WINDOWS_GPU_TEST=1 for installed-driver read-only integration")
	}
	opts := Options{Timeout: 5 * time.Second}
	devices, obs := Discover(context.Background(), opts)
	if len(devices) == 0 {
		t.Fatalf("installed Windows GPU could not be discovered: %+v", obs)
	}
	n := native(context.Background(), "", opts)
	if n.Status != model.Pass || n.CUDAStatus != model.Pass || len(n.CUDAUUIDs) == 0 {
		t.Fatalf("NVML/CUDA UUID enumeration unavailable: %+v", n)
	}
	fallbackDevices, fallbackStatus := smiDiscover(context.Background(), opts)
	if fallbackStatus != model.Pass || len(fallbackDevices) == 0 {
		t.Fatalf("Windows nvidia-smi fallback failed under the restricted collector environment: %s", fallbackStatus)
	}
	for _, device := range devices {
		fallbackSpecs := []fieldSpec{{Name: "uuid", Query: "uuid"}, {Name: "name", Query: "name"}, {Name: "memory_total_bytes", Query: "memory.total", Unit: "bytes"}, {Name: "temperature_gpu_c", Query: "temperature.gpu", Unit: "C"}}
		fallback := smiSnapshotSpecs(context.Background(), device.UUID, opts, fallbackSpecs)
		for _, spec := range fallbackSpecs {
			if value := fallback[spec.Name]; value.Status != model.Pass || value.Value == nil {
				t.Fatalf("Windows selected-target SMI fallback field %s unavailable: %+v", spec.Name, value)
			}
		}
		if fallback["uuid"].Value != device.UUID {
			t.Fatal("Windows SMI fallback selected a different device")
		}
		gpu := GPU(context.Background(), device, opts)
		for _, name := range []string{"uuid", "name", "pci_address", "memory_total_bytes", "compute_capability", "driver_version", "temperature_gpu_c", "virtualization_mode", "driver_model_current"} {
			if o := findField(t, gpu, name); o.Status != model.Pass {
				t.Fatalf("installed GPU field %s unavailable: %+v", name, o)
			}
		}
		if findField(t, gpu, "uuid").Value != device.UUID {
			t.Fatal("selected GPU identity changed")
		}
		for _, o := range gpu {
			if o.Status == model.Unsupported && o.Value != nil {
				t.Fatalf("unsupported native field retained a value: %+v", o)
			}
		}
		telemetry := Telemetry(context.Background(), device, opts)
		for _, name := range []string{"uuid", "temperature_gpu_c", "power_draw_w", "clock_event_reasons", "utilization_gpu_percent", "compute_process_count"} {
			if o := findField(t, telemetry, name); o.Status != model.Pass {
				t.Fatalf("installed GPU telemetry %s unavailable: %+v", name, o)
			}
		}
		t.Logf("Read-only Windows native/SMI discovery, UUID mapping, snapshot, fallback and telemetry passed on %s (driver %s)", device.Name, device.DriverVersion)
	}
}
