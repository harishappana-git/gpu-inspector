//go:build windows

package collect

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/harishappana/gpu-inspector/internal/model"
	"golang.org/x/sys/windows"
)

// The stable public ABI is the same as the Linux adapter. No CUDA toolkit or
// compiler is needed: all DLL exports are discovered at runtime in the isolated
// helper. Unsupported APIs retain their actual error status.
type winNVML struct {
	dll    *windows.DLL
	device uintptr
}
type winNVMemory struct{ Total, Free, Used uint64 }
type winNVPCI struct {
	Legacy                                     [16]byte
	Domain, Bus, Device, DeviceID, SubsystemID uint32
	BusID                                      [32]byte
}
type winNVUtilization struct{ GPU, Memory uint32 }

// Mark pointer-bearing uintptr arguments as escaping, just like Proc.Call.
// Export lookup can grow the Go stack before the native call takes place.
//
//go:uintptrescapes
func (n *winNVML) call(symbol string, args ...uintptr) uintptr {
	p, err := n.dll.FindProc(symbol)
	if err != nil {
		return 13
	}
	rc, _, _ := p.Call(args...)
	return rc
}

func winNVStatus(rc uintptr) model.Status {
	switch rc {
	case 0:
		return model.Pass
	case 3, 13:
		return model.Unsupported
	case 4:
		return model.PermissionDenied
	case 9, 12:
		return model.DependencyMissing
	case 10:
		return model.TimeBudgetExhausted
	default:
		return model.ToolError
	}
}
func winNVField(rc uintptr, value any, unit string) field {
	if rc != 0 {
		return absent(winNVStatus(rc), fmt.Sprintf("NVML returned code %d; unavailable fields are not numeric zeros.", rc))
	}
	return present(value, unit)
}
func winString(buf []byte) string {
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
func winFieldString(f field) string {
	if f.Status == model.Unsupported {
		return "unsupported"
	}
	if f.Status != model.Pass {
		return "unknown"
	}
	return fmt.Sprint(f.Value)
}
func (n *winNVML) text(symbol string, system bool) field {
	var buf [128]byte
	var rc uintptr
	if system {
		rc = n.call(symbol, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	} else {
		rc = n.call(symbol, n.device, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	}
	buf[len(buf)-1] = 0
	value := winString(buf[:])
	if rc == 0 && value == "" {
		return absent(model.ToolError, "NVML returned an empty string.")
	}
	return winNVField(rc, value, "")
}
func (n *winNVML) uint(symbol, unit string, scale float64) field {
	var value uint32
	rc := n.call(symbol, n.device, uintptr(unsafe.Pointer(&value)))
	if scale == 1 {
		return winNVField(rc, uint64(value), unit)
	}
	return winNVField(rc, float64(value)*scale, unit)
}
func (n *winNVML) pair(symbol, unit string) (field, field) {
	var a, b uint32
	rc := n.call(symbol, n.device, uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&b)))
	return winNVField(rc, uint64(a), unit), winNVField(rc, uint64(b), unit)
}
func (n *winNVML) enum(symbol string, kind uintptr, unit string) field {
	var value uint32
	rc := n.call(symbol, n.device, kind, uintptr(unsafe.Pointer(&value)))
	return winNVField(rc, uint64(value), unit)
}
func (n *winNVML) pci() field {
	var value winNVPCI
	rc := n.call("nvmlDeviceGetPciInfo_v3", n.device, uintptr(unsafe.Pointer(&value)))
	return winNVField(rc, winString(value.BusID[:]), "")
}
func (n *winNVML) memory() (winNVMemory, uintptr) {
	var value winNVMemory
	rc := n.call("nvmlDeviceGetMemoryInfo", n.device, uintptr(unsafe.Pointer(&value)))
	return value, rc
}
func (n *winNVML) reasons() field {
	var value uint64
	rc := n.call("nvmlDeviceGetCurrentClocksEventReasons", n.device, uintptr(unsafe.Pointer(&value)))
	if rc == 13 {
		rc = n.call("nvmlDeviceGetCurrentClocksThrottleReasons", n.device, uintptr(unsafe.Pointer(&value)))
	}
	return winNVField(rc, value, "bitmask")
}
func (n *winNVML) processes() field {
	var count uint32
	rc := n.call("nvmlDeviceGetComputeRunningProcesses_v3", n.device, uintptr(unsafe.Pointer(&count)), 0)
	if rc == 7 {
		rc = 0
	} // The NULL-buffer sizing query returns insufficient size when nonempty.
	return winNVField(rc, uint64(count), "processes")
}
func (n *winNVML) utilization() (field, field) {
	var value winNVUtilization
	rc := n.call("nvmlDeviceGetUtilizationRates", n.device, uintptr(unsafe.Pointer(&value)))
	return winNVField(rc, uint64(value.GPU), "percent"), winNVField(rc, uint64(value.Memory), "percent")
}
func (n *winNVML) ecc(kind, counter uintptr) field {
	var value uint64
	rc := n.call("nvmlDeviceGetTotalEccErrors", n.device, kind, counter, uintptr(unsafe.Pointer(&value)))
	return winNVField(rc, value, "errors")
}
func (n *winNVML) remap(f map[string]field) {
	var a, b, p, failed uint32
	rc := n.call("nvmlDeviceGetRemappedRows", n.device, uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&failed)))
	f["row_remap_corrected"] = winNVField(rc, uint64(a), "rows")
	f["row_remap_uncorrected"] = winNVField(rc, uint64(b), "rows")
	f["row_remap_pending"] = winNVField(rc, uint64(p), "")
	f["row_remap_failure"] = winNVField(rc, uint64(failed), "")
}

func nativeCollect(target string) nativeResult   { return winNativeCollect(target, false) }
func nativeTelemetry(target string) nativeResult { return winNativeCollect(target, true) }

func winNativeCollect(target string, minimal bool) nativeResult {
	filename := nvidiaInstalledFile("nvml.dll")
	if filename == "" {
		return nativeResult{Status: model.DependencyMissing, Message: "NVML DLL absent from trusted NVIDIA installation directories; attempting CLI fallback."}
	}
	// Absolute path plus restricted dependency search avoids CWD/PATH DLL loading.
	handle, err := windows.LoadLibraryEx(filename, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nativeResult{Status: model.DependencyMissing, Message: "Windows NVIDIA management library could not be loaded."}
	}
	n := &winNVML{dll: &windows.DLL{Name: filename, Handle: handle}}
	defer n.dll.Release()
	rc := n.call("nvmlInit_v2")
	if rc != 0 {
		return nativeResult{Status: winNVStatus(rc), Message: fmt.Sprintf("Windows NVML initialization returned code %d.", rc)}
	}
	defer n.call("nvmlShutdown")
	if target != "" {
		id, err := windows.BytePtrFromString(target)
		if err != nil {
			return nativeResult{Status: model.ToolError, Message: "Invalid selected UUID."}
		}
		rc = n.call("nvmlDeviceGetHandleByUUID", uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(&n.device)))
		if rc != 0 {
			return nativeResult{Status: winNVStatus(rc), Message: "Selected Windows NVML UUID could not be reopened."}
		}
		return nativeResult{Status: model.Pass, Message: "Read-only Windows NVML snapshot.", Fields: n.snapshot(minimal)}
	}
	var count uint32
	rc = n.call("nvmlDeviceGetCount_v2", uintptr(unsafe.Pointer(&count)))
	if rc != 0 || count > 1024 {
		return nativeResult{Status: model.ToolError, Message: "Windows NVML enumeration failed or exceeded device bound."}
	}
	out := nativeResult{Status: model.Pass, Message: "Read-only Windows NVML enumeration; host/driver reported, not attested."}
	for i := uint32(0); i < count; i++ {
		rc = n.call("nvmlDeviceGetHandleByIndex_v2", uintptr(i), uintptr(unsafe.Pointer(&n.device)))
		if rc != 0 {
			return nativeResult{Status: winNVStatus(rc), Message: "Management device handle unavailable."}
		}
		uuid, name, driver := n.text("nvmlDeviceGetUUID", false), n.text("nvmlDeviceGetName", false), n.text("nvmlSystemGetDriverVersion", true)
		if uuid.Status != model.Pass || !validUUID(winFieldString(uuid)) {
			return nativeResult{Status: model.ToolError, Message: "NVML returned unavailable or invalid stable identity."}
		}
		memory, mrc := n.memory()
		if mrc != 0 {
			memory.Total = 0
		}
		mig, _ := n.pair("nvmlDeviceGetMigMode", "")
		virt := n.uint("nvmlDeviceGetVirtualizationMode", "", 1)
		pci := n.pci()
		out.Devices = append(out.Devices, model.Device{Index: int(i), UUID: winFieldString(uuid), Name: winFieldString(name), SKU: winFieldString(name), PCIAddress: winFieldString(pci), MemoryBytes: memory.Total, MIGMode: winFieldString(mig), VirtualizationMode: winFieldString(virt), DriverVersion: winFieldString(driver), Source: "NVML (Windows)", IdentityAssurance: "host/driver-reported; not attested"})
	}
	out.CUDAUUIDs, out.CUDAStatus = winCUDAUUIDs()
	return out
}

func (n *winNVML) snapshot(minimal bool) map[string]field {
	f := map[string]field{}
	f["uuid"] = n.text("nvmlDeviceGetUUID", false)
	f["temperature_gpu_c"] = n.enum("nvmlDeviceGetTemperature", 0, "C")
	f["power_draw_w"] = n.uint("nvmlDeviceGetPowerUsage", "W", 0.001)
	f["clock_event_reasons"] = n.reasons()
	f["utilization_gpu_percent"], f["utilization_memory_percent"] = n.utilization()
	f["compute_process_count"] = n.processes()
	f["ecc_corrected_volatile"], f["ecc_uncorrected_volatile"] = n.ecc(0, 0), n.ecc(1, 0)
	n.remap(f)
	if minimal {
		return f
	}
	for key, symbol := range map[string]string{"name": "nvmlDeviceGetName", "vbios": "nvmlDeviceGetVbiosVersion", "part_number": "nvmlDeviceGetBoardPartNumber"} {
		f[key] = n.text(symbol, false)
	}
	f["driver_version"], f["nvml_version"] = n.text("nvmlSystemGetDriverVersion", true), n.text("nvmlSystemGetNVMLVersion", true)
	var version int32
	rc := n.call("nvmlSystemGetCudaDriverVersion_v2", uintptr(unsafe.Pointer(&version)))
	f["cuda_driver_api_version"] = winNVField(rc, int(version), "")
	f["pci_address"] = n.pci()
	var major, minor int32
	rc = n.call("nvmlDeviceGetCudaComputeCapability", n.device, uintptr(unsafe.Pointer(&major)), uintptr(unsafe.Pointer(&minor)))
	f["compute_capability"] = winNVField(rc, fmt.Sprintf("%d.%d", major, minor), "")
	memory, mrc := n.memory()
	f["memory_total_bytes"], f["memory_free_bytes"], f["memory_used_bytes"] = winNVField(mrc, memory.Total, "bytes"), winNVField(mrc, memory.Free, "bytes"), winNVField(mrc, memory.Used, "bytes")
	f["mig_current"], f["mig_pending"] = n.pair("nvmlDeviceGetMigMode", "")
	f["virtualization_mode"] = n.uint("nvmlDeviceGetVirtualizationMode", "", 1)
	f["driver_model_current"], f["driver_model_pending"] = n.pair("nvmlDeviceGetDriverModel", "")
	f["ecc_current"], f["ecc_pending"] = n.pair("nvmlDeviceGetEccMode", "")
	f["ecc_corrected_aggregate"], f["ecc_uncorrected_aggregate"] = n.ecc(0, 1), n.ecc(1, 1)
	f["retirement_pending"] = n.uint("nvmlDeviceGetRetiredPagesPendingStatus", "", 1)
	for _, q := range []struct {
		key  string
		kind uintptr
	}{{"retired_pages_corrected", 0}, {"retired_pages_uncorrected", 1}} {
		var count uint32
		rc = n.call("nvmlDeviceGetRetiredPages", n.device, q.kind, uintptr(unsafe.Pointer(&count)), 0)
		if rc == 7 {
			rc = 0
		}
		f[q.key] = winNVField(rc, uint64(count), "pages")
	}
	f["temperature_shutdown_c"], f["temperature_slowdown_c"] = n.enum("nvmlDeviceGetTemperatureThreshold", 0, "C"), n.enum("nvmlDeviceGetTemperatureThreshold", 1, "C")
	f["fan_percent"] = n.uint("nvmlDeviceGetFanSpeed", "percent", 1)
	for key, symbol := range map[string]string{"power_limit_w": "nvmlDeviceGetPowerManagementLimit", "power_default_w": "nvmlDeviceGetPowerManagementDefaultLimit"} {
		f[key] = n.uint(symbol, "W", 0.001)
	}
	f["power_min_w"], f["power_max_w"] = n.pair("nvmlDeviceGetPowerManagementLimitConstraints", "W")
	for _, key := range []string{"power_min_w", "power_max_w"} {
		x := f[key]
		if x.Status == model.Pass {
			x.Value = float64(x.Value.(uint64)) / 1000
			f[key] = x
		}
	}
	f["clock_sm_mhz"], f["clock_memory_mhz"] = n.enum("nvmlDeviceGetClockInfo", 1, "MHz"), n.enum("nvmlDeviceGetClockInfo", 2, "MHz")
	for _, q := range []struct{ key, symbol, unit string }{{"pcie_gen", "nvmlDeviceGetCurrPcieLinkGeneration", "generation"}, {"pcie_max_gen", "nvmlDeviceGetMaxPcieLinkGeneration", "generation"}, {"pcie_width", "nvmlDeviceGetCurrPcieLinkWidth", "lanes"}, {"pcie_max_width", "nvmlDeviceGetMaxPcieLinkWidth", "lanes"}, {"pcie_replay_count", "nvmlDeviceGetPcieReplayCounter", "events"}} {
		f[q.key] = n.uint(q.symbol, q.unit, 1)
	}
	// Memory temperature is queried through the feature-discovered SMI fallback.
	f["temperature_memory_c"] = absent(model.Unsupported, "Memory temperature is not exposed by this NVML adapter; use advertised SMI field if available.")
	return f
}

func winCUDAUUIDs() ([]string, model.Status) {
	dll := windows.NewLazySystemDLL("nvcuda.dll")
	if dll.Load() != nil {
		return nil, model.DependencyMissing
	}
	init, getCount, get, getUUID := dll.NewProc("cuInit"), dll.NewProc("cuDeviceGetCount"), dll.NewProc("cuDeviceGet"), dll.NewProc("cuDeviceGetUuid_v2")
	if getUUID.Find() != nil {
		getUUID = dll.NewProc("cuDeviceGetUuid")
	}
	if init.Find() != nil || getCount.Find() != nil || get.Find() != nil || getUUID.Find() != nil {
		return nil, model.Unsupported
	}
	if rc, _, _ := init.Call(0); rc != 0 {
		return nil, model.ToolError
	}
	var count int32
	if rc, _, _ := getCount.Call(uintptr(unsafe.Pointer(&count))); rc != 0 || count < 0 || count > 1024 {
		return nil, model.ToolError
	}
	uuids := make([]string, 0, count)
	for i := int32(0); i < count; i++ {
		var device int32
		if rc, _, _ := get.Call(uintptr(unsafe.Pointer(&device)), uintptr(i)); rc != 0 {
			return nil, model.ToolError
		}
		var id [16]byte
		if rc, _, _ := getUUID.Call(uintptr(unsafe.Pointer(&id[0])), uintptr(device)); rc != 0 {
			return nil, model.ToolError
		}
		uuids = append(uuids, fmt.Sprintf("GPU-%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]))
	}
	runtime.KeepAlive(dll)
	return uuids, model.Pass
}
