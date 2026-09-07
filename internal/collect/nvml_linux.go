//go:build linux && cgo

package collect

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// Only stable public NVML ABI types are declared here. No NVIDIA SDK is
// required at build time; every optional symbol is feature-detected.
typedef void* device_t;
typedef struct { unsigned long long total, free, used; } memory_t;
typedef struct {
 char busIdLegacy[16]; unsigned int domain, bus, device, pciDeviceId, pciSubSystemId;
 char busId[32];
} pci_v3_t;
static void *lib;
static device_t dev;
static int init_nvml(void) {
 lib=dlopen("libnvidia-ml.so.1",RTLD_NOW|RTLD_LOCAL);
 if(!lib) return 12;
 int (*fn)(void)=dlsym(lib,"nvmlInit_v2");
 return fn ? fn() : 13;
}
static void close_nvml(void) { if(lib) { int (*fn)(void)=dlsym(lib,"nvmlShutdown"); if(fn) fn(); dlclose(lib); lib=NULL; } }
static int count_nvml(unsigned int *out) { int (*fn)(unsigned int*)=dlsym(lib,"nvmlDeviceGetCount_v2"); return fn?fn(out):13; }
static int index_nvml(unsigned int index) { int (*fn)(unsigned int,device_t*)=dlsym(lib,"nvmlDeviceGetHandleByIndex_v2"); return fn?fn(index,&dev):13; }
static int uuid_nvml(const char *uuid) { int (*fn)(const char*,device_t*)=dlsym(lib,"nvmlDeviceGetHandleByUUID"); return fn?fn(uuid,&dev):13; }
static int string_nvml(const char *name,char *buf,unsigned int cap) { int (*fn)(device_t,char*,unsigned int)=dlsym(lib,name); return fn?fn(dev,buf,cap):13; }
static int system_nvml(const char *name,char *buf,unsigned int cap) { int (*fn)(char*,unsigned int)=dlsym(lib,name); return fn?fn(buf,cap):13; }
static int cuda_version_nvml(int *out) { int (*fn)(int*)=dlsym(lib,"nvmlSystemGetCudaDriverVersion_v2"); return fn?fn(out):13; }
static int uint_nvml(const char *name,unsigned int *out) { int (*fn)(device_t,unsigned int*)=dlsym(lib,name); return fn?fn(dev,out):13; }
static int pair_nvml(const char *name,unsigned int *a,unsigned int *b) { int (*fn)(device_t,unsigned int*,unsigned int*)=dlsym(lib,name); return fn?fn(dev,a,b):13; }
static int withkind_nvml(const char *name,unsigned int kind,unsigned int *out) { int (*fn)(device_t,unsigned int,unsigned int*)=dlsym(lib,name); return fn?fn(dev,kind,out):13; }
static int memory_nvml(memory_t *m) { int (*fn)(device_t,memory_t*)=dlsym(lib,"nvmlDeviceGetMemoryInfo"); return fn?fn(dev,m):13; }
static int pci_nvml(char *out) { pci_v3_t pci={0}; int (*fn)(device_t,pci_v3_t*)=dlsym(lib,"nvmlDeviceGetPciInfo_v3"); if(!fn)return 13; int r=fn(dev,&pci); if(!r) { memcpy(out,pci.busId,32); out[31]=0; } return r; }
static int ecc_nvml(unsigned int type,unsigned int counter,unsigned long long *out) { int (*fn)(device_t,unsigned int,unsigned int,unsigned long long*)=dlsym(lib,"nvmlDeviceGetTotalEccErrors"); return fn?fn(dev,type,counter,out):13; }
static int remap_nvml(unsigned int *a,unsigned int *b,unsigned int *p,unsigned int *f) { int (*fn)(device_t,unsigned int*,unsigned int*,unsigned int*,unsigned int*)=dlsym(lib,"nvmlDeviceGetRemappedRows"); return fn?fn(dev,a,b,p,f):13; }
static int retired_nvml(unsigned int type,unsigned int *out) { int (*fn)(device_t,unsigned int,unsigned int*,unsigned long long*)=dlsym(lib,"nvmlDeviceGetRetiredPages"); if(!fn)return 13; int r=fn(dev,type,out,NULL); return r==7?0:r; }
static int processes_nvml(unsigned int *out) { int (*fn)(device_t,unsigned int*,void*)=dlsym(lib,"nvmlDeviceGetComputeRunningProcesses_v3"); if(!fn)return 13; int r=fn(dev,out,NULL); return r==7?0:r; }
static int reasons_nvml(unsigned long long *out) { int (*fn)(device_t,unsigned long long*)=dlsym(lib,"nvmlDeviceGetCurrentClocksEventReasons"); if(!fn)fn=dlsym(lib,"nvmlDeviceGetCurrentClocksThrottleReasons"); return fn?fn(dev,out):13; }
static int capability_nvml(char *out) { int a=0,b=0; int (*fn)(device_t,int*,int*)=dlsym(lib,"nvmlDeviceGetCudaComputeCapability"); if(!fn)return 13; int r=fn(dev,&a,&b); if(!r)snprintf(out,64,"%d.%d",a,b); return r; }
static int utilization_nvml(unsigned int *gpu,unsigned int *memory) { struct {unsigned int gpu,memory;} u={0}; int (*fn)(device_t,void*)=dlsym(lib,"nvmlDeviceGetUtilizationRates"); if(!fn)return 13; int r=fn(dev,&u); *gpu=u.gpu;*memory=u.memory;return r; }

// CUDA enumeration obtains the runtime-visible UUID order without allocating
// device memory or creating a context. It runs only inside this killed-on-
// deadline helper, and inherits only explicit device-visibility variables.
static void *cuda_lib;
static int cuda_start(unsigned int *count) {
 cuda_lib=dlopen("libcuda.so.1",RTLD_NOW|RTLD_LOCAL); if(!cuda_lib)return 12;
 int (*init)(unsigned int)=dlsym(cuda_lib,"cuInit"); int (*getcount)(int*)=dlsym(cuda_lib,"cuDeviceGetCount");
 if(!init||!getcount)return 13; int r=init(0); if(r)return r+1000;
 int n=0;r=getcount(&n); if(r)return r+1000; *count=(unsigned int)n;return 0;
}
static int cuda_uuid(unsigned int index,char *out) {
 int (*get)(int*,int)=dlsym(cuda_lib,"cuDeviceGet");
 int (*getuuid)(void*,int)=dlsym(cuda_lib,"cuDeviceGetUuid_v2");
 if(!getuuid)getuuid=dlsym(cuda_lib,"cuDeviceGetUuid");
 if(!get||!getuuid)return 13; int d=0,r=get(&d,index);if(r)return r+1000;
 unsigned char u[16];r=getuuid(u,d);if(r)return r+1000;
 snprintf(out,64,"GPU-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]);return 0;
}
static void cuda_close(void) { if(cuda_lib) {dlclose(cuda_lib);cuda_lib=NULL;} }
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func nvStatus(rc C.int) model.Status {
	switch int(rc) {
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
func nvField(rc C.int, v any, unit string) field {
	if rc != 0 {
		return absent(nvStatus(rc), fmt.Sprintf("NVML returned code %d; unsupported and denied fields are not numeric zeros.", int(rc)))
	}
	return present(v, unit)
}
func nvString(symbol string, system bool) field {
	name := C.CString(symbol)
	defer C.free(unsafe.Pointer(name))
	var buf [128]C.char
	var rc C.int
	if system {
		rc = C.system_nvml(name, &buf[0], 128)
	} else {
		rc = C.string_nvml(name, &buf[0], 128)
	}
	buf[127] = 0
	value := C.GoString(&buf[0])
	if rc == 0 && value == "" {
		return absent(model.ToolError, "NVML returned an empty string without a usable field value.")
	}
	return nvField(rc, value, "")
}
func nvUint(symbol, unit string, scale float64) field {
	name := C.CString(symbol)
	defer C.free(unsafe.Pointer(name))
	var v C.uint
	rc := C.uint_nvml(name, &v)
	return nvField(rc, float64(v)*scale, unit)
}
func nvPair(symbol, unit string) (field, field) {
	name := C.CString(symbol)
	defer C.free(unsafe.Pointer(name))
	var a, b C.uint
	rc := C.pair_nvml(name, &a, &b)
	return nvField(rc, uint64(a), unit), nvField(rc, uint64(b), unit)
}
func nvEnum(symbol string, kind uint, unit string) field {
	name := C.CString(symbol)
	defer C.free(unsafe.Pointer(name))
	var v C.uint
	rc := C.withkind_nvml(name, C.uint(kind), &v)
	return nvField(rc, uint64(v), unit)
}
func fieldString(f field) string {
	if f.Status != model.Pass {
		return "unknown"
	}
	return fmt.Sprint(f.Value)
}

func nativeCollect(target string) nativeResult   { return nativeCollectMode(target, false) }
func nativeTelemetry(target string) nativeResult { return nativeCollectMode(target, true) }
func nativeCollectMode(target string, minimal bool) nativeResult {
	rc := C.init_nvml()
	if rc != 0 {
		return nativeResult{Status: nvStatus(rc), Message: fmt.Sprintf("Direct NVML initialization returned code %d.", int(rc))}
	}
	defer C.close_nvml()
	if target != "" {
		id := C.CString(target)
		defer C.free(unsafe.Pointer(id))
		rc = C.uuid_nvml(id)
		if rc != 0 {
			return nativeResult{Status: nvStatus(rc), Message: "Selected NVML UUID could not be reopened."}
		}
		fields := map[string]field{}
		if minimal {
			fields = nvMinimal()
		} else {
			fields = nvSnapshot()
		}
		return nativeResult{Status: model.Pass, Message: "Read-only direct NVML snapshot.", Fields: fields}
	}
	var count C.uint
	rc = C.count_nvml(&count)
	if rc != 0 || count > 1024 {
		return nativeResult{Status: model.ToolError, Message: "NVML enumeration failed or exceeded the bounded device count."}
	}
	out := nativeResult{Status: model.Pass, Message: "Read-only direct NVML enumeration; no application access or attestation claim."}
	for i := C.uint(0); i < count; i++ {
		rc = C.index_nvml(i)
		if rc != 0 {
			out.Status = nvStatus(rc)
			out.Message = "One or more management devices could not be safely enumerated."
			return out
		}
		uuid, name, driver := nvString("nvmlDeviceGetUUID", false), nvString("nvmlDeviceGetName", false), nvString("nvmlSystemGetDriverVersion", true)
		if uuid.Status != model.Pass || !validUUID(fieldString(uuid)) {
			out.Status = model.ToolError
			out.Message = "NVML returned unavailable or invalid stable identity."
			return out
		}
		var bus [32]C.char
		prc := C.pci_nvml(&bus[0])
		pci := ""
		if prc == 0 {
			pci = C.GoString(&bus[0])
		}
		var mem C.memory_t
		mrc := C.memory_nvml(&mem)
		var memory uint64
		if mrc == 0 {
			memory = uint64(mem.total)
		}
		mig, _ := nvPair("nvmlDeviceGetMigMode", "")
		virt := nvUint("nvmlDeviceGetVirtualizationMode", "", 1)
		out.Devices = append(out.Devices, model.Device{Index: int(i), UUID: fieldString(uuid), Name: fieldString(name), SKU: fieldString(name), PCIAddress: pci, MemoryBytes: memory, MIGMode: fieldString(mig), VirtualizationMode: fieldString(virt), DriverVersion: fieldString(driver), Source: "NVML", IdentityAssurance: "host/driver-reported; not attested"})
	}
	var nc C.uint
	rc = C.cuda_start(&nc)
	defer C.cuda_close()
	out.CUDAStatus = nvStatus(rc)
	if rc == 0 && nc <= 1024 {
		for i := C.uint(0); i < nc; i++ {
			var buf [64]C.char
			rc = C.cuda_uuid(i, &buf[0])
			if rc != 0 {
				out.CUDAStatus = nvStatus(rc)
				out.CUDAUUIDs = nil
				break
			}
			out.CUDAUUIDs = append(out.CUDAUUIDs, C.GoString(&buf[0]))
		}
	} else if nc > 1024 {
		out.CUDAStatus = model.ToolError
	}
	return out
}

func nvSnapshot() map[string]field {
	f := map[string]field{}
	for _, spec := range gpuFields {
		f[spec.Name] = absent(model.Unsupported, "This direct NVML adapter does not expose the field; qualified CLI fallback may expose it.")
	}
	for key, symbol := range map[string]string{"uuid": "nvmlDeviceGetUUID", "name": "nvmlDeviceGetName", "vbios": "nvmlDeviceGetVbiosVersion", "part_number": "nvmlDeviceGetBoardPartNumber"} {
		f[key] = nvString(symbol, false)
	}
	f["driver_version"] = nvString("nvmlSystemGetDriverVersion", true)
	f["nvml_version"] = nvString("nvmlSystemGetNVMLVersion", true)
	var cudaVersion C.int
	cvrc := C.cuda_version_nvml(&cudaVersion)
	f["cuda_driver_api_version"] = nvField(cvrc, int(cudaVersion), "")
	var bus [32]C.char
	rc := C.pci_nvml(&bus[0])
	f["pci_address"] = nvField(rc, C.GoString(&bus[0]), "")
	var cap [64]C.char
	rc = C.capability_nvml(&cap[0])
	f["compute_capability"] = nvField(rc, C.GoString(&cap[0]), "")
	var m C.memory_t
	rc = C.memory_nvml(&m)
	f["memory_total_bytes"] = nvField(rc, uint64(m.total), "bytes")
	f["memory_free_bytes"] = nvField(rc, uint64(m.free), "bytes")
	f["memory_used_bytes"] = nvField(rc, uint64(m.used), "bytes")
	f["mig_current"], f["mig_pending"] = nvPair("nvmlDeviceGetMigMode", "")
	f["virtualization_mode"] = nvUint("nvmlDeviceGetVirtualizationMode", "", 1)
	f["ecc_current"], f["ecc_pending"] = nvPair("nvmlDeviceGetEccMode", "")
	for _, q := range []struct {
		key          string
		typ, counter uint
	}{{"ecc_corrected_volatile", 0, 0}, {"ecc_uncorrected_volatile", 1, 0}, {"ecc_corrected_aggregate", 0, 1}, {"ecc_uncorrected_aggregate", 1, 1}} {
		var v C.ulonglong
		rc = C.ecc_nvml(C.uint(q.typ), C.uint(q.counter), &v)
		f[q.key] = nvField(rc, uint64(v), "errors")
	}
	var a, b, p, failed C.uint
	rc = C.remap_nvml(&a, &b, &p, &failed)
	f["row_remap_corrected"] = nvField(rc, uint64(a), "rows")
	f["row_remap_uncorrected"] = nvField(rc, uint64(b), "rows")
	f["row_remap_pending"] = nvField(rc, uint64(p), "")
	f["row_remap_failure"] = nvField(rc, uint64(failed), "")
	f["retirement_pending"] = nvUint("nvmlDeviceGetRetiredPagesPendingStatus", "", 1)
	for _, q := range []struct {
		key string
		typ uint
	}{{"retired_pages_corrected", 0}, {"retired_pages_uncorrected", 1}} {
		var v C.uint
		rc = C.retired_nvml(C.uint(q.typ), &v)
		f[q.key] = nvField(rc, uint64(v), "pages")
	}
	f["temperature_gpu_c"] = nvEnum("nvmlDeviceGetTemperature", 0, "C")
	f["temperature_shutdown_c"] = nvEnum("nvmlDeviceGetTemperatureThreshold", 0, "C")
	f["temperature_slowdown_c"] = nvEnum("nvmlDeviceGetTemperatureThreshold", 1, "C")
	var processCount C.uint
	rc = C.processes_nvml(&processCount)
	f["compute_process_count"] = nvField(rc, uint64(processCount), "processes")
	f["fan_percent"] = nvUint("nvmlDeviceGetFanSpeed", "percent", 1)
	for key, symbol := range map[string]string{"power_draw_w": "nvmlDeviceGetPowerUsage", "power_limit_w": "nvmlDeviceGetPowerManagementLimit", "power_default_w": "nvmlDeviceGetPowerManagementDefaultLimit"} {
		f[key] = nvUint(symbol, "W", 0.001)
	}
	f["power_min_w"], f["power_max_w"] = nvPair("nvmlDeviceGetPowerManagementLimitConstraints", "W")
	for _, key := range []string{"power_min_w", "power_max_w"} {
		x := f[key]
		if x.Status == model.Pass {
			x.Value = float64(x.Value.(uint64)) / 1000
			f[key] = x
		}
	}
	var reason C.ulonglong
	rc = C.reasons_nvml(&reason)
	f["clock_event_reasons"] = nvField(rc, uint64(reason), "bitmask")
	f["clock_sm_mhz"] = nvEnum("nvmlDeviceGetClockInfo", 1, "MHz")
	f["clock_memory_mhz"] = nvEnum("nvmlDeviceGetClockInfo", 2, "MHz")
	for key, symbol := range map[string]string{"pcie_gen": "nvmlDeviceGetCurrPcieLinkGeneration", "pcie_max_gen": "nvmlDeviceGetMaxPcieLinkGeneration", "pcie_width": "nvmlDeviceGetCurrPcieLinkWidth", "pcie_max_width": "nvmlDeviceGetMaxPcieLinkWidth", "pcie_replay_count": "nvmlDeviceGetPcieReplayCounter"} {
		unit := "lanes"
		if key == "pcie_gen" || key == "pcie_max_gen" {
			unit = "generation"
		}
		if key == "pcie_replay_count" {
			unit = "events"
		}
		f[key] = nvUint(symbol, unit, 1)
	}
	var gpu, mem C.uint
	rc = C.utilization_nvml(&gpu, &mem)
	f["utilization_gpu_percent"] = nvField(rc, uint64(gpu), "percent")
	f["utilization_memory_percent"] = nvField(rc, uint64(mem), "percent")
	return f
}

func nvMinimal() map[string]field {
	f := map[string]field{"uuid": nvString("nvmlDeviceGetUUID", false), "temperature_gpu_c": nvEnum("nvmlDeviceGetTemperature", 0, "C"), "power_draw_w": nvUint("nvmlDeviceGetPowerUsage", "W", 0.001)}
	var reasons C.ulonglong
	rc := C.reasons_nvml(&reasons)
	f["clock_event_reasons"] = nvField(rc, uint64(reasons), "bitmask")
	var gpu, mem C.uint
	rc = C.utilization_nvml(&gpu, &mem)
	f["utilization_gpu_percent"] = nvField(rc, uint64(gpu), "percent")
	var count C.uint
	rc = C.processes_nvml(&count)
	f["compute_process_count"] = nvField(rc, uint64(count), "processes")
	for _, q := range []struct {
		key string
		typ uint
	}{{"ecc_corrected_volatile", 0}, {"ecc_uncorrected_volatile", 1}} {
		var v C.ulonglong
		rc = C.ecc_nvml(C.uint(q.typ), 0, &v)
		f[q.key] = nvField(rc, uint64(v), "errors")
	}
	var a, b, p, failed C.uint
	rc = C.remap_nvml(&a, &b, &p, &failed)
	f["row_remap_pending"] = nvField(rc, uint64(p), "")
	f["row_remap_failure"] = nvField(rc, uint64(failed), "")
	return f
}
