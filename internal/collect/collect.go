// Package collect contains read-only, bounded, privacy-minimized collectors.
package collect

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

type Options struct {
	Timeout   time.Duration
	Target    string
	Workspace string
	// ProcRoot/SysRoot are injection points for hermetic fixtures; the CLI does
	// not accept arbitrary roots from a report or a worker.
	ProcRoot string
	SysRoot  string
}

type Contract struct {
	ID            string `json:"id"`
	Permissions   string `json:"permissions"`
	Supported     string `json:"supported"`
	Effects       string `json:"effects"`
	EstimatedCost string `json:"estimated_cost"`
	Schema        string `json:"schema"`
	Cancellation  string `json:"cancellation"`
	Fallback      string `json:"fallback"`
}

func Contracts() []Contract {
	return []Contract{
		{"nvml", "Unprivileged driver management access", "Linux NVIDIA; feature-dependent fields", "Read-only; isolated child; no device allocation", "Usually under 2 seconds; bounded by timeout", model.SchemaVersion, "Kill isolated helper on cancellation/deadline", "Allowlisted nvidia-smi queries"},
		{"nvidia-smi", "Unprivileged executable and driver management access", "Linux NVIDIA; version-discovered query fields", "Read-only child process; no peer stress", "Usually under 3 seconds; bounded by timeout", model.SchemaVersion, "Kill child on cancellation/deadline; cap output", "Explicit missing/unsupported fields"},
		{"linux-os", "Read access to allowlisted proc/sys/cgroup metadata", "Linux, cgroup v1/v2 with visibility limits", "Read-only; no process names, command lines, secrets, or network", "Usually under 100 milliseconds; bounded read sizes", model.SchemaVersion, "Context checked between file reads", "Explicit unsupported or denied fields"},
	}
}

type field struct {
	Status  model.Status `json:"status"`
	Value   any          `json:"value,omitempty"`
	Unit    string       `json:"unit,omitempty"`
	Message string       `json:"message,omitempty"`
}
type nativeResult struct {
	Status     model.Status     `json:"status"`
	Message    string           `json:"message,omitempty"`
	Devices    []model.Device   `json:"devices,omitempty"`
	Fields     map[string]field `json:"fields,omitempty"`
	CUDAUUIDs  []string         `json:"cuda_uuids,omitempty"`
	CUDAStatus model.Status     `json:"cuda_status,omitempty"`
}

type fieldSpec struct{ Name, Check, Query, Unit string }

var gpuFields = []fieldSpec{
	{"name", "A01", "name", ""}, {"uuid", "A07", "uuid", ""}, {"pci_address", "A07", "pci.bus_id", ""},
	{"memory_total_bytes", "A02", "memory.total", "bytes"}, {"memory_free_bytes", "A05", "memory.free", "bytes"}, {"memory_used_bytes", "I01", "memory.used", "bytes"},
	{"compute_capability", "A03", "compute_cap", ""}, {"mig_current", "A06", "mig.mode.current", ""}, {"mig_pending", "A06", "mig.mode.pending", ""},
	{"virtualization_mode", "A06", "virtualization.mode", ""}, {"vbios", "A10", "vbios_version", ""}, {"part_number", "A02", "board.part_number", ""},
	{"driver_version", "H01", "driver_version", ""}, {"nvml_version", "H01", "", ""}, {"cuda_driver_api_version", "H01", "", ""}, {"ecc_current", "B01", "ecc.mode.current", ""}, {"ecc_pending", "B01", "ecc.mode.pending", ""},
	{"ecc_corrected_volatile", "B02", "ecc.errors.corrected.volatile.total", "errors"}, {"ecc_uncorrected_volatile", "B03", "ecc.errors.uncorrected.volatile.total", "errors"},
	{"ecc_corrected_aggregate", "B02", "ecc.errors.corrected.aggregate.total", "errors"}, {"ecc_uncorrected_aggregate", "B03", "ecc.errors.uncorrected.aggregate.total", "errors"},
	{"row_remap_corrected", "B04", "remapped_rows.correctable", "rows"}, {"row_remap_uncorrected", "B04", "remapped_rows.uncorrectable", "rows"},
	{"row_remap_pending", "B04", "remapped_rows.pending", ""}, {"row_remap_failure", "B04", "remapped_rows.failure", ""},
	{"retirement_pending", "B05", "retired_pages.pending", ""}, {"retired_pages_corrected", "B05", "retired_pages.single_bit_ecc.count", "pages"}, {"retired_pages_uncorrected", "B05", "retired_pages.double_bit.count", "pages"},
	{"temperature_gpu_c", "D04", "temperature.gpu", "C"}, {"temperature_slowdown_c", "D04", "", "C"}, {"temperature_shutdown_c", "D04", "", "C"}, {"compute_process_count", "I01", "", "processes"}, {"temperature_memory_c", "D05", "temperature.memory", "C"}, {"fan_percent", "D07", "fan.speed", "percent"},
	{"power_draw_w", "D01", "power.draw", "W"}, {"power_limit_w", "D01", "power.limit", "W"}, {"power_default_w", "D01", "power.default_limit", "W"}, {"power_min_w", "D01", "power.min_limit", "W"}, {"power_max_w", "D01", "power.max_limit", "W"},
	{"clock_event_reasons", "D03", "clocks_event_reasons.active", "bitmask"}, {"clock_sm_mhz", "D03", "clocks.current.sm", "MHz"}, {"clock_memory_mhz", "D03", "clocks.current.memory", "MHz"},
	{"pcie_gen", "D08", "pcie.link.gen.current", "generation"}, {"pcie_max_gen", "D08", "pcie.link.gen.max", "generation"}, {"pcie_width", "D08", "pcie.link.width.current", "lanes"}, {"pcie_max_width", "D08", "pcie.link.width.max", "lanes"}, {"pcie_replay_count", "D09", "pcie.replay_counter", "events"},
	{"utilization_gpu_percent", "I01", "utilization.gpu", "percent"}, {"utilization_memory_percent", "I01", "utilization.memory", "percent"},
}

func observation(check, method, resource string, f field, start time.Time) model.Observation {
	switch f.Status {
	case model.NotTested, model.Unsupported, model.PermissionDenied, model.DependencyMissing, model.TimeBudgetExhausted, model.ToolError, model.NotApplicable:
		f.Value = nil
	}
	return model.Observation{CheckID: check, ResourceID: resource, MethodID: method, Version: model.MethodVersion, StartUTC: start.UTC(), DurationMS: float64(time.Since(start).Microseconds()) / 1000, Status: f.Status, Value: f.Value, Unit: f.Unit, SampleCount: 1, SourceKind: "reported", Visibility: "process-visible interfaces; host/driver mediated", Scope: resource, Message: f.Message}
}
func absent(s model.Status, msg string) field { return field{Status: s, Message: msg} }
func present(v any, unit string) field {
	return field{Status: model.Pass, Value: v, Unit: unit, Message: "Reported field collected; this is not a physical-health or authenticity pass."}
}
func timeout(o Options) time.Duration {
	if o.Timeout <= 0 {
		return 5 * time.Second
	}
	return o.Timeout
}

// HandleInternalCommand dispatches the private native helper. Call at the start
// of main, before normal CLI parsing. All output is normalized JSON.
func HandleInternalCommand(args []string) bool {
	if len(args) == 2 && args[0] == "__collect-host" {
		_ = json.NewEncoder(os.Stdout).Encode(hostDirect(context.Background(), Options{Workspace: args[1]}))
		return true
	}
	if len(args) == 0 || args[0] != "__collect-nvml" {
		return false
	}
	r := nativeResult{Status: model.ToolError, Message: "Invalid private collector arguments"}
	if len(args) == 2 && args[1] == "discover" {
		r = nativeCollect("")
	}
	if len(args) == 3 && args[1] == "snapshot" && validUUID(args[2]) {
		r = nativeCollect(args[2])
	}
	if len(args) == 3 && args[1] == "telemetry" && validUUID(args[2]) {
		r = nativeTelemetry(args[2])
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
	return true
}

func native(ctx context.Context, target string, opts Options) nativeResult {
	return nativeMode(ctx, target, opts, "snapshot")
}
func nativeMode(ctx context.Context, target string, opts Options, mode string) nativeResult {
	if runtime.GOOS != "linux" {
		return nativeResult{Status: model.Unsupported, Message: "NVML collector requires Linux."}
	}
	exe, err := os.Executable()
	if err != nil {
		return nativeResult{Status: model.ToolError, Message: "Cannot locate isolated collector executable."}
	}
	args := []string{"__collect-nvml", "discover"}
	if target != "" {
		args = []string{"__collect-nvml", mode, target}
	}
	b, s := run(ctx, exe, args, timeout(opts), 1<<20)
	if s != model.Pass {
		return nativeResult{Status: s, Message: "Isolated NVML helper unavailable or incomplete."}
	}
	r, err := decodeNativeResult(b)
	if err != nil {
		return nativeResult{Status: model.ToolError, Message: "Invalid isolated NVML response."}
	}
	return r
}

func decodeNativeResult(data []byte) (nativeResult, error) {
	var result nativeResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if !result.Status.Valid() {
		return result, errors.New("invalid native status")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return result, errors.New("trailing native response data")
	}
	return result, nil
}

func Discover(ctx context.Context, opts Options) ([]model.Device, []model.Observation) {
	start := time.Now()
	n := native(ctx, "", opts)
	obs := []model.Observation{observation("H02", "nvml.discovery", "allocation", field{Status: n.Status, Message: n.Message}, start)}
	devices := n.Devices
	if n.Status != model.Pass {
		var s model.Status
		devices, s = smiDiscover(ctx, opts)
		obs = append(obs, observation("A08", "nvidia-smi.discovery", "allocation", field{Status: s, Value: len(devices), Message: "Management visibility only; no hidden-host inventory or CUDA access claim."}, start))
	}
	seenUUIDs := map[string]bool{}
	seenIndices := map[int]bool{}
	for _, d := range devices {
		if !validUUID(d.UUID) || seenUUIDs[d.UUID] || seenIndices[d.Index] {
			obs = append(obs, observation("A08", "visibility.uniqueness", "allocation", absent(model.Contaminated, "Duplicate or invalid management identities make target selection ambiguous."), start))
			return nil, obs
		}
		seenUUIDs[d.UUID] = true
		seenIndices[d.Index] = true
	}
	filtered, status, msg := filterVisibility(devices, os.LookupEnv, n.CUDAUUIDs, n.CUDAStatus)
	obs = append(obs, observation("A08", "visibility.selection", "allocation", field{Status: status, Value: len(filtered), Message: msg}, start))
	if len(filtered) == 0 && status == model.Pass {
		obs[len(obs)-1].Status = model.NotTested
		obs[len(obs)-1].Message = "No eligible GPU is visible in the permitted scope."
	}
	return filtered, obs
}

func GPU(ctx context.Context, d model.Device, opts Options) []model.Observation {
	ctx, cancel := context.WithTimeout(ctx, timeout(opts))
	defer cancel()
	start := time.Now()
	if !validUUID(d.UUID) {
		return []model.Observation{observation("A07", "target.identity", d.UUID, absent(model.Contaminated, "Target has no valid stable UUID; snapshot refused."), start)}
	}
	n := native(ctx, d.UUID, opts)
	backend := "nvml"
	fields := n.Fields
	if n.Status != model.Pass {
		fields = smiSnapshot(ctx, d.UUID, opts)
		backend = "nvidia-smi"
	}
	fallback := map[string]field{}
	if n.Status == model.Pass {
		for _, f := range fields {
			if f.Status != model.Pass {
				fallback = smiSnapshot(ctx, d.UUID, opts)
				break
			}
		}
	}
	out := make([]model.Observation, 0, len(gpuFields)+2)
	for _, spec := range gpuFields {
		f, ok := fields[spec.Name]
		if !ok {
			f = absent(n.Status, "Field unavailable; no numeric value inferred.")
			if f.Status == model.Pass {
				f.Status = model.Unsupported
			}
		}
		fieldBackend := backend
		nativeStatus := f.Status
		if replacement, exists := fallback[spec.Name]; f.Status != model.Pass && exists && replacement.Status == model.Pass {
			f = replacement
			fieldBackend = "nvidia-smi"
		}
		o := observation(spec.Check, fieldBackend+"."+spec.Name, d.UUID, f, start)
		o.Conditions = map[string]any{"field": spec.Name, "backend": fieldBackend, "native_status": nativeStatus, "common_trust_domain": "host/driver", "temporal_scope": "instantaneous snapshot; error totals may predate scan"}
		if spec.Name == "uuid" && f.Status == model.Pass && f.Value != d.UUID {
			o.Status = model.Contaminated
			o.Message = "Selected UUID changed; affected observations cannot establish target continuity."
		}
		out = append(out, o)
	}
	out = append(out, observation("B06", "events.history", d.UUID, absent(model.NotTested, "Historical Xid logs and NVML event subscription are not collected by this snapshot adapter; counters do not establish complete event history."), start))
	epoch := observation("B02", "counter.epoch", d.UUID, absent(model.NotTested, "No reliable reset/epoch identifier is exposed by the selected APIs; identical UUID/driver and nondecreasing totals cannot exclude an intervening reset."), start)
	epoch.Conditions = map[string]any{"field": "counter_epoch", "continuity": "unknown"}
	out = append(out, epoch)
	return enforceSnapshotIdentity(out, d.UUID)
}

func validUUID(s string) bool {
	if len(s) > 128 || !(strings.HasPrefix(s, "GPU-") || strings.HasPrefix(s, "MIG-")) {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '/') {
			return false
		}
	}
	return len(s) > 4
}

// filterVisibility never guesses CUDA ordinals from NVML indices. Numeric
// CUDA masks require an independent CUDA-driver enumeration in the helper.
func filterVisibility(ds []model.Device, lookup func(string) (string, bool), cudaUUIDs []string, cudaStatus model.Status) ([]model.Device, model.Status, string) {
	current := append([]model.Device(nil), ds...)
	for _, name := range []string{"NVIDIA_VISIBLE_DEVICES", "CUDA_VISIBLE_DEVICES"} {
		mask, set := lookup(name)
		if !set {
			continue
		}
		mask = strings.TrimSpace(mask)
		if mask == "" || mask == "none" || mask == "void" || mask == "-1" {
			return nil, model.Pass, "Device visibility explicitly disabled by " + name + "."
		}
		if mask == "all" && name == "NVIDIA_VISIBLE_DEVICES" {
			continue
		}
		selected := []model.Device{}
		seen := map[string]bool{}
		for _, token := range strings.Split(mask, ",") {
			token = strings.TrimSpace(token)
			candidates := []model.Device{}
			if strings.HasPrefix(token, "MIG-") {
				return nil, model.Unsupported, "A MIG visibility mask was detected; this adapter does not enumerate partition handles and will not substitute the physical parent."
			}
			if idx, e := strconv.Atoi(token); e == nil {
				if name == "CUDA_VISIBLE_DEVICES" {
					if cudaStatus != model.Pass {
						return nil, model.Contaminated, "Numeric CUDA visibility cannot be mapped safely to NVML ordinals without CUDA-driver UUID enumeration."
					}
					// CUDA enumeration already applies the full CUDA visibility mask.
					_ = idx
					for _, d := range current {
						for _, u := range cudaUUIDs {
							if strings.EqualFold(d.UUID, u) {
								candidates = append(candidates, d)
								break
							}
						}
					}
				} else {
					for _, d := range current {
						if d.Index == idx {
							candidates = append(candidates, d)
						}
					}
				}
			} else if validUUID(token) {
				for _, d := range current {
					if strings.HasPrefix(strings.ToLower(d.UUID), strings.ToLower(token)) {
						candidates = append(candidates, d)
					}
				}
			} else {
				return nil, model.Contaminated, "Unrecognized device visibility token; target mapping unresolved."
			}
			numericCUDA := name == "CUDA_VISIBLE_DEVICES" && cudaStatus == model.Pass && !strings.HasPrefix(token, "GPU-")
			if (!numericCUDA && len(candidates) != 1) || (numericCUDA && len(candidates) == 0) {
				return nil, model.Contaminated, "Device visibility is ambiguous or cannot be resolved within management visibility."
			}
			for _, d := range candidates {
				if !seen[d.UUID] {
					selected = append(selected, d)
					seen[d.UUID] = true
				}
			}
		}
		current = selected
	}
	// Parent devices in MIG mode are reportable context, but worker dispatch must
	// independently reject full-device assumptions until partition mapping exists.
	return current, model.Pass, "Permitted management devices enumerated; runtime access requires a checked worker and stable UUID mapping."
}

type capBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (w *capBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remain := w.limit - w.b.Len()
	if n > remain {
		if remain > 0 {
			_, _ = w.b.Write(p[:remain])
		}
		w.overflow = true
		w.cancel()
		return n, nil
	}
	return w.b.Write(p)
}
func run(parent context.Context, binary string, args []string, limit time.Duration, cap int) ([]byte, model.Status) {
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	if !filepath.IsAbs(binary) {
		found := ""
		for _, dir := range []string{"/usr/local/nvidia/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"} {
			candidate := filepath.Join(dir, binary)
			info, err := os.Stat(candidate)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				found = candidate
				break
			}
		}
		if found == "" {
			return nil, model.DependencyMissing
		}
		binary = found
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/local/nvidia/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C"}
	for _, key := range []string{"CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER", "NVIDIA_VISIBLE_DEVICES"} {
		if v, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	out := &capBuffer{limit: cap, cancel: cancel}
	stderr := &capBuffer{limit: 8192, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = stderr
	cmd.WaitDelay = 200 * time.Millisecond
	prepareCollector(cmd)
	err := cmd.Run()
	if out.overflow || stderr.overflow {
		return nil, model.ToolError
	}
	if ctx.Err() != nil {
		return nil, model.TimeBudgetExhausted
	}
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, model.DependencyMissing
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, model.PermissionDenied
		}
		lower := strings.ToLower(stderr.b.String() + out.b.String())
		if strings.Contains(lower, "insufficient permissions") || strings.Contains(lower, "permission denied") {
			return nil, model.PermissionDenied
		}
		return nil, model.ToolError
	}
	return out.b.Bytes(), model.Pass
}

func smiDiscover(ctx context.Context, opts Options) ([]model.Device, model.Status) {
	b, s := run(ctx, "nvidia-smi", []string{"--query-gpu=index,uuid,name,pci.bus_id,memory.total,driver_version", "--format=csv,noheader,nounits"}, timeout(opts), 1<<20)
	if s != model.Pass {
		return nil, s
	}
	rows, e := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if e != nil {
		return nil, model.ToolError
	}
	out := []model.Device{}
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) != 6 {
			return nil, model.ToolError
		}
		for i := range row {
			row[i] = strings.TrimSpace(row[i])
		}
		idx, e := strconv.Atoi(row[0])
		if e != nil || idx < 0 || !validUUID(row[1]) || seen[row[1]] {
			return nil, model.ToolError
		}
		seen[row[1]] = true
		memoryBytes, _ := scaledUnsigned(row[4], 1<<20)
		out = append(out, model.Device{Index: idx, UUID: row[1], Name: row[2], SKU: row[2], PCIAddress: row[3], MemoryBytes: memoryBytes, DriverVersion: row[5], MIGMode: "unknown", VirtualizationMode: "unknown", Source: "nvidia-smi (NVML-backed)", IdentityAssurance: "host/driver-reported; not attested"})
	}
	return out, model.Pass
}

func smiSnapshot(parent context.Context, uuid string, opts Options) map[string]field {
	return smiSnapshotSpecs(parent, uuid, opts, gpuFields)
}
func smiSnapshotSpecs(parent context.Context, uuid string, opts Options, specs []fieldSpec) map[string]field {
	ctx, cancel := context.WithTimeout(parent, timeout(opts))
	defer cancel()
	fields := map[string]field{}
	help, s := run(ctx, "nvidia-smi", []string{"--help-query-gpu"}, timeout(opts), 1<<20)
	if s != model.Pass {
		for _, f := range specs {
			fields[f.Name] = absent(s, "nvidia-smi query capability discovery unavailable.")
		}
		return fields
	}
	selected := []fieldSpec{}
	queries := []string{}
	for _, f := range specs {
		if f.Query != "" && strings.Contains(string(help), `"`+f.Query+`"`) {
			selected = append(selected, f)
			queries = append(queries, f.Query)
		} else {
			fields[f.Name] = absent(model.Unsupported, "Field is not advertised by this nvidia-smi version.")
		}
	}
	if len(selected) == 0 {
		return fields
	}
	b, s := run(ctx, "nvidia-smi", []string{"--id=" + uuid, "--query-gpu=" + strings.Join(queries, ","), "--format=csv,noheader,nounits"}, timeout(opts), 1<<20)
	if s != model.Pass {
		for _, f := range selected {
			fields[f.Name] = absent(s, "Selected-target nvidia-smi query failed; no value inferred.")
		}
		return fields
	}
	rows, e := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if e != nil || len(rows) != 1 || len(rows[0]) != len(selected) {
		for _, f := range selected {
			fields[f.Name] = absent(model.ToolError, "Malformed or ambiguous selected-target CSV output.")
		}
		return fields
	}
	for i, f := range selected {
		fields[f.Name] = parseSMIField(strings.TrimSpace(rows[0][i]), f)
	}
	return fields
}
func parseSMIField(s string, spec fieldSpec) field {
	l := strings.ToLower(strings.Trim(s, "[] "))
	if l == "n/a" || l == "not supported" || l == "not available" {
		return absent(model.Unsupported, "Driver reports field unavailable or unsupported.")
	}
	if strings.Contains(l, "permission") {
		return absent(model.PermissionDenied, "Driver denied field access.")
	}
	if s == "" || strings.Contains(l, "error") || strings.Contains(l, "unknown") {
		return absent(model.ToolError, "Field contains empty or error output.")
	}
	if spec.Unit == "" {
		return present(s, "")
	}
	if spec.Unit == "bitmask" {
		v, e := strconv.ParseUint(s, 0, 64)
		if e != nil {
			return absent(model.ToolError, "Invalid reason bitmask.")
		}
		return present(v, spec.Unit)
	}
	switch spec.Unit {
	case "errors", "rows", "pages", "events", "processes", "generation", "lanes":
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return absent(model.ToolError, "Invalid exact unsigned counter field.")
		}
		return present(v, spec.Unit)
	case "bytes":
		v, ok := scaledUnsigned(s, 1<<20)
		if !ok {
			return absent(model.ToolError, "Memory amount cannot be represented as an exact unsigned byte count.")
		}
		return present(v, spec.Unit)
	}
	v, e := strconv.ParseFloat(s, 64)
	if e != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return absent(model.ToolError, "Invalid numeric field.")
	}
	return present(v, spec.Unit)
}

// SortedFields exposes the documented scalar names for report/fixture tooling.
func SortedFields() []string {
	out := make([]string, 0, len(gpuFields))
	for _, f := range gpuFields {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// Telemetry samples a small selected-device set. The caller controls cadence;
// timestamps describe actual collection intervals, never an assumed 1 Hz.
func Telemetry(ctx context.Context, d model.Device, opts Options) []model.Observation {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout(opts))
	defer cancel()
	if !validUUID(d.UUID) {
		return []model.Observation{observation("A07", "target.identity", d.UUID, absent(model.Contaminated, "Telemetry target lacks valid stable UUID."), start)}
	}
	selected := []fieldSpec{}
	for _, f := range gpuFields {
		switch f.Name {
		case "uuid", "temperature_gpu_c", "power_draw_w", "clock_event_reasons", "utilization_gpu_percent", "compute_process_count", "ecc_uncorrected_volatile", "ecc_corrected_volatile", "row_remap_failure", "row_remap_pending":
			selected = append(selected, f)
		}
	}
	n := nativeMode(ctx, d.UUID, opts, "telemetry")
	fields := n.Fields
	backend := "nvml"
	if n.Status != model.Pass {
		fields = smiSnapshotSpecs(ctx, d.UUID, opts, selected)
		backend = "nvidia-smi"
	}
	out := []model.Observation{}
	for _, spec := range selected {
		f, ok := fields[spec.Name]
		if !ok {
			f = absent(model.Unsupported, "Lightweight telemetry field unavailable.")
		}
		o := observation(spec.Check, backend+"."+spec.Name, d.UUID, f, start)
		o.Conditions = map[string]any{"field": spec.Name, "backend": backend, "common_trust_domain": "host/driver", "telemetry": true, "sampling_resolution": "driver reported; polling interval recorded by timestamps"}
		out = append(out, o)
	}
	return enforceSnapshotIdentity(out, d.UUID)
}

func enforceSnapshotIdentity(obs []model.Observation, uuid string) []model.Observation {
	mismatch := false
	for _, o := range obs {
		if o.Conditions["field"] == "uuid" && (o.Status == model.Pass || o.Status == model.Contaminated) && o.Value != uuid {
			mismatch = true
		}
	}
	if mismatch {
		for i := range obs {
			if obs[i].Status == model.Pass {
				obs[i].Status = model.Contaminated
				obs[i].Message = "Snapshot identity disagrees with the selected UUID; this field is excluded from trusted target evidence."
			}
		}
	}
	return obs
}

var unsignedDecimal = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)

// Avoid a float64 round-trip for MiB-to-byte conversion, retaining exact counts
// and rejecting an output whose decimal precision implies a fractional byte.
func scaledUnsigned(text string, scale uint64) (uint64, bool) {
	if len(text) == 0 || len(text) > 64 || !unsignedDecimal.MatchString(text) {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(text)
	if !ok {
		return 0, false
	}
	rational.Mul(rational, new(big.Rat).SetInt(new(big.Int).SetUint64(scale)))
	if !rational.IsInt() || !rational.Num().IsUint64() {
		return 0, false
	}
	return rational.Num().Uint64(), true
}
