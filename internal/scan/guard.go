package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

var fullGPUUUID = regexp.MustCompile(`^GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var pciPattern = regexp.MustCompile(`^([0-9a-fA-F]{4,8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$`)

// Select never interprets an ordinal or prefix as ownership authorization.
func Select(devices []model.Device, target string) (model.Device, error) {
	if len(devices) == 0 {
		return model.Device{}, errors.New("no permitted GPU with stable identity is visible")
	}
	uuids, pcis, indices := map[string]bool{}, map[string]bool{}, map[int]bool{}
	for _, d := range devices {
		if !fullGPUUUID.MatchString(d.UUID) {
			return model.Device{}, errors.New("visible inventory contains an invalid or partition UUID; physical-parent substitution is forbidden")
		}
		pci, ok := canonicalPCI(d.PCIAddress)
		if !ok {
			return model.Device{}, errors.New("visible inventory has an unavailable or invalid PCI identity")
		}
		uuid := strings.ToLower(d.UUID)
		if uuids[uuid] || pcis[pci] || indices[d.Index] {
			return model.Device{}, errors.New("visible inventory contains duplicate UUID, PCI, or management index identities")
		}
		uuids[uuid] = true
		pcis[pci] = true
		indices[d.Index] = true
	}
	if target == "" {
		if len(devices) != 1 {
			return model.Device{}, errors.New("multiple permitted GPUs require one explicit full GPU UUID")
		}
		return devices[0], nil
	}
	if !fullGPUUUID.MatchString(target) {
		return model.Device{}, errors.New("target must be a full physical GPU UUID; numeric indices and prefixes are not accepted")
	}
	for _, d := range devices {
		if strings.EqualFold(d.UUID, target) {
			return d, nil
		}
	}
	return model.Device{}, errors.New("explicit GPU UUID is not present in permitted visibility")
}
func canonicalPCI(raw string) (string, bool) {
	m := pciPattern.FindStringSubmatch(raw)
	if len(m) != 5 {
		return "", false
	}
	domain, e := strconv.ParseUint(m[1], 16, 32)
	if e != nil {
		return "", false
	}
	bus, _ := strconv.ParseUint(m[2], 16, 8)
	dev, _ := strconv.ParseUint(m[3], 16, 8)
	if dev > 31 {
		return "", false
	}
	return fmt.Sprintf("%08x:%02x:%02x.%s", domain, bus, dev, m[4]), true
}
func scalarField(o model.Observation) string { v, _ := o.Conditions["field"].(string); return v }
func uniqueField(obs []model.Observation, resource, name string) (model.Observation, bool) {
	var found model.Observation
	count := 0
	for _, o := range obs {
		if scalarField(o) == name && (resource == "" || o.ResourceID == resource) {
			found = o
			count++
		}
	}
	return found, count == 1
}
func passField(obs []model.Observation, resource, name string) (model.Observation, bool) {
	o, ok := uniqueField(obs, resource, name)
	return o, ok && o.Status == model.Pass
}
func modeString(v any) string { return strings.ToLower(strings.TrimSpace(fmt.Sprint(v))) }
func normalizeMIG(v any) string {
	switch modeString(v) {
	case "0", "disabled", "off":
		return "disabled"
	case "1", "enabled", "on":
		return "enabled"
	case "unsupported", "n/a", "[n/a]", "not supported":
		return "unsupported"
	}
	return "unknown"
}
func normalizeVirtualization(v any) string {
	switch modeString(v) {
	case "0", "none", "bare metal", "bare-metal":
		return "none"
	case "1", "passthrough", "pass through", "pass-through":
		return "passthrough"
	case "2", "vgpu", "v-gpu":
		return "vgpu"
	case "3", "host-vgpu", "host vgpu":
		return "host-vgpu"
	case "4", "host-vsgpu", "host vsgpu":
		return "host-vsgpu"
	case "unsupported", "n/a", "[n/a]", "not supported":
		return "unsupported"
	}
	return "unknown"
}

// NormalizeDevice upgrades only fields actually reported for this exact UUID.
// An ambiguous H100 family label never becomes a PCIe reference key.
func NormalizeDevice(d model.Device, pre []model.Observation) model.Device {
	d.MIGMode = normalizeMIG(d.MIGMode)
	d.VirtualizationMode = normalizeVirtualization(d.VirtualizationMode)
	for _, name := range []string{"mig_current", "virtualization_mode", "name", "driver_version", "memory_total_bytes", "pci_address"} {
		o, unique := uniqueField(pre, d.UUID, name)
		if !unique {
			continue
		}
		if o.Status != model.Pass {
			// An explicitly unavailable current mode query cannot preserve an
			// older discovery value as if the current snapshot verified it.
			if name == "mig_current" {
				d.MIGMode = "unknown"
				if o.Status == model.Unsupported {
					d.MIGMode = "unsupported"
				}
			}
			if name == "virtualization_mode" {
				d.VirtualizationMode = "unknown"
				if o.Status == model.Unsupported {
					d.VirtualizationMode = "unsupported"
				}
			}
			continue
		}
		switch name {
		case "mig_current":
			d.MIGMode = normalizeMIG(o.Value)
		case "virtualization_mode":
			d.VirtualizationMode = normalizeVirtualization(o.Value)
		case "name":
			if v, ok := o.Value.(string); ok && strings.TrimSpace(v) != "" {
				d.Name = strings.TrimSpace(v)
			}
		case "driver_version":
			if v, ok := o.Value.(string); ok && v != "" {
				d.DriverVersion = v
			}
		case "memory_total_bytes":
			if n, ok := counter(o.Value); ok && n > 0 {
				d.MemoryBytes = n
			}
		case "pci_address":
			if v, ok := o.Value.(string); ok {
				if _, valid := canonicalPCI(v); valid {
					d.PCIAddress = v
				}
			}
		}
	}
	// A parent discovery SKU is just its reported name unless the exact variant
	// is established by the current snapshot. Keep unknown variants in Name.
	d.SKU = exactSKU(d.Name, d.MemoryBytes)
	return d
}
func words(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "pci-e", "pcie")
	s = strings.NewReplacer("-", " ", "_", " ", "/", " ", "(", " ", ")", " ").Replace(s)
	return strings.Join(strings.Fields(strings.TrimSpace(strings.TrimPrefix(s, "nvidia "))), " ")
}
func exactSKU(name string, memory uint64) string {
	text := words(name)
	if (text == "geforce rtx 5080" || text == "rtx 5080") && memory >= 15<<30 && memory <= 17<<30 {
		return "rtx-5080-16gb"
	}
	hasH100 := false
	for _, token := range strings.Fields(text) {
		if token == "h100" {
			hasH100 = true
		}
	}
	if !hasH100 {
		return "unknown"
	}
	gib := float64(memory) / (1 << 30)
	pcie := strings.Contains(text, "pcie")
	sxm := strings.Contains(text, "sxm")
	nvl := strings.Contains(text, "nvl")
	if boolInt(pcie)+boolInt(sxm)+boolInt(nvl) != 1 {
		return "unknown"
	}
	if pcie && gib >= 75 && gib <= 85 {
		return "h100-pcie-80gb"
	}
	if sxm && gib >= 75 && gib <= 85 {
		return "h100-sxm-80gb"
	}
	if nvl && gib >= 90 && gib <= 100 {
		return "h100-nvl-94gb"
	}
	return "unknown"
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func knownSKU(s string) bool {
	switch s {
	case "h100-pcie-80gb", "h100-sxm-80gb", "h100-nvl-94gb", "rtx-5080-16gb":
		return true
	}
	return false
}

// RTX 5080 has no MIG capability. An explicit unsupported query for that exact
// device is distinct from an unavailable query on a MIG-capable H100.
func fullDeviceMode(d model.Device) bool {
	mig := normalizeMIG(d.MIGMode)
	migOK := mig == "disabled" || (mig == "unsupported" && d.SKU == "rtx-5080-16gb" && exactSKU(d.Name, d.MemoryBytes) == d.SKU)
	virtualization := normalizeVirtualization(d.VirtualizationMode)
	return migOK && (virtualization == "none" || virtualization == "passthrough")
}
func guardObservation(check, method, resource string, status model.Status, value any, message string) model.Observation {
	return model.Observation{CheckID: check, ResourceID: resource, MethodID: method, Version: model.MethodVersion, StartUTC: time.Now().UTC(), Status: status, Value: value, SampleCount: 1, SourceKind: "reported", Visibility: "permitted allocation; host/driver mediated", Scope: resource, Message: message, Conditions: map[string]any{"derived": true}}
}

func GuardObservations(d *model.Device, expected string, devices []model.Device, selectionErr error) []model.Observation {
	resource := "allocation"
	if d != nil {
		resource = d.UUID
	}
	out := []model.Observation{}
	expectationStatus := model.NotApplicable
	expectationMessage := "No expected SKU was declared; this check does not certify a provider listing."
	var expectationValue any
	if strings.TrimSpace(expected) != "" {
		expectationStatus = model.NotTested
		expectationMessage = "A declared expectation is present, but no stable selected device is available to compare."
		expectationValue = map[string]any{"expected": expected}
		if d != nil && selectionErr == nil {
			expectationStatus, expectationMessage = compareExpectation(expected, *d)
			expectationValue.(map[string]any)["observed_name"] = d.Name
			expectationValue.(map[string]any)["observed_sku"] = d.SKU
		}
	}
	out = append(out, guardObservation("A01", "guard.expectation", resource, expectationStatus, expectationValue, expectationMessage))
	variantStatus := model.NotTested
	variantMessage := "Exact variant is unresolved; no qualified SKU reference may be substituted."
	var variant any
	if d != nil && selectionErr == nil {
		variant = map[string]any{"sku": d.SKU, "reported_name": d.Name, "reported_memory_bytes": d.MemoryBytes}
		if knownSKU(d.SKU) && exactSKU(d.Name, d.MemoryBytes) == d.SKU {
			variantStatus = model.Pass
			variantMessage = "Reported name and memory identify the recorded variant; PCIe, SXM and NVL retain different reference keys and remain host-mediated evidence."
		}
	}
	out = append(out, guardObservation("A02", "guard.variant", resource, variantStatus, variant, variantMessage))
	modeStatus := model.NotTested
	modeMessage := "Selected allocation mode is not established."
	var modes any
	if d != nil && selectionErr == nil {
		modes = map[string]string{"mig": d.MIGMode, "virtualization": d.VirtualizationMode}
		modeStatus = model.Unsupported
		modeMessage = "Active full-device testing requires disabled MIG (or an explicitly non-MIG RTX 5080) and none/passthrough virtualization; unknown, partitioned and vGPU modes remain unsupported."
		if fullDeviceMode(*d) {
			modeStatus = model.Pass
			modeMessage = "The selected device reports a supported full-device mode with none/passthrough virtualization; this is not an isolation or attestation certificate."
		}
	}
	out = append(out, guardObservation("A06", "guard.mode", resource, modeStatus, modes, modeMessage))
	selectionStatus := model.Pass
	selectionMessage := "One unique full GPU UUID and PCI identity were selected within permitted visibility; each active worker must recheck identity."
	var selectionValue any
	if d == nil || selectionErr != nil {
		selectionStatus = model.NotTested
		selectionMessage = "No stable permitted target was selected."
		if selectionErr != nil {
			// Absence is a coverage gap. A nonempty inventory that cannot be
			// selected uniquely is an ambiguity and remains contaminated.
			if len(devices) > 0 {
				selectionStatus = model.Contaminated
			}
			selectionMessage = selectionErr.Error()
		}
	} else {
		selected, e := Select(devices, d.UUID)
		selectedPCI, _ := canonicalPCI(selected.PCIAddress)
		currentPCI, validPCI := canonicalPCI(d.PCIAddress)
		if e != nil || selected.UUID != d.UUID || !validPCI || selectedPCI != currentPCI {
			selectionStatus = model.Contaminated
			selectionMessage = "Selected resource no longer resolves uniquely in the permitted inventory."
		} else {
			selectionValue = map[string]any{"uuid": d.UUID, "pci_address": d.PCIAddress}
		}
	}
	out = append(out, guardObservation("A07", "guard.selection", resource, selectionStatus, selectionValue, selectionMessage))
	visibleStatus := model.Pass
	visibleMessage := "Count describes permitted management visibility only; it does not inventory hidden host devices."
	if selectionErr != nil {
		visibleStatus = model.NotTested
		visibleMessage = "Permitted inventory was obtained, but stable unique selection remains unresolved."
	}
	out = append(out, guardObservation("A08", "guard.visible", "allocation", visibleStatus, map[string]any{"permitted_visible_count": len(devices)}, visibleMessage))
	return out
}
func compareExpectation(expected string, d model.Device) (model.Status, string) {
	wanted, actualName, actualSKU := words(expected), words(d.Name), words(d.SKU)
	if wanted == "" {
		return model.NotApplicable, "No expected SKU was declared."
	}
	if wanted == actualName || wanted == actualSKU || expectedTokensMatch(wanted, actualName) || expectedTokensMatch(wanted, actualSKU) {
		return model.Pass, "The declared expectation matches the reported selected-device name/variant; host-mediated agreement is not authenticity proof."
	}
	if strings.Contains(wanted, "h100") && strings.Contains(actualName, "h100") && d.SKU == "unknown" {
		return model.NotTested, "The visible H100 family does not resolve the exact declared variant; no allocation mismatch is inferred from missing variant evidence."
	}
	return model.Fail, "The declared GPU expectation disagrees with the reported selected-device name or exact variant; confirm the allocation before starting."
}

func expectedTokensMatch(expected, actual string) bool {
	wanted := strings.Fields(expected)
	available := map[string]bool{}
	for _, token := range strings.Fields(actual) {
		available[token] = true
	}
	if len(wanted) == 0 {
		return false
	}
	for _, token := range wanted {
		if !available[token] {
			return false
		}
	}
	return true
}

func stableResource(obs []model.Observation) (string, bool) {
	resources := map[string]bool{}
	for _, o := range obs {
		if scalarField(o) == "uuid" && o.Status == model.Pass {
			v, ok := o.Value.(string)
			if ok && fullGPUUUID.MatchString(v) && strings.EqualFold(v, o.ResourceID) {
				resources[o.ResourceID] = true
			}
		}
	}
	if len(resources) != 1 {
		return "", false
	}
	for r := range resources {
		return r, true
	}
	return "", false
}
func contaminatedIdentity(obs []model.Observation, resource string) bool {
	for _, o := range obs {
		if (o.CheckID == "A07" || scalarField(o) == "uuid") && o.Status == model.Contaminated && (o.ResourceID == resource || resource == "") {
			return true
		}
	}
	return false
}
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case float32:
		return float64(n), !math.IsNaN(float64(n)) && !math.IsInf(float64(n), 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint:
		return float64(n), true
	case json.Number:
		value, e := n.Float64()
		return value, e == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
	}
	return 0, false
}
func state(v any) (bool, bool) {
	switch modeString(v) {
	case "true", "yes", "enabled", "pending", "1":
		return true, true
	case "false", "no", "disabled", "not pending", "0":
		return false, true
	}
	return false, false
}

// Idle means sufficient reported idle evidence to proceed, not proof that no
// hidden workload or tenant exists. A busy supported signal overrides a quiet one.
func Idle(pre []model.Observation) (bool, string) {
	resource, ok := stableResource(pre)
	if !ok || contaminatedIdentity(pre, resource) {
		return false, "Idle state is unverified because stable selected-device identity is missing or contaminated."
	}
	observed := false
	if o, ok := passField(pre, resource, "utilization_gpu_percent"); ok {
		if n, valid := number(o.Value); valid && n >= 0 && n <= 100 {
			observed = true
			if n > 10 {
				return false, "Reported GPU utilization exceeds the 10% idle-start policy; wait for the selected resource to become idle."
			}
		}
	}
	if o, ok := passField(pre, resource, "compute_process_count"); ok {
		if n, valid := counter(o.Value); valid {
			observed = true
			if n > 0 {
				return false, "Visible compute processes are reported on the selected device; do not overlap the probe with them."
			}
		}
	}
	if !observed {
		return false, "Neither usable utilization nor compute-process count is available; idle state remains unverified."
	}
	return true, "Available selected-device utilization/process observations meet the idle-start policy; hidden activity and subsequent contention remain possible."
}

// Busy consent relaxes only activity policy, never identity or sensor availability.
func busyOverrideEligible(pre []model.Observation) bool {
	resource, ok := stableResource(pre)
	if !ok || contaminatedIdentity(pre, resource) {
		return false
	}
	if observation, ok := passField(pre, resource, "utilization_gpu_percent"); ok {
		if value, valid := number(observation.Value); valid && value >= 0 && value <= 100 {
			return true
		}
	}
	if observation, ok := passField(pre, resource, "compute_process_count"); ok {
		_, valid := counter(observation.Value)
		return valid
	}
	return false
}

// Safety returns stop=true only for a selected-resource safety/continuity gate.
// It never diagnoses a bad GPU from low clocks, power draw, a fan, or temperature alone.
func Safety(pre, sample []model.Observation, maxTemp float64) (bool, string) {
	resource, ok := stableResource(pre)
	if !ok {
		return true, "Stable selected-device identity is unavailable; active testing cannot continue safely."
	}
	if contaminatedIdentity(pre, resource) || contaminatedIdentity(sample, resource) {
		return true, "Selected-device identity evidence is contaminated; stop the active worker."
	}
	current, ok := stableResource(sample)
	if !ok || current != resource {
		return true, "The active sample does not preserve the selected UUID; target continuity is unresolved."
	}
	for _, key := range []string{"row_remap_failure", "row_remap_pending", "retirement_pending"} {
		if o, ok := passField(sample, resource, key); ok {
			if v, known := state(o.Value); known && v {
				return true, "Reported " + key + " is active on the selected device; stop for provider maintenance/investigation without inferring a physical cause."
			}
		}
	}
	before, bok := passField(pre, resource, "ecc_uncorrected_volatile")
	after, aok := passField(sample, resource, "ecc_uncorrected_volatile")
	if bok && aok {
		b, bvalid := counter(before.Value)
		a, avalid := counter(after.Value)
		if bvalid && avalid && a > b {
			return true, "The selected device's uncorrected volatile counter increased. Stop as a precaution; the observed difference is conditional on counter-epoch continuity and does not establish a physical defect."
		}
	}
	threshold := maxTemp
	basis := "configured temperature stop policy"
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 {
		return true, "Invalid configured temperature stop policy."
	}
	{
		if o, ok := passField(pre, resource, "temperature_slowdown_c"); ok {
			if n, valid := number(o.Value); valid && n > 0 && (threshold == 0 || n < threshold) {
				threshold = n
				basis = "device-reported slowdown threshold"
			}
		}
	}
	if threshold > 0 {
		o, available := passField(sample, resource, "temperature_gpu_c")
		if !available {
			return true, "Current selected-device core temperature is missing, denied or contaminated; the " + basis + " cannot be enforced. Stop because of safety uncertainty, not an inferred thermal defect."
		}
		n, valid := number(o.Value)
		if !valid || n < 0 {
			return true, "Current selected-device core temperature is invalid; the " + basis + " cannot be enforced. Stop because of safety uncertainty."
		}
		if n >= threshold {
			return true, "Core temperature reached the " + basis + "; stop the bounded load without treating this observation as a generic thermal defect."
		}
	}
	return false, "No supported selected-device stop condition was observed in this sample; unavailable fields and counter history remain unresolved."
}

func counter(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case uint:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	case int32:
		if n >= 0 {
			return uint64(n), true
		}
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n < 9007199254740992 && math.Trunc(n) == n {
			return uint64(n), true
		}
	case json.Number:
		x, e := strconv.ParseUint(string(n), 10, 64)
		return x, e == nil
	}
	return 0, false
}
func counterMap(v any) (map[string]uint64, bool) {
	out := map[string]uint64{}
	switch m := v.(type) {
	case map[string]uint64:
		for k, n := range m {
			out[k] = n
		}
	case map[string]any:
		for k, x := range m {
			n, ok := counter(x)
			if !ok {
				return nil, false
			}
			out[k] = n
		}
	case map[string]float64:
		for k, x := range m {
			n, ok := counter(x)
			if !ok {
				return nil, false
			}
			out[k] = n
		}
	default:
		return nil, false
	}
	return out, len(out) > 0
}

// Deltas retain the arithmetic difference separately from whether the epoch,
// resource scope, source units and observation order make it an eligible delta.
func Deltas(pre, post []model.Observation) []model.Observation {
	out := []model.Observation{}
	resource, stable := stableResource(pre)
	postResource, postStable := stableResource(post)
	if resource == "" {
		resource = "selected-gpu"
	}
	if hasGPUCounterSnapshots(pre) || hasGPUCounterSnapshots(post) {
		for _, s := range []struct{ field, check, unit string }{{"ecc_corrected_volatile", "B02", "errors"}, {"ecc_uncorrected_volatile", "B03", "errors"}, {"pcie_replay_count", "D09", "events"}} {
			o := deltaOne(pre, post, resource, s.field, s.check, s.unit, false)
			if !stable || !postStable || postResource != resource || contaminatedIdentity(pre, resource) || contaminatedIdentity(post, resource) {
				o.Status = model.Contaminated
				o.Message = "Counter snapshots do not preserve a unique selected-device UUID; no arithmetic difference is eligible for this target."
			}
			// Driver changes constitute an observed discontinuity even if the numeric
			// counter happened to be nondecreasing after the change.
			if a, ok := passField(pre, resource, "driver_version"); ok {
				if b, bok := passField(post, resource, "driver_version"); bok && modeString(a.Value) != modeString(b.Value) {
					o.Status = model.Contaminated
					o.Message = "Driver version changed between snapshots; counter epoch and scope continuity are not established."
				}
			}
			out = append(out, o)
		}
	}
	out = append(out, deltaOne(pre, post, "process-host", "cgroup_cpu_stat", "E02", "mixed documented CPU counters", true))
	_, hasV2pre := uniqueField(pre, "process-host", "cgroup_memory_events")
	_, hasV2post := uniqueField(post, "process-host", "cgroup_memory_events")
	if hasV2pre || hasV2post {
		out = append(out, deltaOne(pre, post, "process-host", "cgroup_memory_events", "E06", "events", true))
	} else {
		out = append(out, deltaOne(pre, post, "process-host", "cgroup_memory_failcnt", "E06", "limit hits; not OOM kills", false))
	}
	return out
}

func deltaOne(pre, post []model.Observation, resource, name, check, unit string, isMap bool) model.Observation {
	a, aok := uniqueField(pre, resource, name)
	b, bok := uniqueField(post, resource, name)
	o := guardObservation(check, "delta."+name, resource, model.NotTested, nil, "Before/after counter evidence is unavailable; no absent value is replaced with zero.")
	o.Unit = unit
	o.SampleCount = 0
	o.Conditions = map[string]any{"field": name, "derived": true, "counter_epoch": "unknown", "arithmetic_difference": "conditional on unchanged counter epoch, scope and semantics"}
	for _, x := range []model.Observation{a, b} {
		if x.ID != "" {
			o.EvidenceRefs = append(o.EvidenceRefs, x.ID)
		}
	}
	if !aok || !bok {
		if duplicateField(pre, resource, name) || duplicateField(post, resource, name) {
			o.Status = model.Contaminated
			o.Message = "Multiple counter snapshots match the requested boundary; no passing sample was selected opportunistically."
		}
		return o
	}
	o.SampleCount = 2
	if a.Status != model.Pass || b.Status != model.Pass {
		o.Status = missingDeltaStatus(a.Status, b.Status)
		o.Message = "One or both counter snapshots are missing, denied, unsupported or invalid; no eligible interval delta is available."
		return o
	}
	if a.Unit != b.Unit || a.ResourceID != b.ResourceID || (a.Scope != "" && b.Scope != "" && a.Scope != b.Scope) {
		o.Status = model.Contaminated
		o.Message = "Counter units or resource identity changed; snapshots are not comparable."
		return o
	}
	if a.StartUTC.IsZero() || b.StartUTC.IsZero() || !b.StartUTC.After(a.StartUTC) {
		o.Status = model.NotTested
		o.Message = "Counter observation order/timestamps are unavailable or non-increasing; interval attribution remains unverified."
		return o
	}
	o.StartUTC = a.StartUTC
	o.DurationMS = float64(b.StartUTC.Sub(a.StartUTC).Nanoseconds()) / 1e6
	epochA, knownA := epoch(pre, a)
	epochB, knownB := epoch(post, b)
	if knownA && knownB && epochA != epochB {
		o.Status = model.Contaminated
		o.Message = "An exposed counter epoch/scope identifier changed; subtraction would cross a discontinuity."
		return o
	}
	epochKnown := knownA && knownB && epochA == epochB
	if epochKnown {
		o.Conditions["counter_epoch"] = "verified equal exposed identifiers"
	}
	positive := false
	if isMap {
		am, validA := counterMap(a.Value)
		bm, validB := counterMap(b.Value)
		if !validA || !validB {
			o.Message = "Counter map contains invalid or imprecise values; no zeros are inferred."
			return o
		}
		if len(am) != len(bm) {
			o.Status = model.Contaminated
			o.Message = "Counter-map coverage changed between snapshots; no missing keys were treated as zero."
			return o
		}
		delta := map[string]uint64{}
		keys := []string{}
		for k := range am {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			bv, ok := bm[k]
			if !ok {
				o.Status = model.Contaminated
				o.Message = "Counter-map keys changed; no missing value was treated as zero."
				return o
			}
			if bv < am[k] {
				o.Status = model.Contaminated
				o.Message = "A counter decreased, reset or changed scope; this discontinuity is not an improvement or zero delta."
				return o
			}
			delta[k] = bv - am[k]
			if name != "cgroup_cpu_stat" || k == "nr_throttled" || k == "throttled_usec" || k == "throttled_time" {
				positive = positive || delta[k] > 0
			}
		}
		o.Value = map[string]any{"before": am, "after": bm, "conditional_delta": delta}
	} else {
		av, validA := counter(a.Value)
		bv, validB := counter(b.Value)
		if !validA || !validB {
			o.Message = "Counter is absent, invalid, fractional or beyond exact floating-point integer precision; no difference is inferred."
			return o
		}
		if bv < av {
			o.Status = model.Contaminated
			o.Message = "Counter decreased, reset, wrapped or changed scope; this is not an improvement or zero delta."
			return o
		}
		difference := bv - av
		positive = difference > 0
		o.Value = map[string]any{"before": av, "after": bv, "conditional_delta": difference}
	}
	o.Status = model.NotTested
	o.Message = "The arithmetic difference is recorded conditionally; a stable UUID and nondecreasing totals cannot exclude an intervening reset or scope change. No verified zero-error interval is claimed."
	if epochKnown {
		o.Status = model.Pass
		o.Message = "Before/after counters share the exposed epoch identifier and scope; the recorded difference applies only to these observations and their host-mediated trust boundary."
	}
	if positive {
		o.Status = model.Warning
		o.Message = "A positive conditional counter difference was observed; epoch uncertainty, historical scope and alternative causes remain explicit."
		if name == "ecc_uncorrected_volatile" {
			o.Status = model.Fail
			o.Message = "The selected device's uncorrected volatile counter increased; stop as a precaution. The numerical difference is conditional on epoch continuity, and physical cause is unproven."
		}
	}
	return o
}
func duplicateField(obs []model.Observation, resource, name string) bool {
	count := 0
	for _, o := range obs {
		if o.ResourceID == resource && scalarField(o) == name {
			count++
		}
	}
	return count > 1
}
func missingDeltaStatus(a, b model.Status) model.Status {
	for _, s := range []model.Status{model.Contaminated, model.TimeBudgetExhausted, model.PermissionDenied, model.DependencyMissing, model.Unsupported, model.ToolError} {
		if a == s || b == s {
			return s
		}
	}
	return model.NotTested
}
func epoch(obs []model.Observation, o model.Observation) (string, bool) {
	for _, key := range []string{"counter_epoch_id", "epoch_id"} {
		if s, ok := o.Conditions[key].(string); ok && s != "" {
			return s, true
		}
	}
	if e, ok := passField(obs, o.ResourceID, "counter_epoch"); ok {
		if s, ok := e.Value.(string); ok && s != "" && s != "unknown" {
			return s, true
		}
	}
	return "", false
}

func hasGPUCounterSnapshots(obs []model.Observation) bool {
	for _, o := range obs {
		switch scalarField(o) {
		case "uuid", "ecc_corrected_volatile", "ecc_uncorrected_volatile", "pcie_replay_count":
			return true
		}
	}
	return false
}
