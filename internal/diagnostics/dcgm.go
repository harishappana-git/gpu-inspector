package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

const supportedDCGMVersion = "4.6.0"
const localDCGMHost = "127.0.0.1"

var versionPattern = regexp.MustCompile(`(?im)\bversion\s*:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$`)

func dcgm(ctx context.Context, d model.Device, opts Options) model.Observation {
	start := time.Now()
	o := observation("B11", "dcgm.selected_software", d, start)
	o.Conditions["field"] = "vendor_diagnostics"
	o.Conditions["stop_active"] = opts.DCGMEnabled
	o.Conditions["suite"] = "level-1 software deployment checks only"
	o.Conditions["host"] = "existing loopback hostengine"
	o.Conditions["supported_dcgm_version"] = supportedDCGMVersion
	if !opts.DCGMEnabled {
		return finish(o, start, model.NotTested, "DCGM software diagnostics were not explicitly enabled.")
	}
	if !validTarget(d) || !(strings.HasPrefix(strings.ToLower(d.SKU), "h100-") || strings.Contains(strings.ToLower(d.Name), "h100")) || d.MIGMode != "disabled" || (d.VirtualizationMode != "none" && d.VirtualizationMode != "passthrough") {
		return finish(o, start, model.Unsupported, "DCGM dispatch requires a verified full physical H100 UUID/PCI identity, disabled MIG and known non-vGPU mode.")
	}
	ctx, cancel := bounded(ctx, opts.Timeout, 40*time.Second, 60*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) < 4*time.Second {
		return finish(o, start, model.TimeBudgetExhausted, "Insufficient time remains for bounded DCGM discovery, execution and continuity checks.")
	}
	versionResult := runTool(ctx, opts, "dcgmi", []string{"--version"}, 16<<10)
	if status := resultStatus(ctx, versionResult); status != model.Pass {
		return finish(o, start, status, "The installed DCGM version could not be read; no diagnostic was launched.")
	}
	versions := versionPattern.FindAllStringSubmatch(string(versionResult.Stdout), -1)
	if len(versions) != 1 || versions[0][1] != supportedDCGMVersion {
		return finish(o, start, model.Unsupported, "This adapter accepts only installed DCGM 4.6.0; other CLI/JSON versions require separate fixture validation.")
	}
	engineVersion := runTool(ctx, opts, "dcgmi", []string{"--vv", "--host", localDCGMHost}, 16<<10)
	if status := resultStatus(ctx, engineVersion); status != model.Pass {
		return finish(o, start, status, "The existing local DCGM hostengine version was unavailable; no diagnostic or service was started.")
	}
	if !supportedEngineVersion(engineVersion.Stdout) {
		return finish(o, start, model.Unsupported, "Both the installed client and existing loopback hostengine must report DCGM 4.6.0 before diagnostic dispatch.")
	}
	list := runTool(ctx, opts, "dcgmi", []string{"discovery", "--list", "--host", localDCGMHost}, 256<<10)
	if status := resultStatus(ctx, list); status != model.Pass {
		return finish(o, start, status, "The existing local DCGM hostengine was unavailable; no service or embedded hostengine was started.")
	}
	id, ok := selectedDCGMID(list.Stdout, d)
	if !ok {
		return finish(o, start, model.Contaminated, "DCGM discovery did not uniquely map the selected UUID and PCI address; diagnostic dispatch was refused.")
	}
	o.Conditions["dcgm_entity_id"] = id
	verifyArgs := []string{"discovery", "--info", "a", "--gpuid", strconv.Itoa(id), "--host", localDCGMHost}
	before := runTool(ctx, opts, "dcgmi", verifyArgs, 64<<10)
	if status := resultStatus(ctx, before); status != model.Pass {
		return finish(o, start, status, "The immediate DCGM identity query did not complete; no diagnostic was launched.")
	}
	if !selectedAttributes(before.Stdout, d) {
		return finish(o, start, model.Contaminated, "The selected DCGM entity failed the immediate UUID/PCI continuity check; no diagnostic was launched.")
	}
	// Keep a cleanup/identity-check margin beneath the parent's absolute budget.
	seconds := int(time.Until(deadline).Seconds()) - 2
	if seconds < 1 {
		return finish(o, start, model.TimeBudgetExhausted, "No bounded DCGM execution interval remains after discovery.")
	}
	o.Conditions["native_timeout_seconds"] = seconds
	o.Conditions["daemon_completion_known"] = false
	args := []string{"diag", "--run", "1", "--entity-id", "gpu:" + strconv.Itoa(id), "--host", localDCGMHost, "--timeout", strconv.Itoa(seconds), "--enable-heartbeat", "--debugLevel", "NONE", "--statsonfail", "--json"}
	r := runTool(ctx, opts, "dcgmi", args, 1<<20)
	status := resultStatus(ctx, r)
	// Linux exposes DCGM_ST_TIMEOUT (-11) as the low eight exit-status bits.
	if status == model.TimeBudgetExhausted || r.ExitCode == 245 {
		return finish(o, start, model.TimeBudgetExhausted, "The diagnostic client was interrupted or exceeded its bound. The existing daemon received a native timeout and heartbeat requirement, but immediate daemon-side completion is unverified; stop further active tests.")
	}
	if r.Truncated {
		return finish(o, start, model.ToolError, "DCGM output exceeded its bound; diagnostic completion and scope are unverified. Stop further active tests.")
	}
	if status == model.PermissionDenied || status == model.DependencyMissing {
		return finish(o, start, status, "The selected DCGM diagnostic was unavailable or denied; no healthy result was inferred.")
	}
	tests, parsedStatus, parseOK := parseDCGMJSON(r.Stdout, id)
	if !parseOK {
		return finish(o, start, parsedStatus, "DCGM did not return a recognized, single-selected-entity 4.6.0 software result; no result was inferred and further active tests must stop.")
	}
	// Only documented diagnostic outcomes may accompany a structured result.
	if r.ExitCode != 0 && r.ExitCode != 226 && r.ExitCode != 205 {
		return finish(o, start, model.ToolError, "DCGM returned an execution error outside recognized diagnostic-result statuses; no completed check was inferred.")
	}
	after := runTool(ctx, opts, "dcgmi", verifyArgs, 64<<10)
	if resultStatus(ctx, after) != model.Pass || !selectedAttributes(after.Stdout, d) {
		return finish(o, start, model.Contaminated, "DCGM result identity could not be revalidated against the selected UUID/PCI; the result cannot establish device continuity.")
	}
	o.Conditions["daemon_completion_known"] = true
	o.Value = map[string]any{"dcgm_version": supportedDCGMVersion, "suite_level": 1, "tests": tests, "vendor_exit_code": r.ExitCode, "hardware_stress_performed": false}
	o.SampleCount = len(tests)
	if r.ExitCode != 0 && parsedStatus == model.Pass {
		parsedStatus = model.Warning
	}
	o.Conditions["stop_active"] = parsedStatus != model.Pass
	message := "The selected-entity DCGM software checks completed with reported passes. This checks deployment readiness, not H100 hardware stress, performance or physical health."
	if parsedStatus != model.Pass {
		message = "Selected-entity DCGM software checks reported a warning, failure or incomplete coverage. Vendor statuses are retained without attributing a physical GPU defect; stop further active tests."
	}
	return finish(o, start, parsedStatus, message)
}

type discoveredGPU struct {
	id        int
	uuid, pci string
	bad       bool
}

func supportedEngineVersion(data []byte) bool {
	section := ""
	versions := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "Local build info:" || line == "Hostengine build info:" {
			if _, exists := versions[line]; exists {
				return false
			}
			section = line
			versions[section] = ""
			continue
		}
		if strings.HasPrefix(line, "Version") {
			match := versionPattern.FindStringSubmatch(line)
			if section == "" || len(match) != 2 || versions[section] != "" {
				return false
			}
			versions[section] = match[1]
		}
	}
	return len(versions) == 2 && versions["Local build info:"] == supportedDCGMVersion && versions["Hostengine build info:"] == supportedDCGMVersion
}

func selectedDCGMID(data []byte, d model.Device) (int, bool) {
	var devices []discoveredGPU
	current := -1
	gpuSection := false
	for _, line := range strings.Split(string(data), "\n") {
		cols := strings.Split(line, "|")
		if len(cols) != 4 {
			continue
		}
		left, right := strings.TrimSpace(cols[1]), strings.TrimSpace(cols[2])
		if left == "GPU ID" {
			gpuSection = true
			current = -1
			continue
		}
		if left == "Switch ID" || left == "CPU ID" || left == "ConnectX" {
			gpuSection = false
			current = -1
			continue
		}
		if !gpuSection {
			continue
		}
		if left != "" {
			id, err := strconv.Atoi(left)
			if err != nil || id < 0 || id > 1023 {
				return 0, false
			}
			devices = append(devices, discoveredGPU{id: id})
			current = len(devices) - 1
		}
		if current < 0 {
			continue
		}
		entry := &devices[current]
		switch {
		case strings.HasPrefix(right, "Device UUID:"):
			if entry.uuid != "" {
				entry.bad = true
			}
			entry.uuid = strings.TrimSpace(strings.TrimPrefix(right, "Device UUID:"))
		case strings.HasPrefix(right, "PCI Bus ID:"):
			if entry.pci != "" {
				entry.bad = true
			}
			entry.pci = strings.TrimSpace(strings.TrimPrefix(right, "PCI Bus ID:"))
		case strings.HasPrefix(right, "Error:") || strings.HasPrefix(right, "Status:"):
			entry.bad = true
		}
	}
	pci, _ := canonicalPCI(d.PCIAddress)
	selected := -1
	seenIDs := map[int]bool{}
	seenUUID := map[string]bool{}
	for _, entry := range devices {
		if seenIDs[entry.id] {
			return 0, false
		}
		seenIDs[entry.id] = true
		key := strings.ToLower(entry.uuid)
		if key != "" && seenUUID[key] {
			return 0, false
		}
		seenUUID[key] = true
		actual, ok := canonicalPCI(entry.pci)
		if strings.EqualFold(entry.uuid, d.UUID) {
			if selected >= 0 || entry.bad || !ok || actual != pci {
				return 0, false
			}
			selected = entry.id
		}
	}
	return selected, selected >= 0
}

func selectedAttributes(data []byte, d model.Device) bool {
	uuid, pci := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		cols := strings.Split(line, "|")
		if len(cols) != 4 {
			continue
		}
		key, value := strings.TrimSpace(cols[1]), strings.TrimSpace(cols[2])
		if key == "UUID" {
			if uuid != "" {
				return false
			}
			uuid = value
		}
		if key == "PCI Bus ID" {
			if pci != "" {
				return false
			}
			pci = value
		}
	}
	want, ok := canonicalPCI(d.PCIAddress)
	got, actualOK := canonicalPCI(pci)
	return ok && actualOK && got == want && fullUUID.MatchString(uuid) && strings.EqualFold(uuid, d.UUID)
}

type dcgmResult struct {
	Status      string  `json:"status"`
	EntityGroup *uint32 `json:"entity_group_id"`
	EntityID    *uint32 `json:"entity_id"`
	Warnings    []struct {
		ID       *uint32 `json:"error_id"`
		Category *uint32 `json:"error_category"`
		Severity *uint32 `json:"error_severity"`
	} `json:"warnings"`
}
type dcgmTest struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	VendorStatus string   `json:"vendor_status"`
	Scope        string   `json:"scope"`
	ErrorCodes   []uint32 `json:"error_codes,omitempty"`
}

func parseDCGMJSON(data []byte, id int) ([]dcgmTest, model.Status, bool) {
	var doc struct {
		Metadata struct {
			Version string `json:"version"`
		} `json:"metadata"`
		Groups []struct {
			Group    *uint32 `json:"entity_group_id"`
			Entities []struct {
				ID *uint32 `json:"entity_id"`
			} `json:"entities"`
		} `json:"entity_groups"`
		Diagnostic struct {
			RuntimeError string `json:"runtime_error"`
			Categories   []struct {
				Category string `json:"category"`
				Tests    []struct {
					Name    string       `json:"name"`
					Results []dcgmResult `json:"results"`
					Summary *dcgmResult  `json:"test_summary"`
				} `json:"tests"`
			} `json:"test_categories"`
		} `json:"DCGM Diagnostic"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&doc) != nil {
		return nil, model.ToolError, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, model.ToolError, false
	}
	if doc.Metadata.Version != supportedDCGMVersion || doc.Diagnostic.RuntimeError != "" {
		return nil, model.ToolError, false
	}
	if len(doc.Groups) != 1 || doc.Groups[0].Group == nil || *doc.Groups[0].Group != 1 || len(doc.Groups[0].Entities) != 1 || doc.Groups[0].Entities[0].ID == nil || int(*doc.Groups[0].Entities[0].ID) != id {
		return nil, model.Contaminated, false
	}
	tests := []dcgmTest{}
	overall := model.Pass
	for _, category := range doc.Diagnostic.Categories {
		if !strings.EqualFold(category.Category, "Deployment") {
			return nil, model.Contaminated, false
		}
		for _, test := range category.Tests {
			if len(tests) >= 128 || test.Name == "" {
				return nil, model.ToolError, false
			}
			results := test.Results
			if test.Summary != nil {
				results = append(results, *test.Summary)
			}
			if len(results) == 0 {
				return nil, model.ToolError, false
			}
			for _, r := range results {
				if len(tests) >= 128 {
					return nil, model.ToolError, false
				}
				scope := "software deployment context"
				if r.EntityGroup != nil || r.EntityID != nil {
					if r.EntityGroup == nil || r.EntityID == nil || *r.EntityGroup != 1 || int(*r.EntityID) != id {
						return nil, model.Contaminated, false
					}
					scope = "selected GPU"
				}
				switch r.Status {
				case "Pass":
				case "Warn", "Fail", "Skip", "Not Run":
					overall = model.Warning
				default:
					return nil, model.ToolError, false
				}
				codes := []uint32{}
				if len(r.Warnings) > 128 {
					return nil, model.ToolError, false
				}
				for _, w := range r.Warnings {
					if w.ID == nil || w.Category == nil || w.Severity == nil {
						return nil, model.ToolError, false
					}
					codes = append(codes, *w.ID)
				}
				if len(codes) > 0 {
					overall = model.Warning
				}
				name := allowlistedTestName(test.Name)
				if name == "software subcheck (name omitted)" {
					overall = model.Warning
				}
				tests = append(tests, dcgmTest{len(tests) + 1, name, r.Status, scope, codes})
			}
		}
	}
	if len(tests) == 0 {
		return nil, model.ToolError, false
	}
	return tests, overall, true
}

func allowlistedTestName(name string) string {
	for _, known := range []string{"software", "Denylist", "Blacklist", "NVML Library", "CUDA Main Library", "CUDA Runtime Library", "Permissions and OS-related Blocks", "Persistence Mode", "Environmental Variables", "Page Retirement", "Page Retirement/Row Remapping", "Graphics Processes", "Inforom", "Fabric Manager"} {
		if strings.EqualFold(name, known) {
			return known
		}
	}
	return "software subcheck (name omitted)"
}
