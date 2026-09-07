package report

import (
	"fmt"
	"strings"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func markdown(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(plain(value))
}

// Guide uses reviewed static commands. Untrusted observations are never inserted
// into shell source. Variable assignments below must be completed by the user.
func Guide(r model.Report) string {
	var b strings.Builder
	b.WriteString("# Local verification and remediation guide\n\n")
	fmt.Fprintf(&b, "Scan: %s. Rule pack: %s. Verdict: **%s**.\n\n", markdown(r.ScanID), markdown(r.RuleVersion), markdown(r.Verdict))
	if r.Synthetic {
		b.WriteString("**SYNTHETIC FIXTURE:** this guide describes fixture evidence, not a physical GPU measurement.\n\n")
	}
	b.WriteString("This is a reviewed local action plan. The tool has not changed the GPU, restarted a container, terminated a rental, or sent a provider message. Preserve the report and user data before any later lifecycle action.\n\n")
	b.WriteString("## Prerequisites and permissions\n\nUse the same allocation and selected GPU. Read-only inspection requires access to the exposed NVIDIA management interface; no root permission is requested. Commands depend on the installed NVIDIA driver and nvidia-smi version. A denied or unsupported response remains missing evidence. A later scan may run bounded checks and consume rental time; read its scan plan first.\n\n")
	if r.Device != nil {
		fmt.Fprintf(&b, "Recorded driver: %s. Observed selected ID (local only): `%s`. Confirm that it still identifies the intended allocation.\n\n", markdown(r.Device.DriverVersion), markdown(r.Device.UUID))
	}
	b.WriteString("## Exact read-only commands\n\nFill these variables with the existing private report directory and the current GPU UUID before running the commands. Do not paste provider tokens or credentials.\n\n```sh\nGRI_REPORT_DIR='REPLACE_WITH_PRIVATE_REPORT_DIRECTORY'\nGRI_GPU_UUID='REPLACE_WITH_SELECTED_GPU_UUID'\ngri verify --report-dir \"$GRI_REPORT_DIR\"\nnvidia-smi --version\nnvidia-smi --query-gpu=uuid,name,driver_version,pci.bus_id --format=csv --id \"$GRI_GPU_UUID\"\n```\n\n")
	b.WriteString("On native Windows, use the equivalent PowerShell commands with gri.exe available on PATH:\n\n```powershell\n$GRI_REPORT_DIR = 'REPLACE_WITH_PRIVATE_REPORT_DIRECTORY'\n$GRI_GPU_UUID = 'REPLACE_WITH_SELECTED_GPU_UUID'\ngri.exe verify --report-dir $GRI_REPORT_DIR\nnvidia-smi --version\nnvidia-smi --query-gpu=uuid,name,driver_version,pci.bus_id --format=csv --id $GRI_GPU_UUID\n```\n\n")
	b.WriteString("Expected observations: verification reports matching artifact hashes; the NVIDIA query returns one selected device and its current identity. Hash verification detects changed bytes and does not authenticate the measurement host. If the UUID disappeared, changed, or maps to another allocation, stop and select the allocation again. If a command is unavailable, denied, or unsupported by the reported version, retain that result and ask the provider for the relevant observation. Do not substitute an all-device load test.\n\n")
	for _, finding := range r.Findings {
		b.WriteString(findingGuide(finding))
	}
	if len(r.Findings) == 0 {
		b.WriteString("## Current next action\n\n" + markdown(r.NextAction) + "\n\nNo evidence-backed concern was generated; inspect the missing checks and calibration status before treating this as acceptance.\n\n")
	}
	b.WriteString("## Rollback, retest and escalation\n\nThe commands above read state and require no rollback. They cannot erase an earlier failure. No firmware writes, error-counter clearing, GPU reset, power-policy changes, container replacement or rental termination are generated.\n\nFor a fresh Quick observation, fill a **new, unused** report directory and confirm the selected UUID. Quick retesting does not replace a missing Standard correctness or performance method:\n\n```sh\nGRI_RETEST_DIR='REPLACE_WITH_NEW_PRIVATE_REPORT_DIRECTORY'\ngri scan --device \"$GRI_GPU_UUID\" --tier quick --budget-seconds 120 --output \"$GRI_RETEST_DIR\"\n```\n\nFor active correctness errors, preserve evidence and request the provider's supported confirmation procedure before applying more load. For a reproducible failure, ask the provider to investigate or replace the allocation and include a reviewed redacted export. Impact remains unquantified unless a controlled workload measurement supports it. User-space experiments or container changes need workload-specific instructions, data-persistence review, an undo plan and a controlled retest; this guide does not execute them.\n")
	b.WriteString("\nThe same passive Quick retest in PowerShell:\n\n```powershell\n$GRI_RETEST_DIR = 'REPLACE_WITH_NEW_PRIVATE_REPORT_DIRECTORY'\ngri.exe scan --device $GRI_GPU_UUID --tier quick --budget-seconds 120 --output $GRI_RETEST_DIR\n```\n\nWindows evidence uses protected owner-only ACLs; numeric Unix permission commands do not establish that protection. WDDM desktop contention and unsupported RTX ECC/MIG fields remain explicit limitations. A retest does not change TDR, clocks, power limits or driver mode.\n")
	return b.String()
}

func findingGuide(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Finding %s\n\nApplicable rule: %s. Check: %s. Action: %s. Retest: %s.\n\n", markdown(f.ID), markdown(f.RuleVersion), markdown(f.CheckID), markdown(f.ActionID), markdown(f.RetestID))
	fmt.Fprintf(&b, "Observed fact: %s\n\nRationale: %s\n\nAlternative explanations: %s\n\n", markdown(f.Observation), markdown(f.Interpretation), markdown(strings.Join(f.AlternativeCauses, "; ")))
	fmt.Fprintf(&b, "Observation strength: %s. Root-cause strength: %s. Impact: %s. Basis: %s. Evidence: %s.\n\n", markdown(f.ObservationStrength), markdown(f.CauseStrength), markdown(f.Impact), markdown(f.ImpactBasis), markdown(strings.Join(f.EvidenceRefs, ", ")))
	// These are reviewed playbooks selected only by the deterministic action ID;
	// no command is constructed from an observation or guessed root cause.
	switch f.ActionID {
	case "investigate-correctness":
		b.WriteString("Recommended action: stop the test's load, retain mismatches and new-error deltas, and request the provider's supported selected-device confirmation procedure. Do not clear error counters or reset the GPU. Defer further load until that procedure is established; a fixture failure validates the detector only.\n\n")
	case "provider-maintenance":
		b.WriteString("Recommended action: attach the bounded device-specific evidence and ask the provider to interpret the applicable vendor diagnostic catalog. Historical counters, disclosed caps and idle link states alone do not prove an active physical defect. Host power, reset, firmware or link-register changes require provider handling.\n\n")
	case "confirm-allocation":
		b.WriteString("Recommended action: compare the selected UUID, reported variant, MIG/virtualization mode and user-declared expected SKU. Use the read-only identity query below. If they do not match the rental, ask the provider to confirm the allocation; reported identity is not independent authentication.\n\n")
	case "idle-and-retest":
		b.WriteString("Recommended action: repeat the same supported method when your selected allocation is idle, with matching buffer, math and CPU-placement conditions. Pause only your own workload if appropriate. Record all repetitions and spread. Legitimate sharing, quotas and power policy are alternative explanations; do not terminate unrelated processes.\n\n")
	case "qualify-reference":
		b.WriteString("Recommended action: acquire a qualified reference matching the exact GPU variant, mode, method version, precision and transfer/allocation conditions. Preserve raw samples and independent-host coverage. Until qualification and matching pass, healthy-range judgment and readiness scoring remain withheld. A specification ceiling is not a healthy measured range.\n\n")
	case "compatible-worker":
		b.WriteString("Recommended action: obtain a supported CUDA worker from a trusted build/release, verify its digest and method manifest, and run the known-answer qualification harness before enabling measurements. Unsupported compilation, driver compatibility or math mode remains explicit missing evidence. An unsigned or unqualified binary does not establish trusted benchmark provenance.\n\n")
	case "review-exposure":
		b.WriteString("Recommended action: review the reported local access surface and intended tenancy with the provider. Reachability or a background process alone is not evidence of compromise. Retain read-only configuration observations; this guide does not probe endpoints, extract credentials or alter access controls.\n\n")
	case "adjust-own-workload":
		b.WriteString("Recommended action: match the observed host, memory or shared-memory limit to an actual workload symptom. A controlled reduction in your own application's workers or batch size can test a hypothesis, with the original value retained for undo. Do not assume that a small /dev/shm allocation fails every workload. Container replacement requires data-persistence and resource review; no replacement is executed here.\n\n")
	default:
		b.WriteString("Recommended action: preserve the bounded evidence and obtain the explicitly missing permission, dependency or supported observation. Use the read-only verification below; do not interpret unavailable data as a pass.\n\n")
	}
	b.WriteString("Decision branches: if the read-only identity confirmation changes, reselect the device and retain this report. If a required check remains blocked, obtain the missing capability or supported method and keep the verdict inconclusive. If an active correctness failure or required-check failure persists, stop starting the intended workload and request provider investigation; this does not establish a physical defect. A passing retest is additional evidence and does not delete the original event.\n\n")
	return b.String()
}

func Explain(r model.Report, findingID string) (string, error) {
	for _, f := range r.Findings {
		if f.ID == findingID {
			return findingGuide(f) + "For exact read-only commands, permissions, expected outputs, rollback and provider escalation, use guide.md from the same report directory.\n", nil
		}
	}
	return "", fmt.Errorf("finding %q is not in this report", findingID)
}

// TicketDraft is always local text. Provider details are placeholders supplied
// by the user, and no API or transport is invoked.
func TicketDraft(r model.Report) string {
	redacted, err := Redact(r)
	if err != nil {
		return "Unable to create ticket draft: report could not be safely redacted.\n"
	}
	return ticketText(redacted)
}

func ticketText(r model.Report) string {
	var b strings.Builder
	b.WriteString("# Local provider ticket draft — not submitted\n\nSubject: Request investigation/replacement — GPU allocation [provider allocation ID to be supplied]\n\nAllocation: [provider instance ID supplied by user]\n\n")
	if r.Device != nil {
		fmt.Fprintf(&b, "Observed device: %s | %s | selected ID %s\n\n", markdown(r.Device.Name), markdown(r.Device.SKU), markdown(r.Device.UUID))
	} else {
		b.WriteString("Observed device: selected identity unavailable; no authenticated identity claim.\n\n")
	}
	fmt.Fprintf(&b, "Scan: %s to %s | tool %s | method pack %s | rule pack %s\n\nScope: %s | %s | %s\n\nVerdict: %s\n\n", timestamp(r.StartedUTC), timestamp(r.FinishedUTC), markdown(r.ToolVersion), markdown(r.MethodVersion), markdown(r.RuleVersion), markdown(r.ResourceScope), markdown(r.Tier), markdown(r.Profile), markdown(r.Verdict))
	if r.Synthetic {
		b.WriteString("**SYNTHETIC FIXTURE — this is a software demonstration and not evidence of a rental fault.**\n\n")
	}
	b.WriteString("## Observed issue\n\n")
	seen := map[string]bool{}
	for _, f := range r.Findings {
		// Rules already correlate projections of the same worker invocation.
		// Equal text can describe two independent failures; retain both IDs.
		key := f.ID
		if key == "" {
			key = f.CheckID + "\x00" + f.Observation + "\x00" + strings.Join(f.EvidenceRefs, ",")
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(&b, "- %s (%s): %s Evidence: %s. Observation strength: %s; cause strength: %s.\n", markdown(f.ID), markdown(f.Severity), markdown(f.Observation), markdown(strings.Join(f.EvidenceRefs, ", ")), markdown(f.ObservationStrength), markdown(f.CauseStrength))
	}
	if len(seen) == 0 {
		b.WriteString("No evidence-backed issue has been identified. This draft was explicitly requested; please specify the support question without asserting an unobserved defect.\n")
	}
	fmt.Fprintf(&b, "\n## Comparison\n\nReference status: %s. Performance judgment: %s. ", markdown(r.ReferenceStatus), markdown(r.PerformanceJudgment))
	if r.ReferenceID != "" {
		fmt.Fprintf(&b, "Reference ID: %s. ", markdown(r.ReferenceID))
	}
	b.WriteString("Use only the exact configuration and measurements in the report; no unmatched healthy range or score establishes a defect.\n\n## User impact\n\n")
	seen = map[string]bool{}
	for _, f := range r.Findings {
		if f.Impact != "" && !seen[f.Impact] {
			seen[f.Impact] = true
			fmt.Fprintf(&b, "- %s (basis: %s).\n", markdown(f.Impact), markdown(f.ImpactBasis))
		}
	}
	if len(seen) == 0 {
		b.WriteString("Impact not yet quantified; run the applicable workload check when safe.\n")
	}
	b.WriteString("\n## Checks performed and reproduction\n\n")
	for _, o := range r.Observations {
		fmt.Fprintf(&b, "- %s: %s; method %s/%s; %d samples; %.3f ms; evidence %s.\n", markdown(o.CheckID), o.Status, markdown(o.MethodID), markdown(o.Version), o.SampleCount, o.DurationMS, markdown(o.ID))
	}
	b.WriteString("\nUse guide.md for selected-device verification, prerequisites, controls and retest instructions. No raw output dump is attached.\n\n## Limitations\n\n")
	for _, limitation := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", markdown(limitation))
	}
	if len(r.MissingChecks) > 0 {
		fmt.Fprintf(&b, "- Missing checks: %s.\n", markdown(strings.Join(r.MissingChecks, ", ")))
	}
	b.WriteString("\n## Requested action\n\nPlease investigate this allocation and advise on a supported fix or replacement. Please review any billing adjustment under the applicable policy. No entitlement to a refund is asserted. Do not terminate the allocation or discard attached storage without the renter's approval and data-persistence review.\n\nAttachments to review and add: redacted report and minimal redacted evidence bundle. Artifact hashes are in evidence-index.json; verify them with `gri verify --report-dir DIR`. No provider request has been sent.\n")
	return b.String()
}
