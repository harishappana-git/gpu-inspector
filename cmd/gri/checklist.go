package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/harishappana/gpu-inspector/internal/catalog"
	"github.com/harishappana/gpu-inspector/internal/model"
)

type releaseGate struct {
	ID       string       `json:"id"`
	Status   model.Status `json:"status"`
	Required string       `json:"required_evidence"`
}

type acceptanceChecklist struct {
	Version       string              `json:"checklist_version"`
	ScanID        string              `json:"scan_id"`
	Synthetic     bool                `json:"synthetic"`
	Device        *model.Device       `json:"device,omitempty"`
	Verdict       string              `json:"scan_verdict"`
	Qualified     bool                `json:"release_qualified"`
	Passed        int                 `json:"reported_pass_count"`
	NotApplicable int                 `json:"scoped_not_applicable_count"`
	Remaining     int                 `json:"remaining_scan_check_count"`
	Checks        []model.CheckResult `json:"phase1_scan_checks"`
	ReleaseGates  []releaseGate       `json:"release_gates"`
	Limitations   []string            `json:"limitations"`
}

func makeChecklist(r model.Report) acceptanceChecklist {
	c := acceptanceChecklist{Version: "1.0.0", ScanID: r.ScanID, Synthetic: r.Synthetic, Device: r.Device, Verdict: r.Verdict,
		Checks: []model.CheckResult{}, ReleaseGates: []releaseGate{}, Limitations: []string{
			"A verified report index establishes local artifact integrity, not hardware authenticity or qualification.",
			"Reported PASS means that scan's recorded scope only; warnings and failures require review even when a test completed.",
			"This checklist covers Phase 1 Quick and Standard checks for one selected GPU; node-wide peer, NCCL and cluster tests are future scope.",
			"A single report cannot close the repeated-device, sanitizer, reference, distribution or independently reviewed release gates.",
		}}
	byID := map[string]model.CheckResult{}
	for _, check := range r.Checks {
		byID[check.CheckID] = check
	}
	for _, row := range catalog.All() {
		if row.Stage != "Q" && row.Stage != "S" {
			continue
		}
		check, exists := byID[row.ID]
		if !exists {
			check = model.CheckResult{CheckID: row.ID, Name: row.Name, Stage: row.Stage, Status: model.NotTested, Reason: "No retained check result exists."}
		}
		// A Quick run's skipped Standard rows are unfinished acceptance work,
		// not scoped sensor exemptions. Synthetic results cannot close hardware work.
		if r.Tier != "standard" && row.Stage == "S" {
			check.Status, check.Reason = model.NotTested, "Run the Standard tier to collect this check."
		} else if r.Synthetic && (check.Status == model.Pass || check.Status == model.NotApplicable) {
			check.Status, check.Reason = model.NotTested, "Synthetic fixture; collect actual selected-device evidence."
		}
		if check.Status == model.Pass {
			c.Passed++
		} else if check.Status == model.NotApplicable {
			c.NotApplicable++
		} else {
			c.Remaining++
		}
		c.Checks = append(c.Checks, check)
	}
	for _, gate := range []struct{ id, required string }{
		{"WP1", "Native Linux H100 target-isolation campaign: remapped ordinals, multiple visible GPUs, restricted visibility, MIG refusal, disappearance and cancellation."},
		{"WP2", "Pinned Linux driver/NVML ABI, host/container permissions, journal/DCGM availability and denied-data matrix on the selected H100 variant."},
		{"WP3", "SM90 numerical and controlled-corruption review, memcheck/racecheck/initcheck/synccheck, bounded headroom/cancellation, and final relocated worker/library validation."},
		{"WP4", "Independently tracked healthy allocations and hosts, retained raw runs and reviewed exclusions, signed exact-configuration healthy reference."},
		{"WP5", "Independently labeled false-positive/negative and outcome evaluation; evidence-linked findings and provider-facing draft review."},
		{"WP6", "Pinned dependency/license inventory, production key custody/rotation, reproducible signed distribution and independent privacy/cleanup review."},
		{"WP7", "Authorized H100 rental campaign retaining all attempts, actual duration/cost, checksums, limitations and final human release decision."},
	} {
		c.ReleaseGates = append(c.ReleaseGates, releaseGate{ID: gate.id, Status: model.NotTested, Required: gate.required})
	}
	return c
}

func checklistCommand(args []string, out, stderr io.Writer) error {
	f := flags("checklist", stderr)
	path := f.String("report", "", "report.json inside a verified private evidence directory")
	asJSON := f.Bool("json", false, "emit all Phase 1 check states and remaining release gates as JSON")
	all := f.Bool("all", false, "include reported passes and scoped exemptions in text output")
	if err := parse(f, args); err != nil {
		return err
	}
	r, err := loadVerified(*path)
	if err != nil {
		return err
	}
	c := makeChecklist(r)
	if *asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(c)
	}
	fmt.Fprintf(out, "Phase 1 remaining checklist — scan %s\n", c.ScanID)
	fmt.Fprintf(out, "Recorded passes: %d; scoped N/A: %d; pending/review: %d. Release qualified: false.\n", c.Passed, c.NotApplicable, c.Remaining)
	if c.Synthetic {
		fmt.Fprintln(out, "SYNTHETIC report: no hardware qualification evidence.")
	}
	for _, check := range c.Checks {
		if !*all && (check.Status == model.Pass || check.Status == model.NotApplicable) {
			continue
		}
		fmt.Fprintf(out, "[%s] %s %s: %s\n", check.Status, check.CheckID, check.Name, check.Reason)
	}
	fmt.Fprintln(out, "Release gates requiring a separate qualification campaign:")
	for _, gate := range c.ReleaseGates {
		fmt.Fprintf(out, "[%s] %s: %s\n", gate.Status, gate.ID, gate.Required)
	}
	fmt.Fprintln(out, "Procedure: docs/H100_SINGLE_NODE.md and docs/ACCEPTANCE.md. Command success means checklist generation succeeded, not GPU acceptance.")
	return nil
}
