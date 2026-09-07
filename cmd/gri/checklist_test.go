package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestChecklistCannotQualifySyntheticOrSkippedStandard(t *testing.T) {
	r := model.Report{Tier: "quick", Synthetic: true, Checks: []model.CheckResult{
		{CheckID: "B07", Status: model.Pass}, {CheckID: "C04", Status: model.NotApplicable},
	}}
	c := makeChecklist(r)
	if c.Qualified || c.Passed != 0 || c.NotApplicable != 0 || len(c.ReleaseGates) != 7 {
		t.Fatalf("synthetic/absent evidence promoted: %+v", c)
	}
	for _, row := range c.Checks {
		if row.Status != model.NotTested {
			t.Fatalf("missing real acceptance work: %+v", row)
		}
	}
	r.Synthetic, r.Tier = false, "standard"
	r.Checks = []model.CheckResult{{CheckID: "B07", Status: model.Pass}, {CheckID: "B06", Status: model.Warning}}
	c = makeChecklist(r)
	if c.Passed != 1 || c.Qualified || c.Remaining == 0 {
		t.Fatal("one observed pass closed missing evidence or release gates")
	}
}

func TestChecklistVerifiesArtifactBeforeUsingResults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	if code, _, stderr := invoke(t, "demo", "--scenario", "clean", "--output", dir); code != 0 {
		t.Fatal(stderr)
	}
	path := filepath.Join(dir, "report.json")
	code, output, stderr := invoke(t, "checklist", "--report", path, "--json")
	if code != 0 {
		t.Fatal(stderr)
	}
	var c acceptanceChecklist
	if err := json.Unmarshal([]byte(output), &c); err != nil || c.Qualified || !c.Synthetic || c.Remaining == 0 {
		t.Fatalf("invalid checklist: %s %v", output, err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := invoke(t, "checklist", "--report", path); code == 0 {
		t.Fatal("modified report accepted as checklist evidence")
	}
}
