package rules

import (
	"testing"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestSelectedDiagnosticWarningsSurviveSnapshotHistoryGap(t *testing.T) {
	r, _ := reviewQualifiedEvidence()
	r.Tier = "standard"
	r.Observations = append(r.Observations, model.Observation{ID: "snapshot-history", CheckID: "B06", MethodID: "events.history", Status: model.NotTested, Message: "Snapshot does not collect events"})
	for _, tc := range []struct{ check, method string }{{"B06", "linux.xid_scan_interval"}, {"B11", "dcgm.selected_software"}, {"H04", "advisory.driver_issue"}} {
		r.Observations = append(r.Observations, model.Observation{ID: "diagnostic-" + tc.check, CheckID: tc.check, MethodID: tc.method, ResourceID: r.Device.UUID, Version: model.MethodVersion, StartUTC: r.StartedUTC, Status: model.Warning, SourceKind: "reported", Message: "Fixture symptom requiring review; no physical cause established"})
	}
	Evaluate(&r, nil)
	for _, id := range []string{"B06", "B11", "H04"} {
		found := false
		for _, f := range r.Findings {
			if f.CheckID == id {
				found = true
				if f.Severity != "WARNING" || len(f.EvidenceRefs) != 1 || f.EvidenceRefs[0] != "diagnostic-"+id {
					t.Fatalf("wrong diagnostic finding: %+v", f)
				}
			}
		}
		if !found {
			t.Fatalf("diagnostic %s warning was lost", id)
		}
	}
	for _, c := range r.Checks {
		if c.CheckID == "B06" && c.Status != model.Warning {
			t.Fatal("old snapshot history placeholder masked interval event evidence")
		}
	}
}
