package scan

import (
	"testing"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestXidAttributionRequiresBothUUIDAndPCIBoundaries(t *testing.T) {
	d := guardDevice()
	boundary := []model.Observation{
		fixtureObservation("A07", "uuid", d.UUID, d.UUID, model.Pass),
		fixtureObservation("A07", "pci_address", d.UUID, d.PCIAddress, model.Pass),
	}
	if !xidContinuity(d, boundary, boundary, boundary) {
		t.Fatal("consistent selected identity rejected")
	}
	for _, which := range []string{"missing", "reassigned", "denied", "changed during scan"} {
		t.Run(which, func(t *testing.T) {
			after := append([]model.Observation(nil), boundary...)
			all := append([]model.Observation(nil), boundary...)
			switch which {
			case "missing":
				after = after[:1]
			case "reassigned":
				after[0].Value = guardPeer
			case "denied":
				after[1].Status = model.PermissionDenied
			case "changed during scan":
				all = append(all, baseObservation("A07", "guard.recheck", model.Contaminated, "fixture target changed"))
			}
			if xidContinuity(d, boundary, after, all) {
				t.Fatal("kernel PCI evidence could be attributed across uncertain UUID continuity")
			}
		})
	}
}
