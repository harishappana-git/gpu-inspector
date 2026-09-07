package scan

import (
	"context"
	"testing"

	"github.com/harishappana/gpu-inspector/internal/collect"
	"github.com/harishappana/gpu-inspector/internal/diagnostics"
	"github.com/harishappana/gpu-inspector/internal/model"
)

// Only the new full pre-dispatch snapshot is modified. Existing fixture
// telemetry and cancellation hooks keep exercising their original boundaries.
type dcgmSnapshotReviewFixture struct {
	*diagnosticFixture
	change func([]model.Observation) []model.Observation
	after  func()
}

func (f *dcgmSnapshotReviewFixture) GPU(ctx context.Context, d model.Device, o collect.Options) []model.Observation {
	obs := f.integrationBackend.GPU(ctx, d, o)
	if f.change != nil {
		obs = f.change(obs)
	}
	if f.after != nil {
		f.after()
	}
	return obs
}

func TestDCGMRechecksFreshPhysicalModeAndExactIdentity(t *testing.T) {
	for _, mode := range []string{"discovery MIG enabled", "discovery vGPU", "snapshot MIG enabled", "snapshot vGPU", "snapshot mode unavailable", "snapshot mode missing", "snapshot UUID changed", "snapshot PCI changed", "snapshot duplicate mode"} {
		t.Run(mode, func(t *testing.T) {
			o, f, d, pre, j := diagnosticFixtureSetup(t)
			review := &dcgmSnapshotReviewFixture{diagnosticFixture: f}
			switch mode {
			case "discovery MIG enabled":
				f.devices[0].MIGMode = "enabled" // Snapshot still reports disabled.
			case "discovery vGPU":
				f.devices[0].VirtualizationMode = "vgpu" // Snapshot still reports none.
			default:
				review.change = func(obs []model.Observation) []model.Observation {
					switch mode {
					case "snapshot MIG enabled":
						setGuardField(obs, "mig_current", 1.0)
					case "snapshot vGPU":
						setGuardField(obs, "virtualization_mode", 2.0)
					case "snapshot mode unavailable":
						for i := range obs {
							if scalarField(obs[i]) == "mig_current" {
								obs[i].Status, obs[i].Value = model.Unsupported, nil
							}
						}
					case "snapshot mode missing":
						for i := range obs {
							if scalarField(obs[i]) == "virtualization_mode" {
								return append(obs[:i], obs[i+1:]...)
							}
						}
					case "snapshot UUID changed":
						setGuardField(obs, "uuid", guardPeer)
					case "snapshot PCI changed":
						setGuardField(obs, "pci_address", "00000000:02:00.0")
					case "snapshot duplicate mode":
						obs = append(obs, fixtureObservation("A06", "mig_current", d.UUID, 0.0, model.Pass))
					}
					return obs
				}
			}
			got := runDCGM(context.Background(), o, review, &d, pre, j, true)
			if got.Status != model.Contaminated || f.dcgmCalls.Load() != 0 {
				t.Fatalf("stale or contradictory physical scope reached vendor dispatch: %+v calls=%d", got, f.dcgmCalls.Load())
			}
		})
	}
}

func TestDCGMFreshSnapshotCannotEscapeCancellationOrStorageFailure(t *testing.T) {
	for _, mode := range []string{"cancelled", "storage exhausted"} {
		t.Run(mode, func(t *testing.T) {
			o, f, d, pre, j := diagnosticFixtureSetup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			review := &dcgmSnapshotReviewFixture{diagnosticFixture: f, after: func() {
				if mode == "cancelled" {
					cancel()
				} else {
					j.maxBytes = 1
				}
			}}
			got := runDCGM(ctx, o, review, &d, pre, j, true)
			if f.dcgmCalls.Load() != 0 || got.Status == model.Pass {
				t.Fatalf("fresh snapshot bypassed final context/storage gate: %+v", got)
			}
		})
	}
}

func syntheticCompletedDCGM(d model.Device) model.Observation {
	o := fixtureObservation("B11", "dcgm", d.UUID, map[string]any{"vendor_status": "Pass"}, model.Pass)
	o.Conditions["daemon_completion_known"], o.Conditions["stop_active"] = true, false
	return o
}

func TestDCGMWrapperInterruptionClearsStaleCompletedPayload(t *testing.T) {
	for _, mode := range []string{"parent cancellation", "runtime safety"} {
		t.Run(mode, func(t *testing.T) {
			o, f, d, pre, j := diagnosticFixtureSetup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := model.TimeBudgetExhausted
			if mode == "runtime safety" {
				want = model.Contaminated
				f.changeTelemetry = func(n int32, obs []model.Observation) {
					if n >= 2 {
						setGuardField(obs, "temperature_gpu_c", 99.0)
					}
				}
			}
			f.diagnostic = func(diagctx context.Context, device model.Device, _ diagnostics.Options) model.Observation {
				if mode == "parent cancellation" {
					cancel()
				} else {
					<-diagctx.Done()
				}
				return syntheticCompletedDCGM(device)
			}
			got := runDCGM(ctx, o, f, &d, pre, j, true)
			if f.dcgmCalls.Load() != 1 || got.Status != want || got.Value != nil || got.SampleCount != 0 || got.Conditions["daemon_completion_known"] != false || got.Conditions["stop_active"] != true {
				t.Fatalf("interrupted wrapper retained completed vendor evidence: %+v", got)
			}
		})
	}
}

func TestDCGMCompletedPayloadSurvivesOrdinaryCleanup(t *testing.T) {
	o, f, d, pre, j := diagnosticFixtureSetup(t)
	f.diagnostic = func(_ context.Context, device model.Device, _ diagnostics.Options) model.Observation {
		if device.MIGMode != "disabled" || device.VirtualizationMode != "none" {
			t.Fatal("adapter did not receive freshly normalized physical mode")
		}
		return syntheticCompletedDCGM(device)
	}
	got := runDCGM(context.Background(), o, f, &d, pre, j, true)
	if got.Status != model.Pass || got.Value == nil || got.Conditions["daemon_completion_known"] != true || got.Conditions["stop_active"] != false {
		t.Fatalf("normal cleanup invalidated a completed vendor result: %+v", got)
	}
}
