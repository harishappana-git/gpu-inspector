package scan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/advisory"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/collect"
	"github.com/harishappana/gpu-inspector/internal/diagnostics"
	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestDiagnosticOptionsRequireExplicitCompleteSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Options)
	}{
		{"pack without key", func(o *Options) { o.AdvisoryPath = "fixture.json" }},
		{"key without pack", func(o *Options) { o.AdvisoryPublicKey = "fixture.pem" }},
		{"quick advisory", func(o *Options) {
			o.Tier = "quick"
			o.AdvisoryPath = "fixture.json"
			o.AdvisoryPublicKey = "fixture.pem"
		}},
		{"quick DCGM", func(o *Options) { o.Tier = "quick"; o.DCGM = true }},
		{"budget without DCGM", func(o *Options) { o.DCGMBudget = 5 * time.Second }},
		{"negative budget", func(o *Options) { o.DCGM = true; o.DCGMBudget = -time.Second }},
		{"too short budget", func(o *Options) { o.DCGM = true; o.DCGMBudget = 5*time.Second - time.Nanosecond }},
		{"too long budget", func(o *Options) { o.DCGM = true; o.DCGMBudget = 60*time.Second + time.Nanosecond }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := integrationOptions(t)
			o.Tier = "standard"
			tc.change(&o)
			if err := Validate(o); err == nil {
				t.Fatal("invalid diagnostic option combination accepted")
			}
		})
	}
	for _, budget := range []time.Duration{0, 5 * time.Second, 60 * time.Second} {
		o := integrationOptions(t)
		o.Tier = "standard"
		o.DCGM = true
		o.DCGMBudget = budget
		o.AdvisoryPath, o.AdvisoryPublicKey = "fixture.json", "fixture.pem"
		if err := Validate(o); err != nil {
			t.Fatal(err)
		}
	}
}

// All methods stay inside this fixture. These tests must never use localBackend,
// execute DCGM, or inspect actual host kernel logs.
type diagnosticFixture struct {
	*integrationBackend
	discoverCalls, telemetryCalls, dcgmCalls, xidCalls atomic.Int32
	afterDiscover                                      func()
	afterTelemetry                                     func()
	changeTelemetry                                    func(int32, []model.Observation)
	diagnostic                                         func(context.Context, model.Device, diagnostics.Options) model.Observation
}

func (f *diagnosticFixture) Discover(ctx context.Context, o collect.Options) ([]model.Device, []model.Observation) {
	f.discoverCalls.Add(1)
	d, obs := f.integrationBackend.Discover(ctx, o)
	if f.afterDiscover != nil {
		f.afterDiscover()
	}
	return d, obs
}
func (f *diagnosticFixture) Telemetry(ctx context.Context, d model.Device, o collect.Options) []model.Observation {
	n := f.telemetryCalls.Add(1)
	obs := f.integrationBackend.Telemetry(ctx, d, o)
	if f.changeTelemetry != nil {
		f.changeTelemetry(n, obs)
	}
	if f.afterTelemetry != nil {
		f.afterTelemetry()
	}
	return obs
}
func (f *diagnosticFixture) DCGM(ctx context.Context, d model.Device, o diagnostics.Options) model.Observation {
	f.dcgmCalls.Add(1)
	if f.diagnostic != nil {
		return f.diagnostic(ctx, d, o)
	}
	return fixtureObservation("B11", "dcgm", d.UUID, "synthetic adapter result", model.Pass)
}
func (f *diagnosticFixture) Xid(_ context.Context, d model.Device, start, end time.Time, o diagnostics.Options) model.Observation {
	f.xidCalls.Add(1)
	result := fixtureObservation("B06", "xid", d.UUID, nil, model.NotTested)
	result.Conditions["scan_start"], result.Conditions["scan_end"], result.Conditions["timeout"] = start, end, o.Timeout
	return result
}
func diagnosticJournal(t *testing.T) *journal {
	t.Helper()
	j, err := newJournal(filepath.Join(t.TempDir(), "evidence"), "synthetic-diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.close(); err != nil {
			t.Error(err)
		}
	})
	return j
}
func diagnosticFixtureSetup(t *testing.T) (Options, *diagnosticFixture, model.Device, []model.Observation, *journal) {
	t.Helper()
	d := guardDevice()
	f := &diagnosticFixture{integrationBackend: &integrationBackend{devices: []model.Device{d}}}
	pre := f.integrationBackend.GPU(context.Background(), d, collect.Options{})
	o := integrationOptions(t)
	o.Tier = "standard"
	o.DCGM = true
	o.DCGMBudget = 5 * time.Second
	return o, f, d, pre, diagnosticJournal(t)
}

func TestDCGMDoesNotStartWithoutSafeSelectedIdleDevice(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Options, *diagnosticFixture, **model.Device, *bool)
		status model.Status
	}{
		{"no opt in", func(o *Options, _ *diagnosticFixture, _ **model.Device, _ *bool) { o.DCGM = false }, model.NotTested},
		{"not ready", func(_ *Options, _ *diagnosticFixture, _ **model.Device, r *bool) { *r = false }, model.NotTested},
		{"unselected", func(_ *Options, _ *diagnosticFixture, d **model.Device, _ *bool) { *d = nil }, model.NotTested},
		{"partition mode", func(_ *Options, _ *diagnosticFixture, d **model.Device, _ *bool) { (*d).MIGMode = "enabled" }, model.NotTested},
		{"mapping changed", func(_ *Options, f *diagnosticFixture, _ **model.Device, _ *bool) {
			f.devices[0].PCIAddress = "0000:02:00.0"
		}, model.Contaminated},
		{"mapping unavailable", func(_ *Options, f *diagnosticFixture, _ **model.Device, _ *bool) { f.devices = nil }, model.Contaminated},
		{"maintenance", func(_ *Options, f *diagnosticFixture, _ **model.Device, _ *bool) { f.maintenance = true }, model.NotTested},
		{"hot", func(_ *Options, f *diagnosticFixture, _ **model.Device, _ *bool) {
			f.changeTelemetry = func(_ int32, obs []model.Observation) { setGuardField(obs, "temperature_gpu_c", 99.0) }
		}, model.NotTested},
		{"busy despite desktop consent", func(o *Options, f *diagnosticFixture, _ **model.Device, _ *bool) {
			o.AllowBusy = true
			f.changeTelemetry = func(_ int32, obs []model.Observation) { setGuardField(obs, "compute_process_count", uint64(1)) }
		}, model.Contaminated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, f, d, pre, j := diagnosticFixtureSetup(t)
			selected, ready := &d, true
			tc.change(&o, f, &selected, &ready)
			got := runDCGM(context.Background(), o, f, selected, pre, j, ready)
			if got.Status != tc.status || f.dcgmCalls.Load() != 0 {
				t.Fatalf("unsafe diagnostic admission: %+v, adapter calls=%d", got, f.dcgmCalls.Load())
			}
		})
	}
}

func TestDiagnosticBackendNeverFallsThroughToLocalHost(t *testing.T) {
	o, f, d, pre, j := diagnosticFixtureSetup(t)
	if got := runDCGM(context.Background(), o, f.integrationBackend, &d, pre, j, true); got.Status != model.NotTested || got.MethodID != "scheduler.dcgm" {
		t.Fatalf("missing adapter did not remain an explicit gap: %+v", got)
	}
	start, end := time.Now().Add(-time.Second), time.Now()
	if got := runXid(context.Background(), f.integrationBackend, d, start, end); got.Status != model.NotTested || got.MethodID != "scheduler.xid" {
		t.Fatalf("injected backend kernel-log fallback: %+v", got)
	}
	got := runXid(context.Background(), f, d, start, end)
	if f.xidCalls.Load() != 1 || got.ResourceID != d.UUID || got.Conditions["scan_start"] != start || got.Conditions["scan_end"] != end || got.Conditions["timeout"] != 2*time.Second {
		t.Fatalf("Xid interval/target contract changed: %+v", got)
	}
}

func TestDCGMFixtureReceivesBoundedOptInAndNormalCompletion(t *testing.T) {
	for _, configured := range []time.Duration{0, 5 * time.Second} {
		o, f, d, pre, j := diagnosticFixtureSetup(t)
		o.DCGMBudget = configured
		want := configured
		if want == 0 {
			want = 40 * time.Second
		}
		f.diagnostic = func(ctx context.Context, d model.Device, opts diagnostics.Options) model.Observation {
			deadline, ok := ctx.Deadline()
			remaining := time.Until(deadline)
			if !ok || remaining <= 0 || remaining > want || opts.Timeout != want || !opts.DCGMEnabled {
				t.Error("vendor adapter did not receive its own bounded opt-in context")
			}
			return fixtureObservation("B11", "dcgm", d.UUID, "synthetic completion only", model.Pass)
		}
		got := runDCGM(context.Background(), o, f, &d, pre, j, true)
		if got.Status != model.Pass || f.dcgmCalls.Load() != 1 {
			t.Fatalf("completed fixture diagnostic was misclassified by cleanup cancellation: %+v", got)
		}
	}
}

func TestDCGMCancellationBeforeAdmissionNeverCallsAdapter(t *testing.T) {
	for _, stage := range []string{"before discovery", "during discovery", "during telemetry"} {
		t.Run(stage, func(t *testing.T) {
			o, f, d, pre, j := diagnosticFixtureSetup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "before discovery":
				cancel()
			case "during discovery":
				f.afterDiscover = cancel
			case "during telemetry":
				f.afterTelemetry = cancel
			}
			got := runDCGM(ctx, o, f, &d, pre, j, true)
			if f.dcgmCalls.Load() != 0 || got.Status != model.TimeBudgetExhausted {
				t.Fatalf("cancelled preflight entered vendor adapter or lost cancellation: %+v, calls=%d", got, f.dcgmCalls.Load())
			}
		})
	}
}

func TestDCGMDoesNotStartAfterEvidenceStorageExhaustion(t *testing.T) {
	o, f, d, pre, j := diagnosticFixtureSetup(t)
	j.maxBytes = 1 // Exercise real journal overflow during preflight persistence.
	got := runDCGM(context.Background(), o, f, &d, pre, j, true)
	if !j.incomplete() || f.dcgmCalls.Load() != 0 || got.Status == model.Pass {
		t.Fatalf("vendor diagnostic started after losing its evidence: %+v calls=%d", got, f.dcgmCalls.Load())
	}
}

func TestDCGMLatePassCannotEscapeParentDeadline(t *testing.T) {
	o, f, d, pre, j := diagnosticFixtureSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	f.diagnostic = func(ctx context.Context, d model.Device, opts diagnostics.Options) model.Observation {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(parentDeadline) || !opts.DCGMEnabled || opts.Timeout != o.DCGMBudget {
			t.Error("vendor adapter escaped opt-in/budget contract")
		}
		<-ctx.Done()
		return fixtureObservation("B11", "dcgm", d.UUID, "synthetic late completion", model.Pass)
	}
	got := runDCGM(ctx, o, f, &d, pre, j, true)
	if f.dcgmCalls.Load() != 1 || got.Status != model.TimeBudgetExhausted {
		t.Fatalf("late PASS survived deadline: %+v calls=%d", got, f.dcgmCalls.Load())
	}
}

func TestDCGMRuntimeSafetyCancelsAdapterAndRetainsReason(t *testing.T) {
	o, f, d, pre, j := diagnosticFixtureSetup(t)
	f.changeTelemetry = func(n int32, obs []model.Observation) {
		if n >= 2 {
			setGuardField(obs, "temperature_gpu_c", 99.0)
		}
	}
	f.diagnostic = func(ctx context.Context, d model.Device, _ diagnostics.Options) model.Observation {
		<-ctx.Done()
		return fixtureObservation("B11", "dcgm", d.UUID, nil, model.Pass)
	}
	got := runDCGM(context.Background(), o, f, &d, pre, j, true)
	if got.Status != model.Contaminated || f.dcgmCalls.Load() != 1 {
		t.Fatalf("runtime safety stop became a clean completion: %+v", got)
	}
	for _, obs := range j.snapshot() {
		if obs.MethodID == "scheduler.dcgm-safety" && obs.ResourceID == d.UUID && obs.Status == model.Warning {
			return
		}
	}
	t.Fatal("runtime safety reason was not retained")
}

func signedScanAdvisory(t *testing.T, now time.Time) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := advisory.Pack{Kind: "gri-advisory", SchemaVersion: advisory.SchemaVersion, ID: "synthetic-scan-only", Version: "fixture-1", Publisher: "Synthetic fixture, not vendor data", IssuedAt: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), OEM: []advisory.OEMEntry{{ID: "synthetic-oem", SKU: "h100-pcie-80gb", BoardPartNumber: "SYNTHETIC-BOARD", VBIOSVersions: []string{"SYNTHETIC-VBIOS"}, Source: advisory.Source{URL: "https://example.invalid/synthetic", Title: "Synthetic fixture; no production assertion", PublishedAt: now.Add(-2 * time.Hour)}}}}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Sign(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	packPath, keyPath := filepath.Join(dir, "fixture.json"), filepath.Join(dir, "fixture.pem")
	if err := os.WriteFile(packPath, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return packPath, keyPath
}

type advisoryScanFixture struct{ *integrationBackend }

func (f *advisoryScanFixture) GPU(ctx context.Context, d model.Device, o collect.Options) []model.Observation {
	obs := f.integrationBackend.GPU(ctx, d, o)
	return append(obs, fixtureObservation("A10", "part_number", d.UUID, "SYNTHETIC-BOARD", model.Pass), fixtureObservation("A10", "vbios", d.UUID, "SYNTHETIC-VBIOS", model.Pass))
}

func TestSignedAdvisoryPersistsThroughStandardScanWithoutInventingCalibration(t *testing.T) {
	o := integrationOptions(t)
	o.Tier = "standard"
	o.AdvisoryPath, o.AdvisoryPublicKey = signedScanAdvisory(t, time.Now().UTC())
	f := &advisoryScanFixture{&integrationBackend{devices: []model.Device{guardDevice()}}}
	if _, err := RunWithBackend(context.Background(), o, f); err != nil {
		t.Fatal(err)
	}
	r := readVerifiedReport(t, o.Output)
	comparison, ok := observationMethod(r, "advisory.oem_vbios")
	if !ok || comparison.Status != model.Pass || len(comparison.EvidenceRefs) < 2 || comparison.Conditions["pack_sha256"] == nil || comparison.Conditions["trusted_key_sha256"] == nil {
		t.Fatalf("authenticated comparison/provenance lost: %+v", comparison)
	}
	if r.Score != nil || r.Verdict != model.Inconclusive || r.PerformanceJudgment != "UNCALIBRATED" {
		t.Fatal("advisory match became calibrated health")
	}
	for _, c := range r.Checks {
		if c.CheckID == "A10" && c.Status == model.Pass {
			return
		}
	}
	t.Fatal("authenticated advisory was not admitted by rules")
}

func TestAdvisoryAdmissionFailuresStayExplicit(t *testing.T) {
	d := guardDevice()
	for _, mode := range []string{"not selected", "missing key", "wrong key", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			o := integrationOptions(t)
			o.Tier = "standard"
			o.AdvisoryPath, o.AdvisoryPublicKey = signedScanAdvisory(t, time.Now().UTC())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := model.ToolError
			switch mode {
			case "not selected":
				o.AdvisoryPath = ""
				want = model.NotTested
			case "missing key":
				o.AdvisoryPublicKey += ".missing"
			case "wrong key":
				_, o.AdvisoryPublicKey = signedScanAdvisory(t, time.Now().UTC())
			case "cancelled":
				cancel()
				want = model.TimeBudgetExhausted
			}
			got := runAdvisories(ctx, o, &d, nil)
			if len(got) != 2 {
				t.Fatal("both advisory coverage rows must be retained")
			}
			for _, obs := range got {
				if obs.Status != want || obs.ResourceID != d.UUID || obs.Message == "" {
					t.Fatalf("advisory failure not explicit: %+v", obs)
				}
			}
		})
	}
}
