package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/collect"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/report"
)

// This backend is intentionally labeled fixture in every raw observation. It
// exercises persistence and orchestration only, without probing any real GPU,
// launching a worker, or creating remotely publishable measurement evidence.
type integrationBackend struct {
	devices              []model.Device
	unknownMode          bool
	maintenance          bool
	waitDiscovery        bool
	cancelAfterDiscovery context.CancelFunc
	gpuCalls             atomic.Int32
	hostCalls            atomic.Int32
}

func fixtureObservation(check, field, resource string, value any, status model.Status) model.Observation {
	return model.Observation{CheckID: check, ResourceID: resource, MethodID: "fixture." + field, Version: "fixture-only-v1", StartUTC: time.Now().UTC(), DurationMS: 0.001, Status: status, Value: value, SampleCount: 1, SourceKind: "fixture", Visibility: "hermetic test fixture; no real hardware observation", Scope: resource, Message: "Synthetic integration-test input; not hardware measurement or release qualification.", Conditions: map[string]any{"field": field, "fixture": true}}
}
func (f *integrationBackend) Discover(ctx context.Context, _ collect.Options) ([]model.Device, []model.Observation) {
	status := model.Pass
	if f.waitDiscovery {
		<-ctx.Done()
		status = model.TimeBudgetExhausted
	}
	obs := []model.Observation{fixtureObservation("A08", "discovery", "allocation", len(f.devices), status)}
	if f.cancelAfterDiscovery != nil {
		f.cancelAfterDiscovery()
	}
	return append([]model.Device(nil), f.devices...), obs
}
func (f *integrationBackend) GPU(ctx context.Context, d model.Device, _ collect.Options) []model.Observation {
	f.gpuCalls.Add(1)
	status := model.Pass
	if ctx.Err() != nil {
		status = model.TimeBudgetExhausted
	}
	fields := []struct {
		check, name string
		value       any
	}{{"A01", "name", d.Name}, {"A07", "uuid", d.UUID}, {"A07", "pci_address", d.PCIAddress}, {"A02", "memory_total_bytes", d.MemoryBytes}, {"A06", "mig_current", 0.0}, {"A06", "virtualization_mode", 0.0}, {"H01", "driver_version", "fixture-driver"}, {"I01", "utilization_gpu_percent", 0.0}, {"I01", "compute_process_count", uint64(0)}, {"D04", "temperature_gpu_c", 40.0}, {"D04", "temperature_slowdown_c", 95.0}, {"B02", "ecc_corrected_volatile", uint64(0)}, {"B03", "ecc_uncorrected_volatile", uint64(0)}, {"D09", "pcie_replay_count", uint64(0)}, {"B04", "row_remap_pending", false}, {"B04", "row_remap_failure", false}, {"B05", "retirement_pending", false}}
	out := []model.Observation{}
	for _, field := range fields {
		o := fixtureObservation(field.check, field.name, d.UUID, field.value, status)
		if f.unknownMode && (field.name == "mig_current" || field.name == "virtualization_mode") {
			o.Status = model.Unsupported
			o.Value = nil
		}
		if f.maintenance && field.name == "row_remap_pending" {
			o.Value = true
		}
		out = append(out, o)
	}
	out = append(out, fixtureObservation("B02", "counter_epoch", d.UUID, nil, model.NotTested))
	return out
}
func (f *integrationBackend) Telemetry(ctx context.Context, d model.Device, o collect.Options) []model.Observation {
	return f.GPU(ctx, d, o)
}
func (f *integrationBackend) Host(ctx context.Context, _ collect.Options) []model.Observation {
	f.hostCalls.Add(1)
	status := model.Pass
	if ctx.Err() != nil {
		status = model.TimeBudgetExhausted
	}
	return []model.Observation{fixtureObservation("E02", "cgroup_cpu_stat", "process-host", map[string]uint64{"nr_periods": 10, "nr_throttled": 0, "throttled_usec": 0}, status), fixtureObservation("E06", "cgroup_memory_events", "process-host", map[string]uint64{"oom": 0, "oom_kill": 0, "high": 0}, status)}
}
func integrationOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	return Options{Tier: "quick", Profile: "general", Output: filepath.Join(root, "report"), Workspace: root, Budget: time.Second, MemoryMiB: 1, Seed: 1, LockRoot: filepath.Join(root, "locks")}
}
func readVerifiedReport(t *testing.T, dir string) model.Report {
	t.Helper()
	if err := report.Verify(dir); err != nil {
		t.Fatalf("durable report failed verification: %v", err)
	}
	r, err := report.Read(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("durable report did not read back: %v", err)
	}
	return r
}
func observationMethod(r model.Report, method string) (model.Observation, bool) {
	for _, o := range r.Observations {
		if o.MethodID == method {
			return o, true
		}
	}
	return model.Observation{}, false
}

func TestRunWithFixtureBackendPersistsSelectionAndModeGaps(t *testing.T) {
	d := guardDevice()
	peer := d
	peer.UUID = guardPeer
	peer.Index = 1
	peer.PCIAddress = "0000:02:00.0"
	for _, test := range []struct {
		name       string
		backend    *integrationBackend
		device     bool
		modeStatus model.Status
	}{{"no GPU", &integrationBackend{}, false, ""}, {"ambiguous inventory", &integrationBackend{devices: []model.Device{d, peer}}, false, ""}, {"allocation mode unavailable", &integrationBackend{devices: []model.Device{d}, unknownMode: true}, true, model.Unsupported}} {
		t.Run(test.name, func(t *testing.T) {
			opts := integrationOptions(t)
			returned, err := RunWithBackend(context.Background(), opts, test.backend)
			if err != nil {
				t.Fatal(err)
			}
			r := readVerifiedReport(t, opts.Output)
			if r.ScanID != returned.ScanID || r.Score != nil || r.Verdict != model.Inconclusive {
				t.Fatalf("unsupported fixture scan was not honestly persisted: %+v", r)
			}
			if (r.Device != nil) != test.device {
				t.Fatal("wrong selected-device persistence")
			}
			if !test.device && test.backend.gpuCalls.Load() != 0 {
				t.Fatal("GPU snapshot ran despite missing/unresolved ownership")
			}
			if test.modeStatus != "" {
				if o, ok := observationMethod(r, "guard.mode"); !ok || o.Status != test.modeStatus {
					t.Fatalf("missing explicit mode gap: %+v", o)
				}
			}
			if _, ok := observationMethod(r, "scheduler.active-unavailable"); !ok {
				t.Fatal("missing active worker coverage was not retained")
			}
			if len(r.MissingChecks) == 0 {
				t.Fatal("empty missing-coverage list on degraded scan")
			}
		})
	}
}

func TestRunWithFixtureBackendRetainsDeadlineAndCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "parent cancellation"} {
		t.Run(mode, func(t *testing.T) {
			opts := integrationOptions(t)
			backend := &integrationBackend{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				backend.waitDiscovery = true
			} else {
				backend.cancelAfterDiscovery = cancel
			}
			start := time.Now()
			_, err := RunWithBackend(ctx, opts, backend)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("fixture cancellation exceeded bounded report completion")
			}
			r := readVerifiedReport(t, opts.Output)
			if r.Score != nil || r.Verdict != model.Inconclusive {
				t.Fatal("partial deadline evidence became a healthy verdict")
			}
			if mode == "parent cancellation" && !r.Cancelled {
				t.Fatal("parent cancellation flag lost")
			}
			if o, ok := observationMethod(r, "scheduler.completion"); !ok || o.Status != model.TimeBudgetExhausted {
				t.Fatalf("completion gap missing: %+v", o)
			}
			if len(r.Observations) == 0 {
				t.Fatal("partial journal discarded")
			}
		})
	}
}

func TestRunWithFixtureBackendCombinesDeltaBoundariesAndReferences(t *testing.T) {
	opts := integrationOptions(t)
	backend := &integrationBackend{devices: []model.Device{guardDevice()}}
	if _, err := RunWithBackend(context.Background(), opts, backend); err != nil {
		t.Fatal(err)
	}
	r := readVerifiedReport(t, opts.Output)
	if r.Score != nil || r.Verdict != model.Inconclusive {
		t.Fatal("fixture deltas cannot qualify production readiness")
	}
	ids := map[string]model.Observation{}
	for _, o := range r.Observations {
		if o.ID == "" {
			t.Fatal("journal produced blank evidence ID")
		}
		if _, duplicate := ids[o.ID]; duplicate {
			t.Fatal("journal produced duplicate evidence IDs")
		}
		ids[o.ID] = o
	}
	expected := map[string]int{"B02": 0, "B03": 0, "D09": 0, "E02": 0, "E06": 0}
	for _, o := range r.Observations {
		if !strings.HasPrefix(o.MethodID, "delta.") {
			continue
		}
		if o.MethodID == "delta.cpu_steal" {
			// This fixture does not supply /proc/stat CPU accounting. Its separate
			// interval check must preserve absence rather than fabricate zero.
			if o.Status != model.NotTested || len(o.EvidenceRefs) != 0 {
				t.Fatalf("missing CPU accounting was promoted: %+v", o)
			}
			continue
		}
		if _, wanted := expected[o.CheckID]; !wanted {
			t.Fatalf("unexpected counter delta: %+v", o)
		}
		expected[o.CheckID]++
		if len(o.EvidenceRefs) != 2 {
			t.Fatalf("delta lost a raw boundary: %+v", o)
		}
		for _, id := range o.EvidenceRefs {
			raw, ok := ids[id]
			if id == "" || !ok || raw.SourceKind != "fixture" {
				t.Fatalf("delta reference did not resolve to fixture boundary: %q", id)
			}
		}
		if o.Status != model.NotTested {
			t.Fatalf("unknown-epoch zero was promoted or polluted by unrelated scope: %+v", o)
		}
	}
	for check, count := range expected {
		if count != 1 {
			t.Fatalf("expected one combined %s delta, found %d", check, count)
		}
	}
	// The journal and returned report must describe exactly the same assigned IDs.
	file, err := os.Open(filepath.Join(opts.Output, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	journalCount := 0
	for scanner.Scan() {
		var o model.Observation
		if err := json.Unmarshal(scanner.Bytes(), &o); err != nil {
			t.Fatal(err)
		}
		if _, ok := ids[o.ID]; !ok {
			t.Fatalf("journal ID is absent from report: %s", o.ID)
		}
		journalCount++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if journalCount != len(r.Observations) {
		t.Fatal("report and durable journal observation counts differ")
	}
}

func TestRunWithFixtureCurrentMaintenanceStopsEvenWithoutWorker(t *testing.T) {
	opts := integrationOptions(t)
	backend := &integrationBackend{devices: []model.Device{guardDevice()}, maintenance: true}
	if _, err := RunWithBackend(context.Background(), opts, backend); err != nil {
		t.Fatal(err)
	}
	r := readVerifiedReport(t, opts.Output)
	if r.Verdict != model.DoNotStart || r.Score != nil || len(r.Blockers) == 0 {
		t.Fatalf("current maintenance signal lost without active worker: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(opts.Output, "ticket.md")); err != nil {
		t.Fatal("local blocker evidence did not retain its support message")
	}
}

func TestJournalPropagatesAssignedIDsIntoSourceBoundaries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := newJournal(dir, "fixture-journal")
	if err != nil {
		t.Fatal(err)
	}
	source := []model.Observation{fixtureObservation("B03", "ecc_uncorrected_volatile", guardGPU, uint64(0), model.Pass)}
	source[0].ID = "untrusted-input-id"
	j.add(source...)
	assigned := source[0].ID
	if assigned == "" || assigned == "untrusted-input-id" || assigned != j.snapshot()[0].ID {
		t.Fatal("journal did not propagate canonical IDs to caller boundary slice")
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var disk model.Observation
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.ID != assigned {
		t.Fatal("durable and in-memory assigned IDs differ")
	}
}

func TestTargetLockExcludesConcurrentRemappedIndexAndCanRetry(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("file locks unsupported")
	}
	root := filepath.Join(t.TempDir(), "locks")
	initial := guardDevice()
	first, err := acquireLock(root, initial.UUID)
	if err != nil {
		t.Fatal(err)
	}
	remapped := initial
	remapped.Index = 7
	remapped.PCIAddress = "0000:01:00.0"
	selected, err := Select([]model.Device{remapped}, initial.UUID)
	if err != nil {
		t.Fatal(err)
	}
	beforePCI, _ := canonicalPCI(initial.PCIAddress)
	afterPCI, _ := canonicalPCI(selected.PCIAddress)
	if beforePCI != afterPCI {
		t.Fatal("PCI domain padding became a mapping change")
	}
	result := make(chan error, 1)
	go func() {
		second, e := acquireLock(root, selected.UUID)
		if e == nil {
			_ = second.close()
		}
		result <- e
	}()
	if err := <-result; err == nil {
		_ = first.close()
		t.Fatal("remapped management index bypassed selected-UUID lock")
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	retry, err := acquireLock(root, selected.UUID)
	if err != nil {
		t.Fatalf("released lock could not be retried: %v", err)
	}
	if err := retry.close(); err != nil {
		t.Fatal(err)
	}
	different := remapped
	different.PCIAddress = "0001:01:00.0"
	distinct, _ := canonicalPCI(different.PCIAddress)
	if distinct == beforePCI {
		t.Fatal("different PCI domains were collapsed")
	}
}

func TestRunRetainsExistingOutputAndReleasesTargetLock(t *testing.T) {
	opts := integrationOptions(t)
	backend := &integrationBackend{devices: []model.Device{guardDevice()}}
	if _, err := RunWithBackend(context.Background(), opts, backend); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(opts.Output, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := os.ReadFile(filepath.Join(opts.Output, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunWithBackend(context.Background(), opts, backend); err == nil {
		t.Fatal("repeated output directory was silently overwritten")
	}
	again, err := os.ReadFile(filepath.Join(opts.Output, "report.json"))
	if err != nil || !bytes.Equal(original, again) {
		t.Fatal("retained report changed on rejected repeat")
	}
	again, err = os.ReadFile(filepath.Join(opts.Output, "evidence.jsonl"))
	if err != nil || !bytes.Equal(journal, again) {
		t.Fatal("retained journal changed on rejected repeat")
	}
	readVerifiedReport(t, opts.Output)
	opts.Output = filepath.Join(filepath.Dir(opts.Output), "second-report")
	if _, err := RunWithBackend(context.Background(), opts, backend); err != nil {
		t.Fatalf("successful prior run did not release resources: %v", err)
	}
	r := readVerifiedReport(t, opts.Output)
	if _, hasLockError := observationMethod(r, "guard.lock"); hasLockError {
		t.Fatal("completed scan retained its target lock")
	}
}

func TestTargetLockUUIDCaseCannotBypassExclusion(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("file locks unsupported")
	}
	root := filepath.Join(t.TempDir(), "locks")
	first, err := acquireLock(root, guardGPU)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	second, err := acquireLock(root, strings.ToUpper(guardGPU))
	if err == nil {
		_ = second.close()
		t.Fatal("UUID letter case bypassed target ownership lock")
	}
}
