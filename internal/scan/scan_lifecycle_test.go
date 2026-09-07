package scan

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/report"
	"github.com/harishappana/gpu-inspector/internal/rules"
	"github.com/harishappana/gpu-inspector/internal/secureexec"
)

func TestLifecycleCurrencyAndFiniteCost(t *testing.T) {
	for _, s := range []string{"USD", "INR", "EUR"} {
		if !validCurrency(s) {
			t.Fatalf("valid currency rejected: %q", s)
		}
	}
	for _, s := range []string{"usd", "x$x", "U\nD", "US", "USDD", "₹IN"} {
		if validCurrency(s) {
			t.Fatalf("invalid currency accepted: %q", s)
		}
	}
	cost, ok := rentalCost(math.MaxFloat64, 900)
	if !ok || cost != math.MaxFloat64/4 {
		t.Fatal("finite quarter-hour cost overflowed via intermediate multiplication")
	}
	for _, values := range [][2]float64{{math.MaxFloat64, 7200}, {1, math.Inf(1)}, {math.NaN(), 1}, {-1, 1}, {1, -1}} {
		if _, ok := rentalCost(values[0], values[1]); ok {
			t.Fatal("nonfinite/invalid cost accepted")
		}
	}
}
func TestLifecyclePathFailureDiscardsPartiallyDecodedData(t *testing.T) {
	o := Options{Endpoint: "https://example.invalid/explicit-path", DownloadBytes: 1}
	// A successful prefix must not survive an invalid second object.
	raw := `[{"check_id":"G02","method_id":"pathcheck.https.reachability","status":"PASS","conditions":{"opt_in":true}},{"unrecognized":true}]`
	got := decodePathResult(o, secureexec.Result{Stdout: []byte(raw)}, nil)
	if len(got) != 3 {
		t.Fatalf("wrong selected endpoint fallbacks: %d", len(got))
	}
	for _, v := range got {
		if v.Status != model.ToolError || v.MethodID != "path.helper" || v.Conditions["opt_in"] != true || !strings.HasPrefix(v.CheckID, "G") {
			t.Fatalf("partial/unselected evidence survived: %+v", v)
		}
	}
	got = decodePathResult(Options{DiskBytes: 1}, secureexec.Result{Err: errors.New("fixture timeout")}, errors.New("context expired"))
	if len(got) != 4 {
		t.Fatal("disk fallback coverage missing")
	}
	for _, v := range got {
		if v.Status != model.TimeBudgetExhausted || v.Conditions["opt_in"] != true {
			t.Fatal("optional cancellation was not admitted explicitly")
		}
	}
}
func lifecycleReport(scanID string, observations []model.Observation, start, end time.Time) model.Report {
	r := model.Report{SchemaVersion: model.SchemaVersion, ToolVersion: model.ToolVersion, MethodVersion: model.MethodVersion, RuleVersion: model.RuleVersion, ScanID: scanID, ResourceScope: "SYNTHETIC lifecycle fixture; no GPU execution", Tier: "standard", Profile: "general", StartedUTC: start, FinishedUTC: end, ActualDurationSeconds: end.Sub(start).Seconds(), BudgetSeconds: 300, Synthetic: true, Observations: observations, Limitations: []string{"Synthetic lifecycle/report sizing fixture, not a measured GPU allocation."}}
	rules.Evaluate(&r, nil)
	return r
}
func TestLifecycleEvidenceCapRetainsFailureAndWritablePartialReport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "partial")
	j, err := newJournal(dir, "synthetic-cap-fixture")
	if err != nil {
		t.Fatal(err)
	}
	j.maxBytes = 128 << 10
	j.maxRenderBytes = 512 << 10
	start := time.Now().Add(-time.Second)
	for i := 0; i < 12; i++ {
		o := baseObservation("H09", "synthetic.large-context", model.Pass, "Synthetic oversized context")
		o.Value = strings.Repeat("x", 32<<10)
		j.add(o)
	}
	if !j.incomplete() {
		t.Fatal("fixture did not reach evidence capacity")
	}
	wrong := baseObservation("B09", "synthetic.checked-output", model.Fail, "Synthetic deliberate mismatch; not a hardware result")
	wrong.Value = map[string]any{"mismatch_count": 1, "seed": 42}
	j.add(wrong)
	for _, state := range []bool{false, true} {
		o := baseObservation("B04", "nvml.row_remap_failure", model.Pass, "Synthetic changing maintenance state")
		o.Conditions = map[string]any{"field": "row_remap_failure"}
		o.Value = state
		j.add(o)
	}
	retained := j.snapshot()
	foundFailure, foundMarker, states := false, false, 0
	for _, o := range retained {
		if o.CheckID == "B09" && o.Status == model.Fail {
			foundFailure = true
		}
		if o.MethodID == "scheduler.evidence-capacity" {
			foundMarker = true
		}
		if o.MethodID == "nvml.row_remap_failure" {
			states++
		}
	}
	if !foundFailure || !foundMarker || states != 2 {
		t.Fatalf("terminal evidence lost: failure=%v marker=%v changing states=%d", foundFailure, foundMarker, states)
	}
	if err = j.close(); err != nil {
		t.Fatalf("capacity was made a fatal storage error: %v", err)
	}
	r := lifecycleReport("synthetic-cap-fixture", retained, start, time.Now())
	if err = report.Write(dir, r); err != nil {
		t.Fatalf("partial report could not be published: %v", err)
	}
	if err = report.Verify(dir); err != nil {
		t.Fatal(err)
	}
	stored, err := report.Read(filepath.Join(dir, "report.json"))
	if err != nil || len(stored.ArtifactHashes) == 0 || stored.Score != nil {
		t.Fatalf("partial report failed durable integrity/readback: %v", err)
	}
}
func TestLifecycleFullStandardTelemetryFitsPublishedArtifactLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("3000-observation durable report sizing check")
	}
	dir := filepath.Join(t.TempDir(), "standard")
	j, err := newJournal(dir, "synthetic-300-second-timeline")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-301 * time.Second)
	fields := []struct{ name, check, unit string }{{"uuid", "A07", ""}, {"temperature_gpu_c", "D01", "C"}, {"power_draw_w", "D03", "W"}, {"clock_event_reasons", "D04", "bitmask"}, {"utilization_gpu_percent", "D08", "percent"}, {"compute_process_count", "I01", "processes"}, {"ecc_uncorrected_volatile", "B03", "errors"}, {"ecc_corrected_volatile", "B02", "errors"}, {"row_remap_failure", "B04", ""}, {"row_remap_pending", "B04", ""}}
	for second := 0; second < 300; second++ {
		batch := make([]model.Observation, 0, 10)
		for _, f := range fields {
			var value any = float64(0)
			if f.name == "uuid" {
				value = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			}
			if strings.HasPrefix(f.name, "row_remap") {
				value = false
			}
			o := model.Observation{CheckID: f.check, ResourceID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", MethodID: "nvml." + f.name, Version: model.MethodVersion, StartUTC: start.Add(time.Duration(second) * time.Second), DurationMS: 15, Status: model.Pass, Value: value, Unit: f.unit, SampleCount: 1, SourceKind: "reported", Scope: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Visibility: "host/driver-mediated selected-device telemetry", Message: "Synthetic repeated telemetry field; no GPU was queried.", Conditions: map[string]any{"field": f.name, "backend": "nvml", "common_trust_domain": "host/driver", "telemetry": true, "sampling_resolution": "driver reported; polling interval recorded by timestamps"}}
			batch = append(batch, o)
		}
		j.add(batch...)
	}
	if j.incomplete() {
		t.Fatalf("normal 300-second timeline prematurely hit capacity: raw=%d render estimate=%d rows=%d", j.size, j.renderSize, len(j.snapshot()))
	}
	observations := j.snapshot()
	if len(observations) != 3000 {
		t.Fatalf("timeline rows lost: %d", len(observations))
	}
	if err = j.close(); err != nil {
		t.Fatal(err)
	}
	r := lifecycleReport("synthetic-300-second-timeline", observations, start, start.Add(301*time.Second))
	if err = report.Write(dir, r); err != nil {
		t.Fatalf("full Standard synthetic report exceeds publication limits: %v", err)
	}
	for _, name := range []string{"evidence.jsonl", "report.json", "report.html", "guide.md"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > report.MaxArtifactBytes {
			t.Fatalf("%s exceeded artifact limit: %d", name, info.Size())
		}
		t.Logf("%s: %d bytes", name, info.Size())
	}
	if err = report.Verify(dir); err != nil {
		t.Fatal(err)
	}
}
