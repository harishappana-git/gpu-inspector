package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func fixture() model.Report {
	start := time.Date(2026, 9, 6, 12, 34, 56, 123456789, time.UTC)
	return model.Report{
		SchemaVersion: model.SchemaVersion, ToolVersion: model.ToolVersion, RuleVersion: model.RuleVersion, MethodVersion: model.MethodVersion,
		ScanID: "test-scan", ResourceScope: "one selected GPU; container visibility", Profile: "general", Tier: "quick", BudgetSeconds: 120, ActualDurationSeconds: 1,
		StartedUTC: start, FinishedUTC: start.Add(time.Second), Verdict: model.Inconclusive, VerdictScope: "Readiness not established", PerformanceJudgment: "UNCALIBRATED", ReferenceStatus: "UNCALIBRATED",
		Device:   &model.Device{UUID: "GPU-12345678-1234-1234-1234-123456789abc", PCIAddress: "00000000:81:00.0", Name: "NVIDIA H100 PCIe", SKU: "h100-pcie-80gb", DriverVersion: "555.42", IdentityAssurance: "reported, not authenticated"},
		Coverage: model.Coverage{Required: 2, Completed: 1, Eligible: 0}, MissingChecks: []string{"C01"}, Limitations: []string{"No qualified healthy reference"}, NextAction: "Qualify the exact reference before healthy-range acceptance.",
		Checks:       []model.CheckResult{{CheckID: "A01", Name: "Identity", Stage: "Q", Required: true, Status: model.Pass, EvidenceRefs: []string{"obs-1"}}},
		Observations: []model.Observation{{ID: "obs-1", CheckID: "A01", ResourceID: "GPU-12345678-1234-1234-1234-123456789abc", MethodID: "nvidia-smi-query", Version: "1.0.0", StartUTC: start, DurationMS: 12, Status: model.Pass, Value: map[string]any{"memory_bytes": uint64(85899345920)}, SampleCount: 1, SourceKind: "vendor-telemetry", Visibility: "guest", Scope: "selected GPU", Message: "Identity observed"}},
		Highlights:   []model.Highlight{{Text: "Selected device identity observed", Severity: "INFO", EvidenceRefs: []string{"obs-1"}}},
		Findings:     []model.Finding{{ID: "reference-required", RuleVersion: model.RuleVersion, CheckID: "A01", Severity: "INFO", Observation: "No qualified reference supplied", Interpretation: "Performance acceptance is unavailable", ObservationStrength: "high", CauseStrength: "not inferred", Impact: "Impact not quantified", ImpactBasis: "not measured", ActionID: "qualify-reference", RetestID: "same-scope-scan", EvidenceRefs: []string{"obs-1"}}},
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWritePrivateIntegrityAndNoCircularHashes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scan")
	if err := Write(dir, fixture()); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0700 {
		t.Fatalf("directory mode: %v", info.Mode())
	}
	for _, name := range []string{"report.json", "report.html", "guide.md", "evidence-index.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %v", name, info.Mode())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "ticket.md")); !os.IsNotExist(err) {
		t.Fatal("ticket unexpectedly generated without blocker/request")
	}
	r, err := Read(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != nil || r.PerformanceJudgment != "UNCALIBRATED" || r.Verdict != model.Inconclusive {
		t.Fatal("withheld judgment was changed")
	}
	if r.ArtifactHashes["report.json"] != "" || r.ArtifactHashes["evidence-index.json"] != "" {
		t.Fatal("circular report hash")
	}
	if r.ArtifactHashes["report.html"] == "" || r.ArtifactHashes["guide.md"] == "" {
		t.Fatal("missing rendered artifact hashes")
	}
	original := read(t, filepath.Join(dir, "report.json"))
	if err := Write(dir, fixture()); err == nil {
		t.Fatal("overwrote retained report")
	}
	if read(t, filepath.Join(dir, "report.json")) != original {
		t.Fatal("retained evidence changed")
	}
}

func TestJournalAndTicketTriggers(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocker", true: "request"}[explicit], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "evidence.jsonl"), []byte("{\"measurement_id\":\"obs-1\"}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			r := fixture()
			if !explicit {
				r.Blockers = []string{"test blocker"}
			}
			if err := WriteWithOptions(dir, r, Options{Ticket: explicit}); err != nil {
				t.Fatal(err)
			}
			if err := Verify(dir); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(read(t, filepath.Join(dir, "ticket.md")), "not submitted") {
				t.Fatal("ticket missing local draft boundary")
			}
			if !strings.Contains(read(t, filepath.Join(dir, "evidence-index.json")), "evidence.jsonl") {
				t.Fatal("journal not indexed")
			}
		})
	}
}

func TestEvidenceContract(t *testing.T) {
	cases := map[string]func(*model.Report){
		"six highlights": func(r *model.Report) {
			for len(r.Highlights) < 6 {
				r.Highlights = append(r.Highlights, r.Highlights[0])
			}
		},
		"unlinked highlight": func(r *model.Report) { r.Highlights[0].EvidenceRefs = nil },
		"missing evidence":   func(r *model.Report) { r.Highlights[0].EvidenceRefs = []string{"missing"} },
		"missing method":     func(r *model.Report) { r.Observations[0].MethodID = "" },
		"duplicate evidence": func(r *model.Report) { r.Observations = append(r.Observations, r.Observations[0]) },
		"unlinked finding":   func(r *model.Report) { r.Findings[0].EvidenceRefs = nil },
		"invalid status":     func(r *model.Report) { r.Observations[0].Status = "HEALTHY" },
		"unknown finding":    func(r *model.Report) { r.Highlights[0].FindingID = "missing" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := fixture()
			change(&r)
			if _, err := HTML(r); err == nil {
				t.Fatal("invalid evidence contract was accepted")
			}
		})
	}
}

func TestHTMLNoActiveContentAndTerminalControls(t *testing.T) {
	r := fixture()
	r.Highlights[0].Text = "<img src=https://untrusted.invalid/pixel onerror=alert(1)>"
	r.Observations[0].Value = "</pre><script>alert('injected')</script>"
	r.Limitations = append(r.Limitations, "\x1b[2J\x1b[H\x9bmalicious control")
	html, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"<script", "<img", "<iframe", "<link", "src=\"http", "url(http"} {
		if strings.Contains(string(html), prohibited) {
			t.Fatalf("HTML contains active content %q", prohibited)
		}
	}
	if !strings.Contains(string(html), "&lt;img") || !strings.Contains(string(html), "href=\"#"+anchor("obs-1")+"\"") {
		t.Fatal("escaping or evidence link absent")
	}
	if strings.ContainsAny(Terminal(r), "\x1b\x9b") {
		t.Fatal("terminal control sequence leaked")
	}
}

func TestIntegrityDetectsTamperingUnknownFilesAndSymlinks(t *testing.T) {
	cases := map[string]func(string) error{
		"tamper": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "report.html"), []byte("tampered"), 0600)
		},
		"unexpected file": func(dir string) error { return os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("secret"), 0600) },
		"public file":     func(dir string) error { return os.Chmod(filepath.Join(dir, "report.json"), 0644) },
		"symlink": func(dir string) error {
			path := filepath.Join(dir, "report.html")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("guide.md", path)
		},
		"traversal": func(dir string) error {
			var index EvidenceIndex
			if err := json.Unmarshal([]byte(read(t, filepath.Join(dir, "evidence-index.json"))), &index); err != nil {
				return err
			}
			index.Artifacts[0].Name = "../report.html"
			data, err := jsonBytes(index)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "evidence-index.json"), data, 0600)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := Write(dir, fixture()); err != nil {
				t.Fatal(err)
			}
			if err := change(dir); err != nil {
				t.Fatal(err)
			}
			if err := Verify(dir); err == nil {
				t.Fatal("accepted unsafe/changed evidence")
			}
			if err := Export(dir, filepath.Join(t.TempDir(), "export")); err == nil {
				t.Fatal("exported unverified source")
			}
		})
	}
}

func TestExportScrubsSecretsAndRebuildsJournal(t *testing.T) {
	r := fixture()
	r.Observations[0].Conditions = map[string]any{
		"api_key": "SEEDED_SECRET_012345", "environment": map[string]any{"PRIVATE_TOKEN": "SEEDED_ENV_TOKEN_543210"},
		"serial_number": "SERIAL-SECRET-998877", "numeric_serial": uint64(98765432101234567), "hostname": "private-host-0815", "private_path": "/home/alice/private-model/weights.bin",
		"raw_output": "RAW_DUMP_SECRET_112233", "ip_address": "10.52.18.42",
	}
	r.Observations[0].Message = "At /Users/alice/private/project, GPU-12345678-1234-1234-1234-123456789abc on 00000000:81:00.0 contacted 10.52.18.42 and 2001:db8::7; token=TEXT_TOKEN_4556; Bearer TEXT_BEARER_991188"
	r.Findings[0].Observation = "SEEDED_SECRET_012345 seen on private-host-0815"
	source := filepath.Join(t.TempDir(), "source")
	if err := privateDir(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "evidence.jsonl"), []byte("RAW_ORIGINAL_JOURNAL_SECRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteWithOptions(source, r, Options{Ticket: true}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "export")
	if err := Export(source, dest); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dest); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dest)
	for _, entry := range entries {
		contents := read(t, filepath.Join(dest, entry.Name()))
		for _, secret := range []string{"SEEDED_SECRET_012345", "SEEDED_ENV_TOKEN_543210", "SERIAL-SECRET-998877", "98765432101234567", "private-host-0815", "/home/alice", "/Users/alice", "RAW_DUMP_SECRET_112233", "RAW_ORIGINAL_JOURNAL_SECRET", "10.52.18.42", "2001:db8::7", "TEXT_TOKEN_4556", "TEXT_BEARER_991188", r.Device.UUID, r.Device.PCIAddress} {
			if strings.Contains(contents, secret) {
				t.Errorf("%s leaked %q", entry.Name(), secret)
			}
		}
	}
	got, err := Read(filepath.Join(dest, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.StartedUTC.Equal(r.StartedUTC) {
		t.Fatal("redaction corrupted timestamp")
	}
	if got.Device.UUID == r.Device.UUID || got.Device.UUID != got.Observations[0].ResourceID {
		t.Fatal("pseudonym not consistent within report")
	}
	if !strings.Contains(read(t, filepath.Join(dest, "ticket.md")), got.Device.UUID) {
		t.Fatal("ticket and report pseudonyms differ")
	}
	again, err := Redact(got)
	if err != nil {
		t.Fatal(err)
	}
	if again.Device.UUID != got.Device.UUID || len(again.Limitations) != len(got.Limitations) {
		t.Fatal("redaction is not idempotent")
	}
	if got.Score != nil || got.Verdict != model.Inconclusive {
		t.Fatal("redaction changed judgment")
	}
	if err := Export(source, dest); err == nil {
		t.Fatal("overwrote exported evidence")
	}
}

func TestPublicDirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if err := Write(dir, fixture()); err == nil {
		t.Fatal("accepted publicly readable report directory")
	}
}

func TestTicketDeduplicatesAndGuideNeverInterpolatesShell(t *testing.T) {
	r := fixture()
	r.Device.UUID = "GPU-x'; touch /tmp/unsafe; echo '"
	r.Findings = append(r.Findings, r.Findings[0])
	ticket := TicketDraft(r)
	if strings.Count(ticket, "No qualified reference supplied") != 1 {
		t.Fatal("ticket did not deduplicate same issue")
	}
	guide := Guide(r)
	for i, block := range strings.Split(guide, "```") {
		if i%2 == 1 && strings.Contains(block, "touch /tmp/unsafe") {
			t.Fatal("untrusted UUID interpolated into shell command")
		}
	}
	for _, required := range []string{"Prerequisites", "Expected observations", "Decision branches", "Rollback", "retest", "provider", "nvidia-smi --version", "gri verify --report-dir"} {
		if !strings.Contains(guide, required) {
			t.Errorf("guide omitted %q", required)
		}
	}
	if _, err := Explain(r, "missing"); err == nil {
		t.Fatal("unknown finding accepted")
	}
}

func TestExactIntegerEvidenceSurvivesReadReplayAndExport(t *testing.T) {
	r := fixture()
	const before uint64 = 9007199254740992
	const after uint64 = 9007199254740993
	const largest uint64 = 18446744073709551615
	r.Observations[0].Value = map[string]any{"before": before, "after": after, "largest": largest}
	r.Observations[0].Conditions = map[string]any{"large_integer_condition": after, "samples": []any{before, after, largest}}
	dir := filepath.Join(t.TempDir(), "source")
	if err := Write(dir, r); err != nil {
		t.Fatal(err)
	}
	assertExact := func(r model.Report) {
		t.Helper()
		values, ok := r.Observations[0].Value.(map[string]any)
		if !ok {
			t.Fatal("value shape changed")
		}
		parsed := map[string]uint64{}
		for name, want := range map[string]uint64{"before": before, "after": after, "largest": largest} {
			number, ok := values[name].(json.Number)
			if !ok {
				t.Fatalf("%s became %T instead of exact json.Number", name, values[name])
			}
			got, err := strconv.ParseUint(string(number), 10, 64)
			if err != nil || got != want {
				t.Fatalf("%s lost integer evidence: %s", name, number)
			}
			parsed[name] = got
		}
		if parsed["after"]-parsed["before"] != 1 {
			t.Fatal("one-error delta became zero after roundtrip")
		}
		if value, ok := r.Observations[0].Conditions["large_integer_condition"].(json.Number); !ok || string(value) != "9007199254740993" {
			t.Fatal("exact method condition changed")
		}
	}
	loaded, err := Read(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertExact(loaded)
	redacted, err := Redact(loaded)
	if err != nil {
		t.Fatal(err)
	}
	assertExact(redacted)
	// This is the report read/rewrite boundary used by CLI replay. Original
	// observations and their exact integers must survive a new report identity.
	loaded.OriginalScanID = loaded.ScanID
	loaded.ScanID += "-replay"
	replay := filepath.Join(t.TempDir(), "replay")
	if err := Write(replay, loaded); err != nil {
		t.Fatal(err)
	}
	replayed, err := Read(filepath.Join(replay, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertExact(replayed)
	exported := filepath.Join(t.TempDir(), "export")
	if err := Export(dir, exported); err != nil {
		t.Fatal(err)
	}
	shared, err := Read(filepath.Join(exported, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertExact(shared)
	for _, name := range []string{"report.json", "report.html", "evidence.jsonl"} {
		content := read(t, filepath.Join(exported, name))
		if !strings.Contains(content, "9007199254740993") || !strings.Contains(content, "18446744073709551615") {
			t.Errorf("%s omitted or rounded exact integer evidence", name)
		}
	}
}

func TestReadRejectsDuplicateJSONMembersIncludingEscapedNames(t *testing.T) {
	data, err := jsonBytes(fixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"verdict"`, `"\u0076erdict"`} {
		path := filepath.Join(t.TempDir(), "report.json")
		duplicate := []byte("{" + key + `: "KEEP",` + string(data[1:]))
		if err := os.WriteFile(path, duplicate, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil {
			t.Fatal("ambiguous repeated verdict was accepted")
		}
	}
	var value any
	if err := decodeJSON([]byte(`{"observation":{"counter":9007199254740993,"counter":0}}`), &value); err == nil {
		t.Fatal("nested duplicate counter was accepted")
	}
}

func TestVerifyRejectsDuplicateIndexMembers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "source")
	if err := Write(dir, fixture()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence-index.json")
	data := read(t, path)
	if err := os.WriteFile(path, []byte(`{"scan_id":"ignored-poison",`+data[1:]), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir); err == nil {
		t.Fatal("ambiguous evidence index was accepted")
	}
}

func TestTicketRetainsIndependentFindingsWithSameObservation(t *testing.T) {
	r := fixture()
	first := r.Findings[0]
	first.ID = "independent-invocation-one"
	first.CheckID = "B07"
	first.Observation = "Same mismatch text from two independently retained invocations"
	second := first
	second.ID = "independent-invocation-two"
	r.Findings = []model.Finding{first, second}
	ticket := TicketDraft(r)
	if strings.Count(ticket, first.Observation) != 2 || !strings.Contains(ticket, first.ID) || !strings.Contains(ticket, second.ID) {
		t.Fatal("ticket collapsed independent invocation findings with identical text")
	}
}
