package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/report"
	"github.com/harishappana/gpu-inspector/internal/worker"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := run(context.Background(), args, &out, &err)
	return code, out.String(), err.String()
}

func TestManifestRejectsExcessDependenciesBeforePublication(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "manifest.json")
	args := []string{"manifest", "worker", "--platform", "windows-amd64", "--binary", "unread-worker.exe", "--output", dest}
	for i := 0; i <= worker.MaxDependencies; i++ {
		args = append(args, "--dependency", "unread.dll")
	}
	code, _, stderr := invoke(t, args...)
	if code != 1 || !strings.Contains(stderr, "too many worker runtime dependencies") {
		t.Fatalf("oversized manifest not rejected early: %d %s", code, stderr)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("invalid manifest was published")
	}
}
func TestDemoVerifiedExportReplayAndCleanup(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "fixture")
	shared := filepath.Join(root, "shared")
	replayed := filepath.Join(root, "replayed")
	code, text, errText := invoke(t, "demo", "--scenario", "ecc-error", "--output", original)
	if code != 0 {
		t.Fatal(errText)
	}
	if !strings.Contains(text, "SYNTHETIC") || !strings.Contains(text, model.DoNotStart) {
		t.Fatal(text)
	}
	orig, err := os.ReadFile(filepath.Join(original, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"verify", "--report-dir", original}, {"export", "--report-dir", original, "--output", shared}, {"verify", "--report-dir", shared}, {"replay", "--report", filepath.Join(original, "report.json"), "--output", replayed}, {"verify", "--report-dir", replayed}, {"explain", "check-B03", "--report", filepath.Join(original, "report.json")}, {"ticket", "draft", "--report", filepath.Join(original, "report.json"), "--provider", "generic"}} {
		if code, _, errText := invoke(t, args...); code != 0 {
			t.Fatalf("%v: %s", args, errText)
		}
	}
	data, _ := os.ReadFile(filepath.Join(shared, "report.json"))
	if bytes.Contains(data, []byte("GPU-aaaaaaaa")) {
		t.Fatal("raw GPU identity exported")
	}
	r, err := report.Read(filepath.Join(replayed, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Synthetic || r.OriginalScanID == "" || r.Score != nil {
		t.Fatal("replay lost evidence boundary")
	}
	after, _ := os.ReadFile(filepath.Join(original, "report.json"))
	if !bytes.Equal(orig, after) {
		t.Fatal("replay changed original")
	}
	if code, _, _ := invoke(t, "demo", "--scenario", "clean", "--output", original); code == 0 {
		t.Fatal("existing evidence overwritten")
	}
	if err := os.WriteFile(filepath.Join(shared, "user-data.txt"), []byte("do not delete"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := invoke(t, "cleanup", "--report-dir", shared); code == 0 {
		t.Fatal("cleanup accepted unindexed user file")
	}
	if _, err = os.Stat(filepath.Join(shared, "user-data.txt")); err != nil {
		t.Fatal("cleanup changed user data")
	}
	if code, _, errText := invoke(t, "cleanup", "--report-dir", replayed); code != 0 {
		t.Fatal(errText)
	}
	if _, err = os.Stat(replayed); !os.IsNotExist(err) {
		t.Fatal("verified directory retained after cleanup")
	}
}

func TestScanInputValidationAndHonestNoGPUReport(t *testing.T) {
	for _, args := range [][]string{{"scan", "--tier", "deep"}, {"scan", "--budget-seconds", "NaN"}, {"scan", "--budget-seconds", "0"}, {"scan", "--memory-mib", "0"}, {"scan", "--seed", "4294967296"}, {"scan", "--worker", "missing"}, {"scan", "--download-bytes", "1"}, {"scan", "--disk-test-bytes", "100"}, {"scan", "--reference", "untrusted"}, {"scan", "--price-per-hour", "Inf"}, {"scan", "--price-per-hour", "1", "--currency", "x$x"}} {
		args = append(args, "--output", filepath.Join(t.TempDir(), "must-not-create"))
		if code, _, _ := invoke(t, args...); code != 1 {
			t.Fatalf("invalid input accepted: %v = %d", args, code)
		}
	}
	dir := filepath.Join(t.TempDir(), "no-gpu")
	// Explicitly empty visibility prevents inspecting any installed device when
	// this software test runs on a GPU-equipped developer or CI machine.
	t.Setenv("NVIDIA_VISIBLE_DEVICES", "none")
	t.Setenv("CUDA_VISIBLE_DEVICES", "")
	code, text, errText := invoke(t, "scan", "--tier", "quick", "--budget-seconds", "2", "--output", dir)
	if code != 3 {
		t.Fatalf("no GPU scan exit=%d stderr=%s stdout=%s", code, errText, text)
	}
	if !strings.Contains(text, "INCONCLUSIVE") {
		t.Fatal(text)
	}
	if err := report.Verify(dir); err != nil {
		t.Fatal(err)
	}
	r, err := report.Read(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Device != nil || r.Score != nil || r.Synthetic {
		t.Fatal("missing GPU became measured/synthetic success")
	}
}

func TestDevelopmentSigningWorkflowDoesNotQualifyWorker(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	binary := filepath.Join(root, "fixture-worker")
	manifest := filepath.Join(root, "manifest.json")
	signed := filepath.Join(root, "manifest.signed.json")
	if err := os.WriteFile(binary, []byte("explicitly synthetic nonexecutable bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"keys", "generate", "--output", keys}, {"manifest", "worker", "--binary", binary, "--output", manifest}, {"sign", "--input", manifest, "--key", filepath.Join(keys, "private.pem"), "--output", signed}} {
		if code, _, errText := invoke(t, args...); code != 0 {
			t.Fatalf("%v: %s", args, errText)
		}
	}
	pub, err := bundle.LoadPublicKey(filepath.Join(keys, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(signed)
	payload, err := bundle.Verify(data, pub)
	if err != nil {
		t.Fatal(err)
	}
	var m worker.Manifest
	if err = json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	if m.Qualified || len(m.QualificationEvidence) != 0 {
		t.Fatal("local signature became qualification")
	}
	if _, err = worker.Load(binary, signed, pub, false); err == nil {
		t.Fatal("unqualified synthetic bytes accepted for live work")
	}
	if code, _, _ := invoke(t, "sign", "--input", manifest, "--key", filepath.Join(keys, "private.pem"), "--output", signed); code == 0 {
		t.Fatal("signature file silently overwritten")
	}
}

func TestCatalogAndTicketProviderBoundary(t *testing.T) {
	code, text, errText := invoke(t, "catalog", "--json")
	if code != 0 {
		t.Fatal(errText)
	}
	var checks []model.Check
	if err := json.Unmarshal([]byte(text), &checks); err != nil {
		t.Fatal(err)
	}
	if len(checks) != 147 {
		t.Fatal(len(checks))
	}
	if code, _, _ := invoke(t, "ticket", "send"); code == 0 {
		t.Fatal("submission unexpectedly supported")
	}
	if code, _, _ := invoke(t, "ticket", "draft", "--provider", "invented"); code == 0 {
		t.Fatal("unverified provider accepted")
	}
}
