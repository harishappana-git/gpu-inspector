package campaignimport

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/privatefs"
	"github.com/harishappana/gpu-inspector/internal/report"
)

type zipFixtureEntry struct {
	header zip.FileHeader
	data   []byte
	raw    bool
}

func hashFixture(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func partialFixture() map[string][]byte {
	return map[string][]byte{"campaign-status.json": []byte(`{"synthetic_fixture":true,"status":"setup_failed","release_qualified":false}`), "remaining-checklist.json": []byte(`{"synthetic_fixture":true,"remaining":["H100 acceptance"]}`), "remaining-checklist.txt": []byte("Synthetic fixture only. H100 acceptance remains incomplete.\n"), "logs/setup-status.json": []byte(`{"synthetic_fixture":true}`), "logs/setup.log": []byte("Synthetic bootstrap failure fixture; no server accessed\n")}
}
func addReportFixture(t *testing.T, files map[string][]byte, tier string, hostileHTML bool) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fixture")
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	r := model.Report{SchemaVersion: model.SchemaVersion, ScanID: "synthetic-" + tier, Synthetic: true, Tier: tier, Profile: "general", StartedUTC: start, FinishedUTC: start.Add(time.Second), Verdict: model.Inconclusive, PerformanceJudgment: "UNCALIBRATED", ReferenceStatus: "UNCALIBRATED", Limitations: []string{"Synthetic fixture only", `<script>untrusted report data</script>`}}
	if err := report.Write(dir, r); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "runs/" + tier + "/evidence/"
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[prefix+entry.Name()] = data
	}
	if hostileHTML {
		// Integrity does not make downloaded HTML safe to execute. Keep the
		// original internally consistent while verifying the local view ignores it.
		files[prefix+"report.html"] = []byte(`<script>REMOTE-SCRIPT-MARKER</script>`)
		if err := json.Unmarshal(files[prefix+"report.json"], &r); err != nil {
			t.Fatal(err)
		}
		r.ArtifactHashes["report.html"] = hashFixture(files[prefix+"report.html"])
		files[prefix+"report.json"], err = json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var index report.EvidenceIndex
		if err := json.Unmarshal(files[prefix+"evidence-index.json"], &index); err != nil {
			t.Fatal(err)
		}
		for i := range index.Artifacts {
			data := files[prefix+index.Artifacts[i].Name]
			index.Artifacts[i].SHA256, index.Artifacts[i].Bytes = hashFixture(data), int64(len(data))
		}
		files[prefix+"evidence-index.json"], err = json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
	}
}
func manifestFixture(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	qualified := false
	m := Manifest{SchemaVersion: 1, CampaignID: "synthetic-import-fixture", ReleaseQualified: &qualified}
	for name, data := range files {
		m.Files = append(m.Files, File{Path: name, SHA256: hashFixture(data), Bytes: int64(len(data))})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func fixtureEntries(t *testing.T, files map[string][]byte) []zipFixtureEntry {
	t.Helper()
	entries := []zipFixtureEntry{}
	appendEntry := func(name string, data []byte) {
		header := zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		entries = append(entries, zipFixtureEntry{header: header, data: data})
	}
	appendEntry("campaign-manifest.json", manifestFixture(t, files))
	for name, data := range files {
		appendEntry(name, data)
	}
	return entries
}
func writeFixtureArchive(t *testing.T, entries []zipFixtureEntry) string {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, entry := range entries {
		var w io.Writer
		var err error
		if entry.raw {
			w, err = z.CreateRaw(&entry.header)
		} else {
			w, err = z.CreateHeader(&entry.header)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "campaign.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportVerifiesExactReportsWithPrivateLocallyRenderedReview(t *testing.T) {
	files := partialFixture()
	addReportFixture(t, files, "quick", true)
	addReportFixture(t, files, "standard", false)
	files["sanitizer/memcheck/int8_gemm/status.json"] = []byte(`{"synthetic_fixture":true,"status":"NOT_TESTED"}`)
	archive := writeFixtureArchive(t, fixtureEntries(t, files))
	dest := filepath.Join(t.TempDir(), "local review")
	result, err := Import(context.Background(), archive, dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reports) != 2 || result.ReleaseQualified || result.FileCount != len(files)+1 || result.IndexPath != filepath.Join(dest, "index.html") {
		t.Fatalf("import result lost evidence boundaries: %+v", result)
	}
	for _, r := range result.Reports {
		if err := report.Verify(r.Directory); err != nil {
			t.Fatal(err)
		}
		view, err := os.ReadFile(r.ReviewPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(view, []byte("REMOTE-SCRIPT-MARKER")) || bytes.Contains(view, []byte("<script>untrusted report data</script>")) || !bytes.Contains(view, []byte("Content-Security-Policy")) || !bytes.Contains(view, []byte("&lt;script&gt;untrusted report data&lt;/script&gt;")) {
			t.Fatal("local review trusted downloaded HTML or failed to escape report data")
		}
		if !r.Synthetic || r.Verdict != model.Inconclusive {
			t.Fatal("fixture import became hardware qualification")
		}
	}
	for name, expected := range files {
		actual, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(expected, actual) {
			t.Fatalf("original archive bytes changed: %s %v", name, err)
		}
	}
	if err := filepath.WalkDir(dest, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return privatefs.CheckDir(path)
		}
		return privatefs.CheckFile(path)
	}); err != nil {
		t.Fatal("imported tree is not owner-private: ", err)
	}
	index, err := os.ReadFile(result.IndexPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(index, []byte("evidence/report.html")) || !bytes.Contains(index, []byte("review/quick.html")) || !bytes.Contains(index, []byte("not server authenticity")) {
		t.Fatal("index points to imported active content or inflates integrity")
	}
}

func TestImportRetainsFailedCampaignWithoutInventingReports(t *testing.T) {
	archive := writeFixtureArchive(t, fixtureEntries(t, partialFixture()))
	result, err := Import(context.Background(), archive, filepath.Join(t.TempDir(), "partial"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reports) != 0 || result.ReleaseQualified {
		t.Fatal("partial setup archive acquired successful reports")
	}
	index, err := os.ReadFile(result.IndexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(index, []byte("No complete report was present")) {
		t.Fatal("missing report was hidden")
	}
}

func TestImportRejectsUnsafeArchiveNamesTypesAndDuplicates(t *testing.T) {
	for _, name := range []string{"../outside.txt", "/absolute.txt", `C:\outside.txt`, `runs\quick\evidence\report.json`, "runs/quick/evidence/../../escape", "campaign-status.json:stream", "Campaign-status.json", "runs/quick/evidence/CON", "private.pem", "bin/gri", "plugin/custom.json", "runs/quick/evidence/unknown.json", "sanitizer/memcheck/arbitrary_plugin/status.json", "runs/"} {
		t.Run(name, func(t *testing.T) {
			entries := fixtureEntries(t, partialFixture())
			data := []byte("not admitted")
			if strings.HasSuffix(name, "/") {
				data = nil
			}
			entries = append(entries, zipFixtureEntry{header: zip.FileHeader{Name: name, Method: zip.Store}, data: data})
			assertArchiveRejected(t, entries, "")
		})
	}
	for _, kind := range []string{"duplicate", "symlink", "device", "reparse", "encrypted"} {
		t.Run(kind, func(t *testing.T) {
			entries := fixtureEntries(t, partialFixture())
			switch kind {
			case "duplicate":
				entries = append(entries, entries[0])
			case "symlink":
				entries[0].header.SetMode(os.ModeSymlink | 0600)
			case "device":
				entries[0].header.SetMode(os.ModeDevice | 0600)
			case "reparse":
				entries[0].header.ExternalAttrs |= 0x400
			case "encrypted":
				entries[0].header.Flags |= 1
			}
			assertArchiveRejected(t, entries, "")
		})
	}
}

func assertArchiveRejected(t *testing.T, entries []zipFixtureEntry, reason string) {
	t.Helper()
	archive := writeFixtureArchive(t, entries)
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "must-not-remain")
	_, err = Import(context.Background(), archive, dest)
	if err == nil || reason != "" && !strings.Contains(err.Error(), reason) {
		t.Fatalf("invalid campaign accepted or wrong rejection: %v", err)
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatalf("rejected archive left an import tree: %v", err)
	}
	after, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("import rejection modified source ZIP")
	}
}

func TestImportRequiresExactStrictManifestAndDigests(t *testing.T) {
	for _, change := range []string{"unknown field", "duplicate JSON key", "qualified true", "qualification omitted", "schema string", "bad digest", "missing listed file", "unlisted file", "duplicate manifest path"} {
		t.Run(change, func(t *testing.T) {
			entries := fixtureEntries(t, partialFixture())
			var m Manifest
			if err := json.Unmarshal(entries[0].data, &m); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "unknown field":
				entries[0].data = bytes.Replace(entries[0].data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1)
			case "duplicate JSON key":
				entries[0].data = bytes.Replace(entries[0].data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
			case "qualified true":
				entries[0].data = bytes.Replace(entries[0].data, []byte(`"release_qualified":false`), []byte(`"release_qualified":true`), 1)
			case "qualification omitted":
				entries[0].data = bytes.Replace(entries[0].data, []byte(`"release_qualified":false,`), nil, 1)
			case "schema string":
				entries[0].data = bytes.Replace(entries[0].data, []byte(`"schema_version":1`), []byte(`"schema_version":"1"`), 1)
			case "bad digest":
				m.Files[0].SHA256 = strings.Repeat("0", 64)
				entries[0].data, _ = json.Marshal(m)
			case "missing listed file":
				entries = entries[:len(entries)-1]
			case "unlisted file":
				entries = append(entries, zipFixtureEntry{header: zip.FileHeader{Name: "logs/build.log", Method: zip.Store}, data: []byte("unlisted")})
			case "duplicate manifest path":
				m.Files = append(m.Files, m.Files[0])
				entries[0].data, _ = json.Marshal(m)
			}
			assertArchiveRejected(t, entries, "")
		})
	}
}

func TestImportBoundsDeclaredFilesRatiosAndDirectoryCount(t *testing.T) {
	for _, kind := range []string{"oversized file", "compression ratio"} {
		t.Run(kind, func(t *testing.T) {
			entries := fixtureEntries(t, partialFixture())
			header := zip.FileHeader{Name: "logs/build.log", Method: zip.Deflate, CompressedSize64: 1, UncompressedSize64: 1 << 20}
			header.SetMode(0600)
			if kind == "oversized file" {
				header.UncompressedSize64 = uint64(MaxFileBytes) + 1
			}
			entries = append(entries, zipFixtureEntry{header: header, data: []byte{0}, raw: true})
			assertArchiveRejected(t, entries, "size or compression limit")
		})
	}
	archive := writeFixtureArchive(t, fixtureEntries(t, partialFixture()))
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	end := len(data) - 22
	binary.LittleEndian.PutUint16(data[end+8:], MaxFiles+1)
	binary.LittleEndian.PutUint16(data[end+10:], MaxFiles+1)
	if err := os.WriteFile(archive, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(context.Background(), archive, filepath.Join(t.TempDir(), "rejected")); err == nil || !strings.Contains(err.Error(), "ZIP directory") {
		t.Fatalf("unbounded directory count admitted: %v", err)
	}
}

func TestImportManifestTotalAndArchiveSizeBoundsBeforePayloadReads(t *testing.T) {
	qualified := false
	m := Manifest{SchemaVersion: 1, CampaignID: "synthetic", ReleaseQualified: &qualified}
	for _, root := range []string{"campaign-status.json", "remaining-checklist.json", "remaining-checklist.txt"} {
		m.Files = append(m.Files, File{Path: root, SHA256: strings.Repeat("0", 64), Bytes: MaxFileBytes})
	}
	for _, tool := range []string{"memcheck", "racecheck", "initcheck", "synccheck"} {
		for _, method := range []string{"fp32_gemm", "bf16_gemm", "tf32_gemm", "int8_gemm", "fp8_gemm", "hbm_copy", "h2d", "d2h"} {
			m.Files = append(m.Files, File{Path: "sanitizer/" + tool + "/" + method + "/worker.json", SHA256: strings.Repeat("0", 64), Bytes: MaxFileBytes})
		}
	}
	if err := validateManifest(m); err == nil || !strings.Contains(err.Error(), "total byte limit") {
		t.Fatalf("aggregate declaration limit not enforced: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "small")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := zipEntryCount(f, MaxArchiveBytes+1); err == nil || !strings.Contains(err.Error(), "size is out of bounds") {
		t.Fatalf("oversized archive admitted before any payload read: %v", err)
	}
}

func TestImportRejectsPrivateKeysAndRenamedBinaryInAllowedLogs(t *testing.T) {
	for _, data := range [][]byte{[]byte("-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-key\n-----END PRIVATE KEY-----\n"), {'M', 'Z', 0, 1, 2}, {0xff, 0xfe, 'x'}, {0xe2, 0x82}} {
		files := partialFixture()
		files["logs/build.log"] = data
		assertArchiveRejected(t, fixtureEntries(t, files), "")
	}
	guard := &artifactTextGuard{}
	for _, chunk := range [][]byte{[]byte("valid "), {0xe2}, {0x82, 0xac}, []byte(" text")} {
		if _, err := guard.Write(chunk); err != nil {
			t.Fatal("valid split UTF-8 rejected: ", err)
		}
	}
	if err := guard.finish(); err != nil {
		t.Fatal(err)
	}
	guard = &artifactTextGuard{}
	if _, err := guard.Write([]byte("-----BEGIN PRIVATE K")); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Write([]byte("EY-----")); err == nil {
		t.Fatal("private-key marker crossed a read boundary undetected")
	}
}

func TestImportReportVerificationFailureCleansOnlyOwnedOutput(t *testing.T) {
	files := partialFixture()
	addReportFixture(t, files, "quick", false)
	files["runs/quick/evidence/guide.md"] = []byte("Changed after report-index creation; campaign manifest remains self-consistent")
	assertArchiveRejected(t, fixtureEntries(t, files), "verify imported quick report")
	archive := writeFixtureArchive(t, fixtureEntries(t, partialFixture()))
	dest := t.TempDir()
	sentinel := filepath.Join(dest, "retained.txt")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(context.Background(), archive, dest); err == nil {
		t.Fatal("existing directory overwritten")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "preserve" {
		t.Fatal("import changed unrelated existing evidence")
	}
}

type cancelFixtureReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *cancelFixtureReader) Read(p []byte) (int, error) {
	r.calls++
	p[0] = 'x'
	r.cancel()
	return 1, nil
}
func TestImportCancellationIsCheckedBeforeWorkAndPerChunk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dest := filepath.Join(t.TempDir(), "cancelled")
	if _, err := Import(ctx, "not-opened.zip", dest); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled import did work: %v", err)
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("pre-cancel created output")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	source := &cancelFixtureReader{cancel: cancel}
	_, err := io.Copy(io.Discard, contextReader{ctx, source})
	if !errors.Is(err, context.Canceled) || source.calls != 1 {
		t.Fatalf("stream continued after cancellation: %v, reads=%d", err, source.calls)
	}
}

func TestOwnedCleanupPreservesReplacementIdentityAndUnknownFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "owned")
	tree := &ownedTree{}
	if err := tree.mkdir(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "owned.txt")
	if err := tree.write(path, []byte("owned")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(root, "renamed-by-user.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	tree.cleanup()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("cleanup removed replacement file")
	}
	if _, err := os.Stat(filepath.Join(root, "renamed-by-user.txt")); err != nil {
		t.Fatal("cleanup recursively deleted an untracked file")
	}
}
