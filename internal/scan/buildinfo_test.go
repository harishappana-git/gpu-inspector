package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func TestBuildEvidenceExactHashAndMetadataAllowlist(t *testing.T) {
	contents := []byte("fixture executable bytes; not a real executable")
	path := filepath.Join(t.TempDir(), "PRIVATE_EXECUTABLE_NAME")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	info := &debug.BuildInfo{GoVersion: runtime.Version(), Path: "PRIVATE_MODULE_PATH", Main: debug.Module{Path: "PRIVATE_MAIN_MODULE", Version: "SECRET_MODULE_VERSION"}, Deps: []*debug.Module{{Path: "PRIVATE_DEPENDENCY"}}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: strings.Repeat("a", 40)}, {Key: "vcs.modified", Value: "true"}, {Key: "-ldflags", Value: "SECRET_LINKER_FLAGS"}, {Key: "CGO_CFLAGS", Value: "SECRET_COMPILER_PATH"}, {Key: "environment", Value: "SECRET_ENVIRONMENT"}}}
	o := buildEvidenceFrom(path, info)
	if o.Status != model.Pass || o.CheckID != "H10" || o.MethodID != "build.metadata" || o.SampleCount != 1 {
		t.Fatalf("incorrect build evidence state: %#v", o)
	}
	values := o.Value.(map[string]any)
	sum := sha256.Sum256(contents)
	if values["executable_sha256"] != hex.EncodeToString(sum[:]) || values["executable_bytes"] != int64(len(contents)) {
		t.Fatal("hash does not cover exact fixture bytes")
	}
	if values["go_version"] != runtime.Version() || values["goos"] != runtime.GOOS || values["goarch"] != runtime.GOARCH || values["vcs_revision"] != strings.Repeat("a", 40) || values["vcs_modified"] != true {
		t.Fatal("allowlisted exact metadata missing")
	}
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{path, "PRIVATE_EXECUTABLE_NAME", "PRIVATE_MODULE_PATH", "PRIVATE_MAIN_MODULE", "SECRET_MODULE_VERSION", "PRIVATE_DEPENDENCY", "SECRET_LINKER_FLAGS", "SECRET_COMPILER_PATH", "SECRET_ENVIRONMENT"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("build evidence exported %q", secret)
		}
	}
}

func TestBuildEvidenceMissingAndUnboundedInputsDoNotPass(t *testing.T) {
	if o := buildEvidenceFrom("", nil); o.Status == model.Pass {
		t.Fatal("missing executable became a pass")
	}
	path := filepath.Join(t.TempDir(), "oversized")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBuildExecutableBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if o := buildEvidenceFrom(path, nil); o.Status != model.NotTested {
		t.Fatal("oversized executable escaped byte cap")
	}
	small := filepath.Join(t.TempDir(), "small")
	if err := os.WriteFile(small, []byte("bounded fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, status := executableDigest(small, time.Now().Add(-time.Second)); status != model.TimeBudgetExhausted {
		t.Fatal("expired hash budget did not remain explicit")
	}
}

func TestBuildEvidenceRejectsUnexpectedVCSValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	info := &debug.BuildInfo{GoVersion: "PRIVATE_GO_VERSION", Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "SECRET_REVISION_PATH"}, {Key: "vcs.modified", Value: "SECRET_MODIFIED_VALUE"}}}
	o := buildEvidenceFrom(path, info)
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE_GO_VERSION", "SECRET_REVISION_PATH", "SECRET_MODIFIED_VALUE"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("unexpected build value exported: %s", secret)
		}
	}
}
