package worker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/reference"
)

func TestDependencySnapshotAuthenticatesOriginalBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cublas64_12.dll")
	data := []byte("synthetic DLL bytes for signature transport test only")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	d, err := DescribeDependency(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateDependencies([]Dependency{d}, "windows-amd64"); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), d.File)
	if _, err = snapshotDependency(path, snapshot, d); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("tampered later"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(snapshot)
	if err != nil || string(got) != string(data) {
		t.Fatal("authenticated dependency snapshot changed")
	}
	if _, err = snapshotDependency(path, filepath.Join(t.TempDir(), d.File), d); err == nil {
		t.Fatal("tampered dependency accepted")
	}
}

func TestSignedManifestPlatformAndDependencySnapshot(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := []byte("synthetic worker snapshot bytes")
	path := filepath.Join(dir, "worker.exe")
	if err = os.WriteFile(path, binary, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	m := Manifest{Kind: "gri-worker", Version: model.ToolVersion, MethodVersion: model.MethodVersion, Platform: runtime.GOOS + "-" + runtime.GOARCH, File: filepath.Base(path), SHA256: hex.EncodeToString(digest[:])}
	manifestPath := filepath.Join(dir, "manifest.json")
	writeManifest := func() {
		t.Helper()
		payload, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		signed, e := bundle.Sign(payload, priv)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(manifestPath, signed, 0600); e != nil {
			t.Fatal(e)
		}
	}
	originalPlatform := m.Platform
	m.Platform = "wrong-amd64"
	writeManifest()
	if _, err = Load(path, manifestPath, pub, true); err == nil {
		t.Fatal("wrong platform accepted")
	}
	m.Platform = originalPlatform
	if runtime.GOOS == "windows" {
		dependencyPath := filepath.Join(dir, "cudart64_12.dll")
		if err = os.WriteFile(dependencyPath, []byte("synthetic CUDA runtime DLL"), 0600); err != nil {
			t.Fatal(err)
		}
		dependency, e := DescribeDependency(dependencyPath)
		if e != nil {
			t.Fatal(e)
		}
		m.Dependencies = []Dependency{dependency}
		writeManifest()
		worker, e := Load(path, manifestPath, pub, true)
		if e != nil {
			t.Fatal(e)
		}
		defer worker.Close()
		if filepath.Ext(worker.Path) != ".exe" {
			t.Fatal("Windows worker snapshot lacks .exe extension")
		}
		if _, e = os.Stat(filepath.Join(filepath.Dir(worker.Path), dependency.File)); e != nil {
			t.Fatal("signed dependency absent beside snapshot")
		}
		if e = os.WriteFile(dependencyPath, []byte("unsigned modification"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = Load(path, manifestPath, pub, true); e == nil {
			t.Fatal("signed manifest accepted changed DLL")
		}
	}
}

func TestDependencyManifestRejectsUnsafeOrAmbiguousDLLs(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, name := range []string{"../cudart64_12.dll", `..\cudart64_12.dll`, "C:cudart64_12.dll", "kernel32.dll", "nvcuda.dll", "unknown.dll", "cudart64_12.dll:stream"} {
		if validateDependencies([]Dependency{{File: name, SHA256: digest}}, "windows-amd64") == nil {
			t.Fatalf("invalid dependency %q accepted", name)
		}
	}
	d := Dependency{File: "cublas64_12.dll", SHA256: digest}
	if validateDependencies([]Dependency{d, {File: "CUBLAS64_12.DLL", SHA256: digest}}, "windows-amd64") == nil {
		t.Fatal("case-insensitive duplicate DLL accepted")
	}
	if validateDependencies([]Dependency{d}, "linux-amd64") == nil {
		t.Fatal("Windows DLL accepted on Linux")
	}
	d.SHA256 = "not-a-digest"
	if validateDependencies([]Dependency{d}, "windows-amd64") == nil {
		t.Fatal("malformed digest accepted")
	}
}

func TestRTXMemoryBandwidthUsesDeviceMemoryMetric(t *testing.T) {
	r := protocolFixture("hbm_copy", "quick")
	r.Conditions["compute_capability"] = "12.0"
	r.Conditions["device_memory_technology"] = "GDDR7"
	r.Conditions["l2_bytes"] = float64(64 << 20)
	r.Metric.Name = "device_memory_effective_copy_bandwidth"
	if _, err := parsed(t, r); err != nil {
		t.Fatal(err)
	}
	r.Metric.Name = "hbm_effective_copy_bandwidth"
	if _, err := parsed(t, r); err == nil {
		t.Fatal("RTX measurement labeled HBM accepted")
	}
	r.Metric.Name = "device_memory_effective_copy_bandwidth"
	r.Conditions["l2_bytes"] = float64(96 << 20)
	if _, err := parsed(t, r); err == nil {
		t.Fatal("RTX above-cache requirement used an H100 cache size")
	}
}

func TestRuntimeDLLBytesRemainPartOfReferenceConditions(t *testing.T) {
	observationHash := func(digest string) string {
		r := protocolFixture("h2d", "quick")
		b := &Binary{dependencies: []Dependency{{File: "CUBLAS64_12.DLL", SHA256: digest}}}
		out, _ := b.observations(request("h2d", "quick"), model.Observation{}, r, 0)
		digests, ok := out[0].Conditions["runtime_dependency_sha256"].(map[string]string)
		if !ok || digests["cublas64_12.dll"] != digest {
			t.Fatal("signed dependency provenance missing")
		}
		return reference.ConditionsHash(out[0].Conditions)
	}
	if observationHash(strings.Repeat("a", 64)) == observationHash(strings.Repeat("b", 64)) {
		t.Fatal("different runtime DLLs share the same reference key")
	}
}
