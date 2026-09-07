// Package report renders the local evidence model without network resources.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/harishappana/gpu-inspector/internal/bundle"
)

const MaxArtifactBytes int64 = 16 << 20

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// EvidenceIndex deliberately does not hash itself. These hashes detect changed
// bytes; they are not a signature or proof that the measurement host is trusted.
type EvidenceIndex struct {
	SchemaVersion     string     `json:"schema_version"`
	ScanID            string     `json:"scan_id"`
	HashAlgorithm     string     `json:"hash_algorithm"`
	IntegrityBoundary string     `json:"integrity_boundary"`
	Artifacts         []Artifact `json:"artifacts"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("report directory must be a real directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("report directory %q must be private (0700)", dir)
	}
	return nil
}

// publish writes a complete file and atomically creates its final name without
// replacing retained evidence. Hard linking avoids the overwrite race in rename.
func publish(dir, name string, data []byte) error {
	if int64(len(data)) > MaxArtifactBytes {
		return fmt.Errorf("artifact %s exceeds size limit", name)
	}
	tmp, err := os.CreateTemp(dir, ".gri-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("publish %s without overwriting evidence: %w", name, err)
	}
	return nil
}

func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("artifact %q must be a regular file", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("artifact %q must be private (0600)", path)
	}
	if info.Size() > MaxArtifactBytes {
		return nil, fmt.Errorf("artifact %q exceeds size limit", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxArtifactBytes+1))
	if err == nil && int64(len(data)) > MaxArtifactBytes {
		return nil, fmt.Errorf("artifact %q exceeds size limit", path)
	}
	return data, err
}

func jsonBytes(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	return append(data, '\n'), err
}

func decodeJSON(data []byte, dst any) error {
	if int64(len(data)) > MaxArtifactBytes {
		return fmt.Errorf("JSON artifact exceeds size limit")
	}
	if err := bundle.CheckUniqueJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	// Dynamic observation values can contain uint64 error counters. Converting
	// them through float64 would silently round values above 2^53 before replay.
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected content after JSON document")
	}
	return nil
}

func validArtifactName(name string) bool {
	switch name {
	case "report.json", "report.html", "guide.md", "ticket.md", "evidence.jsonl":
		return true
	}
	return false
}

// Verify checks every indexed artifact, rejects unexpected artifacts and path
// traversal, and checks private permissions. It does not authenticate the host.
func Verify(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("evidence directory is not private")
	}
	data, err := readPrivateFile(filepath.Join(dir, "evidence-index.json"))
	if err != nil {
		return err
	}
	var index EvidenceIndex
	if err = decodeJSON(data, &index); err != nil {
		return fmt.Errorf("read evidence index: %w", err)
	}
	if index.SchemaVersion != "1.0.0" || index.HashAlgorithm != "SHA-256" {
		return fmt.Errorf("unsupported evidence index")
	}
	seen := map[string]bool{}
	for _, artifact := range index.Artifacts {
		if !validArtifactName(artifact.Name) || seen[artifact.Name] {
			return fmt.Errorf("invalid or duplicate artifact name %q", artifact.Name)
		}
		seen[artifact.Name] = true
		contents, err := readPrivateFile(filepath.Join(dir, artifact.Name))
		if err != nil {
			return err
		}
		if int64(len(contents)) != artifact.Bytes || digest(contents) != artifact.SHA256 {
			return fmt.Errorf("integrity mismatch: %s", artifact.Name)
		}
	}
	for _, name := range []string{"report.json", "report.html", "guide.md"} {
		if !seen[name] {
			return fmt.Errorf("required artifact missing from index: %s", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "evidence-index.json" && !seen[entry.Name()] {
			return fmt.Errorf("unindexed artifact: %s", entry.Name())
		}
	}
	var report struct {
		ScanID         string            `json:"scan_id"`
		ArtifactHashes map[string]string `json:"artifact_hashes"`
	}
	reportData, err := readPrivateFile(filepath.Join(dir, "report.json"))
	if err != nil {
		return err
	}
	if err = decodeJSON(reportData, &report); err != nil {
		return err
	}
	if index.ScanID != report.ScanID {
		return fmt.Errorf("scan ID differs between report and index")
	}
	for name, hash := range report.ArtifactHashes {
		if name == "report.json" || name == "evidence-index.json" || !seen[name] {
			return fmt.Errorf("invalid report artifact hash: %s", name)
		}
		contents, err := readPrivateFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if digest(contents) != hash {
			return fmt.Errorf("report artifact hash mismatch: %s", name)
		}
	}
	return nil
}

func sortedArtifactNames(artifacts map[string][]byte) []string {
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
