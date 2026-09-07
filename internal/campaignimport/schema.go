// Package campaignimport admits a bounded, data-only campaign ZIP into private
// local files. Hashes establish byte integrity, not trusted-host measurements.
package campaignimport

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxArchiveBytes     int64 = 256 << 20
	MaxTotalBytes       int64 = 512 << 20
	MaxFileBytes        int64 = 16 << 20
	MaxManifestBytes    int64 = 128 << 10
	MaxFiles                  = 512
	MaxCompressionRatio       = 1000
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Manifest struct {
	SchemaVersion    int    `json:"schema_version"`
	CampaignID       string `json:"campaign_id"`
	ReleaseQualified *bool  `json:"release_qualified"`
	Files            []File `json:"files"`
}

type ImportedReport struct {
	Run        string `json:"run"`
	Directory  string `json:"directory"`
	ReviewPath string `json:"review_path"`
	ScanID     string `json:"scan_id"`
	Verdict    string `json:"reported_verdict"`
	Synthetic  bool   `json:"synthetic"`
}

type Result struct {
	CampaignID        string           `json:"campaign_id"`
	OutputDir         string           `json:"output_dir"`
	IndexPath         string           `json:"index_path"`
	ArchiveSHA256     string           `json:"archive_sha256"`
	FileCount         int              `json:"archived_file_count"`
	UncompressedBytes int64            `json:"archived_uncompressed_bytes"`
	Reports           []ImportedReport `json:"verified_reports"`
	ReleaseQualified  bool             `json:"release_qualified"`
	IntegrityBoundary string           `json:"integrity_boundary"`
}

var campaignIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$`)
var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// This list is intentionally closed. New plugins and new archive paths require
// an explicit importer change, rather than automatic extension-based admission.
func allowedPath(name string) bool {
	switch name {
	case "campaign-manifest.json", "campaign-status.json", "remaining-checklist.json", "remaining-checklist.txt", "build-provenance.txt",
		"logs/build.log", "logs/preflight.json", "logs/sanitizer-version.log", "logs/setup.log", "logs/setup-status.json":
		return true
	}
	p := strings.Split(name, "/")
	if len(p) >= 3 && p[0] == "runs" && (p[1] == "quick" || p[1] == "standard") {
		if len(p) == 3 {
			switch p[2] {
			case "terminal.log", "verification.log", "checklist.json", "remaining-checklist.txt", "run-status.json":
				return true
			}
		}
		if len(p) == 4 && p[2] == "evidence" {
			switch p[3] {
			case "report.json", "report.html", "evidence-index.json", "evidence.jsonl", "guide.md", "ticket.md":
				return true
			}
		}
	}
	if len(p) != 4 || p[0] != "sanitizer" {
		return false
	}
	switch p[1] {
	case "memcheck", "racecheck", "initcheck", "synccheck":
	default:
		return false
	}
	switch p[2] {
	case "memory_integrity", "fp32_gemm", "bf16_gemm", "tf32_gemm", "int8_gemm", "fp8_gemm", "hbm_copy", "h2d", "d2h", "working_set", "dispatch_latency", "numa_transfer":
	default:
		return false
	}
	switch p[3] {
	case "worker.json", "sanitizer.log", "stdout.log", "stderr.log", "validation.log", "guard-before.json", "guard-after.json", "status.json":
		return true
	}
	return false
}

func validateManifest(m Manifest) error {
	if m.SchemaVersion != 1 || !campaignIDPattern.MatchString(m.CampaignID) || m.ReleaseQualified == nil || *m.ReleaseQualified {
		return fmt.Errorf("unsupported campaign manifest or qualification claim")
	}
	if len(m.Files) < 3 || len(m.Files) >= MaxFiles {
		return fmt.Errorf("campaign manifest file count is out of bounds")
	}
	seen := map[string]bool{}
	var total int64
	for _, f := range m.Files {
		if f.Path == "campaign-manifest.json" || !allowedPath(f.Path) || seen[f.Path] || !sha256Pattern.MatchString(f.SHA256) || f.Bytes < 0 || f.Bytes > MaxFileBytes {
			return fmt.Errorf("invalid or duplicate campaign manifest entry %q", f.Path)
		}
		seen[f.Path] = true
		total += f.Bytes
		if total > MaxTotalBytes {
			return fmt.Errorf("campaign manifest exceeds total byte limit")
		}
	}
	for _, name := range []string{"campaign-status.json", "remaining-checklist.json", "remaining-checklist.txt"} {
		if !seen[name] {
			return fmt.Errorf("required campaign artifact missing: %s", name)
		}
	}
	return nil
}
