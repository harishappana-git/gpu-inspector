package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

const maxBuildExecutableBytes int64 = 128 << 20
const buildEvidenceBudget = 250 * time.Millisecond

// buildEvidence inventories only the current inspector executable and a small
// allowlist of its build metadata. It does not inspect installed packages,
// dependencies, process arguments, environment variables or neighboring files.
func buildEvidence() model.Observation {
	path, err := os.Executable()
	if runtime.GOOS == "linux" && err == nil {
		// The kernel link retains the running inode even if its old name was
		// replaced. Neither the link nor a private filesystem path is exported.
		path = "/proc/self/exe"
	}
	info, _ := debug.ReadBuildInfo()
	if err != nil {
		path = ""
	}
	return buildEvidenceFrom(path, info)
}

func buildEvidenceFrom(path string, info *debug.BuildInfo) model.Observation {
	start := time.Now()
	o := baseObservation("H10", "build.metadata", model.Pass, "Recorded local executable bytes and allowlisted build metadata. This is host-mediated provenance, not independent authenticity, build reproducibility, dependency qualification or CUDA qualification.")
	o.StartUTC = start.UTC()
	o.SourceKind = "reported-and-locally-measured"
	o.ResourceID = "inspector-executable"
	o.Scope = "current inspector executable and allowlisted build metadata only"
	o.Visibility = "local process and filesystem; host-mediated"
	o.Conditions = map[string]any{"byte_cap": maxBuildExecutableBytes, "cooperative_budget_ms": buildEvidenceBudget.Milliseconds(), "packages_enumerated": false, "environment_collected": false, "paths_exported": false, "hash_scope": "bytes read from the process executable at collection time; non-Linux path resolution does not independently prove original loaded-image identity"}
	values := map[string]any{"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "tool_version": model.ToolVersion, "schema_version": model.SchemaVersion, "rule_version": model.RuleVersion, "method_version": model.MethodVersion, "build_info_available": info != nil}
	if info != nil {
		// Runtime GoVersion is always included. The build-info field is copied
		// only when it agrees, avoiding arbitrary linker-injected free text.
		if info.GoVersion == runtime.Version() {
			values["build_go_version"] = info.GoVersion
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if (len(setting.Value) == 40 || len(setting.Value) == 64) && hexadecimal(setting.Value) {
					values["vcs_revision"] = setting.Value
				}
			case "vcs.modified":
				if setting.Value == "true" || setting.Value == "false" {
					values["vcs_modified"] = setting.Value == "true"
				}
			}
		}
	}
	digest, size, status := executableDigest(path, start.Add(buildEvidenceBudget))
	o.Status = status
	if status == model.Pass {
		values["executable_sha256"] = digest
		values["executable_bytes"] = size
		o.SampleCount = 1
	} else {
		o.Message = "Executable hash is unavailable, exceeded the bounded collection budget, or changed during reading; allowlisted runtime metadata is retained without a reproducible-environment pass. No filesystem path or raw error is exported."
	}
	o.Value = values
	o.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return o
}

func hexadecimal(value string) bool {
	for _, r := range strings.ToLower(value) {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func executableDigest(path string, deadline time.Time) (string, int64, model.Status) {
	if path == "" {
		return "", 0, model.NotTested
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			return "", 0, model.PermissionDenied
		}
		return "", 0, model.ToolError
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 {
		return "", 0, model.ToolError
	}
	if before.Size() > maxBuildExecutableBytes {
		return "", 0, model.NotTested
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if !time.Now().Before(deadline) {
			return "", total, model.TimeBudgetExhausted
		}
		n, err := f.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > maxBuildExecutableBytes {
				return "", total, model.NotTested
			}
			_, _ = hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", total, model.ToolError
		}
	}
	after, err := f.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || total != before.Size() {
		return "", total, model.Contaminated
	}
	return hex.EncodeToString(hash.Sum(nil)), total, model.Pass
}
