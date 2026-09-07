// Package diagnostics contains bounded, selected-device Linux Xid and optional
// DCGM adapters. It exports normalized evidence rather than vendor log text.
package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/secureexec"
)

// Runner is a test/embedding seam. Implementations must honor the context and
// output limit. The tool argument is an allowlisted basename, never shell text.
type Runner func(context.Context, string, []string, map[string]string, int) secureexec.Result

type Options struct {
	Timeout     time.Duration
	Runner      Runner
	DCGMEnabled bool
}

var fullUUID = regexp.MustCompile(`(?i)^GPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var pciPattern = regexp.MustCompile(`(?i)^([0-9a-f]{4}|[0-9a-f]{8}):([0-9a-f]{2}):([0-9a-f]{2})(?:\.([0-7]))?$`)

func canonicalPCI(value string) (string, bool) {
	p := pciPattern.FindStringSubmatch(value)
	if p == nil {
		return "", false
	}
	domain, e := strconv.ParseUint(p[1], 16, 32)
	if e != nil {
		return "", false
	}
	device, _ := strconv.ParseUint(p[3], 16, 8)
	if device > 31 {
		return "", false
	}
	function := p[4]
	if function == "" {
		function = "0"
	}
	return fmt.Sprintf("%08x:%s:%s.%s", domain, strings.ToLower(p[2]), strings.ToLower(p[3]), function), true
}

func validTarget(d model.Device) bool {
	_, ok := canonicalPCI(d.PCIAddress)
	return fullUUID.MatchString(d.UUID) && ok
}

func observation(check, method string, d model.Device, start time.Time) model.Observation {
	return model.Observation{CheckID: check, ResourceID: d.UUID, MethodID: method, Version: model.MethodVersion, StartUTC: start.UTC(), Status: model.NotTested, SourceKind: "reported", Visibility: "selected GPU; local kernel or vendor service mediated", Scope: d.UUID, Conditions: map[string]any{"selected_uuid": d.UUID, "raw_logs_exported": false, "physical_defect_attribution": false}}
}

func finish(o model.Observation, start time.Time, status model.Status, message string) model.Observation {
	o.Status = status
	o.Message = message
	o.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return o
}

func bounded(ctx context.Context, limit, defaultLimit, maxLimit time.Duration) (context.Context, context.CancelFunc) {
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return context.WithTimeout(ctx, limit)
}

func runTool(ctx context.Context, opts Options, tool string, args []string, cap int) secureexec.Result {
	if ctx.Err() != nil {
		return secureexec.Result{Err: ctx.Err(), ExitCode: -1}
	}
	runner := opts.Runner
	if runner != nil {
		r := runner(ctx, tool, args, nil, cap)
		// Enforce parser bounds even if an injected runner violates its contract.
		if len(r.Stdout) > cap {
			r.Stdout, r.Truncated = r.Stdout[:cap], true
		}
		if len(r.Stderr) > cap {
			r.Stderr, r.Truncated = r.Stderr[:cap], true
		}
		return r
	}
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/dcgm/bin"} {
		filename := filepath.Join(dir, tool)
		if info, err := os.Stat(filename); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return secureexec.Run(ctx, filename, args, nil, cap)
		}
	}
	return secureexec.Result{Err: os.ErrNotExist, ExitCode: -1}
}

func resultStatus(ctx context.Context, r secureexec.Result) model.Status {
	if ctx.Err() != nil || errors.Is(r.Err, context.Canceled) || errors.Is(r.Err, context.DeadlineExceeded) {
		return model.TimeBudgetExhausted
	}
	if r.Truncated {
		return model.ToolError
	}
	if errors.Is(r.Err, os.ErrNotExist) {
		return model.DependencyMissing
	}
	text := strings.ToLower(string(r.Stderr) + "\n" + string(r.Stdout))
	if errors.Is(r.Err, os.ErrPermission) || strings.Contains(text, "permission denied") || strings.Contains(text, "insufficient permissions") || strings.Contains(text, "not seeing messages") || strings.Contains(text, "no journal files were opened") {
		return model.PermissionDenied
	}
	if r.Err != nil || r.ExitCode != 0 {
		return model.ToolError
	}
	return model.Pass
}

// Xid reads only the current-boot kernel journal in the supplied scan interval.
// The caller must supply a UUID/PCI pair whose scan continuity was checked.
func Xid(ctx context.Context, d model.Device, scanStart, scanEnd time.Time, opts Options) model.Observation {
	if runtime.GOOS != "linux" {
		start := time.Now()
		return finish(observation("B06", "linux.xid_scan_interval", d, start), start, model.Unsupported, "Device/time-scoped Linux kernel-journal Xid collection is unavailable on this operating system.")
	}
	return xid(ctx, d, scanStart, scanEnd, opts)
}

// DCGM runs only the opted-in level-1 software checks, against an existing
// loopback host engine and a verified single H100 entity. Other suites, service
// startup, resets, configuration changes and global stop operations are absent.
func DCGM(ctx context.Context, d model.Device, opts Options) model.Observation {
	if runtime.GOOS != "linux" {
		start := time.Now()
		o := observation("B11", "dcgm.selected_software", d, start)
		o.Conditions["stop_active"] = opts.DCGMEnabled
		return finish(o, start, model.Unsupported, "The selected-H100 DCGM adapter requires Linux and an existing local DCGM 4.6.0 installation.")
	}
	return dcgm(ctx, d, opts)
}
