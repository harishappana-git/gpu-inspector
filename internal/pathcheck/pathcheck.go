// Package pathcheck provides opt-in, bounded workspace and endpoint tests.
// Neither test runs unless its corresponding option is explicitly populated.
package pathcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"sort"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/privatefs"
)

const (
	DefaultDiskBytes     int64 = 16 << 20
	DefaultDownloadBytes int64 = 8 << 20
	MaxDiskBytes         int64 = 64 << 20
	MaxDownloadBytes     int64 = 64 << 20
	blockBytes                 = 64 << 10
)

type Options struct {
	Workspace     string
	DiskBytes     int64
	URL           string
	DownloadBytes int64
	Timeout       time.Duration
}

func Run(ctx context.Context, opts Options) []model.Observation {
	limit := opts.Timeout
	if limit <= 0 {
		limit = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	out := []model.Observation{}
	if opts.DiskBytes != 0 {
		out = append(out, runDisk(ctx, opts)...)
	}
	if opts.URL != "" {
		out = append(out, runNetwork(ctx, opts, newHTTPClient(limit))...)
	}
	return out
}

func evidence(check, method, resource string, status model.Status, value any, samples int, start time.Time, message string, conditions map[string]any) model.Observation {
	return model.Observation{CheckID: check, ResourceID: resource, MethodID: method, Version: model.MethodVersion, StartUTC: start.UTC(), DurationMS: float64(time.Since(start).Microseconds()) / 1000, Status: status, Value: value, SampleCount: samples, SourceKind: "measured", Visibility: "only explicitly selected path/endpoint", Scope: resource, Message: message, Conditions: conditions}
}
func diskMissing(status model.Status, start time.Time, message string) []model.Observation {
	out := []model.Observation{}
	for _, check := range []string{"F03", "F05", "F06", "F07"} {
		out = append(out, evidence(check, "pathcheck.disk", "selected-workspace", status, nil, 0, start, message, map[string]any{"opt_in": true, "user_files_read": false, "direct_io": false, "cache_drop": false}))
	}
	return out
}
func contextStatus(ctx context.Context, err error) model.Status {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return model.TimeBudgetExhausted
	}
	if errors.Is(err, os.ErrPermission) {
		return model.PermissionDenied
	}
	return model.ToolError
}

type diskMeasurements struct {
	Written, Read         int64
	WriteTimes, ReadTimes []float64
	SyncMS                float64
	Expected, Actual      string
	Complete              bool
	FailureStage          string
}

func runDisk(ctx context.Context, opts Options) []model.Observation {
	start := time.Now()
	if ctx.Err() != nil {
		return diskMissing(model.TimeBudgetExhausted, start, "Disk test did not start because its time budget/cancellation was reached.")
	}
	if opts.Workspace == "" {
		return diskMissing(model.NotTested, start, "Active disk testing requires an explicitly selected workspace.")
	}
	if opts.DiskBytes <= 0 || opts.DiskBytes > MaxDiskBytes {
		return diskMissing(model.ToolError, start, "Disk byte budget must be positive and no greater than 64 MiB.")
	}
	info, err := os.Stat(opts.Workspace)
	if err != nil || !info.IsDir() {
		return diskMissing(contextStatus(ctx, err), start, "Explicit workspace is unavailable or is not a directory.")
	}
	file, err := privatefs.CreateScratch(opts.Workspace)
	if err != nil {
		return diskMissing(contextStatus(ctx, err), start, "Could not create a test-owned scratch file in the explicit workspace.")
	}
	// POSIX unlinks before writes; Windows uses an exclusive delete-on-close
	// handle. Both paths retain only owned-handle I/O and OS process-exit cleanup.
	defer file.Close()
	measurements, err := exerciseFile(ctx, file, opts.DiskBytes)
	status := model.Pass
	if err != nil {
		status = contextStatus(ctx, err)
	}
	conditions := map[string]any{"opt_in": true, "requested_bytes": opts.DiskBytes, "block_bytes": blockBytes, "scratch_mode": privatefs.ScratchMode, "data_pattern": "splitmix64-v1; fixed public seed", "seed": uint64(0x4752495041544831), "direct_io": false, "cache_drop": false, "cache_method": "buffered writes followed by fsync and immediate buffered reread; OS cache may dominate", "parallelism": 1, "generation_and_hashing_in_timed_operations": false, "sync_in_write_throughput": true, "user_files_read": false, "payload_written_bytes": measurements.Written, "payload_read_bytes": measurements.Read, "complete": measurements.Complete}
	if err != nil {
		conditions["failure_stage"] = measurements.FailureStage
	}
	result := map[string]any{"written_bytes": measurements.Written, "read_bytes": measurements.Read, "write_operation_ms": sum(measurements.WriteTimes), "read_operation_ms": sum(measurements.ReadTimes), "sync_ms": measurements.SyncMS}
	writeMS := sum(measurements.WriteTimes) + measurements.SyncMS
	readMS := sum(measurements.ReadTimes)
	if writeMS > 0 && measurements.Written > 0 {
		result["buffered_write_plus_sync_mib_s"] = float64(measurements.Written) / (1 << 20) / (writeMS / 1000)
	}
	if readMS > 0 && measurements.Read > 0 {
		result["immediate_buffered_read_mib_s"] = float64(measurements.Read) / (1 << 20) / (readMS / 1000)
	}
	message := "Measured one bounded buffered file path; cache-sensitive rates do not establish device steady-state speed, physical media identity or persistence."
	if err != nil {
		message = "Disk test ended before completion; retain actual byte counts and failure stage without treating partial evidence as a pass."
	}
	out := []model.Observation{evidence("F03", "pathcheck.disk.sequential", "selected-workspace", status, result, len(measurements.WriteTimes)+len(measurements.ReadTimes), start, message, conditions)}
	latencyStatus := status
	latencyMessage := "Empirical operation latencies describe this bounded file test and do not predict production tail latency; fsync is one separately recorded sample."
	if status == model.Pass && (len(measurements.WriteTimes) < 100 || len(measurements.ReadTimes) < 100) {
		latencyStatus = model.Warning
		latencyMessage = "Fewer than 100 operations per direction: empirical p95 is suppressed by this method convention; only count/min/median/max describe the short sample."
	}
	latency := map[string]any{"write": latencySummary(measurements.WriteTimes), "read": latencySummary(measurements.ReadTimes), "fsync_sample_ms": measurements.SyncMS, "p99": "suppressed; no calibrated tail measurement"}
	out = append(out, evidence("F05", "pathcheck.disk.latency", "selected-workspace", latencyStatus, latency, len(measurements.WriteTimes)+len(measurements.ReadTimes), start, latencyMessage, conditions))
	cacheStatus := model.Warning
	if status != model.Pass {
		cacheStatus = status
	}
	out = append(out, evidence("F06", "pathcheck.disk.cache_context", "selected-workspace", cacheStatus, map[string]any{"cold_cache_established": false, "burst_exhaustion_established": false, "steady_state_established": false}, 0, start, "No cache dropping or burst exhaustion was performed. Immediate reread can be cache-resident, so cold-media and sustained-speed conclusions remain untested.", conditions))
	integrityStatus := status
	var integrity any
	integrityMessage := "Readback did not complete; integrity of the requested byte range remains unverified."
	if measurements.Complete {
		integrity = map[string]any{"tested_bytes": measurements.Read, "expected_sha256": measurements.Expected, "readback_sha256": measurements.Actual, "mismatches": 0}
		integrityMessage = "SHA-256 of the generated bytes matched readback from this test-owned file descriptor; only these bytes and this method were checked."
		if measurements.Expected != measurements.Actual {
			integrityStatus = model.Fail
			integrity.(map[string]any)["mismatches"] = 1
			integrityMessage = "Generated-byte and readback digests differ. Preserve method evidence and investigate; one file mismatch does not establish a physical-media defect."
		}
	}
	integritySamples := 0
	if measurements.Complete {
		integritySamples = 1
	}
	out = append(out, evidence("F07", "pathcheck.disk.integrity", "selected-workspace", integrityStatus, integrity, integritySamples, start, integrityMessage, conditions))
	return out
}

// exerciseFile touches only an already-owned file descriptor. Keeping this
// separate makes cancellation and corruption verification hermetic in tests.
type ownedFile interface {
	io.Reader
	io.Writer
	io.Seeker
	Sync() error
}

func exerciseFile(ctx context.Context, file ownedFile, count int64) (m diskMeasurements, err error) {
	expected, actual := sha256.New(), sha256.New()
	buf := make([]byte, blockBytes)
	state := uint64(0x4752495041544831)
	for remaining := count; remaining > 0; {
		if err = ctx.Err(); err != nil {
			m.FailureStage = "write"
			return
		}
		n := len(buf)
		if int64(n) > remaining {
			n = int(remaining)
		}
		fillPattern(buf[:n], &state)
		_, _ = expected.Write(buf[:n])
		start := time.Now()
		written, e := file.Write(buf[:n])
		elapsed := float64(time.Since(start).Nanoseconds()) / 1e6
		m.WriteTimes = append(m.WriteTimes, elapsed)
		m.Written += int64(written)
		if e != nil {
			err = e
			m.FailureStage = "write"
			return
		}
		if written != n {
			err = io.ErrShortWrite
			m.FailureStage = "write"
			return
		}
		remaining -= int64(written)
	}
	if err = ctx.Err(); err != nil {
		m.FailureStage = "sync"
		return
	}
	start := time.Now()
	err = file.Sync()
	m.SyncMS = float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		m.FailureStage = "sync"
		return
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		m.FailureStage = "seek"
		return
	}
	for remaining := count; remaining > 0; {
		if err = ctx.Err(); err != nil {
			m.FailureStage = "read"
			return
		}
		n := len(buf)
		if int64(n) > remaining {
			n = int(remaining)
		}
		start := time.Now()
		read, e := io.ReadFull(file, buf[:n])
		m.ReadTimes = append(m.ReadTimes, float64(time.Since(start).Nanoseconds())/1e6)
		m.Read += int64(read)
		_, _ = actual.Write(buf[:read])
		if e != nil {
			err = e
			m.FailureStage = "read"
			return
		}
		remaining -= int64(read)
	}
	m.Expected = hex.EncodeToString(expected.Sum(nil))
	m.Actual = hex.EncodeToString(actual.Sum(nil))
	m.Complete = true
	return
}
func fillPattern(buf []byte, state *uint64) {
	for offset := 0; offset < len(buf); {
		*state += 0x9e3779b97f4a7c15
		z := *state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z ^= z >> 31
		for i := 0; i < 8 && offset < len(buf); i++ {
			buf[offset] = byte(z)
			z >>= 8
			offset++
		}
	}
}
func sum(values []float64) float64 {
	n := 0.0
	for _, v := range values {
		n += v
	}
	return n
}
func latencySummary(values []float64) map[string]any {
	out := map[string]any{"count": len(values)}
	if len(values) == 0 {
		return out
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	out["min_ms"] = sorted[0]
	out["median_ms"] = sorted[len(sorted)/2]
	out["max_ms"] = sorted[len(sorted)-1]
	if len(sorted) >= 100 {
		out["p95_ms"] = sorted[int(math.Ceil(.95*float64(len(sorted))))-1]
	}
	return out
}
