package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

// Keep raw evidence below the 16 MiB report artifact cap, with separate room
// for JSON indentation, HTML escaping, derived checks and terminal evidence.
const MaxJournalBytes = 4 << 20
const maxEvidenceRenderBytes = 12 << 20
const journalTerminalReserve = 512 << 10
const renderTerminalReserve = 2 << 20

type journal struct {
	mu                       sync.Mutex
	file                     *os.File
	scanID                   string
	observations             []model.Observation
	size, renderSize         int
	maxBytes, maxRenderBytes int
	truncated                bool
	terminalKeys             map[string]bool
	err                      error
}

func newJournal(dir, scanID string) (*journal, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, fmt.Errorf("scan output must be a new directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "evidence.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &journal{file: f, scanID: scanID, maxBytes: MaxJournalBytes, maxRenderBytes: maxEvidenceRenderBytes, terminalKeys: map[string]bool{}}, nil
}
func normalized(o model.Observation) model.Observation {
	if !o.Status.Valid() {
		o.Status = model.ToolError
		o.Value = nil
		o.Message = "Invalid observation status rejected"
	}
	if o.StartUTC.IsZero() {
		o.StartUTC = time.Now().UTC()
	}
	if o.Version == "" {
		o.Version = model.MethodVersion
	}
	if o.SourceKind == "" {
		o.SourceKind = "interpreted"
	}
	if o.Scope == "" {
		o.Scope = "selected allocation and process-visible environment"
	}
	if o.Visibility == "" {
		o.Visibility = "local process scope"
	}
	return o
}
func journalEncoding(o model.Observation) ([]byte, int, error) {
	line, err := json.Marshal(o)
	if err != nil {
		return nil, 0, err
	}
	pretty, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	value, err := json.MarshalIndent(o.Value, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	conditions, err := json.MarshalIndent(o.Conditions, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	// Estimate the actual HTML fragments rather than escaping every JSON field
	// name as if the entire observation were rendered twice. This preserves a
	// full 300-second/10-fields-per-second Standard timeline while reserving room
	// for markup, evidence links and repeated finding/highlight messages.
	text := o.ID + o.CheckID + o.MethodID + o.Version + o.SourceKind + o.Visibility + o.Scope + o.Message + o.Unit
	htmlCost := len(html.EscapeString(text)) + len(html.EscapeString(string(value))) + len(html.EscapeString(string(conditions))) + 1600 + 2*len(html.EscapeString(o.Message))
	jsonCost := len(pretty) + 6*strings.Count(string(pretty), "\n") + 200
	cost := htmlCost
	if jsonCost > cost {
		cost = jsonCost
	}
	return append(line, '\n'), cost, nil
}
func (j *journal) write(o model.Observation) (model.Observation, bool) {
	o = normalized(o)
	o.ID = fmt.Sprintf("%s-e%06d", j.scanID, len(j.observations)+1)
	line, cost, err := journalEncoding(o)
	if err != nil {
		j.err = err
		return o, false
	}
	if j.size+len(line) > j.maxBytes || j.renderSize+cost > j.maxRenderBytes {
		return o, false
	}
	if _, err = j.file.Write(line); err != nil {
		j.err = err
		return o, false
	}
	j.size += len(line)
	j.renderSize += cost
	j.observations = append(j.observations, o)
	return o, true
}
func boundedString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + " [truncated]"
}
func compactObservation(o model.Observation) model.Observation {
	o = normalized(o)
	originalStatus := o.Status
	o.Message = boundedString(o.Message, 768) + " Detailed payload omitted after evidence-capacity limit; retained status is scoped to the original observation."
	o.MethodID = boundedString(o.MethodID, 128)
	o.Scope = boundedString(o.Scope, 256)
	o.Visibility = boundedString(o.Visibility, 256)
	c := map[string]any{"evidence_detail_truncated": true}
	for _, key := range []string{"field", "seed", "tier", "opt_in", "worker_qualified", "counter_epoch", "counter_epoch_id", "epoch_id", "arithmetic_difference"} {
		if value, exists := o.Conditions[key]; exists {
			if data, err := json.Marshal(value); err == nil && len(data) <= 256 {
				c[key] = value
			}
		}
	}
	o.Conditions = c
	if encoded, err := json.Marshal(o.Value); err != nil || len(encoded) > 2048 {
		o.Value = nil
		if originalStatus == model.Pass {
			o.Status = model.NotTested
		}
		o.Message += " Value too large or invalid for the retained summary."
	}
	return o
}
func terminalEvidence(o model.Observation) bool {
	if o.Status != model.Pass {
		return true
	}
	if strings.HasPrefix(o.MethodID, "delta.") || strings.HasPrefix(o.MethodID, "reference.") || strings.HasPrefix(o.MethodID, "guard.") {
		return true
	}
	field, _ := o.Conditions["field"].(string)
	switch field {
	case "uuid", "driver_version", "counter_epoch", "ecc_corrected_volatile", "ecc_uncorrected_volatile", "pcie_replay_count", "row_remap_failure", "row_remap_pending", "retirement_pending", "temperature_gpu_c", "temperature_slowdown_c", "clock_event_reasons", "power_draw_w", "cgroup_cpu_stat", "cgroup_memory_events", "cgroup_memory_failcnt":
		return true
	}
	return false
}
func (j *journal) capacityMarker() {
	if j.truncated {
		return
	}
	j.truncated = true
	marker := baseObservation("H03", "scheduler.evidence-capacity", model.NotTested, "Evidence capacity reached. Active work stopped; report is partial, with bounded terminal safety/counter summaries retained and repetitive or oversized detail omitted.")
	marker.Conditions = map[string]any{"evidence_detail_truncated": true, "raw_limit_bytes": j.maxBytes, "render_evidence_budget_bytes": j.maxRenderBytes}
	_, _ = j.write(marker)
}
func (j *journal) add(observations ...model.Observation) {
	j.mu.Lock()
	defer func() {
		// One durable flush per complete collector/worker batch avoids making
		// ten telemetry fields trigger ten unrelated filesystem flushes.
		if err := j.file.Sync(); err != nil && j.err == nil {
			j.err = err
		}
		j.mu.Unlock()
	}()
	for index, o := range observations {
		if j.err != nil {
			return
		}
		o = normalized(o)
		// Reserve terminal capacity before admitting another ordinary sample.
		candidate := o
		candidate.ID = fmt.Sprintf("%s-e%06d", j.scanID, len(j.observations)+1)
		line, cost, err := journalEncoding(candidate)
		if err != nil {
			o.Value = nil
			o.Conditions = map[string]any{"invalid_payload_omitted": true}
			o.Status = model.ToolError
			o.Message = "Observation payload could not be serialized; no numeric result was admitted."
			candidate = o
			line, cost, _ = journalEncoding(candidate)
		}
		rawReserve := journalTerminalReserve
		if rawReserve > j.maxBytes/2 {
			rawReserve = j.maxBytes / 2
		}
		renderReserve := renderTerminalReserve
		if renderReserve > j.maxRenderBytes/2 {
			renderReserve = j.maxRenderBytes / 2
		}
		if !j.truncated && (j.size+len(line) > j.maxBytes-rawReserve || j.renderSize+cost > j.maxRenderBytes-renderReserve) {
			j.capacityMarker()
		}
		if j.truncated {
			if !terminalEvidence(o) {
				continue
			}
			o = compactObservation(o)
			value, _ := json.Marshal(o.Value)
			key := o.CheckID + "/" + o.MethodID + "/" + string(o.Status) + "/" + string(value)
			// Repeated telemetry of the same status is not allowed to consume the room
			// reserved for a later mismatch or distinct mandatory error.
			if j.terminalKeys[key] {
				continue
			}
			j.terminalKeys[key] = true
		}
		retained, ok := j.write(o)
		if ok {
			observations[index] = retained
			continue
		}
		if j.err != nil {
			return
		}
		// The capacity marker already withholds completion. A final oversize payload
		// is never allowed to invalidate the readable evidence collected so far.
		j.capacityMarker()
	}
}
func (j *journal) incomplete() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.truncated || j.err != nil
}
func (j *journal) snapshot() []model.Observation {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]model.Observation(nil), j.observations...)
}
func (j *journal) close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return errors.Join(j.err, j.file.Sync(), j.file.Close())
}
