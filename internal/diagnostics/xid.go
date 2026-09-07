package diagnostics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

type xidEvent struct {
	TimeUTC time.Time `json:"time_utc"`
	Code    uint32    `json:"xid"`
}

var xidMessage = regexp.MustCompile(`(?i)^NVRM:\s*Xid\s*\((?:PCI:)?([0-9a-f:.]+)\):\s*([0-9]{1,5})(?:[, ]|$)`)

func xid(ctx context.Context, d model.Device, begin, end time.Time, opts Options) model.Observation {
	start := time.Now()
	o := observation("B06", "linux.xid_scan_interval", d, start)
	if !validTarget(d) || begin.IsZero() || end.Before(begin) || end.Sub(begin) > 24*time.Hour {
		return finish(o, start, model.Contaminated, "Xid collection requires an exact GPU UUID/PCI pair and a valid scan interval no longer than 24 hours.")
	}
	ctx, cancel := bounded(ctx, opts.Timeout, 2*time.Second, 5*time.Second)
	defer cancel()
	pci, _ := canonicalPCI(d.PCIAddress)
	o.Conditions["field"] = "xid_events"
	o.Conditions["pci_address"] = pci
	o.Conditions["interval_start_utc"] = begin.UTC()
	o.Conditions["interval_end_utc"] = end.UTC()
	o.Conditions["complete_event_history"] = false
	o.Conditions["scope_limit"] = "accessible current-boot kernel journal only; retention, privilege, delivery latency and clock changes can omit events"
	args := []string{"--system", "--kernel", "--boot=0", "--no-pager", "--output=json", "--output-fields=__REALTIME_TIMESTAMP,_TRANSPORT,MESSAGE", "--since=@" + unixMicroText(begin), "--until=@" + unixMicroText(end), "--grep=^NVRM:.*Xid"}
	r := runTool(ctx, opts, "journalctl", args, 1<<20)
	status := resultStatus(ctx, r)
	// journalctl --grep returns one when no entry matches. Permission or
	// access diagnostics are deliberately not suppressed with --quiet.
	noEntries := strings.TrimSpace(string(r.Stdout))
	if (status == model.Pass || (status == model.ToolError && r.ExitCode == 1)) && (noEntries == "" || noEntries == "-- No entries --") && len(bytes.TrimSpace(r.Stderr)) == 0 && ctx.Err() == nil && !r.Truncated {
		status = model.Pass
		r.Stdout = nil
	}
	if status != model.Pass && !r.Truncated {
		return finish(o, start, status, "The bounded kernel-journal query was unavailable or incomplete; no Xid count or hardware verdict was inferred.")
	}
	events, partial, records := parseXidJournal(r.Stdout, pci, begin, end)
	partial = partial || r.Truncated
	if records == 0 && partial && len(events) == 0 {
		return finish(o, start, model.ToolError, "Kernel-journal data could not be parsed within bounds; no Xid count was inferred.")
	}
	o.SampleCount = len(events)
	value := map[string]any{"events": events, "observed_count": len(events), "query_result_partial": partial, "complete_event_history": false}
	for _, event := range events {
		// Only bounded, retained, selected-PCI numeric codes become selectors.
		// These booleans describe observations, never causes or hardware verdicts.
		value["xid_"+strconv.FormatUint(uint64(event.Code), 10)+"_observed"] = true
	}
	o.Value = value
	status = model.Pass
	message := "No selected-PCI Xid entries were observed in the accessible scan-interval journal. This is not complete history or proof of GPU health."
	if len(events) > 0 {
		status = model.Warning
		message = "Selected-PCI Xid entries were reported during the scan interval. Numeric driver event codes are symptoms requiring version-specific interpretation; they do not independently prove physical GPU failure."
	}
	if partial {
		status = model.Warning
		message = "Only partial scan-interval kernel evidence could be decoded; the exported selected-PCI Xid entries are a lower bound, not complete history."
	}
	return finish(o, start, status, message)
}

func unixMicroText(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10) + "." + strconv.FormatInt(int64(t.Nanosecond()/1000)+1000000, 10)[1:]
}

func parseXidJournal(data []byte, pci string, begin, end time.Time) ([]xidEvent, bool, int) {
	events := []xidEvent{}
	partial := false
	records := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	seen := map[string]bool{}
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var row struct {
			Timestamp string `json:"__REALTIME_TIMESTAMP"`
			Transport string `json:"_TRANSPORT"`
			Message   string `json:"MESSAGE"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			partial = true
			continue
		}
		records++
		if row.Transport != "kernel" {
			continue
		}
		match := xidMessage.FindStringSubmatch(strings.TrimSpace(row.Message))
		if match == nil {
			partial = true
			continue
		}
		actual, ok := canonicalPCI(match[1])
		if !ok {
			partial = true
			continue
		}
		if actual != pci {
			continue
		}
		micros, err := strconv.ParseInt(row.Timestamp, 10, 64)
		if err != nil || micros < 0 {
			partial = true
			continue
		}
		timestamp := time.UnixMicro(micros).UTC()
		if timestamp.Before(begin) || timestamp.After(end) {
			continue
		}
		code, err := strconv.ParseUint(match[2], 10, 32)
		if err != nil || code == 0 {
			partial = true
			continue
		}
		key := row.Timestamp + ":" + match[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(events) >= 1024 {
			partial = true
			continue
		}
		events = append(events, xidEvent{timestamp, uint32(code)})
	}
	if scanner.Err() != nil {
		partial = true
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].TimeUTC.Equal(events[j].TimeUTC) {
			return events[i].Code < events[j].Code
		}
		return events[i].TimeUTC.Before(events[j].TimeUTC)
	})
	return events, partial, records
}
