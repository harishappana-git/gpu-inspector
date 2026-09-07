package collect

import (
	"github.com/harishappana/gpu-inspector/internal/model"
	"math"
	"strconv"
	"strings"
	"time"
)

func historyObservations(r hostReader, start time.Time) []model.Observation {
	raw, status := r.procFile("uptime")
	values := map[string]any{"host_uptime_seconds": nil, "oldest_accessible_gpu_event_utc": nil, "gpu_reset_epoch": nil, "complete_event_history": false}
	f := field{Status: status, Value: values, Message: "Host uptime and GPU event history are not both available; no rental-reliability history is inferred."}
	if status == model.Pass {
		parts := strings.Fields(raw)
		if len(parts) < 1 {
			f.Status = model.ToolError
		} else {
			seconds, err := strconv.ParseFloat(parts[0], 64)
			if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
				f.Status = model.ToolError
			} else {
				values["host_uptime_seconds"] = seconds
				f.Status = model.Warning
				f.Message = "Host-reported uptime is available; GPU reset epoch and oldest device-scoped event are unknown. Host uptime is not this rental's reliability history."
			}
		}
	}
	o := hostObs("J04", "history_visibility", f, start)
	o.Conditions["logs_read"] = false
	o.Conditions["history_scope"] = "host uptime only; device event-history collector is not implemented"
	return []model.Observation{o}
}
