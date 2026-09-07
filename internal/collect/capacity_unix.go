//go:build linux || darwin

package collect

import (
	"os"
	"syscall"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func capacityObservations(opts Options, start time.Time) []model.Observation {
	out := []model.Observation{}
	workspace := opts.Workspace
	if workspace == "" {
		workspace = "."
	}
	for _, p := range []struct{ path, check, name string }{{workspace, "F01", "workspace_capacity"}, {"/dev/shm", "E08", "shared_memory_capacity"}} {
		var st syscall.Statfs_t
		e := syscall.Statfs(p.path, &st)
		f := field{Status: model.Pass, Unit: "bytes", Message: "Read-only filesystem capacity for the inspected path; no active disk benchmark or file inventory."}
		if e != nil {
			f = absent(model.ToolError, "Path capacity unavailable.")
			if os.IsNotExist(e) {
				f.Status = model.Unsupported
			}
			if os.IsPermission(e) {
				f.Status = model.PermissionDenied
			}
		} else {
			f.Value = map[string]uint64{"total": uint64(st.Blocks) * uint64(st.Bsize), "available_unprivileged": uint64(st.Bavail) * uint64(st.Bsize), "free": uint64(st.Bfree) * uint64(st.Bsize)}
		}
		out = append(out, hostObs(p.check, p.name, f, start))
	}
	return out
}
