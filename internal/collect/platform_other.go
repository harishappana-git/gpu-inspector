//go:build !windows

package collect

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func trustedCollectorBinary(binary string) string {
	if filepath.Base(binary) != binary {
		return ""
	}
	for _, dir := range []string{"/usr/local/nvidia/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"} {
		candidate := filepath.Join(dir, binary)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return candidate
		}
	}
	return ""
}

func collectorEnvironment() []string {
	return []string{"PATH=/usr/local/nvidia/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C"}
}

func platformHost(ctx context.Context, opts Options, start time.Time) []model.Observation {
	return []model.Observation{hostObs("E01", "platform", absent(model.Unsupported, "Host collectors require Linux or Windows."), start)}
}
