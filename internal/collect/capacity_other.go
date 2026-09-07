//go:build !linux && !darwin

package collect

import (
	"github.com/harishappana/gpu-inspector/internal/model"
	"time"
)

func capacityObservations(opts Options, start time.Time) []model.Observation {
	return []model.Observation{hostObs("F01", "workspace_capacity", absent(model.Unsupported, "Filesystem capacity adapter unsupported on this platform."), start)}
}
