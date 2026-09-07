package scan

import (
	"context"
	"encoding/json"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/pathcheck"
	"os"
	"time"
)

func marshalPathOptions(o pathcheck.Options) ([]byte, error) { return json.Marshal(o) }
func HandleInternalCommand(args []string) bool {
	if len(args) == 0 || args[0] != "__pathcheck" {
		return false
	}
	var o pathcheck.Options
	if len(args) != 2 || len(args[1]) > 16384 || bundle.Decode([]byte(args[1]), &o) != nil {
		_ = json.NewEncoder(os.Stdout).Encode([]model.Observation{baseObservation("F03", "path.helper", model.ToolError, "Invalid private path-test request")})
		return true
	}
	if o.Timeout <= 0 || o.Timeout > 30*time.Second {
		o.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	_ = json.NewEncoder(os.Stdout).Encode(pathcheck.Run(ctx, o))
	return true
}
