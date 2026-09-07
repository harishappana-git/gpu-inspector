package collect

import (
	"context"
	"github.com/harishappana/gpu-inspector/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUptimeNeverBecomesRentalHistory(t *testing.T) {
	dir := t.TempDir()
	r := hostReader{ctx: context.Background(), proc: dir, sys: dir}
	if err := os.WriteFile(filepath.Join(dir, "uptime"), []byte("12345.67 22222.00\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := historyObservations(r, time.Now())[0]
	if o.Status != model.Warning || o.Value.(map[string]any)["gpu_reset_epoch"] != nil || o.Value.(map[string]any)["complete_event_history"] != false {
		t.Fatal(o)
	}
	if err := os.WriteFile(filepath.Join(dir, "uptime"), []byte("NaN"), 0600); err != nil {
		t.Fatal(err)
	}
	if o = historyObservations(r, time.Now())[0]; o.Status != model.ToolError {
		t.Fatal("invalid uptime accepted")
	}
}
