// Package secureexec runs bounded local tools without a shell or inherited
// loader settings, credentials, or unrelated environment variables.
package secureexec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/harishappana/gpu-inspector/internal/privatefs"
	"github.com/harishappana/gpu-inspector/internal/processutil"
)

type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
	Truncated      bool
	Duration       time.Duration
	Err            error
}
type cappedBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.b.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, err := b.b.Write(p)
	return n, err
}

func Run(ctx context.Context, executable string, args []string, env map[string]string, limit int) Result {
	return run(ctx, executable, args, env, limit, "")
}

// RunPrivate confines the child working directory and temporary files to an
// authenticated private worker snapshot. No loader paths are inherited.
func RunPrivate(ctx context.Context, executable string, args []string, env map[string]string, limit int, dir string) Result {
	if err := privatefs.CheckDir(dir); err != nil {
		return Result{Err: err, ExitCode: -1}
	}
	return run(ctx, executable, args, env, limit, dir)
}

func run(ctx context.Context, executable string, args []string, env map[string]string, limit int, dir string) Result {
	start := time.Now()
	if limit <= 0 {
		limit = 1 << 20
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = childEnvironment()
	if dir != "" {
		cmd.Dir = dir
		cmd.Env = append(cmd.Env, "TEMP="+dir, "TMP="+dir, "TMPDIR="+dir)
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "CUDA_VISIBLE_DEVICES" || key == "NVIDIA_VISIBLE_DEVICES" || key == "CUDA_DEVICE_ORDER" {
			cmd.Env = append(cmd.Env, key+"="+env[key])
		}
	}
	stdout := &cappedBuffer{limit: limit}
	stderr := &cappedBuffer{limit: limit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 250 * time.Millisecond
	err := processutil.Run(cmd)
	code := 0
	if err != nil {
		code = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
	}
	return Result{Stdout: append([]byte(nil), stdout.b.Bytes()...), Stderr: append([]byte(nil), stderr.b.Bytes()...), ExitCode: code, Truncated: stdout.overflow || stderr.overflow, Duration: time.Since(start), Err: err}
}
