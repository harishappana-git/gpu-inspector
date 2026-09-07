package secureexec

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := Run(ctx, "/bin/sh", []string{"-c", "sleep 10"}, nil, 32)
	if r.Err == nil || r.Duration > 2*time.Second {
		t.Fatalf("unbounded child: %+v", r)
	}
	r = Run(context.Background(), "/bin/sh", []string{"-c", "printf '%0100d' 1"}, nil, 8)
	if !r.Truncated || len(r.Stdout) != 8 {
		t.Fatal("output cap not enforced")
	}
}

func TestNoInheritedSecretsOrShellInterpolation(t *testing.T) {
	t.Setenv("GRI_SEEDED_SECRET", "do-not-export")
	r := Run(context.Background(), "/usr/bin/env", nil, map[string]string{"GRI_SEEDED_SECRET": "bad", "LD_PRELOAD": "bad"}, 1024)
	if bytes.Contains(r.Stdout, []byte("SECRET")) || bytes.Contains(r.Stdout, []byte("LD_PRELOAD")) {
		t.Fatal("environment escaped allowlist")
	}
	r = Run(context.Background(), "/bin/echo", []string{"$(touch forbidden);`id`"}, nil, 1024)
	if string(r.Stdout) != "$(touch forbidden);`id`\n" {
		t.Fatal("arguments interpreted")
	}
}
