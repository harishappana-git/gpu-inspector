package secureexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/privatefs"
)

type privateContext struct{ CWD, Temp, TMP, TMPDIR, TempFile string }

func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "__secureexec-fixture" {
		switch os.Args[2] {
		case "sleep":
			time.Sleep(10 * time.Second)
		case "overflow":
			fmt.Fprint(os.Stdout, strings.Repeat("o", 128))
			fmt.Fprint(os.Stderr, strings.Repeat("e", 128))
		case "environment":
			fmt.Print(strings.Join(os.Environ(), "\n"))
		case "arguments":
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[3:])
		case "private-context":
			cwd, err := os.Getwd()
			if err != nil {
				os.Exit(2)
			}
			f, err := os.CreateTemp("", "worker-temp-")
			if err != nil {
				os.Exit(3)
			}
			filename := f.Name()
			if f.Close() != nil {
				os.Exit(4)
			}
			_ = json.NewEncoder(os.Stdout).Encode(privateContext{cwd, os.TempDir(), os.Getenv("TMP"), os.Getenv("TMPDIR"), filename})
		default:
			os.Exit(5)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fixtureExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := Run(ctx, fixtureExe(t), []string{"__secureexec-fixture", "sleep"}, nil, 32)
	if r.Err == nil || r.Duration > 2*time.Second {
		t.Fatalf("unbounded child: %+v", r)
	}
	ctx, cancelOutput := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelOutput()
	r = Run(ctx, fixtureExe(t), []string{"__secureexec-fixture", "overflow"}, nil, 8)
	if r.Err != nil || !r.Truncated || len(r.Stdout) != 8 || len(r.Stderr) != 8 || string(r.Stdout) != "oooooooo" || string(r.Stderr) != "eeeeeeee" {
		t.Fatalf("independent stdout/stderr caps not enforced: %+v", r)
	}
}

func TestNoInheritedSecretsOrShellInterpolation(t *testing.T) {
	t.Setenv("GRI_SEEDED_SECRET", "do-not-export")
	t.Setenv("LD_PRELOAD", "loader-do-not-export")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := Run(ctx, fixtureExe(t), []string{"__secureexec-fixture", "environment"}, map[string]string{"GRI_SEEDED_SECRET": "bad", "LD_PRELOAD": "bad", "CUDA_VISIBLE_DEVICES": "GPU-fixture", "CUDA_DEVICE_ORDER": "PCI_BUS_ID"}, 4096)
	if r.Err != nil {
		t.Fatalf("environment fixture failed: %+v", r)
	}
	if bytes.Contains(r.Stdout, []byte("SECRET")) || bytes.Contains(r.Stdout, []byte("LD_PRELOAD")) {
		t.Fatal("environment escaped allowlist")
	}
	if !bytes.Contains(r.Stdout, []byte("CUDA_VISIBLE_DEVICES=GPU-fixture")) || !bytes.Contains(r.Stdout, []byte("CUDA_DEVICE_ORDER=PCI_BUS_ID")) {
		t.Fatal("GPU visibility controls were dropped")
	}
	want := []string{"$(touch forbidden);`id`", "argument with spaces", "", `C:\path with spaces\`, "literal\"quote"}
	args := append([]string{"__secureexec-fixture", "arguments"}, want...)
	r = Run(ctx, fixtureExe(t), args, nil, 4096)
	var got []string
	if r.Err != nil || json.Unmarshal(r.Stdout, &got) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments were interpreted or requoted incorrectly: %+v / %#v", r, got)
	}
}

func TestPrivateRunUsesPrivateWorkingAndTemporaryDirectory(t *testing.T) {
	dir, err := privatefs.MkdirTemp(t.TempDir(), "worker-private-")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEMP", "untrusted-temp")
	t.Setenv("TMP", "untrusted-tmp")
	t.Setenv("TMPDIR", "untrusted-tmpdir")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := RunPrivate(ctx, fixtureExe(t), []string{"__secureexec-fixture", "private-context"}, map[string]string{"TEMP": "caller-override", "TMP": "caller-override", "TMPDIR": "caller-override"}, 4096, dir)
	var got privateContext
	if r.Err != nil || json.Unmarshal(r.Stdout, &got) != nil {
		t.Fatalf("private fixture failed: %+v", r)
	}
	for _, path := range []string{got.CWD, got.Temp, got.TMP, got.TMPDIR, filepath.Dir(got.TempFile)} {
		actual, e1 := os.Stat(path)
		expected, e2 := os.Stat(dir)
		if e1 != nil || e2 != nil || !os.SameFile(actual, expected) {
			t.Fatalf("worker path escaped private directory: %q != %q", path, dir)
		}
	}
	checkChildTemporaryFile(t, got.TempFile)
}

func TestPrivateRunRejectsMissingDirectory(t *testing.T) {
	r := RunPrivate(context.Background(), fixtureExe(t), []string{"__secureexec-fixture", "environment"}, nil, 4096, filepath.Join(t.TempDir(), "missing"))
	if r.Err == nil || r.ExitCode != -1 || len(r.Stdout) != 0 || len(r.Stderr) != 0 {
		t.Fatalf("unvalidated working directory executed a child: %+v", r)
	}
}
