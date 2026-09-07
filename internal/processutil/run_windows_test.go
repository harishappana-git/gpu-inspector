//go:build windows

package processutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "__processutil-fixture" {
		switch os.Args[2] {
		case "hello":
			fmt.Print("native-helper-ok")
		case "marker":
			if len(os.Args) != 4 || os.WriteFile(os.Args[3], []byte("started"), 0600) != nil {
				os.Exit(2)
			}
		case "leaf":
			time.Sleep(30 * time.Second)
		case "spawn-wait", "spawn-on-stdin":
			exe, err := os.Executable()
			if err != nil {
				os.Exit(3)
			}
			child := exec.Command(exe, "__processutil-fixture", "leaf")
			child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if child.Start() != nil {
				os.Exit(4)
			}
			fmt.Printf("%d\n", child.Process.Pid)
			if os.Args[2] == "spawn-wait" {
				time.Sleep(30 * time.Second)
			} else {
				var signal [1]byte
				_, _ = os.Stdin.Read(signal[:])
			}
		default:
			os.Exit(5)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func processFixtureExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestWindowsRunBasicCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, processFixtureExe(t), "__processutil-fixture", "hello")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := Run(cmd); err != nil || stdout.String() != "native-helper-ok" {
		t.Fatalf("native command failed: %v / %q", err, stdout.String())
	}
}

func TestWindowsRunCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	marker := filepath.Join(t.TempDir(), "must-not-start")
	cmd := exec.CommandContext(ctx, processFixtureExe(t), "__processutil-fixture", "marker", marker)
	if err := Run(cmd); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancellation lost: %v", err)
	}
	if cmd.Process != nil {
		t.Fatal("pre-cancelled command started a process")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("pre-cancelled child performed work")
	}
}

type lineSignal struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan string
	sent  bool
}

func (s *lineSignal) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.buf.Write(p)
	if !s.sent && strings.Contains(s.buf.String(), "\n") {
		s.sent = true
		s.ready <- strings.SplitN(s.buf.String(), "\n", 2)[0]
	}
	return len(p), nil
}

func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("child/job shutdown exceeded its bound")
		return nil
	}
}

func TestWindowsJobTerminatesDescendants(t *testing.T) {
	for _, normalExit := range []bool{false, true} {
		name := "cancellation"
		if normalExit {
			name = "normal parent exit"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			mode := "spawn-wait"
			if normalExit {
				mode = "spawn-on-stdin"
			}
			cmd := exec.CommandContext(ctx, processFixtureExe(t), "__processutil-fixture", mode)
			output := &lineSignal{ready: make(chan string, 1)}
			cmd.Stdout = output
			cmd.WaitDelay = 250 * time.Millisecond
			var input *io.PipeWriter
			if normalExit {
				var reader *io.PipeReader
				reader, input = io.Pipe()
				cmd.Stdin = reader
				defer reader.Close()
				defer input.Close()
			}
			done := make(chan error, 1)
			go func() { done <- Run(cmd) }()
			var pidText string
			select {
			case pidText = <-output.ready:
			case err := <-done:
				t.Fatalf("parent failed before descendant readiness: %v", err)
			case <-time.After(5 * time.Second):
				cancel()
				_ = waitRun(t, done)
				t.Fatal("descendant did not become ready")
			}
			pid, err := strconv.ParseUint(strings.TrimSpace(pidText), 10, 32)
			if err != nil {
				cancel()
				_ = waitRun(t, done)
				t.Fatalf("invalid descendant PID: %q", pidText)
			}
			// Keep a handle to this exact process to avoid PID reuse ambiguity.
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
			if err != nil {
				cancel()
				_ = waitRun(t, done)
				t.Fatalf("cannot observe descendant: %v", err)
			}
			defer windows.CloseHandle(handle)
			if state, err := windows.WaitForSingleObject(handle, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
				cancel()
				_ = waitRun(t, done)
				t.Fatal("descendant was not alive before shutdown")
			}
			if normalExit {
				_, err = input.Write([]byte{1})
				_ = input.Close()
				if err != nil {
					cancel()
					_ = waitRun(t, done)
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			runErr := waitRun(t, done)
			if normalExit && runErr != nil {
				t.Fatalf("parent normal exit failed: %v", runErr)
			}
			if !normalExit && runErr == nil {
				t.Fatal("cancelled parent returned success")
			}
			state, err := windows.WaitForSingleObject(handle, 2000)
			if err != nil || state != windows.WAIT_OBJECT_0 {
				t.Fatalf("job shutdown left descendant running: wait=%d err=%v", state, err)
			}
		})
	}
}
