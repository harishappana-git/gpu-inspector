//go:build windows

package secureexec

import (
	"bytes"
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsToolEnvironmentUsesOSKnownFolders(t *testing.T) {
	untrusted := t.TempDir()
	for _, key := range []string{"PATH", "SystemRoot", "WINDIR", "ProgramFiles"} {
		t.Setenv(key, untrusted)
	}
	env := strings.Join(childEnvironment(), "\n")
	if strings.Contains(env, untrusted) {
		t.Fatal("caller-supplied installation directory entered the child environment")
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || programFiles == "" || !strings.Contains(env, "ProgramFiles="+programFiles) {
		t.Fatal("OS-resolved ProgramFiles missing from NVIDIA tool environment")
	}
}

func TestWindowsNvidiaSMIReadOnlyIntegration(t *testing.T) {
	if os.Getenv("GRI_WINDOWS_GPU_TEST") != "1" {
		t.Skip("set GRI_WINDOWS_GPU_TEST=1 for installed nvidia-smi integration")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(system, "nvidia-smi.exe")
	if _, err := os.Stat(exe); err != nil {
		programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if err != nil {
			t.Fatal(err)
		}
		exe = filepath.Join(programFiles, "NVIDIA Corporation", "NVSMI", "nvidia-smi.exe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := Run(ctx, exe, []string{"--query-gpu=uuid,name", "--format=csv,noheader,nounits"}, nil, 8192)
	if r.Err != nil || r.Truncated {
		t.Fatalf("Windows nvidia-smi failed with restricted tool environment: exit=%d err=%v stdout=%q stderr=%q", r.ExitCode, r.Err, r.Stdout, r.Stderr)
	}
	rows, err := csv.NewReader(bytes.NewReader(r.Stdout)).ReadAll()
	if err != nil || len(rows) == 0 {
		t.Fatalf("Windows nvidia-smi returned no device records: %q", r.Stdout)
	}
	for _, row := range rows {
		if len(row) != 2 || !strings.HasPrefix(strings.TrimSpace(row[0]), "GPU-") || strings.TrimSpace(row[1]) == "" {
			t.Fatalf("invalid Windows nvidia-smi device record: %#v", row)
		}
	}
	t.Logf("Windows nvidia-smi succeeded with OS-resolved minimal environment for %d device(s)", len(rows))
}
