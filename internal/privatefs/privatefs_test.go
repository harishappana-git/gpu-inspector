package privatefs

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateCreationAndNoOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "evidence")
	if err := MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "journal")
	f, err := OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("retained evidence"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); !os.IsExist(err) {
		t.Fatalf("overwrite not rejected: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, []byte("retained evidence")) {
		t.Fatalf("existing bytes changed: %q %v", got, err)
	}
	if err := CheckFile(dir); err == nil {
		t.Fatal("directory accepted as private file")
	}
	if err := CheckDir(path); err == nil {
		t.Fatal("file accepted as private directory")
	}
	if err := SyncDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(filepath.Join(dir, "public"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); err == nil {
		t.Fatal("public creation accepted")
	}
}

func TestExplicitProtectionAndTempCreation(t *testing.T) {
	dir := t.TempDir()
	if err := Chmod(dir); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	f, err := CreateTemp(dir, "test-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(f.Name()); err != nil {
		t.Fatal(err)
	}
	d, err := MkdirTemp(dir, "test-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(d); err != nil {
		t.Fatal(err)
	}
}

func TestScratchCleanedAfterProcessTermination(t *testing.T) {
	if os.Getenv("GRI_PRIVATEFS_SCRATCH_HELPER") == "1" {
		f, err := CreateScratch(os.Getenv("GRI_PRIVATEFS_SCRATCH_DIR"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if _, err := f.WriteString("only generated scratch bytes"); err != nil {
			os.Exit(3)
		}
		fmt.Println("ready")
		for {
			time.Sleep(time.Hour)
		}
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScratchCleanedAfterProcessTermination$")
	cmd.Env = append(os.Environ(), "GRI_PRIVATEFS_SCRATCH_HELPER=1", "GRI_PRIVATEFS_SCRATCH_DIR="+dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	ready := make(chan bool, 1)
	go func() { s := bufio.NewScanner(stdout); ready <- s.Scan() && s.Text() == "ready" }()
	select {
	case ok := <-ready:
		if !ok {
			_ = cmd.Wait()
			t.Fatalf("scratch helper failed: %s", stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scratch helper did not become ready")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("process death left scratch payload: %v %v", entries, err)
	}
}
