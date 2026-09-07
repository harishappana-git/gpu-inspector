//go:build linux || darwin

package campaignimport

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestImportRejectsNamedPipeBeforeBlockingOpen(t *testing.T) {
	root := t.TempDir()
	pipe := filepath.Join(root, "not-an-archive")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Import(context.Background(), pipe, filepath.Join(root, "output")); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("named pipe admitted as archive")
		}
	case <-time.After(time.Second):
		// Unblock any regressed reader so this test cannot leave a blocked call.
		f, err := os.OpenFile(pipe, os.O_RDWR, 0600)
		if err == nil {
			f.Close()
		}
		<-done
		t.Fatal("import opened a named pipe before checking its file type")
	}
}
