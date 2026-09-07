//go:build !windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPOSIXModesAndPublicRejection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("directory mode: %v %v", info, err)
	}
	f, err := CreateTemp(dir, "file-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if info, err := os.Stat(f.Name()); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file mode: %v %v", info, err)
	}
	if err := os.Chmod(f.Name(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(f.Name()); err == nil {
		t.Fatal("public file accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(dir); err == nil {
		t.Fatal("public existing directory accepted")
	}
}

func TestPOSIXLeafSymlinkRejectionAndAncestorCompatibility(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := Mkdir(real); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(filepath.Join(link, "child")); err != nil {
		t.Fatalf("native ancestor alias rejected: %v", err)
	}
	if err := CheckDir(link); err == nil {
		t.Fatal("symlink directory accepted")
	}
}
