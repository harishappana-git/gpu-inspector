//go:build !windows

package privatefs

import (
	"errors"
	"fmt"
	"os"
)

func validatePath(string) error { return nil }
func checkReparse(string) error { return nil }

const checkAncestors = false

func checkPermissions(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("path %q must be owner-private (0700 directory / 0600 file)", path)
	}
	return nil
}

func Mkdir(path string) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	return os.Mkdir(path, 0700)
}

func Chmod(path string) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if info.IsDir() {
		mode = 0700
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("path must be a regular file or directory")
	}
	return os.Chmod(path, mode)
}

// OpenFile only creates new files, preserving the no-overwrite evidence boundary.
func OpenFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	if flags&(os.O_CREATE|os.O_EXCL) != os.O_CREATE|os.O_EXCL {
		return nil, fmt.Errorf("private file creation requires O_CREATE|O_EXCL")
	}
	if mode.Perm()&0077 != 0 {
		return nil, fmt.Errorf("private file mode must not grant group/other access")
	}
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flags, mode)
}

func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

const ScratchMode = "0600; immediately unlinked; owned descriptor until close"

// CreateScratch unlinks before any payload writes. All I/O subsequently uses
// the owned descriptor and process exit cannot leave payload files behind.
func CreateScratch(dir string) (*os.File, error) {
	f, err := CreateTemp(dir, ".gri-pathcheck-*")
	if err != nil {
		return nil, err
	}
	owned, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	named, err := os.Lstat(f.Name())
	if err != nil || !os.SameFile(owned, named) {
		f.Close()
		return nil, fmt.Errorf("scratch pathname changed before ownership verification")
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		if current, e := os.Lstat(f.Name()); e == nil && os.SameFile(owned, current) {
			_ = os.Remove(f.Name())
		}
		return nil, err
	}
	return f, nil
}
