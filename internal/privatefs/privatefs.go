// Package privatefs creates and verifies owner-private evidence on POSIX and
// Windows. Privacy checks never reinterpret Windows' synthetic POSIX mode bits.
package privatefs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckPath rejects symbolic links at the leaf on POSIX, preserving native
// aliases such as macOS /var -> /private/var. Windows also rejects every reparse
// ancestor, because a directory junction can redirect a private evidence path.
// Missing final components are permitted for creation.
func CheckPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := validatePath(abs); err != nil {
		return err
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("private path %q must not traverse a symbolic link", current)
			}
			if err := checkReparse(current); err != nil {
				return err
			}
		}
		if !checkAncestors || filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

// MkdirAll creates missing directories with owner-private permissions and
// requires an existing final directory to already be private. It never changes
// permissions on existing ancestors.
func MkdirAll(path string) error {
	path = filepath.Clean(path)
	if err := CheckPath(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return CheckDir(path)
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		if err := MkdirAll(parent); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := Mkdir(path); err != nil {
		if os.IsExist(err) {
			return CheckDir(path)
		}
		return err
	}
	return nil
}

func CheckDir(path string) error  { return check(path, true) }
func CheckFile(path string) error { return check(path, false) }

// MkdirTemp creates a new owner-private temporary directory.
func MkdirTemp(dir, pattern string) (string, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if strings.ContainsAny(pattern, `/\\`) {
		return "", fmt.Errorf("temporary pattern contains path separator")
	}
	for attempt := 0; attempt < 100; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		name := pattern + hex.EncodeToString(nonce[:])
		if i := strings.LastIndex(pattern, "*"); i >= 0 {
			name = pattern[:i] + hex.EncodeToString(nonce[:]) + pattern[i+1:]
		}
		path := filepath.Join(dir, name)
		err := Mkdir(path)
		if err == nil {
			return path, nil
		}
		if !os.IsExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("could not allocate a unique private temporary directory")
}

func check(path string, dir bool) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if dir && !info.IsDir() || !dir && !info.Mode().IsRegular() {
		return fmt.Errorf("private path %q has the wrong file type", path)
	}
	return checkPermissions(path, info)
}

// CreateTemp atomically creates an owner-private regular file. It uses 128 bits
// of random name entropy and never opens or truncates an existing file.
func CreateTemp(dir, pattern string) (*os.File, error) {
	return createTemp(dir, pattern, OpenFile)
}

func createTemp(dir, pattern string, open func(string, int, os.FileMode) (*os.File, error)) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if strings.ContainsAny(pattern, `/\\`) {
		return nil, fmt.Errorf("temporary pattern contains path separator")
	}
	for attempt := 0; attempt < 100; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		name := pattern + hex.EncodeToString(nonce[:])
		if i := strings.LastIndex(pattern, "*"); i >= 0 {
			name = pattern[:i] + hex.EncodeToString(nonce[:]) + pattern[i+1:]
		}
		f, err := open(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if !os.IsExist(err) {
			return f, err
		}
	}
	return nil, fmt.Errorf("could not allocate a unique private temporary file")
}
