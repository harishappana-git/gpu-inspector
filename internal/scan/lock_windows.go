//go:build windows

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/harishappana/gpu-inspector/internal/privatefs"
	"golang.org/x/sys/windows"
)

type targetLock struct{ f *os.File }

func acquireLock(root, uuid string) (*targetLock, error) {
	if root == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(cache, "gri", "locks")
	}
	if err := privatefs.MkdirAll(root); err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(strings.ToLower(uuid)))
	path := filepath.Join(root, hex.EncodeToString(hash[:])+".lock")
	f, err := privatefs.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		if err = privatefs.CheckFile(path); err != nil {
			return nil, err
		}
		// OPEN_REPARSE_POINT ensures a raced replacement cannot redirect us.
		p, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return nil, e
		}
		h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return nil, e
		}
		f, err = os.NewFile(uintptr(h), path), nil
	}
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		f.Close()
		return nil, errors.New("target lock must be a private regular file")
	}
	if err = privatefs.CheckFile(path); err != nil {
		f.Close()
		return nil, err
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		f.Close()
		return nil, errors.New("another GRI scan holds this selected-device lock")
	}
	return &targetLock{f: f}, nil
}

func (l *targetLock) close() error { return l.f.Close() }
