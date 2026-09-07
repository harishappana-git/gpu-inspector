//go:build windows

package report

import (
	"errors"
	"runtime"

	"golang.org/x/sys/windows"
)

func unsupportedSymlink(err error) bool { return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) }

// Windows privacy tests modify the real DACL, because os.Chmod(0644) does not.
func makePublic(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	runtime.KeepAlive(sd)
	return err
}
