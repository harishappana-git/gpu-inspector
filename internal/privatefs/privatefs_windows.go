//go:build windows

package privatefs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const checkAncestors = true

func validatePath(path string) error {
	// Alternate data streams and Win32 device namespaces are not evidence files.
	volume := filepath.VolumeName(path)
	if strings.HasPrefix(volume, `\\?`) || strings.HasPrefix(volume, `\\.`) || strings.Contains(path[len(volume):], ":") {
		return fmt.Errorf("private path cannot use a device namespace or alternate data stream")
	}
	return nil
}

func checkReparse(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attr, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("private path %q must not traverse a reparse point", path)
	}
	return nil
}

func ownerSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy()
}

func privateDescriptor(dir bool) (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := ownerSID()
	if err != nil {
		return nil, err
	}
	inheritance := ""
	if dir {
		inheritance = "OICI"
	}
	return windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;" + inheritance + ";FA;;;" + sid.String() + ")")
}

func securityAttributes(dir bool) (*windows.SecurityAttributes, error) {
	sd, err := privateDescriptor(dir)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func metadataHandle(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return h, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return windows.InvalidHandle, fmt.Errorf("private path is a reparse point")
	}
	return h, nil
}

func checkPermissions(path string, _ os.FileInfo) error {
	h, err := metadataHandle(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	sid, err := ownerSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(sid) {
		return fmt.Errorf("private path %q must be owned by the current user", path)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private path %q must have a protected owner-only DACL", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("private path %q has an unrestricted DACL", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		// Only conventional allow/deny ACEs are accepted; unknown conditional or
		// object ACEs are not guessed at. Deny ACEs cannot broaden access.
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("private path %q contains an unsupported access rule", path)
		}
		trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustee.IsValid() || !trustee.Equals(sid) {
			return fmt.Errorf("private path %q grants access to another principal", path)
		}
	}
	runtime.KeepAlive(sd)
	return nil
}

func Mkdir(path string) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa, err := securityAttributes(true)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return CheckDir(path)
}

func Chmod(path string) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("path must be a regular file or directory")
	}
	h, err := metadataHandle(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	sd, err := privateDescriptor(info.IsDir())
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
	runtime.KeepAlive(sd)
	return err
}

// OpenFile atomically creates a file with a protected current-user-only DACL.
// Existing paths are never opened, truncated, or repermissioned.
func OpenFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	return openFile(path, flags, mode, false)
}

func openFile(path string, flags int, mode os.FileMode, scratch bool) (*os.File, error) {
	if flags&(os.O_CREATE|os.O_EXCL) != os.O_CREATE|os.O_EXCL {
		return nil, fmt.Errorf("private file creation requires O_CREATE|O_EXCL")
	}
	if mode.Perm()&0077 != 0 {
		return nil, fmt.Errorf("private file mode must not grant group/other access")
	}
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa, err := securityAttributes(false)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ)
	if flags&os.O_RDWR != 0 {
		access |= windows.GENERIC_WRITE
	} else if flags&os.O_WRONLY != 0 {
		access = windows.GENERIC_WRITE
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	attributes := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if scratch {
		// CREATE_NEW and DELETE_ON_CLOSE make cleanup belong to this handle even
		// after process death. Share mode zero prevents content opens and renames.
		access |= windows.DELETE
		share = 0
		attributes |= windows.FILE_FLAG_DELETE_ON_CLOSE
	}
	h, err := windows.CreateFile(p, access, share, sa, windows.CREATE_NEW, attributes, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// Windows has no directory-fsync equivalent accessible to an unprivileged user.
// Writers flush every file handle before publishing; this check verifies the
// directory remains private but makes no power-loss directory durability claim.
func SyncDir(path string) error { return CheckDir(path) }

const ScratchMode = "protected owner-only Windows DACL; exclusive delete-on-close handle; OS cleanup on process exit"

func CreateScratch(dir string) (*os.File, error) {
	return createTemp(dir, ".gri-pathcheck-*", func(path string, flags int, mode os.FileMode) (*os.File, error) {
		return openFile(path, flags, mode, true)
	})
}
