//go:build windows

package privatefs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsProtectedOwnerDACLAndPublicRejection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	f, err := CreateTemp(dir, "file-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, path := range []string{dir, f.Name()} {
		sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(sd)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkPermissions(path, info); err == nil {
			t.Fatal("DACL granting Everyone accepted")
		}
		if path == dir {
			if err := MkdirAll(dir); err == nil {
				t.Fatal("public directory implicitly repermissioned")
			}
		}
		if err := Chmod(path); err != nil {
			t.Fatal(err)
		}
		if err := checkPermissions(path, info); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWindowsRejectsUnprotectedInheritedDACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "inherited")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err == nil {
		t.Fatal("unprotected inherited DACL accepted")
	}
	if err := Chmod(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRejectsJunctionAncestors(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := Mkdir(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "junction")
	if err := os.Mkdir(link, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A mount-point reparse buffer creates a directory junction without the
	// SeCreateSymbolicLinkPrivilege that file symlinks require on this machine.
	substitute := windows.StringToUTF16(`\??\` + target)
	printName := windows.StringToUTF16(target)
	buf := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(buf[0:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(buf)-8))
	binary.LittleEndian.PutUint16(buf[10:12], uint16((len(substitute)-1)*2))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(len(substitute)*2))
	binary.LittleEndian.PutUint16(buf[14:16], uint16((len(printName)-1)*2))
	for i, v := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(buf[16+2*i:], v)
	}
	var returned uint32
	err = windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &returned, nil)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if err := CheckPath(filepath.Join(link, "new-file")); err == nil {
		t.Fatal("junction ancestor accepted")
	}
	if err := Chmod(link); err == nil {
		t.Fatal("junction permissions changed through redirect")
	}
	if err := MkdirAll(filepath.Join(link, "child")); err == nil {
		t.Fatal("created child through junction")
	}
	if _, err := OpenFile(filepath.Join(link, "file"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
		t.Fatal("created file through junction")
	}
}

func TestWindowsScratchExclusiveAndDeleteOnClose(t *testing.T) {
	f, err := CreateScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if other, err := os.Open(f.Name()); err == nil {
		other.Close()
		t.Fatal("scratch payload accessible through another handle")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatal("scratch unexpectedly reparse")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Fatalf("scratch remains: %v", err)
	}
}

func TestWindowsRejectsAlternateStreams(t *testing.T) {
	if err := CheckPath(filepath.Join(t.TempDir(), "file:secret")); err == nil {
		t.Fatal("alternate data stream accepted")
	}
}
