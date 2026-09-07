//go:build windows

package campaignimport

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestImportRejectsActualWindowsJunctionInputAndOutput(t *testing.T) {
	root := t.TempDir()
	target, link := filepath.Join(root, "target"), filepath.Join(root, "junction")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(link, 0700); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Native directory junctions do not require file-symlink privilege.
	substitute, printed := windows.StringToUTF16(`\??\`+target), windows.StringToUTF16(target)
	buffer := make([]byte, 16+2*(len(substitute)+len(printed)))
	binary.LittleEndian.PutUint32(buffer[0:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buffer[4:6], uint16(len(buffer)-8))
	binary.LittleEndian.PutUint16(buffer[10:12], uint16((len(substitute)-1)*2))
	binary.LittleEndian.PutUint16(buffer[12:14], uint16(len(substitute)*2))
	binary.LittleEndian.PutUint16(buffer[14:16], uint16((len(printed)-1)*2))
	for i, value := range append(substitute, printed...) {
		binary.LittleEndian.PutUint16(buffer[16+2*i:], value)
	}
	var returned uint32
	err = windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil)
	windows.CloseHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	archive := writeFixtureArchive(t, fixtureEntries(t, partialFixture()))
	if _, err := Import(context.Background(), archive, filepath.Join(link, "review")); err == nil {
		t.Fatal("created import output through a junction")
	}
	if _, err := os.Stat(filepath.Join(target, "review")); !os.IsNotExist(err) {
		t.Fatal("junction target changed")
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "archive.zip"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(context.Background(), filepath.Join(link, "archive.zip"), filepath.Join(root, "review")); err == nil {
		t.Fatal("read campaign source through a junction")
	}
}
