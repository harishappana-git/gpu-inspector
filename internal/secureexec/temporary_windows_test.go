//go:build windows

package secureexec

import (
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A third-party child uses ordinary file creation and inherits the private
// parent's owner-only ACL. Unlike authenticated evidence files, its temporary
// files need not set SE_DACL_PROTECTED themselves.
func checkChildTemporaryFile(t *testing.T, filename string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		t.Fatal("child temporary file is not owned by current user")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		t.Fatal("child temporary file has no usable private DACL")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatal("unexpected child temporary-file ACL entry")
		}
		trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustee.IsValid() || !trustee.Equals(user.User.Sid) {
			t.Fatal("child temporary file grants another principal access")
		}
	}
	runtime.KeepAlive(sd)
}
