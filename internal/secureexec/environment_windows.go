//go:build windows

package secureexec

import "golang.org/x/sys/windows"

func childEnvironment() []string {
	root, _ := windows.GetWindowsDirectory()
	system, _ := windows.GetSystemDirectory()
	env := []string{"SystemRoot=" + root, "WINDIR=" + root, "PATH=" + system, "LANG=C", "LC_ALL=C"}
	// Some Windows NVIDIA tools require ProgramFiles even when the executable
	// is in System32. Use the OS-known folder, not an inherited path override.
	if programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && programFiles != "" {
		env = append(env, "ProgramFiles="+programFiles)
	}
	return env
}
