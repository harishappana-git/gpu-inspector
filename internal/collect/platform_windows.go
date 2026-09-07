//go:build windows

package collect

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Resolve only OS-owned installation directories. PATH, SystemRoot and
// ProgramFiles environment variables can be supplied by an untrusted caller.
func nvidiaDirectories() []string {
	var dirs []string
	if system, err := windows.GetSystemDirectory(); err == nil {
		dirs = append(dirs, system)
	}
	if programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil {
		dirs = append(dirs, filepath.Join(programFiles, "NVIDIA Corporation", "NVSMI"))
	}
	return dirs
}

func trustedCollectorBinary(binary string) string {
	if binary != "nvidia-smi" && binary != "nvidia-smi.exe" {
		return ""
	}
	return nvidiaInstalledFile("nvidia-smi.exe")
}

func nvidiaInstalledFile(name string) string {
	for _, dir := range nvidiaDirectories() {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func collectorEnvironment() []string {
	env := []string{"LC_ALL=C", "LANG=C"}
	if root, err := windows.GetWindowsDirectory(); err == nil {
		env = append(env, "SystemRoot="+root, "WINDIR="+root)
	}
	// NVIDIA's Windows CLI needs ProgramFiles to initialize NVML on some
	// driver releases. Resolve it through the OS, never the caller's environment.
	if programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && programFiles != "" {
		env = append(env, "ProgramFiles="+programFiles)
	}
	env = append(env, "PATH="+strings.Join(nvidiaDirectories(), string(os.PathListSeparator)))
	return env
}
