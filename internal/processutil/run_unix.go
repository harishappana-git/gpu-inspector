//go:build linux || darwin

// Package processutil contains the platform process lifetime boundary used by
// collectors and workers. Cancellation includes descendants of the child.
package processutil

import (
	"os"
	"os/exec"
	"syscall"
)

// Run requires a command created with exec.CommandContext, even when the
// caller uses context.Background, because it installs a cancellation handler.
func Run(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	return cmd.Run()
}
