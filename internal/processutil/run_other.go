//go:build !linux && !darwin && !windows

package processutil

import "os/exec"

// Run expects a command created with exec.CommandContext, matching the
// lifetime contract of the Unix and Windows implementations.
func Run(cmd *exec.Cmd) error { return cmd.Run() }
