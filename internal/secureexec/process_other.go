//go:build !linux && !darwin

package secureexec

import "os/exec"

func prepare(cmd *exec.Cmd) {}
