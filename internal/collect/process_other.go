//go:build !linux && !darwin

package collect

import "os/exec"

func prepareCollector(cmd *exec.Cmd) {}
