//go:build !windows

package report

import "os"

func makePublic(path string) error { return os.Chmod(path, 0755) }

func unsupportedSymlink(error) bool { return false }
