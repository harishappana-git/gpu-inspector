//go:build !windows

package secureexec

import (
	"testing"

	"github.com/harishappana/gpu-inspector/internal/privatefs"
)

func checkChildTemporaryFile(t *testing.T, filename string) {
	t.Helper()
	if err := privatefs.CheckFile(filename); err != nil {
		t.Fatalf("child temporary file is not private: %v", err)
	}
}
