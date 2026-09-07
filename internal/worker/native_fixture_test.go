package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// A copied copy of this test executable is a native protocol transport
	// fixture on every OS. No CUDA calls or GPU observations occur in this mode.
	if len(os.Args) > 1 && os.Args[1] == "--device" {
		if os.Getenv("CUDA_VISIBLE_DEVICES") != testUUID || os.Getenv("NVIDIA_VISIBLE_DEVICES") != testUUID {
			os.Exit(9)
		}
		for _, name := range []string{"NVIDIA_TF32_OVERRIDE", "LD_PRELOAD"} {
			if _, present := os.LookupEnv(name); present {
				os.Exit(9)
			}
		}
		executable, err := os.Executable()
		if err != nil {
			os.Exit(9)
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(executable), "protocol-fixture.json"))
		if err != nil {
			os.Exit(9)
		}
		time.Sleep(120 * time.Millisecond)
		fmt.Println(string(data))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func nativeProtocolFixture(t *testing.T, data []byte) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "protocol-fixture"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if err = os.WriteFile(path, binary, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "protocol-fixture.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
