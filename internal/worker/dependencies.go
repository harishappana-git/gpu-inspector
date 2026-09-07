package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/harishappana/gpu-inspector/internal/privatefs"
)

// Dependency binds the exact adjacent Windows runtime DLL bytes into the signed
// worker manifest. NVIDIA's GPU driver and Windows system DLLs stay system-owned.
type Dependency struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

const MaxDependencyBytes int64 = 1 << 30
const MaxDependencyTotalBytes int64 = 2 << 30
const MaxDependencies = 12

func allowedDependency(name string) bool {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\\:`) {
		return false
	}
	switch strings.ToLower(name) {
	case "cudart64_12.dll", "cudart64_13.dll", "cublas64_12.dll", "cublas64_13.dll", "cublaslt64_12.dll", "cublaslt64_13.dll",
		"vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll", "concrt140.dll":
		return true
	}
	return false
}

func validateDependencies(dependencies []Dependency, platform string) error {
	if len(dependencies) > MaxDependencies || (len(dependencies) > 0 && platform != "windows-amd64") {
		return errors.New("worker runtime dependencies require Windows x64 and at most 12 DLLs")
	}
	seen := map[string]bool{}
	for _, dependency := range dependencies {
		normal := strings.ToLower(dependency.File)
		digest, err := hex.DecodeString(dependency.SHA256)
		if !allowedDependency(dependency.File) || seen[normal] || err != nil || len(digest) != sha256.Size || dependency.SHA256 != strings.ToLower(dependency.SHA256) {
			return errors.New("worker dependency filename, digest or uniqueness is invalid")
		}
		seen[normal] = true
	}
	return nil
}

func openDependency(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxDependencyBytes {
		return nil, errors.New("worker dependency must be a nonempty regular file of at most 1 GiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("worker dependency changed while opening")
	}
	return file, nil
}

// DescribeDependency prepares a digest for a manifest author. The dependency
// must be staged beside the worker executable before Load is called.
func DescribeDependency(path string) (Dependency, error) {
	d := Dependency{File: filepath.Base(path)}
	if !allowedDependency(d.File) {
		return d, errors.New("unsupported worker runtime DLL filename")
	}
	source, err := openDependency(path)
	if err != nil {
		return d, err
	}
	defer source.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(source, MaxDependencyBytes+1))
	if err != nil {
		return d, err
	}
	if n <= 0 || n > MaxDependencyBytes {
		return d, errors.New("worker dependency size exceeded limit")
	}
	d.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return d, nil
}

func snapshotDependency(path, snapshot string, expected Dependency) (int64, error) {
	return snapshotDependencyContext(context.Background(), path, snapshot, expected)
}

func snapshotDependencyContext(ctx context.Context, path, snapshot string, expected Dependency) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	source, err := openDependency(path)
	if err != nil {
		return 0, err
	}
	defer source.Close()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	target, err := privatefs.OpenFile(snapshot, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	defer target.Close()
	hash := sha256.New()
	n, err := copyContext(ctx, io.MultiWriter(target, hash), io.LimitReader(source, MaxDependencyBytes+1))
	if err != nil {
		return n, err
	}
	if n <= 0 || n > MaxDependencyBytes {
		return n, errors.New("worker dependency size exceeded limit")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return n, fmt.Errorf("worker dependency digest mismatch: %s", expected.File)
	}
	if err := ctx.Err(); err != nil {
		return n, err
	}
	if err = target.Sync(); err != nil {
		return n, err
	}
	if err := ctx.Err(); err != nil {
		return n, err
	}
	return n, target.Close()
}
