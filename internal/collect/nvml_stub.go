//go:build !windows && (!linux || !cgo)

package collect

import "github.com/harishappana/gpu-inspector/internal/model"

func nativeCollect(target string) nativeResult {
	return nativeResult{Status: model.DependencyMissing, Message: "Direct NVML requires a Linux cgo build; attempting read-only nvidia-smi fallback."}
}

func nativeTelemetry(target string) nativeResult { return nativeCollect(target) }
