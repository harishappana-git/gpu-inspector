package main

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"regexp"
	"time"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/worker"
)

// This command validates existing data only. Its success is protocol admission,
// not a passed GPU or sanitizer test; callers must inspect the returned status.
func workerValidateCommand(args []string, out, stderr io.Writer) error {
	f := flags("worker-validate", stderr)
	input := f.String("input", "", "bounded worker JSON file; no execution")
	device := f.String("device", "", "expected exact full GPU UUID")
	method := f.String("method", "", "expected worker method")
	elapsed := f.Float64("elapsed-ms", 0, "actual observed parent process duration")
	tier := f.String("tier", "quick", "expected quick or standard tier")
	memory := f.Int("memory-mib", 256, "expected allocation cap in MiB")
	seed := f.Uint64("seed", 42, "expected uint32 seed")
	budget := f.Int64("budget-ms", 120000, "expected method deadline, 100..300000 ms")
	if err := parse(f, args); err != nil {
		return err
	}
	if *input == "" || !regexp.MustCompile(`^GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(*device) || math.IsNaN(*elapsed) || math.IsInf(*elapsed, 0) || *elapsed <= 0 || *elapsed > 3600000 || *budget < 100 || *budget > 300000 || *memory < 1 || *memory > 8192 || *seed > math.MaxUint32 || (*tier != "quick" && *tier != "standard") {
		return errors.New("invalid input, UUID, duration or worker request bounds")
	}
	if _, exists := worker.MethodChecks[*method]; !exists {
		return errors.New("unknown worker method")
	}
	info, err := os.Lstat(*input)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("worker input must be a regular file")
	}
	data, err := bundle.ReadLimited(*input, 2<<20)
	if err != nil {
		return err
	}
	q := worker.Request{Device: model.Device{UUID: *device}, Method: *method, Tier: *tier, MemoryMiB: *memory, Seed: *seed, Budget: time.Duration(*budget) * time.Millisecond}
	r, err := worker.ParseRequest(data, q, time.Duration(*elapsed*float64(time.Millisecond)))
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(r)
}
