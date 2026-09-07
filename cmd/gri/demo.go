package main

import (
	"fmt"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/report"
	"github.com/harishappana/gpu-inspector/internal/rules"
	"github.com/harishappana/gpu-inspector/internal/scan"
	"io"
	"time"
)

func demoCommand(args []string, out, stderr io.Writer) error {
	f := flags("demo", stderr)
	scenario := f.String("scenario", "clean", "clean, ecc-error or missing; all synthetic")
	dir := f.String("output", "", "new synthetic report directory")
	if err := parse(f, args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("output is required")
	}
	if *scenario != "clean" && *scenario != "ecc-error" && *scenario != "missing" {
		return fmt.Errorf("unknown synthetic scenario")
	}
	start := time.Now().UTC().Add(-time.Second)
	d := model.Device{UUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", PCIAddress: "00000000:01:00.0", Index: 0, Name: "NVIDIA H100 PCIe", SKU: "h100-pcie-80gb", MemoryBytes: 80 << 30, MIGMode: "disabled", VirtualizationMode: "none", DriverVersion: "synthetic-fixture", Source: "synthetic fixture", IdentityAssurance: "Synthetic; no device was inspected"}
	r := model.Report{SchemaVersion: model.SchemaVersion, ToolVersion: model.ToolVersion, RuleVersion: model.RuleVersion, MethodVersion: model.MethodVersion, ScanID: "demo-" + *scenario + "-" + time.Now().UTC().Format("20060102T150405.000000000"), ResourceScope: "SYNTHETIC one-GPU fixture; no hardware inspected", Device: &d, Profile: "general", Tier: "quick", BudgetSeconds: 90, ActualDurationSeconds: 1, StartedUTC: start, FinishedUTC: start.Add(time.Second), Synthetic: true, Seed: 1, ArtifactHashes: map[string]string{}, Limitations: []string{"SYNTHETIC DEMONSTRATION: these are generated test fixtures, not measurements, calibration or evidence of a real GPU's health.", "No qualified healthy-reference data is bundled. Scores are withheld.", "The fixture does not validate CUDA compilation, real device isolation or rental performance."}}
	r.Observations = scan.GuardObservations(&d, "", []model.Device{d}, nil)
	add := func(check, method string, status model.Status, value any, msg string) {
		r.Observations = append(r.Observations, model.Observation{CheckID: check, ResourceID: d.UUID, MethodID: method, Version: model.MethodVersion, StartUTC: start.Add(100 * time.Millisecond), DurationMS: 1, SampleCount: 1, Status: status, Value: value, SourceKind: "measured", Scope: "SYNTHETIC fixture", Visibility: "synthetic test data only", Message: "SYNTHETIC: " + msg, Conditions: map[string]any{"synthetic": true, "worker_qualified": false}})
	}
	if *scenario != "missing" {
		add("B07", "memory_integrity", model.Pass, map[string]any{"unique_logical_bytes": 4096, "patterns": 3, "mismatches": 0}, "generated passing sampled-memory outcome; no real bytes were tested")
		add("A04", "memory_integrity.execution", model.Pass, true, "generated successful checked execution")
		add("A05", "memory_integrity", model.Pass, 4096, "generated owned-allocation outcome")
		add("B09", "fp32_gemm", model.Pass, true, "generated FP32 correctness outcome")
		add("B09", "bf16_gemm", model.Pass, true, "generated BF16 correctness outcome")
	}
	status := model.NotTested
	message := "epoch unavailable; zero counter difference is not a verified history"
	if *scenario == "ecc-error" {
		status = model.Fail
		message = "generated uncorrectable-counter increase during a fixture interval; precautionary stop, physical cause unproven"
	}
	add("B03", "delta.ecc_uncorrected_volatile", status, map[string]any{"before": 0, "after": map[bool]int{true: 1, false: 0}[*scenario == "ecc-error"]}, message)
	add("H03", "scheduler.worker-qualification", model.NotTested, nil, "no qualified CUDA worker")
	add("A09", "reference.qualification", model.NotTested, nil, "no qualified healthy-reference pack")
	for i := range r.Observations {
		r.Observations[i].ID = fmt.Sprintf("%s-e%04d", r.ScanID, i+1)
		if r.Observations[i].StartUTC.IsZero() || r.Observations[i].StartUTC.After(r.FinishedUTC) {
			r.Observations[i].StartUTC = start
		}
		if r.Observations[i].MethodID == "reference.qualification" {
			r.Observations[i].SourceKind = "interpreted"
		}
	}
	rules.Evaluate(&r, nil)
	if err := report.Write(*dir, r); err != nil {
		return err
	}
	fmt.Fprint(out, report.Terminal(r))
	fmt.Fprintf(out, "Synthetic artifacts: %s\n", *dir)
	return nil
}
