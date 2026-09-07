// Package scan orchestrates bounded serial active tests, retaining an append-only
// evidence journal and honest partial results on every supported failure path.
package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/collect"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/pathcheck"
	"github.com/harishappana/gpu-inspector/internal/reference"
	"github.com/harishappana/gpu-inspector/internal/report"
	"github.com/harishappana/gpu-inspector/internal/rules"
	"github.com/harishappana/gpu-inspector/internal/secureexec"
	"github.com/harishappana/gpu-inspector/internal/worker"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Options struct {
	Device, ExpectedSKU, Tier, Profile, Output, Workspace string
	Budget                                                time.Duration
	MemoryMiB                                             int
	Seed                                                  uint64
	WorkerPath, WorkerManifest, WorkerPublicKey           string
	AllowUnqualifiedWorker                                bool
	ReferencePath, ReferencePublicKey                     string
	Price                                                 *model.Price
	MaxTemperatureC                                       float64
	DiskBytes, DownloadBytes                              int64
	Endpoint                                              string
	LockRoot                                              string // injection point for isolated tests; not a CLI option
	Progress                                              func(string)
}

type Backend interface {
	Discover(context.Context, collect.Options) ([]model.Device, []model.Observation)
	GPU(context.Context, model.Device, collect.Options) []model.Observation
	Telemetry(context.Context, model.Device, collect.Options) []model.Observation
	Host(context.Context, collect.Options) []model.Observation
}
type localBackend struct{}

func (localBackend) Discover(c context.Context, o collect.Options) ([]model.Device, []model.Observation) {
	return collect.Discover(c, o)
}
func (localBackend) GPU(c context.Context, d model.Device, o collect.Options) []model.Observation {
	return collect.GPU(c, d, o)
}
func (localBackend) Telemetry(c context.Context, d model.Device, o collect.Options) []model.Observation {
	return collect.Telemetry(c, d, o)
}
func (localBackend) Host(c context.Context, o collect.Options) []model.Observation {
	return collect.Host(c, o)
}

// ActivePlugin is the typed local plugin contract. Discovery and ownership are
// always enforced by the scheduler, never delegated to an unscoped external tool.
type ActivePlugin interface {
	ID() string
	Checks() []string
	Estimate(string) time.Duration
	Execute(context.Context, worker.Request) ([]model.Observation, bool)
}
type cudaPlugin struct {
	method string
	binary *worker.Binary
}

func (p cudaPlugin) ID() string       { return p.method }
func (p cudaPlugin) Checks() []string { return worker.MethodChecks[p.method] }
func (p cudaPlugin) Estimate(tier string) time.Duration {
	if tier == "standard" {
		return 32 * time.Second
	}
	return 10 * time.Second
}
func (p cudaPlugin) Execute(ctx context.Context, q worker.Request) ([]model.Observation, bool) {
	return p.binary.Run(ctx, q)
}

func Validate(o Options) error {
	if o.Tier != "quick" && o.Tier != "standard" {
		return errors.New("tier must be quick or standard")
	}
	switch o.Profile {
	case "general", "inference", "training", "rendering":
	default:
		return errors.New("unsupported profile")
	}
	if o.Budget < time.Second || o.Budget > 900*time.Second {
		return errors.New("budget-seconds must be between 1 and 900")
	}
	if o.MemoryMiB < 1 || o.MemoryMiB > 8192 {
		return errors.New("memory-mib must be between 1 and 8192")
	}
	if o.Seed > math.MaxUint32 {
		return errors.New("seed must fit unsigned 32 bits")
	}
	if o.Output == "" {
		return errors.New("output directory is required")
	}
	if o.MaxTemperatureC != 0 && (math.IsNaN(o.MaxTemperatureC) || math.IsInf(o.MaxTemperatureC, 0) || o.MaxTemperatureC < 30 || o.MaxTemperatureC > 120) {
		return errors.New("max-temperature-c must be between 30 and 120 when configured")
	}
	if o.Price != nil && (o.Price.PerHour < 0 || math.IsNaN(o.Price.PerHour) || math.IsInf(o.Price.PerHour, 0) || !validCurrency(o.Price.Currency)) {
		return errors.New("price must be finite, nonnegative and have a three-letter currency")
	}
	if o.DiskBytes < 0 || o.DiskBytes > 64<<20 || o.DownloadBytes < 0 || o.DownloadBytes > 64<<20 {
		return errors.New("path-test byte budgets must be between 0 and 64 MiB")
	}
	if (o.DiskBytes > 0 || o.Endpoint != "") && o.Tier != "standard" {
		return errors.New("active path tests require the Standard tier")
	}
	if o.DiskBytes > 0 && o.Workspace == "" {
		return errors.New("disk testing requires an explicit workspace")
	}
	return nil
}
func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}
	return "scan-" + hex.EncodeToString(b)
}
func baseObservation(id, method string, status model.Status, message string) model.Observation {
	return model.Observation{CheckID: id, MethodID: method, Version: model.MethodVersion, Status: status, Message: message, StartUTC: time.Now().UTC(), SourceKind: "interpreted", ResourceID: "allocation", Scope: "one selected GPU and process-visible environment", Visibility: "local process"}
}
func Run(ctx context.Context, o Options) (model.Report, error) {
	return RunWithBackend(ctx, o, localBackend{})
}

func RunWithBackend(parent context.Context, o Options, b Backend) (model.Report, error) {
	if err := Validate(o); err != nil {
		return model.Report{}, err
	}
	start := time.Now()
	id := newID()
	r := model.Report{SchemaVersion: model.SchemaVersion, ToolVersion: model.ToolVersion, RuleVersion: model.RuleVersion, MethodVersion: model.MethodVersion, ScanID: id, ResourceScope: fmt.Sprintf("one selected GPU and process-visible context on %s/%s", runtime.GOOS, runtime.GOARCH), ExpectedSKU: o.ExpectedSKU, Profile: o.Profile, Tier: o.Tier, BudgetSeconds: o.Budget.Seconds(), StartedUTC: start.UTC(), Seed: o.Seed, Price: o.Price, ArtifactHashes: map[string]string{}, Observations: []model.Observation{}, Limitations: []string{
		"Development implementation; real-rental acceptance and CUDA method qualification have not been completed.",
		"Host/driver-mediated identity consistency is not hardware authentication. NVML and nvidia-smi share a trust domain.",
		"Accessible logical allocations are tested; full physical memory coverage, remaining lifetime and real-workload throughput are not established.",
		"Installation time is unknown unless measured by an external installer; actual_duration covers this scan, not installation.",
		"No default outbound telemetry, provider submission, reset, power change, unrelated-process termination or peer test.",
	}}
	j, err := newJournal(o.Output, id)
	if err != nil {
		return r, err
	}
	if o.Price != nil {
		declared := *o.Price
		declared.ScanCost = nil
		declared.ReferenceEquivalentPerHour = nil
		declared.EquivalenceScope = ""
		r.Price = &declared
	}
	progress := func(s string) {
		if o.Progress != nil {
			o.Progress(s)
		}
	}
	// Reserve final snapshot/report time instead of letting a tool consume the
	// entire deadline. A driver wait may outlive userspace process termination.
	reserve := 2 * time.Second
	if o.Budget < 10*time.Second {
		reserve = o.Budget / 4
	}
	ctx, cancel := context.WithDeadline(parent, start.Add(o.Budget-reserve))
	defer cancel()
	if time.Until(start.Add(o.Budget-reserve)) > buildEvidenceBudget && ctx.Err() == nil {
		j.add(buildEvidence())
	}
	copts := collect.Options{Timeout: 2 * time.Second, Workspace: o.Workspace, Target: o.Device}
	progress("Discovering permitted devices and visible execution resources")
	devices, discovery := b.Discover(ctx, copts)
	j.add(discovery...)
	preHost := b.Host(ctx, copts)
	j.add(preHost...)
	d, selectionErr := Select(devices, o.Device)
	var pre []model.Observation
	if selectionErr == nil {
		pre = b.GPU(ctx, d, copts)
		j.add(pre...)
		d = NormalizeDevice(d, pre)
		r.Device = &d
	}
	guards := GuardObservations(r.Device, o.ExpectedSKU, devices, selectionErr)
	j.add(guards...)
	var binary *worker.Binary
	var lock *targetLock
	active := selectionErr == nil && ctx.Err() == nil
	stopAll := false
	blockedStatus := model.NotTested
	workerReason := "Active testing did not satisfy its prerequisites."
	block := func(status model.Status, reason string, critical bool) {
		active = false
		blockedStatus, workerReason = status, reason
		stopAll = stopAll || critical
	}
	if selectionErr != nil {
		block(model.NotTested, "No unambiguous permitted selected GPU is available.", false)
	}
	for _, g := range guards {
		if active && (g.Status == model.Fail || (g.CheckID == "A07" && g.Status == model.Contaminated)) {
			block(model.NotTested, g.Message, true)
		}
	}
	if active {
		lock, err = acquireLock(o.LockRoot, d.UUID)
		if err != nil {
			block(model.Contaminated, err.Error(), true)
			j.add(baseObservation("A07", "guard.lock", model.Contaminated, err.Error()))
		} else {
			defer lock.close()
		}
	}
	if active && (d.MIGMode != "disabled" || (d.VirtualizationMode != "none" && d.VirtualizationMode != "passthrough")) {
		block(model.Unsupported, "Active worker requires a confirmed full GPU with MIG disabled and a supported visible virtualization mode.", false)
		j.add(baseObservation("A06", "guard.active-scope", blockedStatus, workerReason))
	}
	if active {
		if idle, reason := Idle(pre); !idle {
			block(model.Contaminated, reason, false)
			j.add(baseObservation("I01", "scheduler.idle", blockedStatus, reason))
		}
	}
	if active {
		if stop, reason := Safety(pre, pre, o.MaxTemperatureC); stop {
			block(model.NotTested, reason, true)
			j.add(baseObservation("B12", "scheduler.safety", model.Warning, reason))
		}
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		if active {
			block(model.Unsupported, "CUDA execution is unsupported on this operating system/architecture.", false)
		}
		j.add(baseObservation("H03", "scheduler.platform", model.Unsupported, "This development CUDA worker targets Linux x86-64; the current host can produce a degraded context report. Real-GPU qualification remains pending."))
	}
	if active {
		if o.WorkerPath == "" || o.WorkerManifest == "" || o.WorkerPublicKey == "" {
			block(model.DependencyMissing, "A signed CUDA worker, manifest and explicitly trusted public key were not all supplied.", false)
		} else {
			key, keyErr := bundle.LoadPublicKey(o.WorkerPublicKey)
			if keyErr == nil {
				binary, keyErr = worker.Load(o.WorkerPath, o.WorkerManifest, key, o.AllowUnqualifiedWorker)
			}
			if keyErr != nil {
				block(model.ToolError, "Worker artifact rejected: "+keyErr.Error(), false)
			}
		}
	}
	if binary != nil {
		defer binary.Close()
		r.WorkerDigest = binary.Digest
		qualification := baseObservation("H03", "worker.artifact-qualification", model.NotTested, "Signed development worker admitted for explicit acceptance testing; numerical, architecture and dependency qualification remain pending.")
		qualification.Value = map[string]any{"sha256": binary.Digest, "qualified": binary.Qualified}
		if binary.Qualified {
			qualification.Status = model.Pass
			qualification.Message = "Signed worker and its declared qualification were admitted; runtime compatibility is rechecked by each method."
		}
		j.add(qualification)
	}
	if ctx.Err() != nil {
		block(model.TimeBudgetExhausted, "Discovery consumed the scan budget or was cancelled.", true)
	}
	if !active {
		for _, check := range []string{"A04", "A05", "B07", "B08", "B09", "B12", "C01", "C02", "C05", "C07", "H02", "H03"} {
			j.add(baseObservation(check, "scheduler.active-unavailable", blockedStatus, workerReason))
		}
	}
	if active {
		methods := []string{"memory_integrity", "fp32_gemm", "bf16_gemm", "hbm_copy", "h2d", "d2h"}
		if o.Profile == "inference" {
			methods = []string{"memory_integrity", "hbm_copy", "bf16_gemm", "fp32_gemm", "h2d", "d2h"}
		}
		if o.Tier == "standard" {
			methods = append(methods, "tf32_gemm", "working_set", "dispatch_latency")
		}
		for i, method := range methods {
			if ctx.Err() != nil || j.incomplete() {
				stopAll = true
				break
			}
			progress("Checking target identity before " + method)
			visible, obs := b.Discover(ctx, copts)
			j.add(obs...)
			current, e := Select(visible, d.UUID)
			currentPCI, currentValid := canonicalPCI(current.PCIAddress)
			selectedPCI, selectedValid := canonicalPCI(d.PCIAddress)
			if e != nil || !strings.EqualFold(current.UUID, d.UUID) || !currentValid || !selectedValid || currentPCI != selectedPCI {
				stopAll = true
				j.add(baseObservation("A07", "guard.recheck", model.Contaminated, "Selected UUID/PCI mapping changed or became ambiguous before an active test; remaining load stopped."))
				break
			}
			currentPre := b.Telemetry(ctx, d, copts)
			j.add(currentPre...)
			if stop, reason := Safety(pre, currentPre, o.MaxTemperatureC); stop {
				stopAll = true
				j.add(baseObservation("B12", "scheduler.safety", model.Warning, reason))
				break
			}
			if idle, reason := Idle(currentPre); !idle {
				j.add(baseObservation("I01", "scheduler.idle", model.Contaminated, reason))
				break
			}
			remaining := time.Until(start.Add(o.Budget - reserve))
			budget := remaining / time.Duration(len(methods)-i)
			plugin := cudaPlugin{method: method, binary: binary}
			if budget > plugin.Estimate(o.Tier) {
				budget = plugin.Estimate(o.Tier)
			}
			if budget < 100*time.Millisecond {
				stopAll = true
				break
			}
			progress("Running bounded " + method)
			testctx, stopTest := context.WithCancel(ctx)
			done := make(chan struct{})
			safetyStop := make(chan string, 1)
			go func() {
				defer close(done)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-testctx.Done():
						return
					case <-ticker.C:
						samples := b.Telemetry(testctx, d, collect.Options{Timeout: 750 * time.Millisecond, Target: d.UUID, Workspace: o.Workspace})
						if testctx.Err() != nil {
							return
						}
						j.add(samples...)
						if j.incomplete() {
							select {
							case safetyStop <- "Evidence capacity or storage failure stopped active load; report is partial.":
							default:
							}
							stopTest()
							return
						}
						if stop, reason := Safety(pre, samples, o.MaxTemperatureC); stop {
							select {
							case safetyStop <- reason:
							default:
							}
							stopTest()
							return
						}
					}
				}
			}()
			observations, stop := plugin.Execute(testctx, worker.Request{Device: d, Method: method, Tier: o.Tier, Budget: budget, MemoryMiB: o.MemoryMiB, Seed: o.Seed})
			stopTest()
			<-done
			j.add(observations...)
			select {
			case reason := <-safetyStop:
				j.add(baseObservation("B12", "scheduler.safety", model.Warning, reason))
				stop = true
			default:
			}
			if stop || j.incomplete() {
				stopAll = true
				progress("Active load stopped; preserving the observed failure or incomplete result")
				break
			}
		}
	}
	if o.DiskBytes > 0 || o.Endpoint != "" {
		if stopAll || j.incomplete() {
			j.add(pathFallback(o, model.NotTested, "Optional active path tests skipped after a safety, identity, correctness or evidence-capacity stop.")...)
		} else if ctx.Err() != nil {
			j.add(pathFallback(o, model.TimeBudgetExhausted, "Optional path tests did not start before cancellation/deadline.")...)
		} else {
			progress("Running the explicitly selected bounded path tests")
			j.add(runPaths(ctx, o)...)
		}
	}
	progress("Capturing final deltas and writing local evidence")
	finalctx, finalCancel := context.WithDeadline(parent, start.Add(o.Budget-reserve/2))
	defer finalCancel()
	var post []model.Observation
	if r.Device != nil {
		post = b.GPU(finalctx, d, copts)
		j.add(post...)
	}
	postHost := b.Host(finalctx, copts)
	j.add(postHost...)
	before := append(append([]model.Observation(nil), pre...), preHost...)
	after := append(append([]model.Observation(nil), post...), postHost...)
	j.add(Deltas(before, after)...)
	j.add(loadSummary(o.Tier, r.Device, j.snapshot())...)
	j.add(hostSummary(preHost, postHost, j.snapshot())...)
	j.add(clockEvidence(start, time.Now()))
	r.Cancelled = parent.Err() != nil
	if ctx.Err() != nil {
		j.add(baseObservation("J01", "scheduler.completion", model.TimeBudgetExhausted, "Scan cancelled or active-test budget exhausted; unfinished checks remain explicit."))
	}
	r.FinishedUTC = time.Now().UTC()
	r.ActualDurationSeconds = time.Since(start).Seconds()
	var pack *reference.Pack
	refObs := baseObservation("A09", "reference.qualification", model.NotTested, "UNCALIBRATED: no healthy measurements are bundled with this development build.")
	if o.ReferencePath != "" && o.ReferencePublicKey != "" {
		key, e := bundle.LoadPublicKey(o.ReferencePublicKey)
		if e == nil {
			pack, e = reference.Load(o.ReferencePath, key, r.FinishedUTC)
		}
		if e != nil {
			refObs.Status = model.ToolError
			refObs.Message = "Reference pack rejected: " + e.Error()
		} else {
			refObs.Status = model.Pass
			refObs.Value = pack.ID
			refObs.Message = "Signed reference pack admitted; exact scan and method applicability still required."
		}
	}
	j.add(refObs)
	if r.Price != nil {
		cost, costValid := rentalCost(r.Price.PerHour, r.ActualDurationSeconds)
		if costValid {
			r.Price.ScanCost = &cost
		}
		r.Price.Source = "user-declared; not independently validated"
		priceObs := baseObservation("M01", "declared.price", model.Pass, "Rental price supplied by user; excludes storage, egress, minimum billing increments and other charges.")
		priceObs.SourceKind = "declared"
		priceObs.Value = *r.Price
		j.add(priceObs)
		costObs := baseObservation("M04", "measured.scan-cost", model.Pass, "Rental-runtime cost estimate from measured scan time and declared hourly price; other charges excluded.")
		costObs.Conditions = map[string]any{"opt_in": true}
		if costValid {
			costObs.Value = cost
			costObs.Unit = r.Price.Currency
		} else {
			costObs.Status = model.NotTested
			costObs.Message = "Declared price and observed duration cannot produce a finite supported cost estimate."
		}
		j.add(costObs)
	}
	if j.incomplete() {
		r.Limitations = append(r.Limitations, "Evidence capacity was reached or storage failed; active load stopped and retained summaries mark omitted detail. This report is incomplete.")
	}
	r.Observations = j.snapshot()
	if err = j.close(); err != nil {
		return r, fmt.Errorf("evidence journal write failed; partial journal retained: %w", err)
	}
	rules.Evaluate(&r, pack)
	if err = report.Write(o.Output, r); err != nil {
		return r, fmt.Errorf("report generation failed; evidence journal retained: %w", err)
	}
	stored, err := report.Read(filepath.Join(o.Output, "report.json"))
	if err != nil {
		return r, fmt.Errorf("durable report readback failed: %w", err)
	}
	return stored, nil
}

func validCurrency(currency string) bool {
	if len(currency) != 3 {
		return false
	}
	for _, c := range currency {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}
func rentalCost(rate, seconds float64) (float64, bool) {
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return 0, false
	}
	cost := rate * (seconds / 3600)
	return cost, !math.IsNaN(cost) && !math.IsInf(cost, 0) && cost >= 0
}
func pathFallback(o Options, status model.Status, message string) []model.Observation {
	ids := []string{}
	if o.DiskBytes > 0 {
		ids = append(ids, "F03", "F05", "F06", "F07")
	}
	if o.Endpoint != "" {
		ids = append(ids, "G02", "G03", "G04")
	}
	out := []model.Observation{}
	for _, id := range ids {
		x := baseObservation(id, "path.helper", status, message)
		x.Conditions = map[string]any{"opt_in": true}
		out = append(out, x)
	}
	return out
}
func runPaths(ctx context.Context, o Options) []model.Observation {
	exe, err := os.Executable()
	if err != nil {
		return pathFallback(o, model.ToolError, "Cannot locate isolated path-test helper")
	}
	options := pathcheck.Options{Workspace: o.Workspace, DiskBytes: o.DiskBytes, URL: o.Endpoint, DownloadBytes: o.DownloadBytes, Timeout: 30 * time.Second}
	data, err := marshalPathOptions(options)
	if err != nil {
		return pathFallback(o, model.ToolError, "Invalid path options")
	}
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result := secureexec.Run(child, exe, []string{"__pathcheck", string(data)}, nil, 1<<20)
	return decodePathResult(o, result, child.Err())
}
func decodePathResult(o Options, result secureexec.Result, contextErr error) []model.Observation {
	var observations []model.Observation
	if result.Err != nil || result.ExitCode != 0 || result.Truncated || contextErr != nil || bundle.Decode(result.Stdout, &observations) != nil {
		status := model.ToolError
		if contextErr != nil {
			status = model.TimeBudgetExhausted
		}
		return pathFallback(o, status, "Bounded isolated path test did not return complete valid evidence.")
	}
	expected := map[string]bool{}
	for _, fallback := range pathFallback(o, model.NotTested, "") {
		expected[fallback.CheckID] = true
	}
	seen := map[string]bool{}
	for _, observation := range observations {
		if !expected[observation.CheckID] || seen[observation.CheckID] || !observation.Status.Valid() || observation.Conditions["opt_in"] != true {
			return pathFallback(o, model.ToolError, "Path helper returned unexpected, duplicate, invalid or unselected evidence.")
		}
		seen[observation.CheckID] = true
	}
	if len(seen) != len(expected) {
		return pathFallback(o, model.ToolError, "Path helper omitted selected check coverage; no missing observation is a pass.")
	}
	return observations
}
