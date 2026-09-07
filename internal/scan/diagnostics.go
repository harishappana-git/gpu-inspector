package scan

import (
	"context"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/advisory"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/collect"
	"github.com/harishappana/gpu-inspector/internal/diagnostics"
	"github.com/harishappana/gpu-inspector/internal/model"
)

// Kept separate from Backend so an injected fixture can never silently fall
// through to host kernel logs or an installed vendor diagnostic service.
type diagnosticBackend interface {
	Xid(context.Context, model.Device, time.Time, time.Time, diagnostics.Options) model.Observation
	DCGM(context.Context, model.Device, diagnostics.Options) model.Observation
}

func (localBackend) Xid(ctx context.Context, d model.Device, start, end time.Time, o diagnostics.Options) model.Observation {
	return diagnostics.Xid(ctx, d, start, end, o)
}

func (localBackend) DCGM(ctx context.Context, d model.Device, o diagnostics.Options) model.Observation {
	return diagnostics.DCGM(ctx, d, o)
}

func vendorBudget(o Options) time.Duration {
	if o.DCGMBudget != 0 {
		return o.DCGMBudget
	}
	return 40 * time.Second
}

func diagnosticGap(check, method string, d *model.Device, status model.Status, message string) model.Observation {
	o := baseObservation(check, method, status, message)
	if d != nil {
		o.ResourceID = d.UUID
	}
	return o
}

func runXid(ctx context.Context, b Backend, d model.Device, start, end time.Time) model.Observation {
	adapter, ok := b.(diagnosticBackend)
	if !ok {
		return diagnosticGap("B06", "scheduler.xid", &d, model.NotTested, "This injected backend has no kernel-event adapter; host logs were not accessed.")
	}
	return adapter.Xid(ctx, d, start, end, diagnostics.Options{Timeout: 2 * time.Second})
}

func xidContinuity(d model.Device, before, after, all []model.Observation) bool {
	for _, o := range all {
		if o.CheckID == "A07" && (o.Status == model.Fail || o.Status == model.Contaminated) {
			return false
		}
	}
	wantPCI, valid := canonicalPCI(d.PCIAddress)
	if !valid {
		return false
	}
	for _, boundary := range [][]model.Observation{before, after} {
		uuidOK, pciOK := false, false
		for _, o := range boundary {
			if !strings.EqualFold(o.ResourceID, d.UUID) {
				continue
			}
			switch scalarField(o) {
			case "uuid":
				value, ok := o.Value.(string)
				if o.Status != model.Pass || !ok || !strings.EqualFold(value, d.UUID) {
					return false
				}
				uuidOK = true
			case "pci_address":
				value, ok := o.Value.(string)
				pci, valid := canonicalPCI(value)
				if o.Status != model.Pass || !ok || !valid || pci != wantPCI {
					return false
				}
				pciOK = true
			}
		}
		if !uuidOK || !pciOK {
			return false
		}
	}
	return true
}

func runDCGM(ctx context.Context, o Options, b Backend, d *model.Device, pre []model.Observation, j *journal, ready bool) model.Observation {
	gap := func(status model.Status, reason string) model.Observation {
		return diagnosticGap("B11", "scheduler.dcgm", d, status, reason)
	}
	if !o.DCGM {
		return gap(model.NotTested, "DCGM was not enabled; --dcgm explicitly selects the bounded local vendor software suite.")
	}
	if ctx.Err() != nil {
		return gap(model.TimeBudgetExhausted, "DCGM did not start before the scan deadline or cancellation.")
	}
	if !ready || d == nil || !fullDeviceMode(*d) {
		return gap(model.NotTested, "DCGM did not satisfy the selected-device, worker, idle and safety prerequisites.")
	}
	adapter, ok := b.(diagnosticBackend)
	if !ok {
		return gap(model.NotTested, "This injected backend has no vendor diagnostic adapter; no external tool was run.")
	}
	current, obs := b.Discover(ctx, collect.Options{Timeout: time.Second, Target: d.UUID})
	j.add(obs...)
	if ctx.Err() != nil {
		return gap(model.TimeBudgetExhausted, "DCGM discovery exhausted the scan deadline or was cancelled.")
	}
	target, err := Select(current, d.UUID)
	pci, valid := canonicalPCI(target.PCIAddress)
	wantPCI, wantValid := canonicalPCI(d.PCIAddress)
	if err != nil || !strings.EqualFold(target.UUID, d.UUID) || !valid || !wantValid || pci != wantPCI {
		return gap(model.Contaminated, "Selected UUID/PCI mapping changed before DCGM; no vendor diagnostic was started.")
	}
	currentPre := b.Telemetry(ctx, *d, collect.Options{Timeout: time.Second, Target: d.UUID})
	j.add(currentPre...)
	if ctx.Err() != nil {
		return gap(model.TimeBudgetExhausted, "DCGM telemetry exhausted the scan deadline or was cancelled.")
	}
	if stop, reason := Safety(pre, currentPre, o.MaxTemperatureC); stop {
		return gap(model.NotTested, "DCGM safety stop: "+reason)
	}
	if idle, reason := Idle(currentPre); !idle {
		return gap(model.Contaminated, "DCGM requires observed idle conditions: "+reason)
	}
	if ctx.Err() != nil {
		return gap(model.TimeBudgetExhausted, "DCGM prerequisites exhausted the scan deadline or were cancelled.")
	}
	// Discovery identity alone cannot preserve an older full-device mode. A
	// current selected snapshot must explicitly confirm both operating modes.
	fresh := b.GPU(ctx, target, collect.Options{Timeout: time.Second, Target: d.UUID})
	j.add(fresh...)
	if ctx.Err() != nil {
		return gap(model.TimeBudgetExhausted, "DCGM mode/identity snapshot exhausted the scan deadline or was cancelled.")
	}
	freshTarget := NormalizeDevice(target, fresh)
	mig, migOK := uniqueField(fresh, d.UUID, "mig_current")
	virt, virtOK := uniqueField(fresh, d.UUID, "virtualization_mode")
	discoveredVirt := normalizeVirtualization(target.VirtualizationMode)
	if normalizeMIG(target.MIGMode) == "enabled" || discoveredVirt == "vgpu" || discoveredVirt == "host-vgpu" || discoveredVirt == "host-vsgpu" ||
		!xidContinuity(*d, fresh, fresh, fresh) || !migOK || mig.Status != model.Pass || !virtOK || virt.Status != model.Pass || !fullDeviceMode(freshTarget) {
		return gap(model.Contaminated, "Fresh DCGM prerequisites did not consistently confirm the original UUID/PCI in full physical non-vGPU mode; no vendor diagnostic was started.")
	}
	if stop, reason := Safety(pre, fresh, o.MaxTemperatureC); stop {
		return gap(model.NotTested, "DCGM fresh-snapshot safety stop: "+reason)
	}
	if idle, reason := Idle(fresh); !idle {
		return gap(model.Contaminated, "DCGM fresh snapshot requires observed idle conditions: "+reason)
	}
	if j.incomplete() {
		return gap(model.NotTested, "Evidence storage became incomplete before DCGM; no vendor diagnostic was started.")
	}
	diagctx, cancel := context.WithTimeout(ctx, vendorBudget(o))
	defer cancel()
	done := make(chan struct{})
	safety := make(chan string, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-diagctx.Done():
				return
			case <-ticker.C:
				samples := b.Telemetry(diagctx, *d, collect.Options{Timeout: 750 * time.Millisecond, Target: d.UUID})
				if diagctx.Err() != nil {
					return
				}
				j.add(samples...)
				stop, reason := Safety(pre, samples, o.MaxTemperatureC)
				if j.incomplete() {
					stop, reason = true, "Evidence storage became incomplete."
				}
				if stop {
					safety <- reason
					cancel()
					return
				}
			}
		}
	}()
	result := adapter.DCGM(diagctx, freshTarget, diagnostics.Options{DCGMEnabled: true, Timeout: vendorBudget(o)})
	interrupted := diagctx.Err() != nil
	cancel()
	<-done
	markInterrupted := func(status model.Status, message string) {
		result.Status, result.Message = status, message
		if result.Conditions == nil {
			result.Conditions = map[string]any{}
		}
		result.Conditions["daemon_completion_known"] = false
		result.Conditions["stop_active"] = true
		result.Value = nil
		result.SampleCount = 0
	}
	if interrupted {
		markInterrupted(model.TimeBudgetExhausted, "DCGM exceeded its deadline or was cancelled; client completion does not establish daemon-side completion.")
	}
	select {
	case reason := <-safety:
		j.add(diagnosticGap("B12", "scheduler.dcgm-safety", d, model.Warning, reason))
		markInterrupted(model.Contaminated, "DCGM client interrupted by a safety stop; daemon completion must be checked before another active test. "+reason)
	default:
	}
	return result
}

func runAdvisories(ctx context.Context, o Options, d *model.Device, observations []model.Observation) []model.Observation {
	gap := func(status model.Status, reason string) []model.Observation {
		return []model.Observation{
			diagnosticGap("A10", "advisory.oem_vbios", d, status, reason),
			diagnosticGap("H04", "advisory.driver_issue", d, status, reason),
		}
	}
	if o.AdvisoryPath == "" {
		return gap(model.NotTested, "No signed vendor/OEM advisory pack and explicitly trusted public key were supplied; no version-based conclusion was made.")
	}
	if ctx.Err() != nil {
		return gap(model.TimeBudgetExhausted, "Advisory comparison did not complete before the scan deadline or cancellation.")
	}
	key, err := bundle.LoadPublicKey(o.AdvisoryPublicKey)
	if err != nil {
		return gap(model.ToolError, "Advisory trust key could not be read or validated.")
	}
	pack, err := advisory.LoadContext(ctx, o.AdvisoryPath, key, time.Now().UTC())
	if err != nil {
		if ctx.Err() != nil {
			return gap(model.TimeBudgetExhausted, "Advisory admission was interrupted by the scan deadline or cancellation.")
		}
		return gap(model.ToolError, "Advisory pack rejected: "+err.Error())
	}
	return advisory.Evaluate(pack, d, observations, time.Now().UTC())
}
