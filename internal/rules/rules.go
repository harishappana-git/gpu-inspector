// Package rules evaluates retained evidence deterministically. Collection
// success, physical health, and calibrated performance are separate concepts.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/catalog"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/reference"
)

func Number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case float32:
		return Number(float64(n))
	case json.Number:
		f, err := n.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint32:
		return float64(n), true
	case int32:
		return float64(n), true
	}
	return 0, false
}
func booleanState(v any) (bool, bool) {
	if b, ok := v.(bool); ok {
		return b, true
	}
	if n, ok := Number(v); ok {
		if n == 0 || n == 1 {
			return n == 1, true
		}
		return false, false
	}
	s := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
	switch s {
	case "true", "yes", "enabled", "pending", "1":
		return true, true
	case "false", "no", "disabled", "not pending", "0":
		return false, true
	}
	return false, false
}
func field(o model.Observation) string {
	if s, ok := o.Conditions["field"].(string); ok {
		return s
	}
	return ""
}
func rank(s model.Status) int {
	switch s {
	case model.Fail:
		return 100
	case model.Contaminated:
		return 90
	case model.ToolError:
		return 80
	case model.TimeBudgetExhausted:
		return 70
	case model.PermissionDenied:
		return 60
	case model.DependencyMissing:
		return 50
	case model.Unsupported:
		return 40
	case model.NotTested:
		return 30
	case model.Warning:
		return 20
	case model.Pass:
		return 10
	case model.NotApplicable:
		return 1
	}
	return 80
}

// Gate observations override raw inventory fields for checks that require
// execution, interval deltas, bidirectional transfer, or stable target mapping.
func relevant(r model.Report, id string) []model.Observation {
	var out []model.Observation
	for _, o := range r.Observations {
		if o.CheckID != id {
			continue
		}
		use := true
		switch id {
		case "A01", "A02", "A06", "A07", "A08":
			use = strings.HasPrefix(o.MethodID, "guard.")
		case "A04", "A05", "B07", "B08", "B09", "B12", "H02":
			use = o.SourceKind == "measured" || strings.HasPrefix(o.MethodID, "scheduler.")
		case "B02", "B03", "D09", "E02", "E06":
			use = strings.HasPrefix(o.MethodID, "delta.")
		}
		if use {
			if activeWorkerCheck(id) && o.SourceKind == "measured" && (o.Status == model.Pass || o.Status == model.Fail) && (r.Device == nil || o.ResourceID != r.Device.UUID || !withinScan(r, o)) {
				o.Status = model.Contaminated
				o.Message = "Active evidence is missing selected-device identity or falls outside this observation interval."
			}
			out = append(out, o)
		}
	}
	return out
}

func activeWorkerCheck(id string) bool {
	return strings.HasPrefix(id, "C") || id == "A04" || id == "A05" || id == "B07" || id == "B08" || id == "B09" || id == "B12" || id == "H02"
}

type workerFailure struct {
	ID, Method, CheckID, Observation string
	Refs                             []string
	Required, Selected               bool
}

// A worker invocation projects one outcome onto several coverage rows. Group
// only exact invocation identity; different starts/durations/methods/resources
// remain separate events with separate findings and evidence references.
func workerFailures(r model.Report) ([]workerFailure, map[string]bool) {
	primary := map[string]string{"memory_integrity": "B07", "fp32_gemm": "B09", "bf16_gemm": "B09", "tf32_gemm": "B09", "hbm_copy": "C05", "h2d": "C07", "d2h": "C07", "working_set": "C06", "dispatch_latency": "C08"}
	checks := map[string]model.CheckResult{}
	for _, c := range r.Checks {
		checks[c.CheckID] = c
	}
	groups := map[string]*workerFailure{}
	for _, o := range r.Observations {
		if o.Status != model.Fail || o.SourceKind != "measured" || !activeWorkerCheck(o.CheckID) || r.Device == nil || o.ResourceID != r.Device.UUID || !withinScan(r, o) {
			continue
		}
		method := strings.TrimSuffix(strings.TrimSuffix(o.MethodID, ".execution"), ".validation")
		if o.MethodID != method && o.MethodID != method+".execution" && o.MethodID != method+".validation" {
			continue
		}
		checkID, known := primary[method]
		if !known {
			continue
		}
		key := fmt.Sprintf("%s\x00%s\x00%.17g\x00%s", o.ResourceID, o.StartUTC.UTC().Format(time.RFC3339Nano), o.DurationMS, method)
		group := groups[key]
		if group == nil {
			sum := sha256.Sum256([]byte(key))
			group = &workerFailure{ID: "worker-" + strings.ToLower(checkID) + "-" + method + "-" + hex.EncodeToString(sum[:6]), Method: method, CheckID: checkID, Observation: o.Message}
			groups[key] = group
		}
		if o.CheckID == checkID && o.Message != "" {
			group.Observation = o.Message
		}
		if o.ID != "" {
			group.Refs = append(group.Refs, o.ID)
		}
		if c, exists := checks[o.CheckID]; exists && c.Status == model.Fail {
			group.Selected = true
			group.Required = group.Required || c.Required
		}
	}
	out := []workerFailure{}
	grouped := map[string]bool{}
	for _, group := range groups {
		if !group.Selected || len(group.Refs) == 0 {
			continue
		}
		if group.Observation == "" {
			group.Observation = group.Method + ": one selected-device worker invocation reported a failed checked test."
		}
		sort.Strings(group.Refs)
		for _, id := range group.Refs {
			grouped[id] = true
		}
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, grouped
}

func withinScan(r model.Report, o model.Observation) bool {
	return !o.StartUTC.IsZero() && !r.StartedUTC.IsZero() && r.FinishedUTC.After(r.StartedUTC) && !o.StartUTC.Before(r.StartedUTC) && !o.StartUTC.After(r.FinishedUTC) && !math.IsNaN(o.DurationMS) && !math.IsInf(o.DurationMS, 0) && o.DurationMS > 0 && o.DurationMS <= r.FinishedUTC.Sub(r.StartedUTC).Seconds()*1000 && !o.StartUTC.Add(time.Duration(o.DurationMS*float64(time.Millisecond))).After(r.FinishedUTC)
}

var scoringMethods = []string{"fp32_gemm", "bf16_gemm", "hbm_copy", "h2d", "d2h"}
var primaryCheck = map[string]string{"fp32_gemm": "C01", "bf16_gemm": "C02", "hbm_copy": "C05", "h2d": "C07", "d2h": "C07"}

// Optional checks are admitted only from the selected, bounded adapter's exact
// methods and an explicit boolean opt-in. The presence of an arbitrary catalog
// row or a truthy string is not evidence that a user selected the operation.
func optionalEvidence(r model.Report, id string, observations []model.Observation) []model.Observation {
	methods := map[string][]string{
		"F03": {"pathcheck.disk", "pathcheck.disk.sequential"},
		"F05": {"pathcheck.disk", "pathcheck.disk.latency"},
		"F06": {"pathcheck.disk", "pathcheck.disk.cache_context"},
		"F07": {"pathcheck.disk", "pathcheck.disk.integrity"},
		"G02": {"pathcheck.https.reachability"},
		"G03": {"pathcheck.https.download"},
		"G04": {"pathcheck.https.estimate"},
		"M04": {"measured.scan-cost"},
	}
	allowed, exists := methods[id]
	if !exists {
		return nil
	}
	var admitted []model.Observation
	for _, o := range observations {
		optIn, isBoolean := o.Conditions["opt_in"].(bool)
		if !isBoolean || !optIn {
			continue
		}
		if id == "M04" && r.Price == nil {
			continue
		}
		if id != "M04" && r.Tier != "standard" {
			continue
		}
		methodMatches := false
		for _, method := range allowed {
			if o.MethodID == method {
				methodMatches = true
				break
			}
		}
		if id != "M04" && o.MethodID == "path.helper" && rank(o.Status) >= 30 && o.Status != model.Fail {
			methodMatches = true
		}
		if methodMatches {
			admitted = append(admitted, o)
		}
	}
	return admitted
}

// metricCandidate accepts one measured run and its identical projections onto
// correctness/performance checks. Differing repeated runs need an explicit
// aggregation method; selecting the first passing sample would cherry-pick.
func metricCandidate(r model.Report, p *reference.Pack, method string) (*model.Observation, []string, string) {
	var chosen *model.Observation
	refs := []string{}
	reason := ""
	for i := range r.Observations {
		o := &r.Observations[i]
		if o.MethodID != method {
			continue
		}
		if o.ID != "" {
			refs = append(refs, o.ID)
		}
		if o.CheckID != primaryCheck[method] && !(o.CheckID == "B09" && (method == "fp32_gemm" || method == "bf16_gemm")) {
			reason = "Method evidence is attached to an incompatible check."
			continue
		}
		if o.SourceKind != "measured" || o.Status != model.Pass || o.ID == "" || r.Device == nil || o.ResourceID != r.Device.UUID {
			reason = "Every method observation must pass on the selected GPU with measured provenance."
			continue
		}
		if qualified, exists := o.Conditions["worker_qualified"]; exists {
			value, known := booleanState(qualified)
			if !known || !value {
				reason = "Worker qualification was not established for this observation."
				continue
			}
		}
		value, ok := Number(o.Value)
		if !ok || value <= 0 || o.SampleCount <= 0 {
			reason = "A positive finite metric and checked sample count are required."
			continue
		}
		if !withinScan(r, *o) {
			reason = "Method timing is missing or outside this scan's observation interval."
			continue
		}
		if o.Spread != nil && (math.IsNaN(*o.Spread) || math.IsInf(*o.Spread, 0) || *o.Spread < 0) {
			reason = "Measurement spread is invalid."
			continue
		}
		if _, err := p.Metric(*o); err != nil {
			reason = "Method version, units or conditions do not match the qualified reference."
			continue
		}
		if chosen != nil {
			previous, _ := Number(chosen.Value)
			sameSpread := chosen.Spread == nil && o.Spread == nil || chosen.Spread != nil && o.Spread != nil && *chosen.Spread == *o.Spread
			if value != previous || o.Unit != chosen.Unit || !o.StartUTC.Equal(chosen.StartUTC) || o.DurationMS != chosen.DurationMS || o.SampleCount != chosen.SampleCount || !sameSpread || reference.ConditionsHash(o.Conditions) != reference.ConditionsHash(chosen.Conditions) {
				reason = "Conflicting or separate same-method samples require an explicit repeatability and aggregation method."
			}
		}
		if chosen == nil || o.CheckID == primaryCheck[method] {
			chosen = o
		}
	}
	if reason != "" {
		return nil, refs, reason
	}
	if chosen == nil {
		return nil, refs, "No eligible measured result is available."
	}
	if chosen.CheckID != primaryCheck[method] {
		return nil, refs, "A correctness projection cannot substitute for the primary performance check."
	}
	return chosen, refs, ""
}

func Evaluate(r *model.Report, p *reference.Pack) {
	r.RuleVersion = model.RuleVersion
	r.Verdict = model.Inconclusive
	r.Score = nil
	r.PerformanceJudgment = "UNCALIBRATED"
	r.ReferenceStatus = "UNCALIBRATED"
	r.ReferenceID = ""
	r.Checks = []model.CheckResult{}
	r.Findings = []model.Finding{}
	r.Highlights = []model.Highlight{}
	r.Blockers = []string{}
	r.MissingChecks = []string{}
	r.Coverage = model.Coverage{RequiredPerformanceWeight: 100}
	if r.Price != nil {
		r.Price.ReferenceEquivalentPerHour = nil
		r.Price.EquivalenceScope = ""
	}
	for _, c := range catalog.All() {
		cr := model.CheckResult{CheckID: c.ID, Name: c.Name, Stage: c.Stage, Required: catalog.InTier(c, r.Tier) && catalog.Mandatory(c.ID, r.Tier), Status: model.NotTested, Reason: "No eligible evidence was collected.", Fallback: c.Method + " Limit: " + c.Boundary, EvidenceRefs: []string{}}
		obs := relevant(*r, c.ID)
		selected := catalog.InTier(c, r.Tier)
		if c.Stage == "O" {
			obs = optionalEvidence(*r, c.ID, obs)
			selected = len(obs) > 0
		}
		if !selected {
			cr.Status = model.NotApplicable
			if c.Stage == "F" {
				cr.Reason = "Future phase; not assessed by a single-GPU Phase 1 scan."
			} else if c.Stage == "O" {
				cr.Reason = "Optional extension is not enabled in this scan."
			} else {
				cr.Reason = "Standard-tier check not selected in this Quick scan."
			}
		}
		if selected && len(obs) > 0 {
			cr.Status = model.NotApplicable
			for _, o := range obs {
				cr.EvidenceRefs = append(cr.EvidenceRefs, o.ID)
				if rank(o.Status) > rank(cr.Status) {
					cr.Status = o.Status
					cr.Reason = o.Message
				}
			}
			// Individual optional sensor fields may be absent even when context was
			// observed; retain the worst status rather than manufacture full coverage.
		}
		if c.ID == "C07" && cr.Status == model.Pass {
			dirs := map[string]bool{}
			for _, o := range obs {
				if o.Status == model.Pass {
					dirs[o.MethodID] = true
				}
			}
			if !dirs["h2d"] || !dirs["d2h"] {
				cr.Status = model.NotTested
				cr.Reason = "Both separately checked H2D and D2H transfers are required."
			}
		}
		if c.ID == "B09" && cr.Status == model.Pass {
			methods := map[string]bool{}
			for _, o := range obs {
				if o.Status == model.Pass {
					methods[o.MethodID] = true
				}
			}
			if !methods["fp32_gemm"] || !methods["bf16_gemm"] {
				cr.Status = model.NotTested
				cr.Reason = "Both FP32 and BF16 checked results are required."
			}
		}
		if selected && c.ID == "A10" {
			// Reading a version string cannot establish OEM/VBIOS consistency.
			// No qualified signed OEM-comparison adapter exists in this release.
			cr.Status = model.NotTested
			cr.Reason = "Reported VBIOS metadata is retained, but consistency against a qualified signed vendor/OEM reference has not been assessed."
		}
		if cr.Required && cr.Status == model.NotApplicable {
			allowed := c.ID == "A01" && r.ExpectedSKU == "" && len(obs) > 0
			for _, o := range obs {
				if o.MethodID != "guard.expectation" || o.Status != model.NotApplicable {
					allowed = false
				}
			}
			if !allowed {
				cr.Status = model.NotTested
				cr.Reason = "This mandatory check cannot be waived as not applicable."
			}
		}
		if cr.Required {
			r.Coverage.Required++
			if cr.Status == model.Pass || cr.Status == model.Warning || cr.Status == model.Fail || cr.Status == model.NotApplicable {
				r.Coverage.Completed++
			}
			if cr.Status == model.Pass || cr.Status == model.NotApplicable {
				r.Coverage.Eligible++
			}
		}
		if selected && cr.Status != model.Fail && rank(cr.Status) >= 30 {
			r.MissingChecks = append(r.MissingChecks, c.ID)
		}
		r.Checks = append(r.Checks, cr)
	}
	if r.Coverage.Required > 0 {
		r.Coverage.Fraction = float64(r.Coverage.Completed) / float64(r.Coverage.Required)
	}
	evidence := map[string]bool{}
	invalidEvidence := false
	for _, o := range r.Observations {
		if o.ID == "" || o.MethodID == "" || !o.Status.Valid() || evidence[o.ID] {
			invalidEvidence = true
		}
		if o.ID != "" && o.MethodID != "" {
			evidence[o.ID] = true
		}
	}
	add := func(id, check, severity, observation, interpretation, action string, refs []string) bool {
		if len(refs) == 0 {
			return false
		}
		for _, id := range refs {
			if !evidence[id] {
				return false
			}
		}
		for _, f := range r.Findings {
			if f.ID == id {
				return false
			}
		}
		f := model.Finding{ID: id, RuleVersion: model.RuleVersion, CheckID: check, Severity: severity, Observation: observation, Interpretation: interpretation, AlternativeCauses: []string{"Software/test-method behavior and host-mediated visibility may affect the observation."}, ObservationStrength: "Direct within the recorded method and visibility", CauseStrength: "Not established", Impact: "Impact not quantified; a representative workload check is required.", ImpactBasis: "No workload projection", ActionID: action, RetestID: check, EvidenceRefs: refs}
		r.Findings = append(r.Findings, f)
		if severity == "BLOCKER" {
			r.Blockers = append(r.Blockers, id)
		}
		return true
	}
	workerGroups, groupedEvidence := workerFailures(*r)
	for _, group := range workerGroups {
		severity := "WARNING"
		if group.Required {
			severity = "BLOCKER"
		}
		add(group.ID, group.CheckID, severity, group.Observation, "One selected-device worker invocation reported a failed checked test. Related allocation, execution and validation rows describe the same event. Physical defect, device/context loss and library-load failure are not established by a numerical mismatch.", "investigate-correctness", group.Refs)
	}
	for _, c := range r.Checks {
		if c.Status == model.Fail {
			refs := []string{}
			for _, o := range relevant(*r, c.CheckID) {
				if o.Status == model.Fail && !groupedEvidence[o.ID] {
					refs = append(refs, o.ID)
				}
			}
			if len(refs) == 0 {
				continue
			}
			action := "investigate-correctness"
			severity := "BLOCKER"
			interpretation := "A required test or allocation check failed. Preserve evidence and investigate before starting; physical defect is not established."
			if !c.Required {
				severity = "WARNING"
				action = "collect-evidence"
				interpretation = "An ancillary check reported a failure. Review whether this capability is required by the intended workload; a physical defect is not established."
			}
			if strings.HasPrefix(c.CheckID, "A") {
				action = "confirm-allocation"
			}
			add("check-"+c.CheckID, c.CheckID, severity, c.Reason, interpretation, action, refs)
		} else if c.Status == model.Contaminated {
			add("check-"+c.CheckID, c.CheckID, "WARNING", c.Reason, "This result is not eligible for a healthy-range conclusion.", "idle-and-retest", c.EvidenceRefs)
		}
	}
	for _, o := range r.Observations {
		if o.Status != model.Pass && o.Status != model.Warning && o.Status != model.Fail {
			continue
		}
		name := field(o)
		switch name {
		case "row_remap_failure", "row_remap_pending", "retirement_pending":
			if value, known := booleanState(o.Value); known && value && r.Device != nil && o.ResourceID == r.Device.UUID {
				add(name, o.CheckID, "BLOCKER", "Reported "+name+" is active.", "Current maintenance state requires provider investigation; remaining lifetime and physical cause are unknown.", "provider-maintenance", []string{o.ID})
			}
		case "ecc_current":
			if value, known := booleanState(o.Value); known && !value && r.Device != nil && o.ResourceID == r.Device.UUID {
				add("ecc-disabled", "B01", "WARNING", "ECC is reported disabled.", "This scan cannot provide enabled-ECC protection or counter coverage; owned-buffer checks cover only exercised bytes.", "collect-evidence", []string{o.ID})
			}
		}
		if o.CheckID == "I03" && o.Status == model.Warning {
			add("container-exposure", "I03", "WARNING", o.Message, "Observed configuration exposure; host or workload compromise is not established.", "review-exposure", []string{o.ID})
		}
	}
	// A qualified pack is necessary but insufficient: all fixed-weight metrics
	// must match exact conditions, be checked, and pass mandatory evidence gates.
	qualified := p != nil && p.Match(*r) == nil && !r.Synthetic && !invalidEvidence
	if qualified {
		r.ReferenceID = p.ID
		r.ReferenceStatus = "QUALIFIED_MATCH"
		r.PerformanceJudgment = "INCOMPLETE"
		weighted := 0.0
		ratios := map[string]float64{}
		for _, method := range scoringMethods {
			weight := reference.Weights[method]
			chosen, refs, reason := metricCandidate(*r, p, method)
			if chosen == nil {
				add("measurement-ineligible-"+method, primaryCheck[method], "WARNING", reason, "This method is excluded from calibrated performance; preserve all samples and repeat or qualify the declared aggregation method.", "idle-and-retest", refs)
				continue
			}
			m, err := p.Metric(*chosen)
			if err != nil {
				continue
			}
			value, ok := Number(chosen.Value)
			if !ok || value <= 0 {
				continue
			}
			ratio := value / m.HealthyReference
			if !m.HigherIsBetter {
				ratio = m.HealthyReference / value
			}
			ratios[method] = ratio
			weighted += weight * math.Min(1, ratio)
			r.Coverage.PerformanceWeight += weight
			if value < m.HealthyLow || value > m.HealthyHigh {
				severity := "WARNING"
				interp := "Outside the qualified healthy envelope for this exact method. Repeat under comparable idle conditions; this is not a hardware-defect conclusion."
				if add("reference-"+method, chosen.CheckID, severity, fmt.Sprintf("%s measured %.5g %s; matched healthy range %.5g–%.5g; reference %s", method, value, chosen.Unit, m.HealthyLow, m.HealthyHigh, p.ID), interp, "idle-and-retest", []string{chosen.ID}) {
					r.Findings[len(r.Findings)-1].ReferenceID = p.ID
				}
			}
		}
		if len(ratios) == 5 && r.Coverage.PerformanceWeight == 100 {
			r.PerformanceJudgment = "CALIBRATED"
			r.Score = &weighted
		}
	} else if p != nil {
		r.ReferenceStatus = "INAPPLICABLE"
	}
	mandatoryMissing := false
	for _, c := range r.Checks {
		if c.Required && c.Status != model.Pass && c.Status != model.NotApplicable {
			mandatoryMissing = true
		}
	}
	if mandatoryMissing || r.Cancelled || r.Synthetic || invalidEvidence || len(r.Blockers) > 0 || r.ReferenceStatus != "QUALIFIED_MATCH" || r.PerformanceJudgment != "CALIBRATED" {
		r.Score = nil
		if r.PerformanceJudgment == "CALIBRATED" {
			r.PerformanceJudgment = "INCOMPLETE"
		}
	}
	if len(r.Blockers) > 0 {
		r.Verdict = model.DoNotStart
		r.NextAction = "Preserve this evidence and request investigation or correction of the failed allocation/test before starting work."
	} else if r.Score == nil {
		r.Verdict = model.Inconclusive
		r.NextAction = "Collect the named missing checks and a qualified reference for this exact configuration, then repeat the same scope."
	} else if len(r.Findings) > 0 || len(r.MissingChecks) > 0 {
		r.Verdict = model.KeepWithCaveats
		r.NextAction = "Review the specific limitations, confirm they are acceptable for the intended scope, and retest when conditions change."
	} else {
		r.Verdict = model.Keep
		r.NextAction = "Start only the workload/configuration covered by the completed checks; retain this report for comparison."
	}
	if r.ReferenceStatus != "QUALIFIED_MATCH" {
		refs := []string{}
		for _, o := range r.Observations {
			if o.CheckID == "A09" && o.MethodID == "reference.qualification" {
				refs = append(refs, o.ID)
			}
		}
		add("reference-required", "A09", "INFO", "No applicable qualified healthy-reference pack is available.", "Measurements and manufacturer specifications cannot substitute for a calibrated healthy operating envelope.", "qualify-reference", refs)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		priority := map[string]int{"BLOCKER": 0, "WARNING": 1, "INFO": 2}
		if priority[r.Findings[i].Severity] != priority[r.Findings[j].Severity] {
			return priority[r.Findings[i].Severity] < priority[r.Findings[j].Severity]
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	for _, f := range r.Findings {
		if len(r.Highlights) == 5 {
			break
		}
		r.Highlights = append(r.Highlights, model.Highlight{Text: f.Observation, Severity: f.Severity, FindingID: f.ID, EvidenceRefs: f.EvidenceRefs})
	}
	if len(r.Highlights) < 5 {
		for _, id := range []string{"B07", "B09", "A04"} {
			for _, c := range r.Checks {
				if c.CheckID == id && c.Status == model.Pass && len(c.EvidenceRefs) > 0 {
					r.Highlights = append(r.Highlights, model.Highlight{Text: c.Name + ": no failure observed within the recorded checked scope.", Severity: "PASS", EvidenceRefs: c.EvidenceRefs})
					break
				}
			}
			if len(r.Highlights) == 5 {
				break
			}
		}
	}
	r.VerdictScope = "One selected GPU and visible execution environment during this observation interval; no workload, cluster, authenticity or future-life certification."
}
