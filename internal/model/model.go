// Package model defines the versioned evidence contract shared by collectors,
// isolated workers, deterministic rules, and local reports.
package model

import "time"

const SchemaVersion = "1.0.0"
const ToolVersion = "0.1.0-dev"
const RuleVersion = "1.0.0"
const MethodVersion = "1.0.0"

type Status string

const (
	Pass                Status = "PASS"
	Fail                Status = "FAIL"
	Warning             Status = "WARNING"
	NotTested           Status = "NOT_TESTED"
	Unsupported         Status = "UNSUPPORTED"
	PermissionDenied    Status = "PERMISSION_DENIED"
	DependencyMissing   Status = "DEPENDENCY_MISSING"
	TimeBudgetExhausted Status = "TIME_BUDGET_EXHAUSTED"
	Contaminated        Status = "CONTAMINATED"
	ToolError           Status = "TOOL_ERROR"
	NotApplicable       Status = "NOT_APPLICABLE"
)

type Device struct {
	UUID               string `json:"uuid"`
	PCIAddress         string `json:"pci_address"`
	Index              int    `json:"index"`
	Name               string `json:"name"`
	SKU                string `json:"sku"`
	MemoryBytes        uint64 `json:"memory_bytes"`
	MIGMode            string `json:"mig_mode"`
	VirtualizationMode string `json:"virtualization_mode"`
	DriverVersion      string `json:"driver_version"`
	Source             string `json:"source"`
	IdentityAssurance  string `json:"identity_assurance"`
}

// Observation preserves absence as a status, never as a numeric zero. Value
// contains only allowlisted, normalized data; raw logs and environment are not
// part of this interchange format. IDs are assigned by the evidence journal.
type Observation struct {
	ID           string         `json:"measurement_id"`
	CheckID      string         `json:"check_id"`
	ResourceID   string         `json:"resource_id"`
	MethodID     string         `json:"method_id"`
	Version      string         `json:"version"`
	StartUTC     time.Time      `json:"start_utc"`
	DurationMS   float64        `json:"duration_monotonic_ms"`
	Status       Status         `json:"status"`
	Value        any            `json:"value,omitempty"`
	Unit         string         `json:"unit,omitempty"`
	SampleCount  int            `json:"sample_count"`
	Spread       *float64       `json:"spread,omitempty"`
	Conditions   map[string]any `json:"conditions,omitempty"`
	SourceKind   string         `json:"source_kind"`
	Visibility   string         `json:"visibility"`
	Scope        string         `json:"scope"`
	Message      string         `json:"message"`
	EvidenceRefs []string       `json:"evidence_refs,omitempty"`
}

type Check struct {
	ID       string `json:"id"`
	Stage    string `json:"stage"`
	Name     string `json:"name"`
	Method   string `json:"method"`
	Boundary string `json:"boundary"`
}

type CheckResult struct {
	CheckID      string   `json:"check_id"`
	Name         string   `json:"name"`
	Stage        string   `json:"stage"`
	Required     bool     `json:"required"`
	Status       Status   `json:"status"`
	Reason       string   `json:"reason"`
	Fallback     string   `json:"fallback"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type Finding struct {
	ID                  string   `json:"finding_id"`
	RuleVersion         string   `json:"rule_version"`
	CheckID             string   `json:"check_id"`
	Severity            string   `json:"severity"`
	Observation         string   `json:"observation"`
	Interpretation      string   `json:"interpretation"`
	AlternativeCauses   []string `json:"alternative_causes"`
	ObservationStrength string   `json:"observation_strength"`
	CauseStrength       string   `json:"cause_strength"`
	ReferenceID         string   `json:"reference_id,omitempty"`
	Impact              string   `json:"impact"`
	ImpactBasis         string   `json:"impact_basis"`
	ActionID            string   `json:"action_id"`
	RetestID            string   `json:"retest_id"`
	EvidenceRefs        []string `json:"evidence_refs"`
}

type Highlight struct {
	Text         string   `json:"text"`
	Severity     string   `json:"severity"`
	FindingID    string   `json:"finding_id,omitempty"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type Coverage struct {
	Required                  int     `json:"required"`
	Completed                 int     `json:"completed"`
	Eligible                  int     `json:"eligible"`
	Fraction                  float64 `json:"fraction"`
	PerformanceWeight         float64 `json:"tested_eligible_performance_weight"`
	RequiredPerformanceWeight float64 `json:"required_performance_weight"`
}

type Price struct {
	PerHour                    float64  `json:"per_hour"`
	Currency                   string   `json:"currency"`
	Source                     string   `json:"source"`
	ScanCost                   *float64 `json:"scan_cost,omitempty"`
	ReferenceEquivalentPerHour *float64 `json:"reference_equivalent_per_hour,omitempty"`
	EquivalenceScope           string   `json:"equivalence_scope,omitempty"`
}

type Report struct {
	SchemaVersion               string            `json:"schema_version"`
	ToolVersion                 string            `json:"tool_version"`
	RuleVersion                 string            `json:"rule_version"`
	MethodVersion               string            `json:"method_version"`
	ScanID                      string            `json:"scan_id"`
	OriginalScanID              string            `json:"original_scan_id,omitempty"`
	ResourceScope               string            `json:"resource_scope"`
	Device                      *Device           `json:"device,omitempty"`
	ExpectedSKU                 string            `json:"expected_sku,omitempty"`
	Profile                     string            `json:"profile"`
	Tier                        string            `json:"tier"`
	BudgetSeconds               float64           `json:"budget_seconds"`
	ActualDurationSeconds       float64           `json:"actual_duration_seconds"`
	InstallationDurationSeconds *float64          `json:"installation_duration_seconds"`
	StartedUTC                  time.Time         `json:"started_utc"`
	FinishedUTC                 time.Time         `json:"finished_utc"`
	Verdict                     string            `json:"verdict"`
	VerdictScope                string            `json:"verdict_scope"`
	PerformanceJudgment         string            `json:"performance_judgment"`
	Score                       *float64          `json:"score_or_null"`
	Coverage                    Coverage          `json:"coverage"`
	Blockers                    []string          `json:"blockers"`
	Highlights                  []Highlight       `json:"highlights"`
	MissingChecks               []string          `json:"missing_checks"`
	Checks                      []CheckResult     `json:"checks"`
	Findings                    []Finding         `json:"findings"`
	Observations                []Observation     `json:"observations"`
	Limitations                 []string          `json:"limitations"`
	NextAction                  string            `json:"next_action"`
	ReferenceID                 string            `json:"reference_id,omitempty"`
	ReferenceStatus             string            `json:"reference_status"`
	WorkerDigest                string            `json:"worker_digest,omitempty"`
	Seed                        uint64            `json:"seed"`
	Price                       *Price            `json:"price,omitempty"`
	ArtifactHashes              map[string]string `json:"artifact_hashes"`
	Cancelled                   bool              `json:"cancelled"`
	Synthetic                   bool              `json:"synthetic"`
}

const (
	Keep            = "KEEP"
	KeepWithCaveats = "KEEP WITH CAVEATS"
	DoNotStart      = "DO NOT START / REQUEST FIX OR REPLACEMENT"
	Inconclusive    = "INCONCLUSIVE"
)

func (s Status) Valid() bool {
	switch s {
	case Pass, Fail, Warning, NotTested, Unsupported, PermissionDenied, DependencyMissing, TimeBudgetExhausted, Contaminated, ToolError, NotApplicable:
		return true
	}
	return false
}
