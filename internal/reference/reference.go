// Package reference admits only signed, qualified, exact-method measurements.
// No healthy measurements ship with the development source distribution.
package reference

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
	"math"
	"time"
)

type Metric struct {
	Method           string  `json:"method"`
	Unit             string  `json:"unit"`
	ConditionsHash   string  `json:"conditions_hash"`
	HealthyLow       float64 `json:"healthy_low"`
	HealthyHigh      float64 `json:"healthy_high"`
	HealthyReference float64 `json:"healthy_reference"`
	HigherIsBetter   bool    `json:"higher_is_better"`
}
type Pack struct {
	Kind                   string    `json:"kind"`
	ID                     string    `json:"reference_id"`
	Version                string    `json:"version"`
	SKU                    string    `json:"sku"`
	MIGMode                string    `json:"mig_mode"`
	VirtualizationMode     string    `json:"virtualization_mode"`
	DriverVersion          string    `json:"driver_version"`
	MethodVersion          string    `json:"method_version"`
	WorkerDigest           string    `json:"worker_digest"`
	Qualified              bool      `json:"qualified"`
	IndependentAllocations int       `json:"independent_allocations"`
	IndependentHosts       int       `json:"independent_hosts"`
	AcquiredAt             time.Time `json:"acquired_at"`
	ValidUntil             time.Time `json:"valid_until"`
	Approval               string    `json:"approval"`
	Provenance             []string  `json:"provenance"`
	Metrics                []Metric  `json:"metrics"`
}

func Load(path string, key ed25519.PublicKey, now time.Time) (*Pack, error) {
	data, err := bundle.ReadLimited(path, bundle.MaxDocumentBytes)
	if err != nil {
		return nil, err
	}
	payload, err := bundle.Verify(data, key)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err = bundle.Decode(payload, &p); err != nil {
		return nil, err
	}
	if err = p.Validate(now); err != nil {
		return nil, err
	}
	return &p, nil
}
func (p *Pack) Validate(now time.Time) error {
	if p.Kind != "gri-reference" || p.ID == "" || p.Version == "" || !p.Qualified {
		return errors.New("reference is not a qualified versioned GRI pack")
	}
	// These are authenticated acquisition assertions, not independent proof of
	// distinct physical rentals. Structured allocation/host provenance and its
	// reviewed measurement logs remain a release qualification requirement.
	if p.IndependentAllocations < 5 || p.IndependentHosts < 2 || p.IndependentHosts > p.IndependentAllocations || len(p.Provenance) < p.IndependentAllocations || p.Approval == "" {
		return errors.New("reference does not meet provisional acquisition and approval policy")
	}
	seen := map[string]bool{}
	for _, s := range p.Provenance {
		if s == "" || seen[s] {
			return errors.New("reference provenance is empty or duplicated")
		}
		seen[s] = true
	}
	if p.AcquiredAt.IsZero() || p.AcquiredAt.After(now) || !p.ValidUntil.After(now) || !p.ValidUntil.After(p.AcquiredAt) {
		return errors.New("reference is expired or has invalid acquisition dates")
	}
	if p.SKU == "" || p.MIGMode == "" || p.VirtualizationMode == "" || p.DriverVersion == "" || p.MethodVersion != model.MethodVersion || !hexDigest(p.WorkerDigest) {
		return errors.New("reference exact configuration is incomplete")
	}
	if len(p.Metrics) == 0 {
		return errors.New("qualified reference contains no metrics")
	}
	seen = map[string]bool{}
	for _, m := range p.Metrics {
		if seen[m.Method] || m.Method == "" || m.Unit == "" || !hexDigest(m.ConditionsHash) || !positive(m.HealthyLow) || !positive(m.HealthyHigh) || !positive(m.HealthyReference) || m.HealthyLow > m.HealthyReference || m.HealthyHigh < m.HealthyReference {
			return errors.New("invalid or duplicate reference metric")
		}
		seen[m.Method] = true
	}
	return nil
}
func positive(f float64) bool { return f > 0 && !math.IsNaN(f) && !math.IsInf(f, 0) }
func hexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
func (p *Pack) Match(r model.Report) error {
	if err := p.Validate(r.FinishedUTC); err != nil {
		return err
	}
	d := r.Device
	if d == nil {
		return errors.New("no selected device")
	}
	if d.SKU != p.SKU || d.MIGMode != p.MIGMode || d.VirtualizationMode != p.VirtualizationMode || d.DriverVersion != p.DriverVersion || r.MethodVersion != p.MethodVersion || r.WorkerDigest != p.WorkerDigest {
		return errors.New("reference SKU, mode, driver, worker or method does not exactly match")
	}
	return nil
}

// ConditionsHash binds every declared condition in this initial conservative
// key. Free-memory, seed or budget changes can prevent a match; there is no
// fallback that drops conditions to obtain a score. A future method-specific
// key requires versioned qualification of time/input/host/power comparability.
// Empty means serialization failed (for example NaN or an unsupported value),
// and must never become an eligible reference key. Timing/sample observations
// belong outside Conditions; no healthy reference ships with this source.
func ConditionsHash(conditions map[string]any) string {
	data, err := json.Marshal(conditions)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func (p *Pack) Metric(o model.Observation) (Metric, error) {
	hash := ConditionsHash(o.Conditions)
	if hash == "" {
		return Metric{}, errors.New("method conditions cannot be serialized into an eligible reference key")
	}
	for _, m := range p.Metrics {
		if m.Method == o.MethodID {
			if o.Version != p.MethodVersion || o.Unit != m.Unit || !hexDigest(m.ConditionsHash) || hash != m.ConditionsHash {
				return Metric{}, errors.New("numeric mode, shape, placement, power, duration or transfer method mismatch")
			}
			return m, nil
		}
	}
	return Metric{}, fmt.Errorf("no reference for method %s", o.MethodID)
}

var Weights = map[string]float64{"fp32_gemm": 10, "bf16_gemm": 30, "hbm_copy": 40, "h2d": 10, "d2h": 10}
