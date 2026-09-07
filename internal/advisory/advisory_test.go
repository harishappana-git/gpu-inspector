package advisory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
)

var fixtureNow = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

const fixtureUUID = "GPU-00000000-0000-0000-0000-000000000001"

// Every advisory, part, VBIOS and driver condition below is synthetic test data.
// The example.invalid source is deliberately not an actual vendor publication.
func fixturePack() Pack {
	source := Source{URL: "https://example.invalid/synthetic-advisory", Title: "Synthetic fixture; no vendor or production assertion", PublishedAt: fixtureNow.Add(-48 * time.Hour)}
	return Pack{Kind: "gri-advisory", SchemaVersion: SchemaVersion, ID: "synthetic-test-only", Version: "fixture-1", Publisher: "Synthetic test publisher; not vendor data", IssuedAt: fixtureNow.Add(-24 * time.Hour), ValidUntil: fixtureNow.Add(24 * time.Hour),
		OEM:    []OEMEntry{{ID: "synthetic-oem", SKU: "h100-pcie-80gb", BoardPartNumber: "TEST-BOARD-A", VBIOSVersions: []string{"96.00.AA.00.01"}, Source: source}},
		Driver: []DriverEntry{{ID: "synthetic-driver", SKU: "h100-pcie-80gb", DriverMin: "535.90", DriverMax: "535.130", Symptom: Selector{CheckID: "B06", MethodID: "linux.xid", Status: model.Warning, Field: "xid_code", Value: json.Number("43")}, Summary: "Synthetic matcher fixture only; this is not a documented NVIDIA driver issue.", Source: source}},
	}
}

func fixtureDevice() model.Device {
	return model.Device{UUID: fixtureUUID, SKU: "h100-pcie-80gb", DriverVersion: "535.104.05"}
}
func fixtureObservations() []model.Observation {
	field := func(id, name string, value any) model.Observation {
		return model.Observation{ID: id, CheckID: "A10", MethodID: "nvml." + name, Version: model.MethodVersion, ResourceID: fixtureUUID, StartUTC: fixtureNow.Add(-time.Minute), Status: model.Pass, Value: value, Conditions: map[string]any{"field": name}, SourceKind: "synthetic-test-fixture"}
	}
	return []model.Observation{field("board-1", "part_number", "TEST-BOARD-A"), field("vbios-1", "vbios", "96.00.AA.00.01"), field("driver-1", "driver_version", "535.104.05"),
		{ID: "symptom-1", CheckID: "B06", MethodID: "linux.xid", Version: model.MethodVersion, ResourceID: fixtureUUID, StartUTC: fixtureNow.Add(-30 * time.Second), Status: model.Warning, Value: map[string]any{"xid_code": uint64(43)}, SourceKind: "synthetic-test-fixture"},
	}
}

func loadPayload(t *testing.T, payload []byte) (*Pack, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Sign(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic-pack.json")
	if err := os.WriteFile(path, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path, pub, fixtureNow)
}
func loadFixture(t *testing.T, p Pack) *Pack {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPayload(t, data)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestSignedExactMatchesRetainSourcesAndEvidence(t *testing.T) {
	p := loadFixture(t, fixturePack())
	device := fixtureDevice()
	obs := fixtureObservations()
	// Repeated matching snapshots remain separate evidence, not ambiguity.
	post := obs[1]
	post.ID = "vbios-2"
	post.StartUTC = fixtureNow.Add(-time.Second)
	obs = append(obs, post)
	results := Evaluate(p, &device, obs, fixtureNow)
	if len(results) != 2 || results[0].Status != model.Pass || results[1].Status != model.Warning {
		t.Fatalf("exact signed matches failed: %+v", results)
	}
	if results[0].Value.(map[string]any)["comparison"] != "known_version_match" || len(results[0].EvidenceRefs) != 3 {
		t.Fatalf("OEM provenance lost: %+v", results[0])
	}
	for _, o := range results {
		if o.ResourceID != fixtureUUID || o.Conditions["pack_id"] != p.ID || len(o.Conditions["pack_sha256"].(string)) != 64 || len(o.Conditions["trusted_key_sha256"].(string)) != 64 {
			t.Fatalf("signature provenance missing: %+v", o)
		}
		if o.Conditions["official_vendor_identity_verified"] != false || o.Conditions["host_attestation"] != false {
			t.Fatal("signature inflated into vendor/host attestation")
		}
	}
	matches := results[1].Value.(map[string]any)["matches"].([]map[string]any)
	if len(matches) != 1 || matches[0]["source"].(Source).URL != p.Driver[0].Source.URL || len(matches[0]["symptom_evidence_refs"].([]string)) != 1 {
		t.Fatal("driver source/symptom references missing")
	}
}

func TestOEMUnknownNeverMeansModifiedOrMismatchedFirmware(t *testing.T) {
	for name, change := range map[string]func(*model.Device, []model.Observation) []model.Observation{
		"unrecognized version": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[1].Value = "96.00.AA.00.FF"
			return o
		},
		"unrecognized board": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[0].Value = "TEST-BOARD-B"
			return o
		},
		"unavailable VBIOS": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[1].Status = model.Unsupported
			o[1].Value = nil
			return o
		},
		"another resource": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[1].ResourceID = "different-device"
			return o
		},
		"unretained metadata": func(_ *model.Device, o []model.Observation) []model.Observation { o[1].ID = ""; return o },
		"changed snapshot": func(_ *model.Device, o []model.Observation) []model.Observation {
			x := o[1]
			x.ID = "later-vbios"
			x.Value = "96.00.AA.00.FF"
			return append(o, x)
		},
		"different SKU": func(d *model.Device, o []model.Observation) []model.Observation { d.SKU = "rtx-5080-16gb"; return o },
	} {
		t.Run(name, func(t *testing.T) {
			d := fixtureDevice()
			o := change(&d, fixtureObservations())
			result := Evaluate(loadFixture(t, fixturePack()), &d, o, fixtureNow)[0]
			if result.Status != model.NotTested {
				t.Fatalf("unknown inferred as judgment: %+v", result)
			}
		})
	}
}

func TestDriverRequiresExactRangeSKUAndStructuredObservedSymptom(t *testing.T) {
	for name, change := range map[string]func(*model.Device, []model.Observation) []model.Observation{
		"old driver alone": func(d *model.Device, o []model.Observation) []model.Observation {
			d.DriverVersion = "535.89"
			o[2].Value = d.DriverVersion
			return o
		},
		"new driver outside range": func(d *model.Device, o []model.Observation) []model.Observation {
			d.DriverVersion = "535.131"
			o[2].Value = d.DriverVersion
			return o
		},
		"ambiguous driver text": func(d *model.Device, o []model.Observation) []model.Observation {
			d.DriverVersion = "535.104-beta"
			o[2].Value = d.DriverVersion
			return o
		},
		"driver snapshot changed": func(_ *model.Device, o []model.Observation) []model.Observation {
			x := o[2]
			x.ID = "new-driver"
			x.Value = "535.105"
			return append(o, x)
		},
		"wrong SKU": func(d *model.Device, o []model.Observation) []model.Observation { d.SKU = "h100-sxm-80gb"; return o },
		"wrong GPU symptom": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[3].ResourceID = "different-device"
			return o
		},
		"wrong method": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[3].MethodID = "unrelated.warning"
			return o
		},
		"wrong check":  func(_ *model.Device, o []model.Observation) []model.Observation { o[3].CheckID = "B11"; return o },
		"wrong status": func(_ *model.Device, o []model.Observation) []model.Observation { o[3].Status = model.Pass; return o },
		"message substring only": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[3].Message = "xid_code 43"
			o[3].Value = map[string]any{"xid_code": 44}
			return o
		},
		"numeric string not code": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[3].Value = map[string]any{"xid_code": "43"}
			return o
		},
		"future symptom": func(_ *model.Device, o []model.Observation) []model.Observation {
			o[3].StartUTC = fixtureNow.Add(time.Minute)
			return o
		},
		"missing symptom evidence ID": func(_ *model.Device, o []model.Observation) []model.Observation { o[3].ID = ""; return o },
	} {
		t.Run(name, func(t *testing.T) {
			d := fixtureDevice()
			o := change(&d, fixtureObservations())
			r := Evaluate(loadFixture(t, fixturePack()), &d, o, fixtureNow)[1]
			if r.Status != model.NotTested {
				t.Fatalf("unmatched advisory inferred: %+v", r)
			}
		})
	}
}

func TestDriverRangeUsesNumericComponentsAndInclusiveBounds(t *testing.T) {
	for _, v := range []string{"535.90", "535.090.0", "535.104.05", "535.130.0.0"} {
		d := fixtureDevice()
		d.DriverVersion = v
		o := fixtureObservations()
		o[2].Value = v
		if r := Evaluate(loadFixture(t, fixturePack()), &d, o, fixtureNow)[1]; r.Status != model.Warning {
			t.Fatalf("numeric in-range version %s rejected: %+v", v, r)
		}
	}
}

func TestStrictPackSchemaAndSourceRejections(t *testing.T) {
	for name, change := range map[string]func(*Pack){
		"wrong kind":                   func(p *Pack) { p.Kind = "reference" },
		"wrong schema":                 func(p *Pack) { p.SchemaVersion = "2.0.0" },
		"missing publisher":            func(p *Pack) { p.Publisher = "" },
		"expired":                      func(p *Pack) { p.ValidUntil = fixtureNow },
		"future issue":                 func(p *Pack) { p.IssuedAt = fixtureNow.Add(time.Hour) },
		"future source":                func(p *Pack) { p.Driver[0].Source.PublishedAt = fixtureNow },
		"undated source":               func(p *Pack) { p.OEM[0].Source.PublishedAt = time.Time{} },
		"missing source":               func(p *Pack) { p.Driver[0].Source.URL = "" },
		"insecure source":              func(p *Pack) { p.Driver[0].Source.URL = "http://example.invalid/source" },
		"credential source":            func(p *Pack) { p.Driver[0].Source.URL = "https://user:secret@example.invalid/source" },
		"source query":                 func(p *Pack) { p.Driver[0].Source.URL = "https://example.invalid/source?token=secret" },
		"unknown SKU":                  func(p *Pack) { p.Driver[0].SKU = "unknown" },
		"noncanonical SKU":             func(p *Pack) { p.Driver[0].SKU = "H100 PCIe" },
		"duplicate ID":                 func(p *Pack) { p.Driver[0].ID = p.OEM[0].ID },
		"duplicate OEM board":          func(p *Pack) { o := p.OEM[0]; o.ID = "another-oem"; p.OEM = append(p.OEM, o) },
		"duplicate normalized VBIOS":   func(p *Pack) { p.OEM[0].VBIOSVersions = append(p.OEM[0].VBIOSVersions, "96.00.aa.00.01") },
		"unknown VBIOS asserted known": func(p *Pack) { p.OEM[0].VBIOSVersions = []string{"UNKNOWN"} },
		"no entries":                   func(p *Pack) { p.OEM = nil; p.Driver = nil },
		"too many entries": func(p *Pack) {
			for i := 0; i < MaxEntries; i++ {
				p.Driver = append(p.Driver, p.Driver[0])
			}
		},
		"reversed range":          func(p *Pack) { p.Driver[0].DriverMin = "536.0" },
		"non-numeric range":       func(p *Pack) { p.Driver[0].DriverMax = "latest" },
		"incomplete range":        func(p *Pack) { p.Driver[0].DriverMin = "" },
		"age only status":         func(p *Pack) { p.Driver[0].Symptom.Status = model.Pass },
		"missing explicit method": func(p *Pack) { p.Driver[0].Symptom.MethodID = "" },
		"field without value":     func(p *Pack) { p.Driver[0].Symptom.Value = nil },
		"value without field":     func(p *Pack) { p.Driver[0].Symptom.Field = "" },
		"complex selector value":  func(p *Pack) { p.Driver[0].Symptom.Value = []int{43} },
		"unbounded exponent":      func(p *Pack) { p.Driver[0].Symptom.Value = json.Number("1e999999999") },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixturePack()
			change(&p)
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadPayload(t, data); err == nil {
				t.Fatal("invalid signed pack accepted")
			}
		})
	}

	for _, payload := range []string{
		`{"kind":"gri-advisory","kind":"gri-advisory"}`,
		`{"kind":"gri-advisory","\u006bind":"gri-advisory"}`,
		`{"unrecognized_topology":true}`,
	} {
		if _, err := loadPayload(t, []byte(payload)); err == nil {
			t.Fatal("ambiguous/unknown schema accepted")
		}
	}
	p := fixturePack()
	data, _ := json.Marshal(p)
	data = []byte(strings.Replace(string(data), `"summary":`, `"extra":true,"summary":`, 1))
	if _, err := loadPayload(t, data); err == nil {
		t.Fatal("unknown nested entry field accepted")
	}
}

func TestSignatureTrustMutationAndExpiryBoundaries(t *testing.T) {
	d := fixtureDevice()
	o := fixtureObservations()
	raw := fixturePack()
	if r := Evaluate(&raw, &d, o, fixtureNow); r[0].Status != model.ToolError || r[1].Status != model.ToolError {
		t.Fatal("unsigned in-memory pack treated as authenticated")
	}
	p := loadFixture(t, raw)
	p.Driver[0].Summary = "Changed after signature verification"
	if r := Evaluate(p, &d, o, fixtureNow); r[0].Status != model.ToolError || r[1].Status != model.ToolError {
		t.Fatal("post-authentication mutation accepted")
	}
	p = loadFixture(t, raw)
	if r := Evaluate(p, &d, o, raw.ValidUntil); r[0].Status != model.ToolError || r[1].Status != model.ToolError {
		t.Fatal("expired authenticated pack accepted")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := json.Marshal(raw)
	signed, _ := bundle.Sign(payload, priv)
	path := filepath.Join(t.TempDir(), "pack.json")
	if err := os.WriteFile(path, signed, 0600); err != nil {
		t.Fatal(err)
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Load(path, wrong, fixtureNow); err == nil {
		t.Fatal("untrusted signing key accepted")
	}
	var envelope bundle.Envelope
	_ = json.Unmarshal(signed, &envelope)
	envelope.Payload = "e30="
	changed, _ := json.Marshal(envelope)
	_ = os.WriteFile(path, changed, 0600)
	if _, err := Load(path, pub, fixtureNow); err == nil {
		t.Fatal("changed signed payload accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadContext(ctx, "missing-pack", pub, fixtureNow); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancellation not respected: %v", err)
	}
}

func TestPrimitiveSymptomsPreserveExactIntegersAndScalarFields(t *testing.T) {
	selector := Selector{CheckID: "B06", MethodID: "linux.xid", Status: model.Warning, Field: "xid_code", Value: json.Number("9007199254740993")}
	o := fixtureObservations()[3]
	o.Value = map[string]uint64{"xid_code": 9007199254740993}
	if !matchesSymptom(selector, o) {
		t.Fatal("exact uint64 structured symptom did not match")
	}
	o.Value = map[string]uint64{"xid_code": 9007199254740992}
	if matchesSymptom(selector, o) {
		t.Fatal("one-error difference rounded away")
	}
	selector.Value = true
	o.Conditions = map[string]any{"field": "xid_code"}
	o.Value = true
	if !matchesSymptom(selector, o) {
		t.Fatal("scalar typed field not matched")
	}
	selector.Value = "explicit-code"
	o.Value = "explicit-code"
	if !matchesSymptom(selector, o) {
		t.Fatal("exact string symptom not matched")
	}
	o.Value = "prefix-explicit-code-suffix"
	if matchesSymptom(selector, o) {
		t.Fatal("substring symptom accepted")
	}
}
