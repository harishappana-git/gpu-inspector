package advisory

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

// Evaluate emits exactly one A10 and one H04 observation. Source signatures
// authenticate the caller-selected pack, not its publisher's real-world identity,
// the measurement host or the device firmware. Unknowns never become mismatches.
func Evaluate(p *Pack, d *model.Device, observations []model.Observation, now time.Time) []model.Observation {
	resource := "selected-gpu"
	if d != nil {
		resource = d.UUID
	}
	base := func(check, method string) model.Observation {
		return model.Observation{CheckID: check, ResourceID: resource, MethodID: method, Version: SchemaVersion, StartUTC: now.UTC(), Status: model.NotTested, SourceKind: "signed-advisory-comparison", Visibility: "selected-device retained observations and explicitly trusted pack", Scope: resource, Message: "No explicitly trusted current advisory pack was supplied.", Conditions: map[string]any{"derived": true, "host_attestation": false, "official_vendor_identity_verified": false}}
	}
	oem, driver := base("A10", "advisory.oem_vbios"), base("H04", "advisory.driver_issue")
	out := []model.Observation{oem, driver}
	if p == nil {
		return out
	}
	canonical, err := json.Marshal(p)
	if err != nil || !p.authenticated || sha256.Sum256(canonical) != p.seal {
		for i := range out {
			out[i].Status = model.ToolError
			out[i].Message = "Advisory pack has not been signature-verified or changed after authentication."
		}
		return out
	}
	if err := p.Validate(now); err != nil {
		for i := range out {
			out[i].Status = model.ToolError
			out[i].Message = "Advisory pack is no longer applicable: " + err.Error()
		}
		return out
	}
	for i := range out {
		out[i].Conditions["pack_id"] = p.ID
		out[i].Conditions["pack_version"] = p.Version
		out[i].Conditions["pack_sha256"] = p.digest
		out[i].Conditions["trusted_key_sha256"] = p.keyDigest
		out[i].Conditions["publisher_assertion"] = p.Publisher
		out[i].Conditions["pack_issued_at"] = p.IssuedAt
		out[i].Conditions["pack_valid_until"] = p.ValidUntil
	}
	if d == nil || d.UUID == "" || d.SKU == "unknown" || !skuPattern.MatchString(d.SKU) {
		for i := range out {
			out[i].Message = "A selected device with an exact normalized SKU is required; no reference was substituted."
		}
		return out
	}
	out[0] = evaluateOEM(out[0], p, *d, observations)
	out[1] = evaluateDriver(out[1], p, *d, observations, now)
	return out
}

func evaluateOEM(o model.Observation, p *Pack, d model.Device, obs []model.Observation) model.Observation {
	part, partRefs, partOK := metadata(obs, d.UUID, []string{"part_number", "board.part_number"}, o.StartUTC)
	vbios, vbiosRefs, vbiosOK := metadata(obs, d.UUID, []string{"vbios", "vbios_version"}, o.StartUTC)
	o.EvidenceRefs = uniqueRefs(append(partRefs, vbiosRefs...))
	o.SampleCount = len(o.EvidenceRefs)
	if !partOK || !vbiosOK || !hardwareToken(part) || !hardwareToken(vbios) {
		o.Message = "Consistent retained board-part and VBIOS metadata are unavailable; OEM consistency is unknown. Missing or changed metadata does not establish modified firmware."
		return o
	}
	for _, entry := range p.OEM {
		if entry.SKU != d.SKU || normalizeHardware(entry.BoardPartNumber) != normalizeHardware(part) {
			continue
		}
		o.Conditions["source"] = entry.Source
		o.Conditions["entry_id"] = entry.ID
		o.Value = map[string]any{"sku": d.SKU, "board_part_number": part, "observed_vbios": vbios, "comparison": "unrecognized"}
		for _, known := range entry.VBIOSVersions {
			if normalizeHardware(known) == normalizeHardware(vbios) {
				o.Status = model.Pass
				o.Value.(map[string]any)["comparison"] = "known_version_match"
				o.Message = "Reported SKU, board part number and VBIOS version match an entry in the explicitly trusted signed pack. This is metadata agreement, not firmware attestation or proof the image is unmodified."
				return o
			}
		}
		o.Message = "Reported VBIOS version is not recognized for this exact SKU/board in the trusted pack. Coverage may be incomplete; no modified-firmware or counterfeit conclusion is made."
		return o
	}
	o.Message = "The trusted pack has no entry for the exact reported SKU and board part number; OEM/VBIOS consistency remains unknown."
	return o
}

func evaluateDriver(o model.Observation, p *Pack, d model.Device, obs []model.Observation, now time.Time) model.Observation {
	observed, refs, ok := metadata(obs, d.UUID, []string{"driver_version"}, now)
	driver, err := parseDriver(strings.TrimSpace(observed))
	declared, declaredErr := parseDriver(strings.TrimSpace(d.DriverVersion))
	o.EvidenceRefs = refs
	if !ok || err != nil || declaredErr != nil || compareDriver(driver, declared) != 0 {
		o.Message = "Consistent selected-device numeric driver metadata are unavailable; no exact driver advisory can be matched."
		return o
	}
	matches := []map[string]any{}
	for _, entry := range p.Driver {
		if entry.SKU != d.SKU {
			continue
		}
		minimum, _ := parseDriver(entry.DriverMin)
		maximum, _ := parseDriver(entry.DriverMax)
		if compareDriver(driver, minimum) < 0 || compareDriver(driver, maximum) > 0 {
			continue
		}
		symptomRefs := []string{}
		for _, evidence := range obs {
			if evidence.ID == "" || evidence.ResourceID != d.UUID || evidence.StartUTC.IsZero() || evidence.StartUTC.After(now) || strings.HasPrefix(evidence.MethodID, "advisory.") {
				continue
			}
			if !matchesSymptom(entry.Symptom, evidence) {
				continue
			}
			symptomRefs = append(symptomRefs, evidence.ID)
		}
		if len(symptomRefs) == 0 {
			continue
		}
		symptomRefs = uniqueRefs(symptomRefs)
		o.EvidenceRefs = append(o.EvidenceRefs, symptomRefs...)
		matches = append(matches, map[string]any{"entry_id": entry.ID, "sku": entry.SKU, "driver_min": entry.DriverMin, "driver_max": entry.DriverMax, "summary": entry.Summary, "source": entry.Source, "symptom": entry.Symptom, "symptom_evidence_refs": symptomRefs})
	}
	o.EvidenceRefs = uniqueRefs(o.EvidenceRefs)
	o.SampleCount = len(o.EvidenceRefs)
	o.Value = map[string]any{"driver_version": observed, "matches": matches, "no_match_is_clean_bill": false}
	if len(matches) == 0 {
		o.Message = "No current trusted entry matches this exact SKU, numeric driver range and retained explicit symptom together. This does not establish an issue-free driver; age or version alone is not a defect."
		return o
	}
	o.Status = model.Warning
	o.Conditions["sources"] = func() []Source {
		sources := []Source{}
		for _, m := range matches {
			sources = append(sources, m["source"].(Source))
		}
		return sources
	}()
	o.Message = "A current trusted advisory matches the exact SKU, driver range and an explicit retained symptom. Review the cited vendor/OEM source; the match is a possible documented explanation, not proven causality or a physical-GPU defect."
	return o
}

func matchesSymptom(selector Selector, o model.Observation) bool {
	if selector.CheckID != o.CheckID || selector.MethodID != o.MethodID || selector.Status != o.Status {
		return false
	}
	if selector.Field == "" {
		return true
	}
	var value any
	if o.Conditions["field"] == selector.Field {
		value = o.Value
	} else {
		v := reflect.ValueOf(o.Value)
		if !v.IsValid() || v.Kind() != reflect.Map || v.Type().Key().Kind() != reflect.String {
			return false
		}
		field := v.MapIndex(reflect.ValueOf(selector.Field).Convert(v.Type().Key()))
		if !field.IsValid() {
			return false
		}
		value = field.Interface()
	}
	expected, expectedOK := primitive(selector.Value)
	actual, actualOK := primitive(value)
	return expectedOK && actualOK && expected == actual
}

// A change or unavailable snapshot prevents opportunistically selecting an older
// passing value. Repeated matching pre/post snapshots are retained as references.
func metadata(obs []model.Observation, uuid string, fields []string, now time.Time) (string, []string, bool) {
	var value string
	refs := []string{}
	valid := true
	for _, o := range obs {
		if o.ResourceID != uuid {
			continue
		}
		field, _ := o.Conditions["field"].(string)
		matched := false
		for _, name := range fields {
			if field == name {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if o.ID != "" {
			refs = append(refs, o.ID)
		}
		current, ok := o.Value.(string)
		if o.ID == "" || o.Status != model.Pass || o.StartUTC.IsZero() || o.StartUTC.After(now) || !ok || strings.TrimSpace(current) == "" {
			valid = false
			continue
		}
		current = strings.TrimSpace(current)
		if value == "" {
			value = current
		} else if normalizeHardware(value) != normalizeHardware(current) {
			valid = false
		}
	}
	return value, uniqueRefs(refs), valid && value != ""
}

func uniqueRefs(refs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, ref := range refs {
		if ref != "" && !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out
}
