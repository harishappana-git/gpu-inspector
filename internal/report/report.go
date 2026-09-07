package report

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/privatefs"
)

type Options struct{ Ticket bool }

// Write creates private local reports. A ticket is generated when blockers are
// present. Use WriteWithOptions to explicitly request a ticket for another scan.
func Write(dir string, r model.Report) error { return WriteWithOptions(dir, r, Options{}) }

func WriteWithOptions(dir string, r model.Report, options Options) error {
	if err := validate(r); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	for _, name := range []string{"report.json", "report.html", "guide.md", "ticket.md", "evidence-index.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("retained artifact already exists: %s", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	artifacts := map[string][]byte{"guide.md": []byte(Guide(r))}
	r.ArtifactHashes = make(map[string]string)
	if _, err := os.Lstat(filepath.Join(dir, "evidence.jsonl")); err == nil {
		data, err := readPrivateFile(filepath.Join(dir, "evidence.jsonl"))
		if err != nil {
			return err
		}
		artifacts["evidence.jsonl"] = data
	} else if !os.IsNotExist(err) {
		return err
	}
	if options.Ticket || len(r.Blockers) > 0 || r.Verdict == model.DoNotStart {
		redacted, err := Redact(r)
		if err != nil {
			return err
		}
		artifacts["ticket.md"] = []byte(ticketText(redacted))
	}
	html, err := HTML(r)
	if err != nil {
		return err
	}
	artifacts["report.html"] = html
	for name, data := range artifacts {
		r.ArtifactHashes[name] = digest(data)
	}
	data, err := jsonBytes(r)
	if err != nil {
		return err
	}
	artifacts["report.json"] = data
	index := EvidenceIndex{SchemaVersion: "1.0.0", ScanID: r.ScanID, HashAlgorithm: "SHA-256", IntegrityBoundary: "Hashes cover listed bytes, excluding this index; integrity is not authenticity or host attestation."}
	for _, name := range sortedArtifactNames(artifacts) {
		contents := artifacts[name]
		index.Artifacts = append(index.Artifacts, Artifact{Name: name, SHA256: digest(contents), Bytes: int64(len(contents))})
		if name != "evidence.jsonl" {
			if err := publish(dir, name, contents); err != nil {
				return err
			}
		}
	}
	data, err = jsonBytes(index)
	if err != nil {
		return err
	}
	if err = publish(dir, "evidence-index.json", data); err != nil {
		return err
	}
	if err := privatefs.SyncDir(dir); err != nil {
		return err
	}
	return Verify(dir)
}

func Read(path string) (model.Report, error) {
	var r model.Report
	data, err := readPrivateFile(path)
	if err != nil {
		return r, err
	}
	if err = decodeJSON(data, &r); err != nil {
		return r, fmt.Errorf("read report: %w", err)
	}
	if err = validate(r); err != nil {
		return r, err
	}
	return r, nil
}

func validate(r model.Report) error {
	if r.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported report schema %q", r.SchemaVersion)
	}
	if r.ScanID == "" {
		return fmt.Errorf("report requires a scan ID")
	}
	switch r.Verdict {
	case model.Keep, model.KeepWithCaveats, model.DoNotStart, model.Inconclusive:
	default:
		return fmt.Errorf("unsupported verdict %q", r.Verdict)
	}
	if len(r.Highlights) > 5 {
		return fmt.Errorf("report contains more than five highlights")
	}
	if r.Score != nil && (math.IsNaN(*r.Score) || math.IsInf(*r.Score, 0)) {
		return fmt.Errorf("non-finite score")
	}
	evidence := map[string]model.Observation{}
	for _, o := range r.Observations {
		if o.ID == "" || o.MethodID == "" {
			return fmt.Errorf("observation requires an evidence ID and method")
		}
		if _, exists := evidence[o.ID]; exists {
			return fmt.Errorf("duplicate evidence ID %q", o.ID)
		}
		if !o.Status.Valid() {
			return fmt.Errorf("invalid evidence status %q", o.Status)
		}
		evidence[o.ID] = o
	}
	checkRefs := func(refs []string) error {
		for _, id := range refs {
			if _, exists := evidence[id]; !exists {
				return fmt.Errorf("unresolved evidence reference %q", id)
			}
		}
		return nil
	}
	findings := map[string]bool{}
	for _, finding := range r.Findings {
		if finding.ID == "" || findings[finding.ID] {
			return fmt.Errorf("missing or duplicate finding ID")
		}
		findings[finding.ID] = true
		if len(finding.EvidenceRefs) == 0 {
			return fmt.Errorf("finding %q has no evidence", finding.ID)
		}
		if err := checkRefs(finding.EvidenceRefs); err != nil {
			return err
		}
	}
	for _, h := range r.Highlights {
		if len(h.EvidenceRefs) == 0 {
			return fmt.Errorf("highlight has no supporting evidence")
		}
		if h.FindingID != "" && !findings[h.FindingID] {
			return fmt.Errorf("highlight refers to missing finding")
		}
		if err := checkRefs(h.EvidenceRefs); err != nil {
			return err
		}
	}
	for _, check := range r.Checks {
		if !check.Status.Valid() {
			return fmt.Errorf("invalid check status")
		}
		if err := checkRefs(check.EvidenceRefs); err != nil {
			return err
		}
	}
	return nil
}

func timestamp(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' || r == 127 || r >= 0x80 && r <= 0x9f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}
func anchor(s string) string { return "e-" + digest([]byte(s))[:16] }

func Terminal(r model.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "VERDICT: %s\nScope: %s | %s | %s\nObservation: %s to %s (%.3f seconds)\n", r.Verdict, r.ResourceScope, r.Tier, r.Profile, timestamp(r.StartedUTC), timestamp(r.FinishedUTC), r.ActualDurationSeconds)
	fmt.Fprintf(&b, "Fit: %s\nPerformance: %s | Reference: %s\n", r.VerdictScope, r.PerformanceJudgment, r.ReferenceStatus)
	if r.Score == nil {
		b.WriteString("Measured readiness score: withheld\n")
	} else {
		fmt.Fprintf(&b, "Measured readiness score: %.2f\n", *r.Score)
	}
	if r.Synthetic {
		b.WriteString("SYNTHETIC FIXTURE — not a real GPU measurement\n")
	}
	if r.Cancelled {
		b.WriteString("PARTIAL — scan cancelled; unfinished checks remain explicit\n")
	}
	b.WriteByte('\n')
	for i, h := range r.Highlights {
		if i >= 5 {
			break
		}
		fmt.Fprintf(&b, "%s: %s [evidence: %s]\n", h.Severity, h.Text, strings.Join(h.EvidenceRefs, ", "))
	}
	fmt.Fprintf(&b, "\nCoverage: %d/%d required checks completed; %d eligible\n", r.Coverage.Completed, r.Coverage.Required, r.Coverage.Eligible)
	for _, limitation := range r.Limitations {
		fmt.Fprintf(&b, "LIMITATION: %s\n", limitation)
	}
	if len(r.MissingChecks) > 0 {
		fmt.Fprintf(&b, "Missing checks: %s\n", strings.Join(r.MissingChecks, ", "))
	}
	fmt.Fprintf(&b, "NEXT: %s\n", r.NextAction)
	return plain(b.String())
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"utc": timestamp, "anchor": anchor,
	"json": func(v any) string {
		data, err := jsonBytes(v)
		if err != nil {
			return "value cannot be represented"
		}
		return string(data)
	},
	"join": strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>GPU Rental Inspector — {{.ScanID}}</title>
<style>body{font:16px/1.55 system-ui,sans-serif;margin:0;background:#f4f6fa;color:#182437}main{max-width:1150px;margin:auto;padding:32px 22px}header,section{background:white;padding:24px;margin:0 0 20px;border:1px solid #dce3ed;border-radius:12px}h1{font-size:1.6rem;margin:8px 0}h2{font-size:1.2rem}h3{font-size:1rem}a{color:#125c9f}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #dde3ec}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6fa;padding:12px}code{overflow-wrap:anywhere}.muted{color:#526075}.notice{border-left:4px solid #c26b14;padding-left:12px}.scroll{overflow-x:auto}li{margin:8px 0}dt{font-weight:600}dd{margin:0 0 10px;overflow-wrap:anywhere}.highlight{border-bottom:1px solid #dde3ec;padding:10px 0}@media print{body{background:white}section,header{break-inside:avoid;border-radius:0}main{padding:0}}</style></head>
<body><main><header><span class="muted">GPU RENTAL INSPECTOR · LOCAL REPORT · {{.ToolVersion}}</span><h1>{{.Verdict}}</h1>
{{if .Synthetic}}<p class="notice"><strong>SYNTHETIC FIXTURE — not a real GPU measurement.</strong></p>{{end}}
{{if .Cancelled}}<p class="notice">Partial report: scan was cancelled. Unfinished checks remain explicit.</p>{{end}}
<p><strong>Scope:</strong> {{.ResourceScope}} · {{.Tier}} · {{.Profile}}</p><p><strong>Fit:</strong> {{.VerdictScope}}</p>
<p><strong>Observation:</strong> {{utc .StartedUTC}} to {{utc .FinishedUTC}} · {{.ActualDurationSeconds}} seconds</p>
<p><strong>Measured readiness score:</strong> {{if .Score}}{{.Score}}{{else}}withheld{{end}} · <strong>Performance:</strong> {{.PerformanceJudgment}} · <strong>Reference:</strong> {{.ReferenceStatus}}</p>
{{range .Highlights}}<div class="highlight"><strong>{{.Severity}}:</strong> {{.Text}} <span class="muted">Evidence: {{range .EvidenceRefs}}<a href="#{{anchor .}}">{{.}}</a> {{end}}</span></div>{{end}}
<p><strong>Next action:</strong> {{.NextAction}}</p><p class="muted">Identity readings are scoped observations; report integrity is not host attestation. No fault observed is not proof of future health.</p></header>
<section><h2>Coverage and limitations</h2><p>{{.Coverage.Completed}} / {{.Coverage.Required}} required checks completed; {{.Coverage.Eligible}} eligible. Performance weight tested: {{.Coverage.PerformanceWeight}} / {{.Coverage.RequiredPerformanceWeight}}.</p>
{{if .Blockers}}<h3>Blockers</h3><ul>{{range .Blockers}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .MissingChecks}}<h3>Missing checks</h3><ul>{{range .MissingChecks}}<li>{{.}}</li>{{end}}</ul>{{end}}
<ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
{{if .Device}}<h3>Selected allocation</h3><dl><dt>Reported device</dt><dd>{{.Device.Name}} · {{.Device.SKU}}</dd><dt>Selected identifier</dt><dd>{{.Device.UUID}} · {{.Device.PCIAddress}}</dd><dt>Visibility and identity assurance</dt><dd>{{.Device.Source}} · {{.Device.IdentityAssurance}}</dd><dt>Configuration</dt><dd>MIG: {{.Device.MIGMode}} · virtualization: {{.Device.VirtualizationMode}} · driver: {{.Device.DriverVersion}}</dd></dl>{{end}}
{{if .Price}}<h3>User-declared price context</h3><p>{{.Price.PerHour}} {{.Price.Currency}} per hour. Source: {{.Price.Source}}. {{.Price.EquivalenceScope}}</p>{{if .Price.ScanCost}}<p>Observed scan-duration rental cost: {{.Price.ScanCost}} {{.Price.Currency}}.</p>{{end}}{{end}}
</section><section><h2>Check results</h2><div class="scroll"><table><thead><tr><th>Check</th><th>Status</th><th>Observed scope / reason</th><th>Fallback and evidence</th></tr></thead><tbody>
{{range .Checks}}<tr><td>{{.CheckID}} — {{.Name}}<br>{{.Stage}}{{if .Required}} · required{{end}}</td><td>{{.Status}}</td><td>{{.Reason}}</td><td>{{.Fallback}}<br>{{range .EvidenceRefs}}<a href="#{{anchor .}}">{{.}}</a> {{end}}</td></tr>{{end}}</tbody></table></div></section>
<section><h2>Findings and interpretation</h2>{{range .Findings}}<article><h3>{{.ID}} · {{.Severity}}</h3><dl><dt>Observed fact</dt><dd>{{.Observation}}</dd><dt>Interpretation</dt><dd>{{.Interpretation}}</dd><dt>Alternative explanations</dt><dd>{{join .AlternativeCauses "; "}}</dd><dt>Evidence strength</dt><dd>Observation: {{.ObservationStrength}} · cause: {{.CauseStrength}}</dd><dt>Impact and basis</dt><dd>{{.Impact}} · {{.ImpactBasis}}</dd><dt>Reference</dt><dd>{{if .ReferenceID}}{{.ReferenceID}}{{else}}No applicable qualified comparison supplied{{end}}</dd><dt>Safe action / retest</dt><dd>{{.ActionID}} / {{.RetestID}}</dd><dt>Rule and supporting evidence</dt><dd>{{.RuleVersion}} · {{range .EvidenceRefs}}<a href="#{{anchor .}}">{{.}}</a> {{end}}</dd></dl></article>{{else}}<p>No evidence-backed finding was generated.</p>{{end}}</section>
<section><h2>Evidence and methods</h2>{{range .Observations}}<article id="{{anchor .ID}}"><h3>{{.ID}} · {{.Status}}</h3><p>{{.CheckID}} · {{.MethodID}} · version {{.Version}} · {{.SourceKind}} · {{.Visibility}}</p><p>{{utc .StartUTC}} · {{.DurationMS}} ms monotonic duration · {{.SampleCount}} samples · scope {{.Scope}}</p><p>{{.Message}}</p><details><summary>Normalized value, unit and conditions</summary><pre>{{json .Value}}</pre><p>Unit: {{.Unit}}{{if .Spread}} · spread: {{.Spread}}{{end}}</p><pre>{{json .Conditions}}</pre></details></article>{{end}}</section>
<section><h2>Audit trail</h2><p>Scan {{.ScanID}}{{if .OriginalScanID}} · original scan {{.OriginalScanID}}{{end}} · schema {{.SchemaVersion}} · rule {{.RuleVersion}} · methods {{.MethodVersion}}</p><p>Reference {{.ReferenceID}} / {{.ReferenceStatus}} · worker digest {{.WorkerDigest}} · recorded seed {{.Seed}}</p><p>Budget {{.BudgetSeconds}} seconds. Installation duration: {{if .InstallationDurationSeconds}}{{.InstallationDurationSeconds}} seconds{{else}}not recorded; excluded from scan duration{{end}}.</p><p>Artifact hashes are recorded in evidence-index.json. Run <code>gri verify --report-dir DIR</code> before sharing. Hashes detect changed bytes; they do not authenticate an untrusted host. The local guide and any ticket are drafts; no provider request has been sent.</p></section>
</main></body></html>`))

func HTML(r model.Report) ([]byte, error) {
	if err := validate(r); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := htmlTemplate.Execute(&b, r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
