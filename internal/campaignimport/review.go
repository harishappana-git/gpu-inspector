package campaignimport

import (
	"bytes"
	"html/template"
)

var indexTemplate = template.Must(template.New("campaign-review").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Imported H100 campaign</title><style>body{font:16px system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.5}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.7rem;border-bottom:1px solid #ddd}.notice{padding:1rem;background:#fff4d5}code{overflow-wrap:anywhere}</style></head><body>
<h1>Imported H100 campaign</h1><p>Campaign: <strong>{{.CampaignID}}</strong></p>
<p class="notice">{{.IntegrityBoundary}} All results remain development evidence. Import does not establish release qualification.</p>
<p>{{.FileCount}} archived files passed the campaign hash checks. {{len .Reports}} report directories passed their evidence-index checks. These views were rendered locally from validated report data.</p>
<table><thead><tr><th>Run</th><th>Reported verdict</th><th>Scope</th><th>Local review</th></tr></thead><tbody>
{{range .Reports}}<tr><td>{{.Run}}</td><td>{{.Verdict}}</td><td>{{if .Synthetic}}Synthetic fixture; not hardware evidence{{else}}Server-reported observations; host authenticity not established{{end}}</td><td><a href="review/{{.Run}}.html">Open locally rendered report</a></td></tr>{{else}}<tr><td colspan="4">No complete report was present. Review the retained failure status and remaining checklist.</td></tr>{{end}}
</tbody></table><p><a href="campaign-status.json">Campaign status</a> · <a href="remaining-checklist.txt">Remaining checklist</a> · <a href="campaign-manifest.json">Archived artifact hashes</a></p>
<p>Original server report HTML is retained as evidence; these review links use the local renderer.</p><p>Archive SHA-256: <code>{{.ArchiveSHA256}}</code></p></body></html>`))

func writeIndex(tree *ownedTree, result Result) error {
	var out bytes.Buffer
	if err := indexTemplate.Execute(&out, result); err != nil {
		return err
	}
	return tree.write(result.IndexPath, out.Bytes())
}
