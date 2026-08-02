// Package scanner provides report export in JSON, SARIF, and HTML formats.
package scanner

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ExportFormat specifies the report output format.
type ExportFormat int

const (
	FormatJSON ExportFormat = iota
	FormatSARIF
	FormatHTML
)

// ExportResult holds exported report bytes.
type ExportResult struct {
	Format ExportFormat
	Bytes  []byte
	Error  error
}

// Report represents a full scan report.
type Report struct {
	GeneratedAt      time.Time  `json:"generated_at"`
	Scope            string     `json:"scope"`
	TotalExchanges   int        `json:"total_exchanges"`
	ScannedExchanges int        `json:"scanned_exchanges"`
	Findings         []*Finding `json:"findings"`
	PassiveCoverage  string     `json:"passive_coverage"`
	ActiveSummary    string     `json:"active_summary"`
}

// SARIF types
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     sarifDesc   `json:"shortDescription"`
	FullDescription      sarifDesc   `json:"fullDescription"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}
type sarifDesc struct {
	Text string `json:"text"`
}
type sarifConfig struct {
	Level string `json:"level"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}
type sarifPhysLoc struct {
	ArtifactLocation sarifArtLoc `json:"artifactLocation"`
	Region           sarifRegion `json:"region"`
}
type sarifArtLoc struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// Export exports the current findings in the requested format.
func (s *ActiveScanner) Export(e ExportFormat, scope *core.Scope) *ExportResult {
	s.findingsMu.RLock()
	findings := make([]*Finding, len(s.findings))
	copy(findings, s.findings)
	s.findingsMu.RUnlock()

	_, totalEx := s.store.Count()

	report := Report{
		GeneratedAt:      time.Now(),
		Scope:            scopeSnapshot(scope),
		TotalExchanges:   totalEx,
		ScannedExchanges: 0,
		Findings:         findings,
		PassiveCoverage:  "passive checks: headers, cookies, info disclosure",
		ActiveSummary:    fmt.Sprintf("%d active checks configured", countActiveChecks(s.config)),
	}

	switch e {
	case FormatJSON:
		return s.exportJSON(report)
	case FormatSARIF:
		return s.exportSARIF(report)
	case FormatHTML:
		return s.exportHTML(report)
	default:
		return &ExportResult{Format: e, Error: fmt.Errorf("unknown format %d", e)}
	}
}

func scopeSnapshot(scope *core.Scope) string {
	if scope == nil {
		return "all"
	}
	return "custom scope"
}

func countActiveChecks(cfg *ScanConfig) int {
	n := 0
	if cfg.CheckSqli {
		n++
	}
	if cfg.CheckXss {
		n++
	}
	if cfg.CheckPathTraversal {
		n++
	}
	if cfg.CheckSSRF {
		n++
	}
	if cfg.CheckXXE {
		n++
	}
	if cfg.CheckJwtWeak {
		n++
	}
	if cfg.CheckJSVulns {
		n++
	}
	return n
}

func (s *ActiveScanner) exportJSON(r Report) *ExportResult {
	b, err := json.MarshalIndent(r, "", "  ")
	return &ExportResult{Format: FormatJSON, Bytes: b, Error: err}
}

func (s *ActiveScanner) exportSARIF(r Report) *ExportResult {
	severityToLevel := map[string]string{
		"critical": "error",
		"high":     "error",
		"medium":   "warning",
		"low":      "note",
		"info":     "note",
	}

	rules := make([]sarifRule, 0)
	ruleSet := make(map[string]bool)
	results := make([]sarifResult, 0)

	for _, f := range r.Findings {
		if !ruleSet[f.Name] {
			ruleSet[f.Name] = true
			rules = append(rules, sarifRule{
				ID:                   strings.ToLower(strings.ReplaceAll(f.Name, " ", "-")),
				Name:                 f.Name,
				ShortDescription:     sarifDesc{Text: f.Description},
				FullDescription:      sarifDesc{Text: f.Solution},
				DefaultConfiguration: sarifConfig{Level: severityToLevel[f.Severity]},
			})
		}
		results = append(results, sarifResult{
			RuleID:  strings.ToLower(strings.ReplaceAll(f.Name, " ", "-")),
			Level:   severityToLevel[f.Severity],
			Message: sarifMessage{Text: f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtLoc{URI: f.URL},
					Region:           sarifRegion{StartLine: 1},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "burpsy-scanner",
					InformationURI: "https://github.com/burpsy/burpsy",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	b, err := json.MarshalIndent(log, "", "  ")
	return &ExportResult{Format: FormatSARIF, Bytes: b, Error: err}
}

const htmlTemplateStr = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Burpsy Scan Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
h1 { color: #333; }
h2 { color: #555; border-bottom: 1px solid #eee; padding-bottom: 5px; }
.table { width: 100%; border-collapse: collapse; margin: 10px 0; }
.table th, .table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
.table th { background: #f5f5f5; }
.critical { background: #ffebee; }
.high { background: #fff3e0; }
.medium { background: #fffde7; }
.low { background: #e8f5e9; }
.info { background: #e3f2fd; }
.badge { padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
.badge-critical { background: #c62828; color: white; }
.badge-high { background: #ef6c00; color: white; }
.badge-medium { background: #f9a825; color: white; }
.badge-low { background: #66bb6a; color: white; }
.badge-info { background: #29b6f6; color: white; }
.badge-certain { border: 1px solid #2e7d32; }
.badge-firm { border: 1px solid #f57c00; }
.badge-tentative { border: 1px solid #78909c; }
.meta { color: #666; font-size: 0.9em; margin-bottom: 20px; }
</style>
</head>
<body>
<h1>Burpsy Security Scan Report</h1>
<div class="meta">
Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}}<br>
Scope: {{.Scope}}<br>
Total Exchanges: {{.TotalExchanges}}<br>
Scanned: {{.ScannedExchanges}}<br>
Passive Coverage: {{.PassiveCoverage}}<br>
Active Summary: {{.ActiveSummary}}
</div>

{{if .Findings}}
<h2>Findings ({{len .Findings}})</h2>
<table class="table">
<thead>
<tr><th>Severity</th><th>Confidence</th><th>Name</th><th>Description</th><th>URL</th><th>Method</th><th>Evidence</th><th>Solution</th></tr>
</thead>
<tbody>
{{range .Findings}}
<tr class="{{.Severity}}">
<td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
<td><span class="badge badge-{{.Confidence}}">{{.Confidence}}</span></td>
<td>{{.Name}}</td>
<td>{{.Description}}</td>
<td><code>{{.URL}}</code></td>
<td>{{.Method}}</td>
<td><code>{{.Evidence}}</code></td>
<td>{{.Solution}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No findings.</p>
{{end}}
</body>
</html>`

func (s *ActiveScanner) exportHTML(r Report) *ExportResult {
	tmpl, err := template.New("report").Parse(htmlTemplateStr)
	if err != nil {
		return &ExportResult{Format: FormatHTML, Error: err}
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, r); err != nil {
		return &ExportResult{Format: FormatHTML, Error: err}
	}
	return &ExportResult{Format: FormatHTML, Bytes: []byte(buf.String()), Error: nil}
}
