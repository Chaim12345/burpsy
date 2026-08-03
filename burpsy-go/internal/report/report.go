// Package report renders scan findings in the three downloadable formats the
// web UI links to (scanner.ts) and the CLI can emit: plain JSON, SARIF 2.1.0,
// and a self-contained HTML page. The package depends only on core so both the
// web layer and the CLI share one implementation instead of drifting.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// Row is one finding, already resolved to its display form. Hosts are resolved
// by the caller (they need a store); the renderers never guess.
type Row struct {
	ID          uint64   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Hosts       []string `json:"hosts"`
	Occurrences int      `json:"occurrences"`
}

// JSON renders the plain-JSON report.
func JSON(rows []Row) ([]byte, error) {
	return json.MarshalIndent(map[string]interface{}{
		"findings": rows,
		"total":    len(rows),
	}, "", "  ")
}

// sarifLevel maps a severity onto the SARIF "level" vocabulary.
func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

// SARIF renders a SARIF 2.1.0 document with one rule+result per finding.
func SARIF(rows []Row) ([]byte, error) {
	rules := make([]map[string]interface{}, 0, len(rows))
	results := make([]map[string]interface{}, 0, len(rows))
	for _, f := range rows {
		ruleID := fmt.Sprintf("BURPSY-%d", f.ID)
		rules = append(rules, map[string]interface{}{
			"id":               ruleID,
			"name":             f.Name,
			"shortDescription": map[string]interface{}{"text": f.Description},
			"help":             map[string]interface{}{"text": f.Remediation},
		})
		results = append(results, map[string]interface{}{
			"ruleId":  ruleID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]interface{}{"text": f.Description},
		})
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "burpsy",
						"informationUri": "https://github.com/burpsy-go/burpsy",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// HTML renders a self-contained report page. Every operator/attacker-controllable
// field (finding name, description, remediation) is escaped: a finding whose text
// carries markup from a scanned response must not become a script in the report.
func HTML(rows []Row) []byte {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>burpsy scan report</title></head><body>\n")
	b.WriteString(fmt.Sprintf("<h1>burpsy scan report</h1>\n<p>%d finding(s)</p>\n<ul>\n", len(rows)))
	for _, f := range rows {
		b.WriteString(fmt.Sprintf("<li><strong>%s</strong> (%s, %s) — %s",
			html.EscapeString(f.Name), html.EscapeString(f.Severity),
			html.EscapeString(f.Confidence), html.EscapeString(f.Description)))
		if f.Remediation != "" {
			b.WriteString(fmt.Sprintf("<br><em>Remediation:</em> %s", html.EscapeString(f.Remediation)))
		}
		b.WriteString("</li>\n")
	}
	b.WriteString("</ul>\n</body></html>\n")
	return []byte(b.String())
}
