package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/report"
)

// ---- Scanner report export: /api/report/{json|sarif|html} ---------------------------------------

// The UI links to these endpoints as plain downloads (scanner.ts), so each format is generated
// from the finding store's current contents. Rendering lives in the shared report package; this
// handler only resolves hosts against the store and wires the download headers.

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	format := strings.TrimPrefix(r.URL.Path, "/api/report/")
	format = strings.TrimSuffix(format, "/")

	// The report honours a filter (burpsy-react-ui-8r6): severity as a comma list, host as a
	// substring, and false positives excluded on request — the axes the Issues page already
	// filters by, so "the High and Critical findings on this host" is the query string rather
	// than a manual pass over the whole-store export. An unknown severity value is refused
	// rather than ignored: a filter parameter that silently does not filter would produce a
	// report claiming to be the filtered set while carrying everything.
	query := r.URL.Query()
	var filter reportFilter
	if raw := query.Get("severity"); raw != "" {
		// ParseSeverity coerces an unknown value to informational rather than failing, which is
		// right for captured data and wrong for a filter: a typo would silently produce a report
		// of only-informational findings while claiming to be the filtered set. Matched here,
		// case-insensitively, against the values the engine can actually hold.
		valid := map[string]core.Severity{
			"critical": core.SeverityCritical, "high": core.SeverityHigh, "medium": core.SeverityMedium,
			"low": core.SeverityLow, "informational": core.SeverityInformational,
		}
		for _, name := range strings.Split(raw, ",") {
			sev, ok := valid[strings.ToLower(strings.TrimSpace(name))]
			if !ok {
				http.Error(w, "unknown severity "+strconv.Quote(name)+"; the accepted values are critical, high, medium, low, informational", http.StatusBadRequest)
				return
			}
			filter.severities = append(filter.severities, sev)
		}
	}
	filter.host = strings.TrimSpace(query.Get("host"))
	filter.hideFalsePositives = query.Get("exclude_false_positives") == "true"

	switch format {
	case "json":
		s.reportJSON(w, filter)
	case "sarif":
		s.reportSARIF(w, filter)
	case "html":
		s.reportHTML(w, filter)
	default:
		http.NotFound(w, r)
	}
}

// reportFilter is the subset the export carries, decoded from the query string. Zero value
// means no constraint — the whole store, exactly what the unparameterised URL always meant.
type reportFilter struct {
	severities         []core.Severity
	host               string
	hideFalsePositives bool
}

// applies says whether one finding survives the filter. Every axis is a keep-if-match; an
// empty axis never constrains.
func (f reportFilter) applies(finding *core.Finding, hosts []string) bool {
	if len(f.severities) > 0 {
		kept := false
		for _, sev := range f.severities {
			// EffectiveSeverity, not Severity: the operator's override is the severity this
			// finding HAS. Filtering on the engine's original dropped a finding they had just
			// raised to Critical from a ?severity=critical export, and included it in a
			// ?severity=low one as though the triage never happened (burpsy-react-ui-5qfr).
			if finding.EffectiveSeverity() == sev {
				kept = true
				break
			}
		}
		if !kept {
			return false
		}
	}
	if f.host != "" {
		kept := false
		for _, h := range hosts {
			if strings.Contains(strings.ToLower(h), strings.ToLower(f.host)) {
				kept = true
				break
			}
		}
		if !kept {
			return false
		}
	}
	if f.hideFalsePositives && finding.FalsePositive {
		return false
	}
	return true
}

// reportRows turns the finding store into report rows, resolving each finding's hosts from the
// store's exchanges (left empty rather than guessed when the store cannot resolve them). The
// filter decides which findings are carried; zero value carries everything.
func (s *Server) reportRows(filter reportFilter) []report.Row {
	findings := s.findings.All()
	rows := make([]report.Row, 0, len(findings))
	for _, f := range findings {
		hosts := s.findingHosts(f)
		if !filter.applies(f, hosts) {
			continue
		}
		row := report.Row{
			ID:   f.ID,
			Name: f.Name,
			// The same values the Issues page shows (api_capture.go's findingToIssueView), for the
			// same reason: a report is the document the triage exists to produce, so it cannot be
			// the one surface that ignores it.
			Severity:    f.EffectiveSeverity().String(),
			Confidence:  f.EffectiveConfidence().String(),
			Description: f.Description,
			Remediation: f.Remediation,
			Hosts:       hosts,
			Occurrences: len(f.Occurrences),
			Params:      f.Params,
			Evidence:    s.findingEvidence(f),
		}
		// The catalogue was already resolved for /api/issues and then thrown away at the report
		// boundary, so the exported artefact — the thing that actually leaves the tool and gets read
		// by someone who was not driving it — carried the least context of any surface. Same resolver
		// as the API so a finding cannot describe itself one way on screen and another in the file.
		def, note := s.advisories.Resolve(f.Name)
		if def != nil {
			row.Advisory = advisoryForReport(def)
		} else {
			row.AdvisoryNote = note
		}
		rows = append(rows, row)
	}
	return rows
}

// advisoryForReport converts a catalogue entry into the renderer's shape, sanitising the two HTML
// fragments here — at the boundary — so the renderer never has to decide whether to trust them.
func advisoryForReport(d *advisory.Definition) *report.Advisory {
	a := &report.Advisory{
		Name:            d.Name,
		TypeIndex:       d.HexIndex(),
		TypicalSeverity: string(d.Severity),
		DescriptionHTML: advisory.SanitisedHTML(d.Description),
		RemediationHTML: advisory.SanitisedHTML(d.Remediation),
	}
	for _, r := range d.References {
		a.References = append(a.References, report.Link{Title: r.Title, URL: r.URL})
	}
	for _, c := range d.Classification {
		a.Classifications = append(a.Classifications, report.Link{Title: c.Title, URL: c.URL})
	}
	return a
}

// findingEvidence lists where a finding was actually observed. A finding with no location is an
// assertion; one with a method, host and path is something a reader can go and reproduce, which is
// the difference between a report that gets acted on and one that gets argued with.
//
// ExchangeByRequest for the same reason findingHosts uses it: an occurrence holds a request *message*
// id, and GetExchange would resolve that number against the exchange id space and return an unrelated
// row.
func (s *Server) findingEvidence(f *core.Finding) []report.Evidence {
	seen := map[string]bool{}
	var out []report.Evidence
	for _, occ := range f.Occurrences {
		ex, err := s.store.ExchangeByRequest(occ.Request)
		if err != nil {
			continue
		}
		key := ex.Method + " " + ex.Host + ex.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		e := report.Evidence{Host: ex.Host, Path: ex.Path, Method: ex.Method}
		if ex.Status != nil {
			e.Status = int(*ex.Status)
		}
		out = append(out, e)
	}
	return out
}

// findingHosts lists the hosts a finding was observed on.
//
// ExchangeByRequest, not GetExchange: an occurrence holds a request *message* id, and looking an
// exchange up by it returns an unrelated exchange rather than an error. That put the wrong hostname
// on findings in every exported report — the artefact that leaves the tool and gets acted on.
func (s *Server) findingHosts(f *core.Finding) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, occ := range f.Occurrences {
		ex, err := s.store.ExchangeByRequest(occ.Request)
		if err != nil {
			continue
		}
		if !seen[ex.Host] {
			seen[ex.Host] = true
			hosts = append(hosts, ex.Host)
		}
	}
	return hosts
}

func (s *Server) reportJSON(w http.ResponseWriter, filter reportFilter) {
	doc, err := report.JSON(s.reportRows(filter))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.json"`)
	w.Write(doc)
}

func (s *Server) reportSARIF(w http.ResponseWriter, filter reportFilter) {
	doc, err := report.SARIF(s.reportRows(filter))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.sarif"`)
	w.Write(doc)
}

func (s *Server) reportHTML(w http.ResponseWriter, filter reportFilter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.html"`)
	w.Write(report.HTML(s.reportRows(filter)))
}
