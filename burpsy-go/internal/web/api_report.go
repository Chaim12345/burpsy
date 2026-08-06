package web

import (
	"net/http"
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
	switch format {
	case "json":
		s.reportJSON(w)
	case "sarif":
		s.reportSARIF(w)
	case "html":
		s.reportHTML(w)
	default:
		http.NotFound(w, r)
	}
}

// reportRows turns the finding store into report rows, resolving each finding's hosts from the
// store's exchanges (left empty rather than guessed when the store cannot resolve them).
func (s *Server) reportRows() []report.Row {
	findings := s.findings.All()
	rows := make([]report.Row, 0, len(findings))
	for _, f := range findings {
		row := report.Row{
			ID:          f.ID,
			Name:        f.Name,
			Severity:    f.Severity.String(),
			Confidence:  f.Confidence.String(),
			Description: f.Description,
			Remediation: f.Remediation,
			Hosts:       s.findingHosts(f),
			Occurrences: len(f.Occurrences),
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

func (s *Server) reportJSON(w http.ResponseWriter) {
	doc, err := report.JSON(s.reportRows())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.json"`)
	w.Write(doc)
}

func (s *Server) reportSARIF(w http.ResponseWriter) {
	doc, err := report.SARIF(s.reportRows())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.sarif"`)
	w.Write(doc)
}

func (s *Server) reportHTML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.html"`)
	w.Write(report.HTML(s.reportRows()))
}
