package web

import (
	"net/http"
	"strings"

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
		rows = append(rows, report.Row{
			ID:          f.ID,
			Name:        f.Name,
			Severity:    f.Severity.String(),
			Confidence:  f.Confidence.String(),
			Description: f.Description,
			Remediation: f.Remediation,
			Hosts:       s.findingHosts(f),
			Occurrences: len(f.Occurrences),
		})
	}
	return rows
}

func (s *Server) findingHosts(f *core.Finding) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, occ := range f.Occurrences {
		ex, err := s.store.GetExchange(uint64(occ.Request))
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
