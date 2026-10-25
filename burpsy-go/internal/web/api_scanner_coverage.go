package web

import (
	"encoding/json"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

type coverageCheckView struct {
	Name      string `json:"name"`
	Ran       uint64 `json:"ran"`
	Findings  uint64 `json:"findings"`
	Errored   uint64 `json:"errored"`
	LastError string `json:"last_error,omitempty"`
	State     string `json:"state"`
}

type coveragePartitionView struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// handleScannerCoverage serves GET /api/scanner/coverage with passive check runtime coverage.
func (s *Server) handleScannerCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.passiveScanner == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
			"hint":    "passive BCheck scanning is not enabled; start with --bchecks DIR",
		})
		return
	}

	report := s.passiveScanner.Coverage()
	checks := make([]coverageCheckView, 0, len(report.Checks))
	for _, c := range report.Checks {
		checks = append(checks, coverageCheckView{
			Name:      c.Name,
			Ran:       c.Ran,
			Findings:  c.Findings,
			Errored:   c.Errored,
			LastError: c.LastError,
			State:     c.State().String(),
		})
	}
	partition := make([]coveragePartitionView, 0, len(scanner.CoverageStateAll))
	for _, p := range report.Partition() {
		partition = append(partition, coveragePartitionView{
			State: p.State.String(),
			Count: p.Count,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":   s.passiveScanner.Loaded() > 0,
		"loaded":    s.passiveScanner.Loaded(),
		"summary":   report.Summary(),
		"checks":    checks,
		"skips":     report.Skips,
		"partition": partition,
		// Responses the checks ran on with a body this build could not decode (an encoding
		// chain, a broken stream) — a caveat on every clean result over them (burpsy-react-ui-jgnf).
		"undecoded_bodies": report.UndecodedBodies,
	})
}
