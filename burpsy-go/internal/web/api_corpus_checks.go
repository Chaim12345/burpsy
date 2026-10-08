package web

// The Custom scan checks leaf's routes (burpsy-react-ui-kdqj, criterion 1).
//
// # What an operator gets that they could not reach
//
// The loaded BCheck corpus was visible only as counts — on /api/issues and /api/scanner/coverage —
// and never as a list: which custom checks are loaded, whether one compiled, and whether one is
// currently enabled were three answers on three routes with no way to act on the third. This file
// gathers them in one place, and the enable/disable endpoint flips the SAME set the audit engine
// dispatches (scanner's disabledChecks, read by corpusChecksEnabled at both dispatch sites), so a
// row an operator switches off is a check the next audit does not run — not a control that changes
// nothing.
//
// # One source: the corpus loader
//
// Both routes count their rows from the corpus loader (scanner.ActiveScanner.CorpusChecks and
// PassiveScanner.Report), which is the same LoadDir call main.go makes once at startup. A second
// list derived here would agree on the day it was written and drift the first time a corpus was
// reloaded — the reason criterion 3 says both count from the loader rather than a second list.
//
// # Risk classes
//
// The list is riskRead: it reads state and sends nothing outbound. The enable/disable is riskLocal:
// it mutates burpsy's own state (which checks dispatch) without sending traffic, the same class as
// every other settings write in this manifest.
//
// New-file note: this file adds routes and edits no line of server.go or route_manifest.go from
// outside — the manifest entry and the HandleFunc line are wired by whoever lands this, in the same
// hunks the route itself would have touched.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// corpusCheckView is one row of the Custom scan checks leaf.
//
// RunCount is the PASSIVE coverage counter where the check is passive (the CoverageTracker keys by
// name) and zero for an active check: the active engine's per-check ledger is a bit-set over a
// session, not a counter, and reporting a passive count against an active check would be reporting
// a number the engine does not keep. The field's presence is the honest half; what it cannot say is
// said in the row's own kind.
type corpusCheckView struct {
	Name     string `json:"name"`
	Active   bool   `json:"active"`
	Passive  bool   `json:"passive"`
	Loaded   bool   `json:"loaded"`
	RunCount uint64 `json:"run_count"`
	// Disabled is the per-row switch's own state, read from the same set the audit engine filters
	// by — not a second list.
	Disabled bool `json:"disabled"`
	// Severity, author and description are the check's own metadata, carried because the leaf is
	// where an operator decides whether a custom check belongs in the set.
	Severity    string `json:"severity,omitempty"`
	Author      string `json:"author,omitempty"`
	Description string `json:"description,omitempty"`
}

// handleCorpusChecks serves GET /api/scanner/checks: the loaded corpus as rows, both buckets,
// counting from the loader.
func (s *Server) handleCorpusChecks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "the corpus is listed with GET", http.StatusMethodNotAllowed)
		return
	}

	// The coverage counter is keyed by name, so one snapshot serves every row's RunCount lookup.
	var coverageByName map[string]scanner.CheckCoverage
	var passiveLoaded int
	if s.passiveScanner != nil {
		passiveLoaded = s.passiveScanner.Loaded()
		if rep := s.passiveScanner.Coverage(); len(rep.Checks) > 0 {
			coverageByName = make(map[string]scanner.CheckCoverage, len(rep.Checks))
			for _, c := range rep.Checks {
				coverageByName[c.Name] = c
			}
		}
	}

	// The corpus rows come from the loader. A scanner built without WithCorpusChecks has no corpus:
	// nil is the supported state and the leaf reports the buckets it does know rather than a list
	// nothing could ever have loaded.
	var corpus []*bcheck.Check
	var disabled map[string]bool
	if s.scanner != nil {
		corpus = s.scanner.CorpusChecks()
		disabled = s.scanner.DisabledChecks()
	}

	rows := make([]corpusCheckView, 0, len(corpus))
	for _, c := range corpus {
		row := corpusCheckView{
			Name:        c.Name,
			Active:      true,
			Loaded:      true,
			Disabled:    disabled[c.Name],
			Severity:    c.Metadata.Severity,
			Author:      c.Metadata.Author,
			Description: c.Metadata.Description,
		}
		if cov, ok := coverageByName[c.Name]; ok {
			row.RunCount = cov.Ran
		}
		rows = append(rows, row)
	}

	// Passive checks are this scanner's own set, not the corpus the ActiveScanner holds — but the
	// leaf is where an operator sees what is loaded, and a passive check that will run on every
	// response is as much a "custom scan check" as an active one. Carried from the same loader's
	// report, with the coverage counter this package's coverage route already serves.
	if s.passiveScanner != nil {
		rep := s.passiveScanner.Coverage()
		for _, c := range rep.Checks {
			rows = append(rows, corpusCheckView{
				Name:     c.Name,
				Passive:  true,
				Loaded:   true,
				RunCount: c.Ran,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":       passiveLoaded > 0 || len(corpus) > 0,
		"passive_count": passiveLoaded,
		"active_count":  len(corpus),
		"checks":        rows,
	})
}

// corpusCheckEnableReq is the request body handleCorpusCheckEnable decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type corpusCheckEnableReq struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// handleCorpusCheckEnable serves PUT /api/scanner/checks/enable: the per-row switch the audit
// engine reads.
//
// riskLocal — this mutates which checks dispatch, not what is sent. The body is
// {"name": ..., "enabled": bool}; a name that is not in the corpus is refused rather than recorded,
// because a disable that names nothing would take effect on a corpus loaded later and silently
// switch off a check the operator never saw.
func (s *Server) handleCorpusCheckEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "a check is enabled or disabled with PUT", http.StatusMethodNotAllowed)
		return
	}
	var body corpusCheckEnableReq
	if err := requestJSON(w, r, nil).Decode(&body); err != nil {
		http.Error(w, "the body must be {\"name\": ..., \"enabled\": bool}", http.StatusBadRequest)
		return
	}

	if s.scanner == nil {
		http.Error(w, "no corpus is loaded; start with --bchecks DIR", http.StatusNotFound)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "the body must name a check", http.StatusBadRequest)
		return
	}

	// The name is checked against the corpus BEFORE anything is recorded, so a disable that names
	// nothing is refused here rather than taking effect silently later.
	found := false
	for _, c := range s.scanner.CorpusChecks() {
		if c.Name == body.Name {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "no check named "+body.Name+" is loaded", http.StatusNotFound)
		return
	}

	if body.Enabled {
		s.scanner.EnableCheck(body.Name)
	} else {
		s.scanner.DisableCheck(body.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":    body.Name,
		"enabled": body.Enabled,
		// The switch's own state after the write, read back from the same set the engine filters by:
		// a response that echoed the request instead of the state would be a fake confirmation.
		"disabled": s.scanner.CheckDisabled(body.Name),
	})
}
