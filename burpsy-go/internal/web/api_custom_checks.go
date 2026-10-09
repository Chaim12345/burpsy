package web

// Console authoring of custom scan checks (burpsy-react-ui-kbu1): Burp's Extensions > Custom scan
// checks — "Click Import", "Click Validate", "Send to Custom scan checks editor … Run test", Export,
// Delete and reload. The corpus leaf (api_corpus_checks.go) listed and toggled; these routes change
// what is loaded, through the passive scanner's one entry list (scanner/custom_checks.go), and push the
// result into the audit engine so the two scanners never disagree about the corpus.
//
// Risk classes: validate and source reads are riskRead (nothing changes, nothing is sent); import,
// delete and reload are riskLocal (they change which checks dispatch); a test run is riskAttack,
// because an active check sends its probes to the exchange's target — through the same scope-gated
// sender an audit uses.

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// maxCheckTestExchanges bounds one test run: a test is a handful of chosen messages, not an audit.
const maxCheckTestExchanges = 20

// checkParseError is a parse failure with the position the parser reported, when it reported one.
type checkParseError struct {
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

var parsePosRe = regexp.MustCompile(`^line (\d+):(\d+): (.*)$`)

func toParseError(err error) checkParseError {
	msg := err.Error()
	if m := parsePosRe.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		col, _ := strconv.Atoi(m[2])
		return checkParseError{Message: m[3], Line: line, Column: col}
	}
	return checkParseError{Message: msg}
}

// checkKind names how the corpus classifies a check, in the classifier's own order.
func checkKind(c *bcheck.Check) string {
	switch {
	case c.NeedsCollaborator():
		return "collaborator"
	case c.NeedsTool():
		return "tool"
	case c.IsPassive():
		return "passive"
	case c.M2Runnable():
		return "active"
	default:
		return "insertion_point"
	}
}

// checkValidateReq is POST /api/scanner/checks/validate's body.
type checkValidateReq struct {
	Source string `json:"source" desc:"the BCheck draft's full source text"`
}

// checkImportReq is POST /api/scanner/checks/import's body.
type checkImportReq struct {
	Source  string `json:"source" desc:"the BCheck's full source text; its metadata name is the check's name in the corpus"`
	Replace bool   `json:"replace" desc:"replace a console-imported check of the same name; a check loaded from a --bchecks file is never replaced (409)"`
}

// checkTestReq is POST /api/scanner/checks/test's body.
type checkTestReq struct {
	Source      string   `json:"source" desc:"the BCheck draft's full source text; it is run, not loaded into the corpus"`
	ExchangeIDs []uint64 `json:"exchange_ids" desc:"captured exchanges to run the draft against, 1-20; an active draft sends its probes to each one's target"`
}

func readCheckBody(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, 1<<20)).Decode(into); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// handleCheckValidate serves POST /api/scanner/checks/validate {source}: Burp's Validate. Always 200
// with {valid, …} — an invalid draft is the answer, not a bad request.
func (s *Server) handleCheckValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a check is validated with POST", http.StatusMethodNotAllowed)
		return
	}
	var body checkValidateReq
	if !readCheckBody(w, r, &body) {
		return
	}
	c, err := bcheck.Parse(body.Source)
	if err != nil {
		pe := toParseError(err)
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": pe})
		return
	}
	out := map[string]any{"valid": true, "name": c.Name, "kind": checkKind(c)}
	if s.passiveScanner != nil {
		if e, ok := s.passiveScanner.Entry(c.Name); ok {
			// Import would conflict (a file) or replace (a console check): say which before the click.
			out["existing_origin"] = originLabel(e.Origin)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func originLabel(origin string) string {
	if origin == scanner.OriginConsole {
		return "console"
	}
	return "file"
}

// syncCorpus pushes the passive scanner's active set into the audit engine and persists the console
// checks. Called after every change.
func (s *Server) syncCorpus() error {
	// Under scannerBuild so a lazy activeScanner build cannot interleave with this push: otherwise a
	// build that read the old corpus could be stored just after this saw no scanner, and the new
	// check set would never reach the audit engine (burpsy-react-ui-h68z).
	s.scannerBuild.Lock()
	if active := s.wiredScanner(); active != nil {
		active.WithCorpusChecks(s.passiveScanner.ActiveChecks())
	}
	s.scannerBuild.Unlock()
	if s.persist != nil {
		return s.persist.SaveCustomScanChecks(s.passiveScanner.ConsoleSources())
	}
	return nil
}

// handleCheckImport serves POST /api/scanner/checks/import {source, replace}: Burp's Import and Save.
func (s *Server) handleCheckImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a check is imported with POST", http.StatusMethodNotAllowed)
		return
	}
	var body checkImportReq
	if !readCheckBody(w, r, &body) {
		return
	}
	if s.passiveScanner == nil {
		http.Error(w, "this server has no scanner to load checks into", http.StatusServiceUnavailable)
		return
	}
	c, err := s.passiveScanner.ImportCheck(body.Source, body.Replace)
	switch {
	case errors.Is(err, scanner.ErrCheckConflict):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": toParseError(err)})
		return
	}
	perr := s.syncCorpus()
	out := map[string]any{"name": c.Name, "kind": checkKind(c), "origin": "console", "persisted": s.persist != nil && perr == nil}
	if perr != nil {
		out["persist_error"] = perr.Error()
	}
	writeJSON(w, http.StatusCreated, out)
}

// handleCheckSource serves GET and DELETE /api/scanner/checks/source?name=: a check's source for
// Export and the editor, and Delete for a console check.
func (s *Server) handleCheckSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "a check's source is read with GET and deleted with DELETE", http.StatusMethodNotAllowed)
		return
	}
	if s.passiveScanner == nil {
		http.Error(w, "this server has no scanner", http.StatusServiceUnavailable)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "name a check: ?name=", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodDelete {
		err := s.passiveScanner.RemoveCheck(name)
		switch {
		case errors.Is(err, scanner.ErrCheckNotConsole):
			http.Error(w, err.Error(), http.StatusConflict)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if perr := s.syncCorpus(); perr != nil {
			http.Error(w, "deleted, but the project could not be saved: "+perr.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	e, ok := s.passiveScanner.Entry(name)
	if !ok {
		http.Error(w, "no check named "+name+" is loaded", http.StatusNotFound)
		return
	}
	out := map[string]any{"name": e.Name, "origin": originLabel(e.Origin), "source": e.Source, "kind": checkKind(e.Check)}
	if e.Origin != scanner.OriginConsole {
		out["file"] = filepath.Base(e.Origin)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCheckReload serves POST /api/scanner/checks/reload: re-read the --bchecks directory.
func (s *Server) handleCheckReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the directory is reloaded with POST", http.StatusMethodNotAllowed)
		return
	}
	if s.passiveScanner == nil {
		http.Error(w, "this server has no scanner", http.StatusServiceUnavailable)
		return
	}
	rep, shadowed, err := s.passiveScanner.ReloadDir()
	if errors.Is(err, scanner.ErrNoCheckDir) {
		http.Error(w, err.Error()+"; start with --bchecks DIR to have a directory to reload", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if perr := s.syncCorpus(); perr != nil {
		http.Error(w, "reloaded, but the project could not be saved: "+perr.Error(), http.StatusInternalServerError)
		return
	}
	errs := make([]map[string]string, 0, len(rep.Errors))
	for _, e := range rep.Errors {
		errs = append(errs, map[string]string{"file": filepath.Base(e.File), "error": e.Err})
	}
	if shadowed == nil {
		shadowed = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": rep.Summary(), "errors": errs, "shadowed": shadowed})
}

type checkTestFinding struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Param      string `json:"param,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

type checkTestResult struct {
	ExchangeID  uint64             `json:"exchange_id"`
	URL         string             `json:"url"`
	Findings    []checkTestFinding `json:"findings"`
	Sent        int                `json:"sent"`
	Refused     int                `json:"refused"`
	Unresolved  []string           `json:"unresolved"`
	Declined    []string           `json:"declined"`
	Unsupported string             `json:"unsupported,omitempty"`
	Error       string             `json:"error,omitempty"`
}

// handleCheckTest serves POST /api/scanner/checks/test {source, exchange_ids}: Burp's "Run test" —
// the draft runs against chosen messages exactly as the scanner would run it, and nothing is filed.
func (s *Server) handleCheckTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a check is tested with POST", http.StatusMethodNotAllowed)
		return
	}
	var body checkTestReq
	if !readCheckBody(w, r, &body) {
		return
	}
	if s.passiveScanner == nil {
		http.Error(w, "this server has no scanner", http.StatusServiceUnavailable)
		return
	}
	if len(body.ExchangeIDs) == 0 || len(body.ExchangeIDs) > maxCheckTestExchanges {
		http.Error(w, fmt.Sprintf("name between 1 and %d exchanges to test against", maxCheckTestExchanges), http.StatusBadRequest)
		return
	}
	c, err := bcheck.Parse(body.Source)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": toParseError(err)})
		return
	}
	kind := checkKind(c)
	if kind != "passive" && s.wiredScanner() == nil {
		http.Error(w, "an active check needs the audit engine, and this server has none", http.StatusServiceUnavailable)
		return
	}
	results := make([]checkTestResult, 0, len(body.ExchangeIDs))
	for _, id := range body.ExchangeIDs {
		res := checkTestResult{ExchangeID: id, Findings: []checkTestFinding{}, Unresolved: []string{}, Declined: []string{}}
		ex, gerr := s.store.GetExchange(core.ExchangeID(id))
		if gerr != nil || ex == nil {
			res.Error = "no such exchange"
			results = append(results, res)
			continue
		}
		scheme := "http"
		if ex.TLS {
			scheme = "https"
		}
		res.URL = fmt.Sprintf("%s://%s:%d%s", scheme, ex.Host, ex.Port, ex.Path)
		var trial scanner.CheckTrial
		if kind == "passive" {
			trial = s.passiveScanner.TrialPassiveCheck(ex, c)
		} else {
			trial = s.wiredScanner().TrialCorpusCheck(r.Context(), ex, c)
		}
		res.Sent, res.Refused, res.Unsupported = trial.Sent, trial.Refused, trial.Unsupported
		if trial.Unresolved != nil {
			res.Unresolved = trial.Unresolved
		}
		if trial.Declined != nil {
			res.Declined = trial.Declined
		}
		if err := trial.Err(); err != nil && res.Unsupported == "" {
			res.Error = err.Error()
		}
		for _, f := range trial.Findings {
			res.Findings = append(res.Findings, checkTestFinding{Name: f.Name, Severity: f.Severity, Confidence: f.Confidence, Param: f.Param, Evidence: f.Evidence})
		}
		results = append(results, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": c.Name, "kind": kind, "results": results})
}
