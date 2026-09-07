// The audit endpoints, and the built-in scan configuration one can be run under.
//
// Moved verbatim out of api_tools.go apart from the SCAN-03 additions, which are noted where they are.
// That file is a grab-bag of every tool's routes, and the audit surface is the part SCAN-03 touches:
// both doors and the runAudit behind them. Keeping them in one file beside resolveAuditConfig in
// api_scanner_configs.go is what makes "a configuration name is resolved in exactly one place"
// checkable by reading rather than by grep.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

type scannerAuditReq struct {
	Method     string          `json:"method"`
	Target     string          `json:"target"`
	ExchangeID core.ExchangeID `json:"exchange_id,omitempty"`
	// Config names one of scanner.BuiltInConfigs to run under. Empty means the server default. An
	// unknown name is refused rather than ignored — see Server.resolveAuditConfig.
	Config string `json:"config,omitempty"`
	// Pool names a saved resource pool to bound this audit's probes. Empty means unpaced, which is
	// how every audit ran before pools existed — the audit path had no rate limit at all, which is
	// the gap a named pool closes here.
	//
	// It bounds *requests*, not items: scanner.ScanConfig.MaxConcurrency still decides how many items
	// an audit works on at once, because Burp's dialog says "max concurrent requests" and one item can
	// send many. An unknown name is refused rather than defaulted — see Server.poolLimiter.
	Pool string `json:"pool,omitempty"`
}

// auditContext binds a named pool's limiter to this audit's context, so every probe the checks send
// is paced by it.
//
// A context value rather than a field on the scanner, because the scanner is shared and long-lived
// while the pool is per-audit: mutating its pacer per request would let two concurrent audits under
// two different pools race, and the loser would run under bounds nobody chose. The limiter itself is
// shared per pool name, so two audits under one pool contend for the same slots rather than getting
// four concurrent requests each out of a pool of four. See internal/pool/limiter.go.
func (s *Server) auditContext(ctx context.Context, poolName string) (context.Context, error) {
	limiter, err := s.poolLimiter(poolName)
	if err != nil {
		return nil, err
	}
	return pool.WithLimiter(ctx, limiter), nil
}

// handleScannerAudit is the legacy /api/scanner/audit alias for /api/audit/{id}.
func (s *Server) handleScannerAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scannerAuditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// No id guard at all, and deliberately so. Exchange ids are a dense counter from zero
	// (core.ExchangeID is a uint64 handed out by an incrementing store), so exchange 0 is the first
	// request captured in a session and the one an operator reaches for first; rejecting it as
	// "exchange_id is required" refused a real row and reported a missing field for an id that had
	// been supplied. Nor is existence checked here: an id that names no capture is already answered
	// honestly one layer down, as outcome.state "unauditable" carrying the reason — a richer reply
	// than a bare 404, and through the same shape every other audit uses.
	cfg, named, cerr := s.resolveAuditConfig(req.Config)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	ctx, perr := s.auditContext(r.Context(), req.Pool)
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(ctx, req.ExchangeID, cfg, named))
}

// handleAuditByPath serves POST /api/audit/{id}, running an active scan over one exchange.
func (s *Server) handleAuditByPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/audit/")
	id, err := strconv.ParseUint(strings.TrimSuffix(idStr, "/"), 10, 64)
	// `err != nil` only — a parse failure, nothing else. Zero is a valid exchange id, not a sentinel:
	// ids are a dense counter from zero, so /api/audit/0 names the first captured exchange of the
	// session. Rejecting it as "Invalid exchange id" made the very first row in HTTP history the one
	// row that could not be audited, and called a well-formed real id malformed. An id that names no
	// capture is not this handler's complaint: the engine answers it as outcome.state "unauditable"
	// with the reason on the wire.
	if err != nil {
		http.Error(w, "Invalid exchange id", http.StatusBadRequest)
		return
	}
	// The body is optional here and always has been — every caller predating SCAN-03 posts nothing —
	// so an empty or absent body means "the default configuration", and only a body that is present
	// and malformed is an error. Decoding into a zero-valued struct and treating io.EOF as "no body"
	// is what keeps those two apart.
	var req scannerAuditReq
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil && derr != io.EOF {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	cfg, named, cerr := s.resolveAuditConfig(req.Config)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	ctx, perr := s.auditContext(r.Context(), req.Pool)
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(ctx, core.ExchangeID(id), cfg, named))
}

// auditTarget names one audited exchange for the task list, falling back to the id when the exchange
// is not readable — an unnamed task is still better than a task that does not appear.
func auditTarget(store *core.TrafficStore, id core.ExchangeID) string {
	if ex, err := store.GetExchange(id); err == nil {
		return fmt.Sprintf("%s %s%s", ex.Method, ex.Host, ex.Path)
	}
	return fmt.Sprintf("exchange %d", id)
}

// runAudit audits one exchange and returns the response body both audit endpoints send.
//
// The body carries the engine's AuditOutcome, matching what the Rust route returns from its audit
// hook (`{enabled, exchange, active_checks, outcome}`). Before the audit engine existed the reply was
// `{started: true, exchange_id: N}` and the findings went to the finding store — so an operator who
// audited a host that had stopped answering saw the same "started: true" as one whose whole check set
// ran. Those two keys are kept for compatibility, and the outcome is what makes them mean something:
// `dispositions` names every check that was *not* dispatched and why.
//
// cfg is the configuration to audit under and named is the built-in configuration the caller asked
// for, or "" for the server default. Both come from Server.resolveAuditConfig, and both are echoed in
// the reply: SCAN-03's whole risk is an endpoint that accepts a configuration name and audits under
// something else, and a reply that did not state what it ran under could not rule that out.
//
// scanner.ts renders this by pretty-printing the JSON it gets back, so the richer body needs no
// change on the TypeScript side — there is no typed audit response to keep in sync.
func (s *Server) runAudit(ctx context.Context, id core.ExchangeID, cfg scanner.AuditConfig, named string) map[string]interface{} {
	if s.scanner == nil {
		// Built with the engagement scope: an active audit sends real traffic, and the engine refuses
		// an out-of-scope exchange before it plans any work. The corpus's active checks ride along
		// when a passive scanner (loaded via --bchecks) is attached — the same source main.go wires
		// explicitly, so an unwired server and a wired one cannot disagree about which checks run.
		active := scanner.NewActiveScanner(s.store, s.logger).WithScope(s.scope).WithPace(pool.ContextPacer{})
		if s.passiveScanner != nil {
			active = active.WithCorpusChecks(s.passiveScanner.ActiveChecks())
		}
		if s.toolRunner != nil {
			active = active.WithToolRunner(s.toolRunner)
		}
		s.scanner = active
	}
	body := map[string]interface{}{
		"started":       true,
		"exchange_id":   id,
		"active_checks": s.scanner.ActiveCheckCount(),
		"unimplemented": s.scanner.UnimplementedCheckCount(),
		// The configuration this run actually used. Reported for SCAN-03: a reply that looked the same
		// whether or not a named preset was honoured could not be told apart from one that accepted the
		// name and ignored it. Empty config_name means the server default was used, which is a
		// different statement from "a preset was applied", so it is not filled in with a placeholder.
		"config_name": named,
		"config":      newAuditConfigView(cfg),
	}
	// On the dashboard while it runs, not only once it answers (DASH-01). Total is the check set,
	// which is known up front for a single item.
	task := s.tasks.Start(dash.KindAudit, auditTarget(s.store, id), uint64(s.scanner.ActiveCheckCount()))
	// Attached here, in the one place both audit routes and the re-audit action pass through, so no
	// entry point can run an audit that never appears in the queue. The reply's `config` block above
	// is deliberately rendered from the caller's cfg rather than this one: the queue is observation,
	// not configuration, and echoing it back would suggest the operator had asked for it.
	outcome, findings := s.scanner.AuditWithin(ctx, id, s.withAuditItems(cfg))
	task.Advance(uint64(outcome.Considered()))
	task.FinishWithNote(outcome.Breakdown(), outcome.Summary())
	body["outcome"] = outcome
	body["dispositions"] = outcome.Dispositions()
	body["summary"] = outcome.Summary()
	// The same four buckets the dashboard reads, on the audit's own response: a caller of this
	// endpoint gets the count and what it does not account for without having to fold nine
	// dispositions itself (DASH-03).
	body["breakdown"] = dash.NewSummary("Audit", "findings", "checks",
		outcome.Breakdown(), outcome.BreakdownReasons()...)
	if outcome.Error != "" {
		s.logger.Warn("audit refused", zap.Uint64("exchange_id", uint64(id)), zap.String("reason", outcome.Error))
		return body
	}
	ex, gerr := s.store.GetExchange(id)
	if gerr == nil {
		// nil: this row stands for a whole audit of the exchange, not for one request/response pair, so
		// there is no single response whose length it could honestly report.
		exID := uint64(ex.ID)
		s.toolLog.RecordWithExchange(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, ex.Method, ex.Path, 0, nil, 0, "audit", &exID)
	}
	for _, f := range findings {
		s.findings.Add(s.activeFinding(f, task.ID()))
	}
	return body
}

// activeFinding converts one active-scanner finding into a store finding, carrying the two links
// that make it usable: the exchange it was found at, and the run that produced it.
//
// Both used to be dropped here. The active paths built a core.NewFinding from the name, severity,
// confidence, description and remediation and nothing else — so every finding an audit produced
// reached the store with no occurrences at all, and the issues API, having nothing to resolve,
// reported it with an empty host and an empty path. A finding that cannot say where it was found is
// not actionable, and it looked identical to the misattribution bug next door in findingToIssueView.
func (s *Server) activeFinding(f *scanner.Finding, taskID uint64) core.NewFinding {
	nf := core.NewFinding{
		Name:        f.Name,
		Severity:    core.ParseSeverity(f.Severity),
		Confidence:  core.ParseConfidence(f.Confidence),
		Description: f.Description,
		Remediation: f.Solution,
		TaskID:      taskID,
		Param:       f.Param,
	}
	// Resolved through the store so the occurrence carries the message ids the issues API reads, not
	// just an exchange id. An exchange that has since rolled out of the store leaves the occurrence
	// off rather than half-filled: no location is honest, a partial one is not.
	if ex, err := s.store.GetExchange(f.ExchangeID); err == nil {
		nf.Occurrences = []core.Occurrence{{
			ExchangeID: ex.ID,
			Request:    ex.Request,
			Response:   ex.Response,
		}}
		// The dedup target, from the same exchange the occurrence came from. Left zero when the
		// exchange did not resolve, which disables merging for this finding — the same rule as the
		// occurrence above: an unknown location is recorded as unknown, never guessed, and a finding
		// with a guessed target would merge into the wrong issue.
		nf.Target = core.FindingTarget{Host: ex.Host, Port: ex.Port, TLS: ex.TLS, Path: ex.Path}
	}
	return nf
}
