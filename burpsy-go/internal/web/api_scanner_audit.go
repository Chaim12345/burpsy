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
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

type scannerAuditReq struct {
	Method     string `json:"method"`
	Target     string `json:"target"`
	ExchangeID uint64 `json:"exchange_id,omitempty"`
	// Config names one of scanner.BuiltInConfigs to run under. Empty means the server default. An
	// unknown name is refused rather than ignored — see Server.resolveAuditConfig.
	Config string `json:"config,omitempty"`
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
	if req.ExchangeID == 0 {
		http.Error(w, "exchange_id is required", http.StatusBadRequest)
		return
	}
	cfg, named, cerr := s.resolveAuditConfig(req.Config)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(r.Context(), req.ExchangeID, cfg, named))
}

// handleAuditByPath serves POST /api/audit/{id}, running an active scan over one exchange.
func (s *Server) handleAuditByPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/audit/")
	id, err := strconv.ParseUint(strings.TrimSuffix(idStr, "/"), 10, 64)
	if err != nil || id == 0 {
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(r.Context(), id, cfg, named))
}

// auditTarget names one audited exchange for the task list, falling back to the id when the exchange
// is not readable — an unnamed task is still better than a task that does not appear.
func auditTarget(store *core.TrafficStore, id uint64) string {
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
func (s *Server) runAudit(ctx context.Context, id uint64, cfg scanner.AuditConfig, named string) map[string]interface{} {
	if s.scanner == nil {
		// Built with the engagement scope: an active audit sends real traffic, and the engine refuses
		// an out-of-scope exchange before it plans any work.
		s.scanner = scanner.NewActiveScanner(s.store, s.logger).WithScope(s.scope)
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
	outcome, findings := s.scanner.AuditWithin(ctx, id, cfg)
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
		s.logger.Warn("audit refused", zap.Uint64("exchange_id", id), zap.String("reason", outcome.Error))
		return body
	}
	ex, gerr := s.store.GetExchange(id)
	if gerr == nil {
		s.toolLog.Record(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, ex.Method, ex.Path, 0, 0, "audit")
	}
	for _, f := range findings {
		s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
		})
	}
	return body
}
