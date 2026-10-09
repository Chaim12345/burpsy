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
	// InsertionSpans are operator-marked [start,end) byte ranges over the audited request's raw bytes
	// (burpsy-react-ui-806w). When present, the audit tests exactly those and skips the enumerator's
	// heuristics — Burp's "actively scan this marked request". Meaningful only for a single-exchange
	// audit, which is the only path that reads it.
	InsertionSpans [][2]int `json:"insertion_spans,omitempty"`
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
	cfg, named, unapplied, cerr := s.resolveAuditConfig(req.Config)
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
	json.NewEncoder(w).Encode(s.runAudit(ctx, req.ExchangeID, cfg, named, unapplied))
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
	cfg, named, unapplied, cerr := s.resolveAuditConfig(req.Config)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	// Operator-marked spans apply to this one request only (burpsy-react-ui-806w).
	cfg.ManualSpans = req.InsertionSpans
	ctx, perr := s.auditContext(r.Context(), req.Pool)
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(ctx, core.ExchangeID(id), cfg, named, unapplied))
}

// activeScanner returns this server's active scanner, building it on first use.
//
// Extracted from runAudit because a second caller arrived: the audit half of a crawl-and-audit scan
// needs exactly this wiring, and the two must not drift. Left inline, the wiring would be copied, and
// the copy that drifted would be the one with fewer checks or no scope gate — a crawl-and-audit that
// audited a fraction of what a hand-driven audit does, with nothing on screen to say so.
//
// Built with the engagement scope: an active audit sends real traffic, and the engine refuses an
// out-of-scope exchange before it plans any work. The corpus's active checks ride along when a
// passive scanner (loaded via --bchecks) is attached — the same source main.go wires explicitly, so
// an unwired server and a wired one cannot disagree about which checks run.
//
// The construction is memoised on s.scanner, which is what makes the corpus checks a property of the
// process rather than of whichever route ran first: a server that has never served an audit and one
// that has just served a hundred build the same scanner.
func (s *Server) activeScanner() *scanner.ActiveScanner {
	if s.scanner == nil {
		active := scanner.NewActiveScanner(s.store, s.logger).
			WithScope(s.scope).
			WithPace(pool.ContextPacer{}).
			// The dashboard's Pause all tasks reaches the audit loop (burpsy-react-ui-cijs).
			WithSuiteGate(s.tasks.GateCheck)
		if s.passiveScanner != nil {
			active = active.WithCorpusChecks(s.passiveScanner.ActiveChecks())
		}
		if s.toolRunner != nil {
			active = active.WithToolRunner(s.toolRunner)
		}
		s.scanner = active
	}
	return s.scanner
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
func (s *Server) runAudit(ctx context.Context, id core.ExchangeID, cfg scanner.AuditConfig, named string, unapplied []string) map[string]interface{} {
	s.scanner = s.activeScanner()
	body := map[string]interface{}{
		"started":     true,
		"exchange_id": id,
		// The check set THIS run dispatches, so it equals outcome.considered for a dispatched item. The
		// configuration-free count overstated it whenever the run's configuration removed checks.
		"active_checks": s.scanner.ActiveCheckCountUnder(cfg),
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
	task := s.tasks.Start(dash.KindAudit, auditTarget(s.store, id), uint64(s.scanner.ActiveCheckCountUnder(cfg)))
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
		s.toolLog.Record(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, ex.Method, ex.Path, 0, nil, 0, "audit", &ex.ID)
	}
	for _, f := range findings {
		s.findings.Add(s.activeFinding(f, task.ID()))
	}
	// The deferred half of a scan (gxbk). Stored-XSS claims cannot be answered by the audit itself —
	// the canary is planted during it, so no response it saw could carry it. FinishScan re-fetches the
	// targets the scan knows, renders the stored DOM surface when a browser is attached, and asks every
	// registered claim once more. Guarded by PendingCount so an audit that planted nothing sends no
	// second-pass traffic at all: a stored re-fetch is real traffic to the target, and paying it when
	// no claim could settle would be a request the operator never got value from.
	if s.scanner.PendingCount() > 0 {
		deferred, completion := s.scanner.FinishScan(ctx, cfg)
		body["deferred"] = completion
		for _, f := range deferred {
			s.findings.Add(s.activeFinding(f, task.ID()))
		}
	}
	return body
}

// ---- Auditing a selection, rather than one exchange or everything ---------------------------------
//
// Burp's New-scan dialog's third option is "Audit selected items" — "Identifies vulnerabilities in the
// selected items" (Zhw0) — and burpsy had no way to run it: POST /api/audit/{id} and its legacy alias
// audit one exchange per call, and the live sweep decides for itself which traffic to look at. The
// nearest thing to a bulk audit was the crawl-and-audit phase, which has a list of ids for the same
// reason this door does: something else decided which exchanges they are.
//
// That is the whole shape of this file's addition. The engine work is scanner.AuditSession; what was
// missing was a launch surface that takes a selection, and a place for both surfaces to share the
// half-dozen side effects of running one (the task row, the queue, the findings, the event, the two
// change notifications).

// auditSelectedReq is the POST body of the selection-driven launch.
type auditSelectedReq struct {
	// ExchangeIDs is the selection. Required and non-empty: an audit of nothing is not a scan, and
	// accepting one would put a task row on the dashboard whose meaning is "the operator's click did
	// nothing". Refused rather than started-and-immediately-finished, because the two look the same in
	// the task list and only one of them is a mistake worth naming.
	//
	// Duplicates are dropped rather than refused — see uniqueExchangeIDs — because a selection is a set
	// and a caller that assembled one from two tables has not made an error about the work.
	ExchangeIDs []core.ExchangeID `json:"exchange_ids"`
	// Config and Pool are the same two knobs /api/audit/{id} takes, resolved by the same code, so the
	// three doors cannot disagree about what a named configuration or a named pool means.
	Config string `json:"config,omitempty"`
	Pool   string `json:"pool,omitempty"`
}

// handleAuditSelected serves POST /api/audit/selected: one active scan over a list of captured
// exchanges, launched from an operator's selection in the console.
//
// # Why this answers 202 where its two siblings answer with the outcome
//
// /api/audit/{id} audits one exchange and answers when it is finished, and that is honest for one
// item: the caller waits a bounded time for a bounded answer. A selection has no such bound — the
// operator ticks what they ticked — so a synchronous reply would be an HTTP request held open for the
// length of a scan, which times out in a browser, in a proxy, and in front of whichever reverse proxy
// an engagement hides behind. The task row is the answer instead, which is exactly how /api/crawl
// reports a launched scan, and the dashboard already renders that row.
//
// # What it refuses to leave unsaid
//
// The reply echoes the count actually handed to the engine and the number of duplicates dropped, so a
// caller whose list was twice as long as the work cannot conclude the scan was twice as big. It also
// carries the configuration name and any settings the preset could not apply, for the reason SCAN-03
// exists: an endpoint that accepts a configuration name and runs something else must be detectable
// from its own reply.
func (s *Server) handleAuditSelected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req auditSelectedReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	// Resolved before anything is registered, so a bad configuration or a pool that is not saved is a
	// status code the caller can act on rather than a task row that failed already.
	cfg, named, unapplied, cerr := s.resolveAuditConfig(req.Config)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	limiter, perr := s.poolLimiter(req.Pool)
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusNotFound)
		return
	}
	ids, dropped := uniqueExchangeIDs(req.ExchangeIDs)
	if len(ids) == 0 {
		http.Error(w, "at least one exchange id is required — tick the items to audit, or POST "+
			"/api/audit/{id} to audit a single exchange", http.StatusBadRequest)
		return
	}
	target := selectionTarget(s.store, ids)
	task := s.tasks.Start(dash.KindAuditSession, target, uint64(len(ids)))

	// Detached from the request context, and with the task's own cancel attached: a scan outlives the
	// HTTP call that started it, and the dashboard's Cancel on this row has to reach the run or the row
	// is advertising a control that does nothing. Handle.WithCancel is nil-safe, so a server with no
	// task registry still gets a cancellable context here.
	go func() {
		ctx, cancel := task.WithCancel(context.Background())
		defer cancel()
		s.runBulkAudit(pool.WithLimiter(ctx, limiter), task, target, ids, cfg, "no items were selected")
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id":            task.ID(),
		"kind":               string(dash.KindAuditSession),
		"count":              len(ids),
		"exchange_ids":       ids,
		"duplicates_dropped": dropped,
		"target":             target,
		"config_name":        named,
		"unapplied":          unapplied,
		"pool":               req.Pool,
	})
}

// runBulkAudit runs one active scan over a fixed list of exchanges and reports it against the task it
// was given. Shared by the launch surfaces that audit a known list all at once — a selection, and the
// API-only scan through auditFetchedExchanges — so they cannot disagree about what a bulk audit does:
// the same item queue attached, the same findings landed on the same task, the same bounded-run
// caveats logged.
//
// It does not register the task, because its callers need the id before the run starts: the selection
// launch has to answer an HTTP request with it while the scan continues, and the API scan's run is
// inside a goroutine that must finish its own report first.
//
// The audit half of a crawl-and-audit no longer comes through here. It is fed one fetch at a time
// while the crawl is still running (crawlAuditFeed), so it has no fixed list to be handed and its
// task is finished by the feed rather than by this one call.
func (s *Server) runBulkAudit(ctx context.Context, task *dash.Handle, target string, ids []core.ExchangeID, cfg scanner.AuditConfig, emptyNote string) *scanner.SessionOutcome {
	// The task is finished even when there is nothing to audit, because "there was nothing to audit"
	// and "the audit did not run" are different facts and only one of them is a problem. The callers
	// that can be empty say which of the two the row means in their own words.
	if len(ids) == 0 {
		task.FinishWithNote(dash.Breakdown{}, emptyNote)
		return nil
	}
	// The queue, for the same reason the live sweep attaches it: a bulk audit is exactly the caller that
	// makes "which of these did the budget bound" answerable.
	cfg.Items = s.auditItems
	active := s.activeScanner()
	outcome, findings := active.AuditSession(ctx, ids, cfg)
	task.Advance(uint64(len(ids)))
	// The deferred half (gxbk), same guard and same reasoning as runAudit's tail: settle only when a
	// claim was actually registered. This is the site crawl-audit and API scans land in, so it is the
	// one that closes the gap for operator-launched batch scans.
	//
	// Deliberately BEFORE the task's finish call: the bulk paths' context is the task's own
	// (Handle.WithCancel), and Handle.finish both calls and clears the task's cancel — a finished
	// task must not be cancellable, but a finish invoked before the second look would cancel the
	// re-fetch pass mid-flight. The stored re-fetch needs the live context, so it runs first and
	// its findings land on the same task row the audit's did.
	if active.PendingCount() > 0 {
		deferred, completion := active.FinishScan(ctx, cfg)
		s.events.RecordFor(task.ID(), dash.EventAuditBounded, dash.SeverityInfo, fmt.Sprintf(
			"deferred phase of %s: %s (outstanding: %d)", target, completion.Pending, len(completion.Outstanding)))
		for _, f := range deferred {
			s.findings.Add(s.activeFinding(f, task.ID()))
		}
	}
	// A cancelled run is reported as stopped, not done. Those two rows mean different things to the
	// operator reading them — "the scan looked at all of it" and "someone stopped it after four of two
	// hundred" — and only one of them is a result. SessionOutcome carries no cancelled flag of its own,
	// because the per-item states already say how far it got; the context is the only thing that knows
	// the difference between finishing and being stopped.
	if ctx.Err() != nil {
		task.Stop(outcome.Breakdown(), "stopped: "+outcome.Summary())
	} else {
		task.FinishWithNote(outcome.Breakdown(), outcome.Summary())
	}
	for _, f := range findings {
		s.findings.Add(s.activeFinding(f, task.ID()))
	}
	s.events.RecordFor(task.ID(), dash.EventAuditBounded, auditOutcomeSeverity(outcome), fmt.Sprintf(
		"audit of %s: %s", target, outcome.Summary()))
	s.logger.Debug("bulk audit",
		zap.Int("exchanges", len(ids)),
		zap.Int("findings", len(findings)),
		zap.String("engine", outcome.Summary()))
	if outcome.Paused || outcome.TimedOut {
		s.logger.Warn("a bulk audit was bounded before it finished",
			zap.Int("exchanges", len(ids)),
			zap.Int("checks_not_admitted", outcome.NotAdmitted()),
			zap.Bool("paused", outcome.Paused),
			zap.Bool("timed_out", outcome.TimedOut))
	}
	s.live.notify(changeIssues)
	s.live.notify(changeDashboard)
	return outcome
}

// uniqueExchangeIDs drops repeats while preserving the caller's order, and returns how many it
// dropped. The count is returned rather than merely logged because it is the difference between the
// selection the caller sent and the work that ran, and a reply that reported only the latter could not
// be told apart from one that silently ignored half of a malformed list.
//
// Deliberately not api_toolkit.go's dedupeExchangeIDs, which is a different function with a similar
// name: that one assumes its input is already sorted and collapses runs of equal ids in place, which
// is what its callers have (site-map node id lists) and is not what a selection is. A selection's
// order is the operator's — the table's order at the time they ticked — so collapsing in place would
// reorder the work and report nothing about what it dropped.
func uniqueExchangeIDs(in []core.ExchangeID) ([]core.ExchangeID, int) {
	seen := make(map[core.ExchangeID]struct{}, len(in))
	out := make([]core.ExchangeID, 0, len(in))
	for _, id := range in {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, len(in) - len(out)
}

// selectionTarget names a selection for the task row: the first item the operator picked, then how
// many follow it. Naming only the first would read as a scan of that one exchange with no sign that
// more were involved; naming only a count would leave the row with nothing an operator can recognise.
func selectionTarget(store *core.TrafficStore, ids []core.ExchangeID) string {
	if len(ids) == 1 {
		return "1 selected item: " + auditTarget(store, ids[0])
	}
	return fmt.Sprintf("%d selected items: %s and %d more", len(ids), auditTarget(store, ids[0]), len(ids)-1)
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
		// The DOM dynamic tier's verdict (m97j). Carried from the scanner Finding to the store
		// here, beside Confidence — a confirmed DOM finding must reach the issues API with its
		// verdict attached, or promotion is invisible everywhere but the log.
		Confirm: string(f.Confirm),
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
