package web

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/query"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Live active audit ------------------------------------------------------------------------
//
// Mirrors crates/web/src/routes/liveaudit.rs: a switch plus two counters, owned by the web
// server (which holds the scanner) and flipped by the UI. The sweep itself is a background
// loop, bounded the way the Rust one is: walk newly-completed in-scope exchanges in id order
// (append-only store, so position is the id), hand a batch to the active scanner, and record
// what happened. An exchange whose response has not landed simply waits for a later tick.

// LiveAuditState is the operator-visible state of the live sweep: whether it is enabled and
// how many exchanges/findings the sweep has accumulated so far.
//
// `skipped` and `stalledAt` exist because `swept` alone cannot distinguish a sweep that has
// audited everything from a sweep whose cursor stopped moving. The sweep walks ids in order and
// waits at an exchange whose response has not landed — correct for a proxied request still in
// flight, and indistinguishable, from `swept` alone, from a cursor that will never move again. See
// liveAuditTick for why one such exchange used to end coverage permanently.
type LiveAuditState struct {
	enabled  atomic.Bool
	swept    atomic.Uint64
	findings atomic.Uint64
	// skipped counts exchanges the cursor advanced past without auditing, because their response
	// never landed. Never folded into swept: an exchange nobody looked at is not an exchange that
	// came back clean.
	skipped atomic.Uint64
	// stalledAt is the id the cursor is currently waiting on, +1 so that zero means "not waiting"
	// (id 0 is a real exchange id in a position-is-the-id store). Read only for the operator view.
	stalledAt atomic.Uint64
	// reached and recorded are where the cursor has walked to and how many exchanges the store held
	// when it got there. Their difference is Behind(): the sweep's backlog.
	//
	// This is the arithmetic that makes the pane honest under a crawl. The sweep admits at most 200
	// exchanges every liveAuditSweepInterval — about 66 a second at the shipped interval — and a
	// crawler outpaces that without trying. `swept` then keeps climbing while the gap between it and
	// the capture grows, so the pane whose job is to demonstrate DASH-03 would be the one reporting a
	// count with no idea how much it was behind.
	reached  atomic.Uint64
	recorded atomic.Uint64
	// collapsed counts checks the shared ledger refused because an identical (dispatch unit, check)
	// had already run. Not a caveat — this work ran, see SessionOutcome.AlreadyCovered — but reported,
	// because it is the whole reason the sweep shares a ledger across ticks and the only way to see
	// the saving is happening.
	collapsed atomic.Uint64
	// ledgerResets counts how many times the shared ledger was dropped at its unit cap. Each reset
	// means checks that had already been collapsed will re-dispatch once more, so a nonzero count is
	// something the operator should be able to see rather than infer from a request rate.
	ledgerResets atomic.Uint64

	// queryMu guards the DSL-03 filter below. A mutex rather than an atomic because the expression
	// and the source text it was parsed from must never be read apart: the view reports the text and
	// the sweep evaluates the expression, and a pane showing one query while another filters traffic
	// is worse than no filter at all.
	queryMu  sync.RWMutex
	query    *query.Expr
	querySrc string
}

// NewLiveAuditState creates a disabled live audit state.
func NewLiveAuditState() *LiveAuditState {
	return &LiveAuditState{}
}

// IsEnabled reports whether the sweep loop should run.
func (la *LiveAuditState) IsEnabled() bool { return la.enabled.Load() }

// SetEnabled flips the switch.
func (la *LiveAuditState) SetEnabled(on bool) { la.enabled.Store(on) }

// Record accumulates the outcome of one sweep tick.
func (la *LiveAuditState) Record(swept, findings uint64) {
	la.swept.Add(swept)
	la.findings.Add(findings)
}

// Swept returns the total exchanges handed to the scanner.
func (la *LiveAuditState) Swept() uint64 { return la.swept.Load() }

// FindingCount returns the total findings the sweep produced.
func (la *LiveAuditState) FindingCount() uint64 { return la.findings.Load() }

// Skipped returns how many exchanges the cursor advanced past unaudited because their response
// never landed. Reported alongside Swept rather than added to it — DASH-03's rule, applied to the
// pane that exists to demonstrate it.
func (la *LiveAuditState) Skipped() uint64 { return la.skipped.Load() }

// StalledAt returns the exchange id the cursor is waiting on and whether it is waiting at all. A
// sweep waiting on an in-flight response is normal; a sweep waiting on the same id for many ticks
// is the shape of lost coverage, which is why the id is exposed rather than merely counted.
func (la *LiveAuditState) StalledAt() (uint64, bool) {
	v := la.stalledAt.Load()
	if v == 0 {
		return 0, false
	}
	return v - 1, true
}

// recordSkipped accounts for one exchange the cursor gave up waiting on.
func (la *LiveAuditState) recordSkipped(n uint64) { la.skipped.Add(n) }

// Behind reports how many recorded exchanges the cursor has not reached yet — the sweep's backlog.
//
// Saturating rather than signed: `recorded` and `reached` are written by the same goroutine but read
// by handlers, so a reader can catch them mid-update and see reached briefly ahead. Zero is the right
// answer for that instant; a negative backlog is not an answer at all.
func (la *LiveAuditState) Behind() uint64 {
	recorded, reached := la.recorded.Load(), la.reached.Load()
	if reached >= recorded {
		return 0
	}
	return recorded - reached
}

// Collapsed reports checks the shared ledger refused as already covered. See the field doc: reported,
// never a caveat.
func (la *LiveAuditState) Collapsed() uint64 { return la.collapsed.Load() }

// LedgerResets reports how many times the shared ledger was dropped at its unit cap.
func (la *LiveAuditState) LedgerResets() uint64 { return la.ledgerResets.Load() }

// recordPosition stores where the cursor reached and how much had been recorded when it got there.
func (la *LiveAuditState) recordPosition(reached, recorded uint64) {
	la.reached.Store(reached)
	la.recorded.Store(recorded)
}

func (la *LiveAuditState) recordCollapsed(n uint64) { la.collapsed.Add(n) }
func (la *LiveAuditState) recordLedgerReset()       { la.ledgerResets.Add(1) }

// SetQuery installs the live-audit scope query (DSL-03), or clears it when src is empty.
//
// The full grammar is accepted with no field restriction, which is the difference between this gate
// and the crawler's. The crawler decides *before* the fetch, so `status`, `mime` and `body` have no
// obtainable value and it refuses any query naming them (see internal/query/fields.go). Live audit
// decides *after* the response is stored, so all five fields are real answers and every query the
// parser accepts can be evaluated honestly here.
//
// A parse error is returned and nothing is installed: the previous filter — including "no filter" —
// stays in force. Installing a partially-understood query would silently change which traffic is
// audited, which is the one thing an operator setting a filter must be able to rely on.
func (la *LiveAuditState) SetQuery(src string) error {
	if src == "" {
		la.queryMu.Lock()
		la.query, la.querySrc = nil, ""
		la.queryMu.Unlock()
		return nil
	}
	expr, err := query.Parse(src)
	if err != nil {
		return err
	}
	la.queryMu.Lock()
	la.query, la.querySrc = expr, src
	la.queryMu.Unlock()
	return nil
}

// Query returns the installed filter and the source text it was parsed from, together — see queryMu.
func (la *LiveAuditState) Query() (*query.Expr, string) {
	la.queryMu.RLock()
	defer la.queryMu.RUnlock()
	return la.query, la.querySrc
}

// noteStall records which id the cursor is waiting on, or clears it when the cursor is moving.
func (la *LiveAuditState) noteStall(id uint64, waiting bool) {
	if !waiting {
		la.stalledAt.Store(0)
		return
	}
	la.stalledAt.Store(id + 1)
}

// liveAuditView mirrors dashboard.ts's LiveAuditResp.
//
// Skipped and StalledAt are carried next to Swept rather than folded into it: "audited 400" and
// "audited 400, gave up on 3, currently waiting on 404" are different claims about coverage, and
// only the second one is honest when it is true. This is DASH-03's rule applied to the pane whose
// job is to demonstrate it.
type liveAuditView struct {
	Wired    bool   `json:"wired"`
	Enabled  bool   `json:"enabled"`
	Hint     string `json:"hint,omitempty"`
	Swept    uint64 `json:"swept,omitempty"`
	Findings uint64 `json:"findings,omitempty"`
	Skipped  uint64 `json:"skipped,omitempty"`
	// Behind is recorded-but-not-yet-reached exchanges: the sweep's backlog. Not omitempty, unlike the
	// counters above — a zero backlog is the single most useful thing this field ever says ("the sweep
	// is caught up"), and omitting it would make caught-up indistinguishable from an older build that
	// did not report a backlog at all.
	Behind uint64 `json:"behind"`
	// Collapsed is checks the shared ledger refused as already covered, and LedgerResets is how many
	// times that ledger was dropped at its unit cap. Reported, never folded into a caveat: this work
	// ran. See LiveAuditState's field docs.
	Collapsed    uint64 `json:"collapsed"`
	LedgerResets uint64 `json:"ledger_resets"`
	// Query is the DSL-03 filter as the operator wrote it, empty for none.
	Query string `json:"query,omitempty"`
	// StalledAt is the exchange id the cursor is waiting on, omitted when it is moving.
	StalledAt *uint64 `json:"stalled_at,omitempty"`
}

// liveAuditUnwired reports a 200 with wired:false rather than a 404, matching the other
// feature surfaces so an unwired process does not look like a typo in the route.
func liveAuditUnwired() liveAuditView {
	return liveAuditView{
		Wired:   false,
		Enabled: false,
		Hint:    "live active audit needs a loaded check set; start with --bchecks",
	}
}

func (s *Server) liveAuditStatus() liveAuditView {
	if s.liveAudit == nil {
		return liveAuditUnwired()
	}
	_, querySrc := s.liveAudit.Query()
	v := liveAuditView{
		Wired:        true,
		Enabled:      s.liveAudit.IsEnabled(),
		Swept:        s.liveAudit.Swept(),
		Findings:     s.liveAudit.FindingCount(),
		Skipped:      s.liveAudit.Skipped(),
		Behind:       s.liveAudit.Behind(),
		Collapsed:    s.liveAudit.Collapsed(),
		LedgerResets: s.liveAudit.LedgerResets(),
		Query:        querySrc,
	}
	if id, waiting := s.liveAudit.StalledAt(); waiting {
		v.StalledAt = &id
	}
	return v
}

// auditedExchangeQuery adapts a stored, completed exchange to query.Queryable for the live-audit gate
// (DSL-03).
//
// Distinct from filteredExchangeQuery, which serves the history filter and deliberately reports Mime
// as absent and Body as the *request* body. Live audit runs after the response is stored, so all five
// fields have real answers, and reporting two of them absent here would make `mime = "text/html"`
// false for every exchange and `not mime = "text/html"` true for every one — the silent-wrong-answer
// this package's Fields() machinery exists to prevent, arrived at from the other direction.
//
// Mime and Body read the response through the store on demand, and cache it: the sweep evaluates one
// query per exchange and a query naming both fields would otherwise resolve the message twice. A query
// naming neither never resolves it at all, which is why this is lazy rather than eager — the common
// case is a host or status filter that touches no bytes.
type auditedExchangeQuery struct {
	store *core.TrafficStore
	ex    *core.Exchange
	// resolved is the memo flag; resp is nil either because there is no response or because reading it
	// failed. Both mean the same thing to a comparison: absent, never a wrong value.
	resolved bool
	resp     *core.StoredMessage
}

func (q *auditedExchangeQuery) Host() string   { return q.ex.Host }
func (q *auditedExchangeQuery) Method() string { return q.ex.Method }
func (q *auditedExchangeQuery) Path() string   { return q.ex.Path }
func (q *auditedExchangeQuery) Status() int {
	if q.ex.Status == nil {
		return 0
	}
	return int(*q.ex.Status)
}

func (q *auditedExchangeQuery) response() *core.StoredMessage {
	if q.resolved {
		return q.resp
	}
	q.resolved = true
	if q.ex.Response == nil {
		return nil
	}
	if msg, err := q.store.Get(*q.ex.Response); err == nil {
		q.resp = msg
	}
	return q.resp
}

// Mime is the response Content-Type with any parameters stripped, so `mime = "text/html"` matches
// `text/html; charset=utf-8` — the form servers actually send.
//
// The stored value first, because since core.Exchange carries Mime this is the same answer without
// resolving the response at all. The fallback is not dead code: a row restored from a database
// written before the mime column existed has an empty Mime and real response bytes, and reading the
// header is strictly better than reporting "absent" for a response whose type is right there. Both
// paths go through core.MimeFromContentType so the two cannot reduce the value differently — the
// local strip-and-trim that used to live here also did not fold case, which made this row's `mime`
// comparison disagree with the History column beside it on a server sending `text/HTML`.
func (q *auditedExchangeQuery) Mime() string {
	if q.ex.Mime != "" {
		return q.ex.Mime
	}
	msg := q.response()
	if msg == nil {
		return ""
	}
	return core.MimeFromContentType(string(msg.Header("Content-Type")))
}

func (q *auditedExchangeQuery) Body() []byte {
	msg := q.response()
	if msg == nil {
		return nil
	}
	return msg.Body()
}

// Annotation answers from the index row. See filteredExchangeQuery.Annotation for why known is true.
func (q *auditedExchangeQuery) Annotation() (string, string, bool) {
	comment := ""
	if q.ex.Notes != nil {
		comment = *q.ex.Notes
	}
	return q.ex.Highlight, comment, true
}

// Header reads the response head through the same memoised resolution Mime and Body use, so a query
// naming a header and a body resolves the message once rather than twice.
func (q *auditedExchangeQuery) Header(name string) ([]string, bool) {
	msg := q.response()
	if msg == nil {
		return nil, false
	}
	raw, present := msg.HeaderValues(name)
	if !present {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		out = append(out, string(value))
	}
	return out, true
}

// ResponseLen and DurationUs both read the index row rather than the message, so neither forces the
// lazy response resolution above. Same absence rules as filteredExchangeQuery: presence comes from
// Response and from Measured, never from the value being non-zero.
func (q *auditedExchangeQuery) ResponseLen() (int64, bool) {
	if q.ex.Response == nil {
		return 0, false
	}
	return int64(q.ex.ResponseLen), true
}

func (q *auditedExchangeQuery) DurationUs() (int64, bool) {
	if !q.ex.Duration.Measured {
		return 0, false
	}
	return int64(q.ex.Duration.Us), true
}

// liveAuditAdmits is the sweep's whole admission decision for one exchange: the engagement scope, then
// the operator's query.
//
// Scope first and always. The query narrows what the operator wants audited; it can never widen it
// past the engagement, so an exchange out of scope is refused before the query is even parsed against
// it.
func (s *Server) liveAuditAdmits(ex *core.Exchange) bool {
	if !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
		return false
	}
	// An exchange with no response is refused before the query is consulted, and this is not merely
	// defensive. It is what makes the full grammar safe here.
	//
	// The premise of accepting `mime` and `body` at all is that live audit runs after the response is
	// stored, so those fields have real values. For an exchange with no response they do not, and the
	// query package's absent-field rule then bites in the direction internal/query/fields.go warns
	// about: `mime = "text/html"` is correctly false, and `not mime = "text/html"` is *true* — so a
	// negated filter would admit exactly the exchanges that cannot be audited at all.
	//
	// The sweep's walk already stops at such an exchange, so today nothing reaches here with one. That
	// makes this an invariant held by one caller, which is the kind that stops being true when a second
	// caller appears. Held locally instead.
	if ex.Response == nil {
		return false
	}
	expr, _ := s.liveAudit.Query()
	if expr == nil {
		return true
	}
	return expr.Match(&auditedExchangeQuery{store: s.store, ex: ex})
}

// liveAuditSweepInterval is how often the loop looks for newly-completed exchanges.
//
// Three seconds is a compromise the operator feels in both directions: long enough that an idle
// process is not walking the store continuously, short enough that a click on the toggle produces
// visible findings while the operator is still looking at the tab.
const liveAuditSweepInterval = 3 * time.Second

// liveAuditBatchSize bounds how many exchanges one tick admits.
//
// Named because it is half of the sweep's throughput ceiling — 200 every liveAuditSweepInterval is
// about 66 exchanges a second, which a crawler outpaces without trying. The bound stays; what changed
// is that LiveAuditState.Behind() now reports the backlog it creates, so the pane says "swept 400,
// 9,000 behind" rather than "swept 400".
const liveAuditBatchSize = 200

// liveAuditSeverity grades a finished sweep for the event log. A sweep the breaker paused or the budget
// bounded is a warning: the next tick starts again against a target that has already stopped answering,
// and an operator scanning the log must be able to see that without reading every line's counts.
func liveAuditSeverity(outcome *scanner.SessionOutcome) dash.Severity {
	if outcome == nil {
		return dash.SeverityInfo
	}
	if outcome.Paused || outcome.TimedOut || outcome.FailedItems > 0 {
		return dash.SeverityWarn
	}
	return dash.SeverityInfo
}

// liveAuditTarget names the batch for the task list. The first exchange's host stands for the sweep
// because a batch is walked in id order from one high-water mark, so it is overwhelmingly one host's
// traffic; the count is appended so a batch spanning several is not misread as one.
func liveAuditTarget(store *core.TrafficStore, ids []core.ExchangeID) string {
	if len(ids) == 0 {
		return "no exchanges"
	}
	ex, err := store.GetExchange(ids[0])
	if err != nil {
		return fmt.Sprintf("%d exchange(s)", len(ids))
	}
	return fmt.Sprintf("%s (%d exchange(s))", ex.Host, len(ids))
}

// StartLiveAuditSweep launches the background sweep loop. It walks newly-completed
// in-scope exchanges in id order and hands batches to the active scanner while enabled.
// The caller owns the context; when it is cancelled the loop stops at the next tick.
func (s *Server) StartLiveAuditSweep(ctx context.Context) {
	s.startLiveAuditSweep(ctx, liveAuditSweepInterval)
}

// startLiveAuditSweep is StartLiveAuditSweep with the interval exposed, so a test can pin the
// opt-in (CRAWL-06) against a real target inside a test's patience rather than waiting whole
// multiples of the shipped interval to observe that nothing was sent.
func (s *Server) startLiveAuditSweep(ctx context.Context, every time.Duration) {
	if s.liveAudit == nil {
		s.liveAudit = NewLiveAuditState()
	}
	go s.liveAuditLoop(ctx, every)
}

func (s *Server) liveAuditLoop(ctx context.Context, every time.Duration) {
	run := liveAuditRun{}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// The switch is read here, before anything else happens — before the store is walked,
			// before a batch is built, and long before the scanner is reached. CRAWL-06 is that
			// nothing is audited until the operator opts in, and the cheapest way to be sure of that
			// is for the disabled path to do nothing at all.
			if !s.liveAudit.IsEnabled() {
				continue
			}
			s.liveAuditTick(ctx, &run)
		}
	}
}

// liveAuditRun is everything one sweep loop carries between ticks.
//
// The ledger is here, rather than being rebuilt inside each AuditSession call, because the sweep is the
// one audit caller that repeats forever. See AuditConfig.Ledger: a per-run ledger makes every
// host-scoped and path-scoped check re-dispatch every liveAuditSweepInterval for the life of the
// process, which is invisible against trickling proxy traffic and a request storm against a crawl.
//
// Everything else about a run stays per-tick. The time budget, the request budget and both failure
// breakers are properties of one batch, and carrying those across ticks would let one slow minute
// bound the sweep permanently — the same wedge the cursor's stall counter exists to prevent, arrived
// at through the budget instead.
type liveAuditRun struct {
	cursor liveAuditCursor
	ledger *scanner.AuditLedger
}

// liveAuditLedgerUnitCap bounds the shared ledger by dispatch units — hosts and paths.
//
// Twenty thousand units is a few megabytes of keys and bitsets, and comfortably more paths than any
// single engagement's in-scope surface. Past it the ledger is dropped and rebuilt rather than grown
// without limit, because a ledger that grows with the site is the one piece of audit state that does,
// and an unbounded one turns a long crawl into a memory leak.
//
// A reset is not free and is not silent: the checks it had collapsed will each re-dispatch once more,
// so the reset is counted, reported in the view, and recorded as an event. That is the honest trade —
// a bounded, visible re-dispatch instead of either unbounded memory or a silent cap.
const liveAuditLedgerUnitCap = 20_000

// auditLedger returns the ledger for this tick, rebuilding it when it has outgrown its unit cap.
func (r *liveAuditRun) auditLedger(state *LiveAuditState, events *dash.EventLog, logger *zap.Logger) *scanner.AuditLedger {
	if r.ledger == nil {
		r.ledger = scanner.NewAuditLedger()
		return r.ledger
	}
	if units := r.ledger.Units(); units > liveAuditLedgerUnitCap {
		r.ledger = scanner.NewAuditLedger()
		state.recordLedgerReset()
		events.Record(dash.EventLedgerReset, dash.SeverityWarn, fmt.Sprintf(
			"the live sweep's admission ledger passed its cap of %d dispatch units (%d) and was reset; already-covered checks will dispatch once more",
			liveAuditLedgerUnitCap, units))
		if logger != nil {
			logger.Warn("live audit admission ledger reset at its unit cap",
				zap.Int("units", units),
				zap.Int("cap", liveAuditLedgerUnitCap))
		}
	}
	return r.ledger
}

// liveAuditCursor is the sweep's position, plus how long it has been stuck there.
//
// The stall count is the whole point. The sweep must wait at an exchange whose response has not
// landed, because ids are handed out when a request is captured and a later id can complete first —
// auditing past a gap would skip the request still in flight. But "wait" and "wait forever" are
// different behaviours, and before this counter existed only the first was implemented: one
// exchange that never got a response ended live-audit coverage for the life of the process, while
// Swept() went on reporting the number it had reached. A silent permanent coverage loss is the
// exact failure this codebase's style exists to prevent, so the wait is now bounded and what it
// gave up on is counted.
type liveAuditCursor struct {
	at core.ExchangeID
	// stalls counts consecutive ticks that made no progress from `at`.
	stalls int
}

// liveAuditStallTicks is how many consecutive no-progress ticks the sweep tolerates before it
// advances past the exchange it is waiting on.
//
// Ten ticks at the shipped three-second interval is thirty seconds — comfortably longer than any
// response the proxy is still streaming, and short enough that an operator watching the pane sees
// the number move again rather than concluding the feature is broken. The exchange it gives up on
// is counted as skipped, never as swept.
const liveAuditStallTicks = 10

// liveAuditTick collects one bounded batch of newly-completed in-scope exchanges and hands
// them to the scanner, recording the outcome. Sequential and bounded rather than
// exhaustive: an exchange whose response has not landed waits for a later tick, and
// everything after it waits with it.
func (s *Server) liveAuditTick(ctx context.Context, run *liveAuditRun) {
	cursor := &run.cursor
	_, total := s.store.Count()
	ids := make([]core.ExchangeID, 0, liveAuditBatchSize)
	next := cursor.at
	// waitingOn is the id the walk stopped at because its response had not landed. Distinct from
	// "ran out of exchanges": only the former is something the cursor can get permanently stuck on.
	var waitingOn core.ExchangeID
	waiting := false
	for uint64(next) < uint64(total) && len(ids) < liveAuditBatchSize {
		ex, err := s.store.GetExchange(next)
		if err != nil {
			break
		}
		if ex.Response == nil {
			waitingOn, waiting = next, true
			break
		}
		if s.liveAuditAdmits(ex) {
			ids = append(ids, next)
		}
		next++
	}
	// Recorded before any early return, so the backlog is current even on a tick that does no work —
	// a sweep parked behind a stalled exchange while a crawl races ahead is exactly when an operator
	// needs to see how far behind it is.
	s.liveAudit.recordPosition(uint64(next), uint64(total))

	if next == cursor.at {
		// No progress. If we are parked on a response that never landed, give it a bounded number of
		// ticks and then step over it, counting it as skipped — an exchange nobody audited is not an
		// exchange that came back clean. Without this the sweep waits here forever.
		if waiting {
			cursor.stalls++
			s.liveAudit.noteStall(uint64(waitingOn), true)
			if cursor.stalls >= liveAuditStallTicks {
				s.logger.Warn("live audit advancing past an exchange whose response never landed",
					zap.Uint64("exchange", uint64(waitingOn)),
					zap.Int("ticks_waited", cursor.stalls))
				s.events.Record(dash.EventLiveAuditSkipped, dash.SeverityWarn, fmt.Sprintf(
					"exchange %d never recorded a response after %d sweeps; the live audit advanced past it unaudited",
					waitingOn, cursor.stalls))
				cursor.at = waitingOn + 1
				cursor.stalls = 0
				s.liveAudit.recordSkipped(1)
				s.liveAudit.noteStall(0, false)
			} else if cursor.stalls == 1 {
				// Once, on the tick the wait begins, rather than every tick it continues: a stall that
				// resolves normally is unremarkable and should not fill the log.
				s.events.Record(dash.EventLiveAuditStalled, dash.SeverityInfo, fmt.Sprintf(
					"the live audit is waiting for exchange %d's response before it can go further", waitingOn))
			}
		}
		return
	}

	cursor.at = next
	cursor.stalls = 0
	s.liveAudit.noteStall(uint64(waitingOn), waiting)
	if len(ids) == 0 {
		return
	}

	if s.scanner == nil {
		s.logger.Warn("live audit enabled but no active scanner wired")
		return
	}
	// Registered per sweep-with-work rather than per tick: a tick that found nothing new returned
	// above, and a registry filling with empty three-second ticks would bury the runs that matter.
	task := s.tasks.Start(dash.KindLiveAudit, liveAuditTarget(s.store, ids), uint64(len(ids)))
	start := time.Now()
	// AuditSession rather than AuditMultiple: this is the highest-volume audit path in the process, so
	// it is where the engine's bounding pays for itself — a sweep over 200 captures of one host
	// dispatches each per-URL check once and refuses the rest as already covered. The session outcome
	// is the only place that saving is visible, and a sweep that reported "200 exchanges, 3 findings"
	// while quietly admitting a fraction of the work would be the exact claim the engine exists to
	// prevent.
	// The ledger is the one part of the config that outlives this tick — see liveAuditRun.
	cfg := s.scanner.AuditConfig()
	cfg.Ledger = run.auditLedger(s.liveAudit, s.events, s.logger)
	// The sweep is the highest-volume producer of audit items, so it is the one that makes the queue
	// worth having: this is where "swept 400" becomes 400 rows an operator can ask which of them the
	// budget bounded. The queue's own cap (scanner.DefaultAuditItemCap) is what keeps a sweep that
	// runs for hours from growing it without limit, and the endpoint reports the evictions.
	cfg.Items = s.auditItems
	outcome, findings := s.scanner.AuditSession(ctx, ids, cfg)
	s.liveAudit.recordCollapsed(uint64(outcome.AlreadyCovered()))
	task.Advance(uint64(len(ids)))
	// The engine's own outcome, projected onto the dashboard's four buckets: a sweep the failure
	// breaker paused or the budget bounded finishes here with a non-complete result, so the
	// dashboard shows it as a run that stopped looking rather than as a clean one.
	task.FinishWithNote(outcome.Breakdown(), outcome.Summary())
	for _, f := range findings {
		s.findings.Add(s.activeFinding(f, task.ID()))
	}
	s.liveAudit.Record(uint64(len(ids)), uint64(len(findings)))
	// This used to be a toollog row: Record(ToolScanner, host, port, tls, "LIVE", "/audit", 0, ...) —
	// a *request* row for something that is not a request, with an invented method and an invented
	// path, so that a sweep completing could travel down a pipe shaped for sent requests. The probes
	// the sweep actually sends belong in toollog and are logged by the sender that sends them; the
	// sweep finishing is an event. See internal/dash/events.go on why the two logs are separate.
	//
	// Recorded per sweep-with-work, matching the task registration above, so the event log and the task
	// table describe the same set of runs.
	s.events.RecordFor(task.ID(), dash.EventLiveAuditBounded, liveAuditSeverity(outcome), fmt.Sprintf(
		"live sweep of %s: %s", liveAuditTarget(s.store, ids), outcome.Summary()))
	s.logger.Debug("live audit sweep",
		zap.Int("exchanges", len(ids)),
		zap.Int("findings", len(findings)),
		zap.String("engine", outcome.Summary()),
		zap.Duration("took", time.Since(start)))
	// A sweep the failure breaker stopped is not a sweep that found nothing, and it is worth more than
	// a debug line: the next tick will start again against a target that has already stopped answering.
	if outcome.Paused || outcome.TimedOut {
		s.logger.Warn("live audit sweep was bounded before it finished",
			zap.Int("exchanges", len(ids)),
			zap.Int("checks_not_admitted", outcome.NotAdmitted()),
			zap.Bool("paused", outcome.Paused),
			zap.Bool("timed_out", outcome.TimedOut))
	}
}
