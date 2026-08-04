// Tests for the audit engine driving real ActiveScanner.Audit runs — the half of gap 3 that a ported
// but uncalled engine would leave open. Every test here asserts two things together: that a budget or
// breaker actually stopped dispatch, and that what was skipped came back *named* rather than missing.
package scanner

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// seedAuditExchange puts one request/response pair in the store and indexes an exchange over it,
// returning the exchange id (which is its position, so the first is 0).
func seedAuditExchange(t *testing.T, store *core.TrafficStore, host string, port uint16, path, body string) uint64 {
	t.Helper()
	reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+body), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     host,
		Port:     port,
		Method:   "GET",
		Path:     path,
	}
	store.AddExchange(ex)
	return ex.ID
}

// reflectingTarget starts a server that echoes ?xss= back into its body, so probes that reach it
// succeed and the request meter counts real sends.
func reflectingTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>" + r.URL.Query().Get("xss") + "</body></html>"))
		}))
	}()
	return targetPort(t, ln.Addr().String())
}

// deadTarget returns a port with nothing listening on it: every probe to it fails to connect, which
// is what the failure breakers exist for.
func deadTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := targetPort(t, ln.Addr().String())
	ln.Close()
	return port
}

func targetPort(t *testing.T, addr string) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return uint16(port)
}

// probeChecksOnly enables the three implemented probe checks and nothing else: one per-URL dispatch
// unit with three steps in it, which is the smallest shape that shows a unit being abandoned.
func probeChecksOnly() *ScanConfig {
	return &ScanConfig{
		MaxConcurrency:     1,
		Timeout:            10 * time.Second,
		CheckSqli:          true,
		CheckXss:           true,
		CheckPathTraversal: true,
	}
}

func Test_the_disposition_counts_partition_the_enabled_check_set(t *testing.T) {
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "h.test", 80, "/", "<html>nothing here</html>")
	// Every switch on, no sender: the offline path, where no probe is attempted at all.
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{
		MaxConcurrency:     1,
		Timeout:            5 * time.Second,
		CheckSqli:          true,
		CheckXss:           true,
		CheckPathTraversal: true,
		CheckSSRF:          true,
		CheckXXE:           true,
		CheckJwtWeak:       true,
		CheckJSVulns:       true,
	})

	outcome, _ := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if got, want := outcome.Considered(), scan.ActiveCheckCount(); got != want {
		t.Errorf("considered = %d, want the whole enabled check set (%d)", got, want)
	}
	if got, want := scan.ActiveCheckCount(), 7; got != want {
		t.Errorf("enabled checks = %d, want %d", got, want)
	}
	if outcome.State != ItemStateAudited {
		t.Errorf("state = %s, want audited", outcome.State.Label())
	}
	// The histogram must sum to the same number: it is the same partition, read a different way.
	sum := 0
	for _, d := range outcome.Dispositions() {
		sum += d.Count
		if d.Reason == "" {
			t.Errorf("%s carries no reason", d.Disposition)
		}
	}
	if sum != outcome.Considered() {
		t.Errorf("disposition histogram sums to %d, want %d", sum, outcome.Considered())
	}
}

func Test_unimplemented_checks_are_reported_unsupported_rather_than_silently_absent(t *testing.T) {
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "h.test", 80, "/", "<html></html>")
	// The two switches with nothing behind them, and nothing else. Before the audit engine these
	// produced an audit indistinguishable from a clean one.
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{
		MaxConcurrency: 1,
		CheckSSRF:      true,
		CheckXXE:       true,
	})
	if got := scan.UnimplementedCheckCount(); got != 2 {
		t.Fatalf("unimplemented checks = %d, want 2", got)
	}

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 from checks that cannot run", len(findings))
	}
	if outcome.Ran != 0 {
		t.Errorf("ran = %d, want 0", outcome.Ran)
	}
	if outcome.Skipped != 2 {
		t.Errorf("skipped = %d, want both unimplemented checks counted", outcome.Skipped)
	}
	if outcome.Considered() != 2 {
		t.Errorf("considered = %d, want 2", outcome.Considered())
	}
	for _, d := range outcome.Dispositions() {
		if d.Disposition == DispositionUnsupported && d.Count != 2 {
			t.Errorf("unsupported bucket = %d, want 2", d.Count)
		}
	}
	if outcome.RequestsSent != 0 {
		t.Errorf("requests sent = %d, want 0", outcome.RequestsSent)
	}
}

func Test_a_zero_request_budget_admits_nothing_and_names_the_reason_for_every_check(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(probeChecksOnly())

	cfg := DefaultAuditConfig()
	// A cap of zero, which is not the same value as "uncapped" — that distinction is what OptUint32
	// exists for, and this is the run that proves it is load-bearing.
	cfg.MaxRequests = SomeUint32(0)
	outcome, findings := scan.AuditWithin(context.Background(), id, cfg)

	if outcome.State != ItemStateBounded {
		t.Errorf("state = %s, want bounded", outcome.State.Label())
	}
	if outcome.RequestsSent != 0 {
		t.Errorf("requests sent = %d, want 0: a spent budget must stop dispatch, not trim it", outcome.RequestsSent)
	}
	if outcome.RequestBudgetSpent != 3 {
		t.Errorf("request-budget-spent = %d, want all 3 checks attributed", outcome.RequestBudgetSpent)
	}
	if outcome.Considered() != 3 {
		t.Errorf("considered = %d, want 3", outcome.Considered())
	}
	if outcome.NotAdmitted() != 3 {
		t.Errorf("not admitted = %d, want 3", outcome.NotAdmitted())
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
	if outcome.State.CompletedAudit() {
		t.Error("a bounded item must not count as a completed audit")
	}
}

func Test_a_spent_request_budget_stops_dispatch_after_the_check_that_spent_it(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(probeChecksOnly())

	cfg := DefaultAuditConfig()
	// One probe. The first check overshoots it — admission bounds what *starts*, and a check already
	// running is never killed halfway — and the rest are refused.
	cfg.MaxRequests = SomeUint32(1)
	outcome, _ := scan.AuditWithin(context.Background(), id, cfg)

	if outcome.State != ItemStateBounded {
		t.Errorf("state = %s, want bounded", outcome.State.Label())
	}
	if outcome.Ran != 1 {
		t.Errorf("ran = %d, want exactly the one check that was admitted", outcome.Ran)
	}
	if outcome.RequestsSent == 0 {
		t.Error("the admitted check should have sent its probes")
	}
	if outcome.RequestBudgetSpent != 2 {
		t.Errorf("request-budget-spent = %d, want the 2 checks never started", outcome.RequestBudgetSpent)
	}
	if outcome.Considered() != 3 {
		t.Errorf("considered = %d, want 3", outcome.Considered())
	}
}

func Test_a_spent_time_budget_bounds_a_real_audit_rather_than_reporting_it_clean(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(probeChecksOnly())

	cfg := DefaultAuditConfig()
	cfg.TimeBudget = time.Nanosecond
	outcome, findings := scan.AuditWithin(context.Background(), id, cfg)

	if outcome.State != ItemStateBounded {
		t.Errorf("state = %s, want bounded", outcome.State.Label())
	}
	if !outcome.TimedOut {
		t.Error("timed out should be set, so a caller can tell this from a clean run")
	}
	if outcome.NotRun != 3 {
		t.Errorf("not-run = %d, want all 3 checks attributed to the spent time budget", outcome.NotRun)
	}
	if outcome.RequestsSent != 0 {
		t.Errorf("requests sent = %d, want 0: nothing may go out after the budget is spent", outcome.RequestsSent)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
	if outcome.Cancelled {
		t.Error("the context was live; only the engine's own budget was spent")
	}
}

func Test_a_cancelled_context_bounds_the_run_and_is_distinguishable_from_a_spent_budget(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(probeChecksOnly())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, _ := scan.AuditWithin(ctx, id, DefaultAuditConfig())

	if outcome.State != ItemStateBounded {
		t.Errorf("state = %s, want bounded", outcome.State.Label())
	}
	if !outcome.Cancelled {
		t.Error("cancelled should be set: the operator stopped this, the budget did not")
	}
	if outcome.NotRun != 3 {
		t.Errorf("not-run = %d, want all 3 checks attributed", outcome.NotRun)
	}
	if outcome.Considered() != 3 {
		t.Errorf("considered = %d, want 3", outcome.Considered())
	}
}

func Test_auditing_two_captures_of_one_url_dispatches_each_per_url_check_once(t *testing.T) {
	store := core.NewTrafficStore()
	first := seedAuditExchange(t, store, "h.test", 80, "/shop?id=1", "<html>one</html>")
	second := seedAuditExchange(t, store, "h.test", 80, "/shop?id=1", "<html>two</html>")
	// Offline, and one worker: the ledger's refusal is what is under test, not the network, and with
	// one worker the *attribution* is deterministic — the second capture is the one refused.
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{
		MaxConcurrency:     1,
		CheckSqli:          true,
		CheckPathTraversal: true,
		CheckJwtWeak:       true,
	})

	session, _ := scan.AuditSession(context.Background(), []uint64{first, second}, DefaultAuditConfig())

	if len(session.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(session.Items))
	}
	if got := session.Items[0].Outcome.Ran; got != 3 {
		t.Errorf("first capture ran %d checks, want all 3", got)
	}
	if got := session.Items[1].Outcome.AlreadyCovered; got != 2 {
		t.Errorf("second capture refused %d checks as already covered, want the 2 per-URL ones", got)
	}
	if got := session.Items[1].Outcome.Ran; got != 1 {
		t.Errorf("second capture ran %d checks, want the 1 per-request check", got)
	}
	// One per-URL unit shared by both captures, plus one per-request unit each.
	if session.DispatchUnits != 3 {
		t.Errorf("dispatch units = %d, want 3", session.DispatchUnits)
	}
	if session.NotAdmitted() != 2 {
		t.Errorf("not admitted = %d, want 2", session.NotAdmitted())
	}
	// Scope collapse is a saving, not a coverage regression: both items still completed.
	if session.Completed() != 2 {
		t.Errorf("completed = %d, want 2", session.Completed())
	}
	if session.Items[0].ExchangeID != first || session.Items[1].ExchangeID != second {
		t.Error("items must come back in the order requested")
	}
}

// The Go engine's one behavioural divergence from Rust is that a session dispatches items
// concurrently, so the bound has to hold under contention rather than by construction. The totals are
// what must be exact; which worker won the admission is not.
func Test_a_concurrent_session_admits_each_pair_once_however_the_workers_interleave(t *testing.T) {
	store := core.NewTrafficStore()
	ids := make([]uint64, 8)
	for i := range ids {
		ids[i] = seedAuditExchange(t, store, "h.test", 80, "/shop?id=1", "<html></html>")
	}
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{
		MaxConcurrency: 8,
		CheckSqli:      true, // one per-URL check, so all eight captures contend for one ledger bit
	})

	session, _ := scan.AuditSession(context.Background(), ids, DefaultAuditConfig())

	ran, covered := 0, 0
	for _, item := range session.Items {
		ran += item.Outcome.Ran
		covered += item.Outcome.AlreadyCovered
		if item.Outcome.Considered() != 1 {
			t.Errorf("exchange %d considered %d, want 1", item.ExchangeID, item.Outcome.Considered())
		}
	}
	if ran != 1 {
		t.Errorf("dispatches = %d, want exactly 1 across the whole session", ran)
	}
	if covered != 7 {
		t.Errorf("already-covered refusals = %d, want 7", covered)
	}
	if session.DispatchUnits != 1 {
		t.Errorf("dispatch units = %d, want 1", session.DispatchUnits)
	}
	for i, item := range session.Items {
		if item.ExchangeID != ids[i] {
			t.Fatalf("item %d is exchange %d, want %d: order must survive concurrency", i, item.ExchangeID, ids[i])
		}
	}
}

func Test_a_dead_target_trips_the_item_breaker_and_the_remaining_checks_are_reported(t *testing.T) {
	store := core.NewTrafficStore()
	port := deadTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(probeChecksOnly())

	cfg := DefaultAuditConfig()
	// One failure abandons the unit; one abandoned unit fails the item. The default is 2 and 2; this
	// is the same machinery wound one notch tighter so the test does not need a second unit.
	cfg.ConsecutiveCheckFailuresToAbandonUnit = 1
	cfg.ConsecutiveUnitFailuresToFailItem = 1
	outcome, findings := scan.AuditWithin(context.Background(), id, cfg)

	if outcome.State != ItemStateFailed {
		t.Errorf("state = %s, want failed", outcome.State.Label())
	}
	if outcome.SendFailures != 1 {
		t.Errorf("send failures = %d, want the one check that tried and could not reach the target", outcome.SendFailures)
	}
	if outcome.UnitAbandoned != 2 {
		t.Errorf("unit-abandoned = %d, want the 2 checks the breaker stopped from starting", outcome.UnitAbandoned)
	}
	if outcome.Considered() != 3 {
		t.Errorf("considered = %d, want 3: a failed item still accounts for its whole check set", outcome.Considered())
	}
	if outcome.State.CompletedAudit() {
		t.Error("a failed item must not count as a completed audit")
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 from a target that never answered", len(findings))
	}
}

func Test_findings_from_a_check_whose_probes_never_went_out_are_dropped_and_counted(t *testing.T) {
	// The stored response carries the exact string the path-traversal check looks for, so the offline
	// path reports a finding. With a sender pointed at a dead port the check tries to probe, fails,
	// falls back to that same stored response — and would report "path traversal" about a payload
	// that never left the process.
	body := "<html>hello root:x:0:0: world</html>"
	cfg := &ScanConfig{MaxConcurrency: 1, CheckPathTraversal: true}

	offlineStore := core.NewTrafficStore()
	offlineID := seedAuditExchange(t, offlineStore, "h.test", 80, "/", body)
	offline := NewActiveScanner(offlineStore, zap.NewNop()).WithConfig(cfg)
	offlineOutcome, offlineFindings := offline.AuditWithin(context.Background(), offlineID, DefaultAuditConfig())
	if len(offlineFindings) != 1 {
		t.Fatalf("offline findings = %d, want 1: the fallback path is unchanged for a caller with no sender", len(offlineFindings))
	}
	if offlineOutcome.Ran != 1 || offlineOutcome.SendFailures != 0 {
		t.Errorf("offline outcome ran = %d, send failures = %d; want 1 and 0 (no probe was attempted)",
			offlineOutcome.Ran, offlineOutcome.SendFailures)
	}

	deadStore := core.NewTrafficStore()
	deadID := seedAuditExchange(t, deadStore, "127.0.0.1", deadTarget(t), "/", body)
	dead := NewActiveScanner(deadStore, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(cfg)
	outcome, findings := dead.AuditWithin(context.Background(), deadID, DefaultAuditConfig())

	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0: a check that saw no probe response has no evidence", len(findings))
	}
	if outcome.Findings != 0 {
		t.Errorf("outcome findings = %d, want 0", outcome.Findings)
	}
	if outcome.FindingsDropped != 1 {
		t.Errorf("findings dropped = %d, want 1 — the drop must be counted, not silent", outcome.FindingsDropped)
	}
	if outcome.SendFailures != 1 {
		t.Errorf("send failures = %d, want 1", outcome.SendFailures)
	}
	if len(dead.GetFindings()) != 0 {
		t.Errorf("scanner retained %d findings, want 0", len(dead.GetFindings()))
	}
}

func Test_the_session_breaker_pauses_a_run_and_the_remaining_items_say_so(t *testing.T) {
	store := core.NewTrafficStore()
	port := deadTarget(t)
	ids := []uint64{
		seedAuditExchange(t, store, "127.0.0.1", port, "/one", "<html></html>"),
		seedAuditExchange(t, store, "127.0.0.1", port, "/two", "<html></html>"),
		seedAuditExchange(t, store, "127.0.0.1", port, "/three", "<html></html>"),
	}
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(probeChecksOnly()) // MaxConcurrency 1: the pause lands on a known item boundary.

	cfg := DefaultAuditConfig()
	cfg.ConsecutiveCheckFailuresToAbandonUnit = 1
	cfg.ConsecutiveUnitFailuresToFailItem = 1
	cfg.PauseSessionAfterFailedItems = 1
	session, _ := scan.AuditSession(context.Background(), ids, cfg)

	if !session.Paused {
		t.Fatal("the session breaker should have paused the run after the first failed item")
	}
	if session.FailedItems != 1 {
		t.Errorf("failed items = %d, want 1", session.FailedItems)
	}
	if session.Items[0].Outcome.State != ItemStateFailed {
		t.Errorf("first item = %s, want failed", session.Items[0].Outcome.State.Label())
	}
	for _, item := range session.Items[1:] {
		if item.Outcome.State != ItemStatePaused {
			t.Errorf("exchange %d = %s, want paused", item.ExchangeID, item.Outcome.State.Label())
		}
		if item.Outcome.SessionPaused != 3 {
			t.Errorf("exchange %d attributed %d checks to the pause, want its whole check set (3)",
				item.ExchangeID, item.Outcome.SessionPaused)
		}
		if item.Outcome.Considered() != 3 {
			t.Errorf("exchange %d considered %d, want 3", item.ExchangeID, item.Outcome.Considered())
		}
		if item.Outcome.RequestsSent != 0 {
			t.Errorf("exchange %d sent %d probes after the pause, want 0", item.ExchangeID, item.Outcome.RequestsSent)
		}
	}
	if session.Completed() != 0 {
		t.Errorf("completed = %d, want 0: nothing in this run finished its check set", session.Completed())
	}
}

func Test_an_exchange_outside_the_engagement_scope_is_refused_before_any_probe(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scope := core.NewScope()
	scope.AddInclude("other.test")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope).
		WithConfig(probeChecksOnly())

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if outcome.State != ItemStateOutOfScope {
		t.Errorf("state = %s, want out of scope", outcome.State.Label())
	}
	if outcome.Error == "" {
		t.Error("an out-of-scope refusal must name itself")
	}
	if outcome.RequestsSent != 0 {
		t.Errorf("requests sent = %d, want 0: scope is enforced before a byte is built", outcome.RequestsSent)
	}
	if outcome.Considered() != 0 {
		t.Errorf("considered = %d, want 0: no check was reached", outcome.Considered())
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
	// The two-value signature has to carry this somehow, and an empty finding list would read as clean.
	if _, err := scan.Audit(context.Background(), id); err == nil {
		t.Error("Audit must report an error for an item it refused, not an empty finding list")
	}
}

func Test_a_probe_whose_own_url_leaves_the_scope_is_refused_and_counted(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search", "<html>seed</html>")
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	// The captured exchange is /search, which stays in scope; every probe appends a query string, and
	// this rule takes those out. auditItem's check on the exchange cannot see that — only the bytes
	// about to go out can.
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/search?"))
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope).
		WithConfig(&ScanConfig{MaxConcurrency: 1, CheckXss: true})

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if outcome.State == ItemStateOutOfScope {
		t.Fatal("the exchange itself is in scope; only its probes are not")
	}
	if outcome.RequestsRefused == 0 {
		t.Error("refused probes must be counted, or a refusal reads as a target that came back clean")
	}
	if outcome.RequestsSent != 0 {
		t.Errorf("requests sent = %d, want 0: nothing may reach the target", outcome.RequestsSent)
	}
	if outcome.SendFailures != 1 {
		t.Errorf("send failures = %d, want 1: the check saw no probe response", outcome.SendFailures)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
}

func Test_an_exchange_with_no_response_is_unauditable_rather_than_clean(t *testing.T) {
	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Host: "h.test", Port: 80, Method: "GET", Path: "/"}
	store.AddExchange(ex)
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(probeChecksOnly())

	outcome, _ := scan.AuditWithin(context.Background(), ex.ID, DefaultAuditConfig())
	if outcome.State != ItemStateUnauditable {
		t.Errorf("state = %s, want unauditable", outcome.State.Label())
	}
	if outcome.Error == "" {
		t.Error("an unauditable item must name why")
	}
	if outcome.State.CompletedAudit() {
		t.Error("an unauditable item is not a completed audit")
	}

	missing, _ := scan.AuditWithin(context.Background(), 9999, DefaultAuditConfig())
	if missing.State != ItemStateUnauditable {
		t.Errorf("state for an absent exchange = %s, want unauditable", missing.State.Label())
	}
}

func Test_the_audit_time_budget_comes_from_scan_config_rather_than_a_second_timeout(t *testing.T) {
	scan := NewActiveScanner(core.NewTrafficStore(), zap.NewNop())
	// NewActiveScanner's ScanConfig.Timeout is 30s, which used to be set by every caller and read by
	// nobody. Two wall-clock knobs that could disagree is exactly what this reconciliation avoids.
	if got := scan.AuditConfig().TimeBudget; got != 30*time.Second {
		t.Errorf("time budget = %s, want ScanConfig.Timeout (30s)", got)
	}
	scan.WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 7 * time.Second, CheckXss: true})
	if got := scan.AuditConfig().TimeBudget; got != 7*time.Second {
		t.Errorf("time budget = %s, want the new ScanConfig.Timeout (7s)", got)
	}
	// A ScanConfig with no timeout falls back to the shipped default rather than auditing nothing.
	scan.WithConfig(&ScanConfig{MaxConcurrency: 1, CheckXss: true})
	if got := scan.AuditConfig().TimeBudget; got != DefaultAuditBudget {
		t.Errorf("time budget = %s, want the default %s", got, DefaultAuditBudget)
	}
	// An explicit AuditConfig wins, whichever order the setters were called in.
	explicit := DefaultAuditConfig()
	explicit.TimeBudget = 3 * time.Second
	scan.WithAuditConfig(explicit)
	scan.WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 90 * time.Second, CheckXss: true})
	if got := scan.AuditConfig().TimeBudget; got != 3*time.Second {
		t.Errorf("time budget = %s, want the explicit 3s override", got)
	}
}

func Test_an_empty_check_set_audits_nothing_and_claims_nothing(t *testing.T) {
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "h.test", 80, "/", "<html></html>")
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{MaxConcurrency: 1})

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())
	if outcome.Considered() != 0 {
		t.Errorf("considered = %d, want 0 with no checks enabled", outcome.Considered())
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
	if outcome.NotAdmitted() != 0 {
		t.Errorf("not admitted = %d, want 0: nothing was declined, there was nothing to decline", outcome.NotAdmitted())
	}
}

// The session summary is what a report prints, so it must not collapse the refusals back into a
// total — the one thing the whole disposition model exists to prevent.
func Test_the_session_summary_names_the_checks_it_did_not_admit(t *testing.T) {
	store := core.NewTrafficStore()
	first := seedAuditExchange(t, store, "h.test", 80, "/shop", "<html>one</html>")
	second := seedAuditExchange(t, store, "h.test", 80, "/shop", "<html>two</html>")
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{
		MaxConcurrency: 1,
		CheckSqli:      true,
	})

	session, _ := scan.AuditSession(context.Background(), []uint64{first, second}, DefaultAuditConfig())
	summary := session.Summary()
	if summary == "" {
		t.Fatal("a session summary must say something")
	}
	if session.NotAdmitted() != 1 {
		t.Fatalf("not admitted = %d, want 1", session.NotAdmitted())
	}
	if !strings.Contains(summary, "1 check(s) not admitted") {
		t.Errorf("summary %q does not state the checks it never admitted", summary)
	}
	itemSummary := session.Items[1].Outcome.Summary()
	if !strings.Contains(itemSummary, "already covered") {
		t.Errorf("item summary %q does not name the reason", itemSummary)
	}
}
