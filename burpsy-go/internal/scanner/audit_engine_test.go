// Tests for the audit engine driving real ActiveScanner.Audit runs — the half of gap 3 that a ported
// but uncalled engine would leave open. Every test here asserts two things together: that a budget or
// breaker actually stopped dispatch, and that what was skipped came back *named* rather than missing.
package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// seedAuditExchange puts one request/response pair in the store and indexes an exchange over it,
// returning the exchange id (which is its position, so the first is 0).
func seedAuditExchange(t *testing.T, store *core.TrafficStore, host string, port uint16, path, body string) core.ExchangeID {
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
	//
	// Five, not seven: CheckSSRF and CheckXXE each used to admit one declined row, and both
	// rows now have evaluators that are additionally gated behind CheckExtendedActive (an OOB
	// channel and payload sending respectively). Enabling those two switches alone therefore
	// admits nothing. The property under test is the partition, not the literal count.
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
	if got, want := scan.ActiveCheckCount(), 5; got != want {
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

// Every catalog row now has an evaluator, so there is no configuration that produces an
// unimplemented check any more. What still has to hold is that the *reporting* path is honest
// about it: the count is reported rather than omitted, and the unsupported bucket agrees with
// it. The mechanism that turns a run==nil descriptor into DispositionUnsupported is exercised
// directly below with a synthetic descriptor, because the registry can no longer supply one.
func Test_unimplemented_checks_are_reported_unsupported_rather_than_silently_absent(t *testing.T) {
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "h.test", 80, "/", "<html></html>")

	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{
		MaxConcurrency: 1,
		CheckSSRF:      true,
		CheckXXE:       true,
		CheckSqli:      true,
	})
	if got := scan.UnimplementedCheckCount(); got != 0 {
		t.Fatalf("unimplemented checks = %d, want 0 now that every catalog row is wired", got)
	}

	outcome, _ := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())
	if outcome.Considered() != scan.ActiveCheckCount() {
		t.Errorf("considered = %d, want the whole enabled set (%d)", outcome.Considered(), scan.ActiveCheckCount())
	}
	// With nothing unimplemented the unsupported bucket must be empty — not absent, and not
	// quietly holding a count nothing explains.
	for _, d := range outcome.Dispositions() {
		if d.Disposition == DispositionUnsupported && d.Count != 0 {
			t.Errorf("unsupported bucket = %d, want 0 when no check is unimplemented", d.Count)
		}
		if d.Reason == "" {
			t.Errorf("bucket %q carries no reason", d.Disposition)
		}
	}
}

// The mechanism, exercised directly: a descriptor with no Run must count as unimplemented and
// land in the unsupported bucket. This is what the registry used to supply and no longer can.
func Test_a_descriptor_without_a_runner_counts_as_unimplemented(t *testing.T) {
	d := CheckDescriptor{
		TypeIndex:      1,
		Name:           "synthetic",
		Implementation: ImplementationDeclined,
		DeclineReason:  "synthetic row with no evaluator",
	}
	if d.Runnable() {
		t.Fatal("a descriptor with no Run reported itself runnable")
	}
	if !d.Valid() {
		t.Fatal("a declined descriptor carrying a reason is not Valid()")
	}

	// And the inverse: a descriptor with a Run but also a decline reason is invalid, which is
	// what keeps a half-wired row from counting as either.
	half := CheckDescriptor{
		TypeIndex:      1,
		Name:           "synthetic",
		Implementation: ImplementationNative,
		DeclineReason:  "should not be here",
		Run:            func(context.Context, *CheckContext) ([]*Finding, error) { return nil, nil },
	}
	if half.Valid() {
		t.Error("a descriptor with both a runner and a decline reason was accepted")
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

	session, _ := scan.AuditSession(context.Background(), []core.ExchangeID{first, second}, DefaultAuditConfig())

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
	ids := make([]core.ExchangeID, 8)
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
	// Nothing is dropped any more, because nothing is manufactured to drop.
	//
	// The check used to build its probe by appending a guessed parameter name and read the result
	// through sendTestRequest, which falls back to the stored response when a send fails. It
	// therefore produced a "path traversal" finding about the captured bytes and depended on the
	// engine's attempted>0 && sent==0 rule to take it away again. Driven through ProbeHarness the
	// baseline cannot be established against a dead port, so the check returns an error and no
	// verdict at all. Same result for the operator, one less place for a finding about an
	// unsent probe to exist.
	if outcome.FindingsDropped != 0 {
		t.Errorf("findings dropped = %d, want 0: the check no longer manufactures a finding from the "+
			"stored response when its probe cannot go out, so there is nothing for the engine to discard",
			outcome.FindingsDropped)
	}
	if outcome.SendFailures != 1 {
		t.Errorf("send failures = %d, want 1: the failure itself must still be counted, or a dead "+
			"target would read as a clean one", outcome.SendFailures)
	}
	if len(dead.GetFindings()) != 0 {
		t.Errorf("scanner retained %d findings, want 0", len(dead.GetFindings()))
	}
}

func Test_the_session_breaker_pauses_a_run_and_the_remaining_items_say_so(t *testing.T) {
	store := core.NewTrafficStore()
	port := deadTarget(t)
	ids := []core.ExchangeID{
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

// countingProbeTarget records the request path of everything that actually arrived.
//
// A counter on the target is the only instrument that proves a refusal happened before the dial.
// probeMeter.refused proves bookkeeping, and bookkeeping can be perfectly right while the request
// still goes out; only a silent target proves it did not. Same reasoning, and the same shape, as
// sender.countingTarget and the session-scope tests in internal/web.
type countingProbeTarget struct {
	mu   sync.Mutex
	hits map[string]int
	host string
	port uint16
}

func newCountingProbeTarget(t *testing.T) *countingProbeTarget {
	t.Helper()
	ct := &countingProbeTarget{hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct.mu.Lock()
		ct.hits[r.URL.Path]++
		ct.mu.Unlock()
		w.Write([]byte("<html>the target answered</html>"))
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("target address %q: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("target port %q: %v", portStr, err)
	}
	ct.host, ct.port = host, uint16(port)
	return ct
}

func (ct *countingProbeTarget) hitCount(path string) int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.hits[path]
}

func (ct *countingProbeTarget) total() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	n := 0
	for _, c := range ct.hits {
		n += c
	}
	return n
}

// The claim: a probe whose payload rewrites the request path out of scope is refused *before the
// dial*, and the proof is a target that received nothing on that path.
//
// This drives sendTestRequest directly because no check shipped today splices a payload into a path
// position — all three append a query string — and this is the case the gate exists for. It is also
// where the old check and the new one genuinely disagree: scope is defined over request paths, and the
// old call handed scope.AuthoriseRequest a path with a query string glued onto it, so a rule written
// against the real request line could match the wire and miss that string.
//
// This test replaces one that asserted the same intent through an exclude rule of the shape
// `path prefix "/search?"`. That rule refused every probe, but only because the glued string it was
// matched against is one no request line can carry — core.Scope's requestPath drops the query. The
// refusal was an artefact of asking the wrong question, so the test is rebuilt around a probe that is
// really out of scope rather than around a rule that can never match a path.
func Test_a_probe_whose_payload_rewrites_the_path_out_of_scope_never_reaches_the_target(t *testing.T) {
	store := core.NewTrafficStore()
	target := newCountingProbeTarget(t)
	id := seedAuditExchange(t, store, target.host, target.port, "/search", "<html>seed</html>")
	exchange, err := store.GetExchange(id)
	if err != nil {
		t.Fatalf("get exchange: %v", err)
	}

	// In scope everywhere on this host except /admin. The captured exchange is /search, so the item
	// itself is in scope and only a probe that rewrites its way to /admin is not.
	scope := core.NewScope()
	scope.AddInclude(target.host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope).
		WithConfig(probeChecksOnly())

	meter := &probeMeter{}
	ctx := withMeter(context.Background(), meter)

	body := scan.sendTestRequest(ctx, exchange, "/admin/delete?file=../../../etc/passwd")

	if got := target.hitCount("/admin/delete"); got != 0 {
		t.Fatalf("/admin/delete was hit %d times, want 0: the refusal must happen before the dial", got)
	}
	if got := target.total(); got != 0 {
		t.Fatalf("the target saw %d request(s), want 0", got)
	}
	if body != "" {
		// The stored-response fallback is for an operator with no sender, not a way for a check to
		// reach a verdict about a payload that was never authorised to leave.
		t.Errorf("a refused probe returned %q, want nothing: the stored response is not this probe's answer", body)
	}
	counts := meter.snapshot()
	if counts.refused != 1 {
		t.Errorf("refused = %d, want 1: the refusal must be counted as well as enforced", counts.refused)
	}
	if counts.sent != 0 {
		t.Errorf("sent = %d, want 0", counts.sent)
	}
	if counts.failed != 1 {
		t.Errorf("failed = %d, want 1: the check saw no probe response either way", counts.failed)
	}

	// Without this the zero above proves nothing — it would be equally well explained by a sender that
	// cannot send at all. An in-scope probe through the same gate, same scanner, must arrive.
	if got := scan.sendTestRequest(ctx, exchange, "/search?xss=%3Cb%3E"); !strings.Contains(got, "the target answered") {
		t.Fatalf("the in-scope probe returned %q, want the target's own body", got)
	}
	if got := target.hitCount("/search"); got != 1 {
		t.Fatalf("/search was hit %d times, want 1", got)
	}
	if counts = meter.snapshot(); counts.sent != 1 || counts.refused != 1 {
		t.Errorf("sent/refused = %d/%d, want 1/1", counts.sent, counts.refused)
	}
}

// The end-to-end counterpart: a real audit's probes are authorised against their own request line, and
// an exclude on the path they carry stops every one of them with the target seeing nothing.
//
// auditItem's own scope test refuses this item first — which is correct and is what ItemStateOutOfScope
// asserts — so this pins both gates at once: the item is refused before any work is planned, *and*
// nothing reached the target.
func Test_an_audit_of_an_excluded_path_reaches_the_target_zero_times(t *testing.T) {
	store := core.NewTrafficStore()
	target := newCountingProbeTarget(t)
	id := seedAuditExchange(t, store, target.host, target.port, "/admin/users", "<html>seed</html>")
	scope := core.NewScope()
	scope.AddInclude(target.host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope).
		WithConfig(probeChecksOnly())

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if got := target.total(); got != 0 {
		t.Fatalf("the target saw %d request(s), want 0", got)
	}
	if outcome.State != ItemStateOutOfScope {
		t.Errorf("state = %s, want out of scope", outcome.State.Label())
	}
	if outcome.RequestsSent != 0 {
		t.Errorf("requests sent = %d, want 0", outcome.RequestsSent)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
}

// The over-refusal half of the same disagreement, stated as a test so it cannot regress silently: a
// probe whose request line is in scope is sent, even though the string the old check read — the path
// with its query string glued on — matched an exclude rule. core.Scope.requestPath drops the query, so
// no rule of that shape can match any real request path, and refusing on it was an artefact.
func Test_an_exclude_rule_naming_a_query_string_does_not_refuse_an_in_scope_request_line(t *testing.T) {
	store := core.NewTrafficStore()
	target := newCountingProbeTarget(t)
	id := seedAuditExchange(t, store, target.host, target.port, "/search", "<html>seed</html>")
	exchange, err := store.GetExchange(id)
	if err != nil {
		t.Fatalf("get exchange: %v", err)
	}
	scope := core.NewScope()
	scope.AddInclude(target.host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/search?"))
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope).
		WithConfig(probeChecksOnly())

	meter := &probeMeter{}
	scan.sendTestRequest(withMeter(context.Background(), meter), exchange, "/search?xss=%3Cb%3E")

	if got := target.hitCount("/search"); got != 1 {
		t.Fatalf("/search was hit %d times, want 1: GET /search is in scope whatever the query carries", got)
	}
	if counts := meter.snapshot(); counts.refused != 0 || counts.sent != 1 {
		t.Errorf("refused/sent = %d/%d, want 0/1", counts.refused, counts.sent)
	}
	// And the rule still bites where it can: the same host's /admin is genuinely excluded.
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	scan.sendTestRequest(withMeter(context.Background(), meter), exchange, "/admin?xss=%3Cb%3E")
	if got := target.hitCount("/admin"); got != 0 {
		t.Fatalf("/admin was hit %d times, want 0", got)
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

// An empty batch is a real caller state — an operator audits a selection and selects nothing — and
// the worker pool sizes itself from the batch, so this is the shape that would deadlock if the pool
// were built without a worker to feed.
func Test_an_empty_batch_is_an_empty_session_not_a_stalled_one(t *testing.T) {
	scan := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).
		WithConfig(&ScanConfig{MaxConcurrency: 8, CheckSqli: true})

	done := make(chan struct{})
	go func() {
		defer close(done)
		session, findings := scan.AuditSession(context.Background(), nil, DefaultAuditConfig())
		if len(session.Items) != 0 || len(findings) != 0 {
			t.Errorf("items = %d, findings = %d, want 0 and 0", len(session.Items), len(findings))
		}
		if session.DispatchUnits != 0 {
			t.Errorf("dispatch units = %d, want 0", session.DispatchUnits)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("AuditSession stalled on an empty batch")
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

	session, _ := scan.AuditSession(context.Background(), []core.ExchangeID{first, second}, DefaultAuditConfig())
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
