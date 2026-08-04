package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ---- CRAWL-06: live audit runs against proxied traffic only when the operator opts in -----------
//
// The existing tests in liveaudit_test.go pin the *switch*: that it reads false by default, that a
// POST flips it, that an unwired process says so. None of them proves the switch is load-bearing.
// A sweep loop that ignored the flag, or read it after building its batch, or read it after handing
// the batch to the scanner, would pass all three — and would be sending active checks at a live host
// nobody authorised.
//
// So this file works at the only level that can settle it: a real HTTP target that counts what
// reaches it. The positive control in the second half is what makes the first half mean anything —
// without it, "zero requests arrived" is equally consistent with a check set that never sends
// anything at all, which is exactly the way a test like this gets faked.

// targetHostPort splits an httptest server's URL into the host and port an Exchange carries.
func targetHostPort(t *testing.T, raw string) (string, uint16) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse target url %q: %v", raw, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse target port from %q: %v", raw, err)
	}
	return u.Hostname(), uint16(port)
}

// auditableServer builds a server whose store holds two completed, in-scope exchanges addressed at
// target, with an active scanner that really sends. Everything the live sweep needs is present; the
// only thing left to vary is the opt-in.
func auditableServer(t *testing.T, targetURL string) *Server {
	t.Helper()
	s := newTestServer()
	host, port := targetHostPort(t, targetURL)

	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": host}); rec.Code != http.StatusOK {
		t.Fatalf("include target in scope: status = %d", rec.Code)
	}

	reqID, err := s.store.Put([]byte("GET /?q=1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	for _, path := range []string{"/", "/second"} {
		s.store.AddExchange(&core.Exchange{
			Request:  reqID,
			Response: &respID,
			Host:     host,
			Port:     port,
			Method:   "GET",
			Path:     path,
		})
	}

	return s.
		WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).
			WithSender(sender.NewSender(sender.DefaultSenderConfig())).
			WithScope(s.scope)).
		WithLiveAudit(NewLiveAuditState())
}

// sweepTick is short enough that a handful of ticks fit inside a test's patience, and long enough
// that the loop is not spinning. The shipped interval is liveAuditSweepInterval.
const sweepTick = 5 * time.Millisecond

// waitForHits polls until the target has been reached at least once, or the deadline passes.
func waitForHits(hits *atomic.Int64, within time.Duration) int64 {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if n := hits.Load(); n > 0 {
			return n
		}
		time.Sleep(sweepTick)
	}
	return hits.Load()
}

// waitForQuiet polls until the count has stopped moving for quietFor, and returns it.
//
// A sweep hands a whole batch to the scanner, so "a request has arrived" does not mean the batch is
// finished. A test that froze its baseline on the first arrival would be comparing a mid-batch count
// against a finished one and calling the difference a leak — which is exactly the flake this replaces.
func waitForQuiet(hits *atomic.Int64, quietFor, within time.Duration) int64 {
	deadline := time.Now().Add(within)
	last := hits.Load()
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(sweepTick)
		if n := hits.Load(); n != last {
			last = n
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= quietFor {
			return last
		}
	}
	return hits.Load()
}

// With live audit off — its default — the sweep loop must not send a single request at the target,
// however much in-scope traffic is sitting in the store waiting to be audited. Then, with nothing
// else changed but the switch, it must.
func TestLiveAuditOffSendsNothingAtTheTargetAndOnSendsSomething(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := auditableServer(t, target.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)

	if s.liveAudit.IsEnabled() {
		t.Fatal("live audit is enabled straight after startup; CRAWL-06 requires it default-off")
	}
	// Long enough for many ticks at sweepTick. Nothing to poll for here — the assertion is that
	// nothing happens — so this is the one place a fixed wait is the right instrument.
	time.Sleep(40 * sweepTick)
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d request(s) reached the target with live audit off; nothing may be sent until the operator opts in", n)
	}
	if s.liveAudit.Swept() != 0 {
		t.Errorf("swept = %d with live audit off, want 0", s.liveAudit.Swept())
	}

	// The positive control. Flip the switch through the same surface the operator uses, and the same
	// store, scope, scanner and exchanges must now produce traffic — which is what makes the zero
	// above evidence of the opt-in rather than of an inert check set.
	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scanner/live: status = %d, want 200", rec.Code)
	}
	if n := waitForHits(&hits, 10*time.Second); n == 0 {
		t.Fatal("no request reached the target with live audit on; the opt-in switch gates nothing, so the zero above proves nothing")
	}
}

// Turning the sweep back off must stop it, not merely stop it from starting. A loop that read the flag
// once at startup would pass the test above and fail this one.
//
// Fresh traffic is recorded *after* the switch goes off, because that is the only way to distinguish
// "the loop re-read the switch" from "the loop had already consumed everything in the store": the
// sweep advances a high-water mark, so with no new exchanges a later tick would find nothing to do and
// send nothing whatever the switch said.
func TestLiveAuditTurnedBackOffStopsSendingAtTheTarget(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)

	s.liveAudit.SetEnabled(true)
	if n := waitForHits(&hits, 10*time.Second); n == 0 {
		t.Fatal("no request reached the target with live audit on; cannot test that switching it off stops it")
	}
	settled := waitForQuiet(&hits, 150*time.Millisecond, 20*time.Second)
	if settled == 0 {
		t.Fatal("the first sweep never settled")
	}

	s.liveAudit.SetEnabled(false)
	reqID, err := s.store.Put([]byte("GET /after HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: &respID, Host: host, Port: port, Method: "GET", Path: "/after",
	})

	time.Sleep(40 * sweepTick)
	if n := hits.Load(); n != settled {
		t.Errorf("%d request(s) reached the target after live audit was switched off; the loop must re-read the switch every tick", n-settled)
	}
	if s.liveAudit.Swept() == 0 {
		t.Error("swept = 0; the enabled phase of this test never actually swept anything")
	}
}

// A disabled sweep must also leave no trace on the dashboard's own count: the Live audit summary
// reports its findings as gated, so "0 findings" cannot be read as "audited and clean".
func TestDashboardReportsADisabledLiveAuditAsGatedNotClean(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())

	sum := dashboardSummary(t, s, "Live audit")
	if sum.Breakdown.Complete {
		t.Error("a switched-off live audit reports a complete count; 0 findings from an audit that never ran is not a clean result")
	}
	if sum.Breakdown.Gated == 0 {
		t.Errorf("gated = 0 for a switched-off live audit, want it counted as gated (breakdown %+v)", sum.Breakdown)
	}
	if len(sum.Reasons) == 0 {
		t.Error("no reason given for the gated live-audit count")
	}
}

// ---- The cursor must not wait forever ----------------------------------------------------------
//
// The sweep walks exchange ids in order and stops at one whose response has not landed, because ids
// are handed out when a request is captured and a later id can complete first — auditing past a gap
// would skip the request still in flight. That much is correct and stays.
//
// What was missing is a bound on the waiting. An exchange whose response *never* lands — a transport
// failure indexed by a producer that tolerates it — parked the cursor on that id for the life of the
// process, and Swept() went on reporting the number it had reached, so the pane showed a healthy
// steady state while auditing nothing. That is a silent permanent coverage loss, and it is exactly
// what this codebase's whole style exists to prevent.
//
// The fix is not "audit it anyway" — there is no response to audit. It is to give up after a bounded
// number of ticks, step over it, and count it as skipped rather than swept.
func TestTheSweepAdvancesPastAnExchangeWhoseResponseNeverLandsAndCountsIt(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)

	// A response-less exchange at the head of everything the sweep has not reached yet. This is the
	// id the cursor will park on.
	reqID, err := s.store.Put([]byte("GET /never HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: nil,
		Host: host, Port: port, Method: "GET", Path: "/never",
	})
	// And a complete one behind it, so "the sweep got past the gap" is observable as real work rather
	// than merely as a moved counter.
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: &respID,
		Host: host, Port: port, Method: "GET", Path: "/after-the-gap",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scanner/live: status = %d, want 200", rec.Code)
	}

	// The cursor must reach the exchange beyond the gap. Before the bound existed this never
	// happened, no matter how long the test waited.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.liveAudit.Skipped() > 0 && hits.Load() > 0 {
			break
		}
		time.Sleep(sweepTick)
	}

	if got := s.liveAudit.Skipped(); got == 0 {
		t.Error("skipped = 0; the exchange the sweep gave up on must be counted, not forgotten")
	}
	if got := hits.Load(); got == 0 {
		t.Error("no request reached the target; the cursor never got past the response-less exchange")
	}
	// The one it gave up on must not be laundered into the audited total.
	if s.liveAudit.Swept() == 0 {
		t.Error("swept = 0 although the sweep audited the exchange beyond the gap")
	}

	view := s.liveAuditStatus()
	if view.Skipped == 0 {
		t.Error("the operator view hides the skip; a count that omits what it gave up on overstates coverage")
	}
}
