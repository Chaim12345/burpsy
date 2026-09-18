package web

// The stall/skip lifecycle (burpsy-react-ui-iyqg): a skip is no longer a death sentence, and
// the operator gets an action. What these tests pin, building on the same harness the original
// stall test built:
//
//   - a skipped exchange whose response LATER LANDS is audited on one bounded retry, counted
//     as retried (distinct from swept and from skipped: "gave up on 1" and "gave up on 1,
//     took 1 back" are different coverage claims);
//   - the retry is ONCE: a second give-up stays a skip, no infinite re-file;
//   - the operator's retry action rewinds the cursor to the stalled id and carries the stall
//     budget rather than restarting it — an invisible second thirty-second wait for the same
//     answer is a lie of its own;
//   - a retry requested while not stalled is a 409, not a silent 200 — the operator must learn
//     the stall already cleared.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestASkippedExchangeWhoseResponseLaterLandsIsAuditedOnceAsRetried(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)

	// The exchange whose response has not landed: id 0.
	reqID, err := s.store.Put([]byte("GET /late HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: nil,
		Host: host, Port: port, Method: "GET", Path: "/late",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scanner/live: status = %d, want 200", rec.Code)
	}

	// Wait for the give-up: the response-less exchange is skipped.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Skipped() == 0 {
		time.Sleep(sweepTick)
	}
	if s.liveAudit.Skipped() == 0 {
		t.Fatal("the sweep never gave up on the response-less exchange — control case missing")
	}
	// ...and the retry slot holds that id — whichever it was; the harness's store may hold
	// seeded exchanges before ours.
	id, pending := s.liveAudit.pendingRetryID()
	if !pending {
		t.Fatal("pending retry slot is empty: the give-up must file the id it skipped")
	}
	if ex, err := s.store.GetExchange(id); err != nil || ex.Path != "/late" {
		t.Fatalf("pending retry = %d, which is not our response-less /late exchange (err=%v)", id, err)
	}

	// The response lands: the producer writes it onto the same exchange row the sweep will
	// re-read. GetExchange hands back the store's own *Exchange pointer, so this mutation IS
	// the store's state — the shape a tolerant producer (one that indexes a transport failure
	// and completes the row when the bytes finally arrive) produces.
	lateResp, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nlate but real"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put late response: %v", err)
	}
	ex, err := s.store.GetExchange(id)
	if err != nil {
		t.Fatalf("get the stalled exchange: %v", err)
	}
	ex.Response = &lateResp

	// The next tick takes the retry: retried grows by exactly one, and the slot clears.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Retried() == 0 {
		time.Sleep(sweepTick)
	}
	if got := s.liveAudit.Retried(); got != 1 {
		t.Fatalf("retried = %d, want 1: the exchange whose response landed after the skip must be audited once on its second chance", got)
	}
	if _, stillPending := s.liveAudit.pendingRetryID(); stillPending {
		t.Error("the retry slot did not clear after the one retry — the retry is once, not forever")
	}

	// The operator view carries both numbers, because "gave up on 1" and "gave up on 1, took
	// 1 back" are different coverage claims.
	view := s.liveAuditStatus()
	if view.Skipped == 0 || view.Retried != 1 {
		t.Errorf("view = skipped %d retried %d, want the skip visible AND the take-back visible", view.Skipped, view.Retried)
	}
}

func TestTheRetryIsOnceASecondGiveUpStaysASkip(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)
	reqID, err := s.store.Put([]byte("GET /never2 HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: nil,
		Host: host, Port: port, Method: "GET", Path: "/never2",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Skipped() == 0 {
		time.Sleep(sweepTick)
	}
	if s.liveAudit.Skipped() == 0 {
		t.Fatal("control case missing: the sweep never skipped")
	}
	// The retry slot holds the id, but no response ever lands. takePendingRetry must clear
	// the slot on its first read (the retry is once), so a later landing cannot resurrect it.
	if _, landed := s.liveAudit.takePendingRetry(s.store); landed {
		t.Fatal("takePendingRetry reported a landing for an exchange with no response")
	}
	if _, stillPending := s.liveAudit.pendingRetryID(); stillPending {
		t.Fatal("the retry slot survived a take that found no response — the retry must be once, not re-filed forever")
	}
}

func TestTheOperatorRetryRewindsTheCursorAndCarriesTheStallBudget(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)
	// A response-less exchange at the head; the sweep will stall on it.
	reqID, err := s.store.Put([]byte("GET /still-waiting HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: nil,
		Host: host, Port: port, Method: "GET", Path: "/still-waiting",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	// Wait for the stall to be visible.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, waiting := s.liveAudit.StalledAt(); waiting {
			break
		}
		time.Sleep(sweepTick)
	}
	stalledID, waiting := s.liveAudit.StalledAt()
	if !waiting {
		t.Fatal("control case missing: the sweep never showed a stall for the operator to retry")
	}

	// The operator action, over the API, and the refusal shape when not stalled is not part
	// of this test's stall (it IS stalled): the rewind must happen and answer 200.
	rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": true, "retry_stalled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST retry_stalled: status = %d, want 200", rec.Code)
	}

	// The rewind itself is observable immediately: the cursor is back at the stalled id and
	// the stall budget is at its limit, NOT reset — a fresh budget would read 0. This is the
	// carried-budget assertion, checked where it is a fact about the rewind rather than a
	// race against the sweep's next tick.
	s.liveAudit.retryMu.Lock()
	cur := s.liveAudit.retryCursor
	stallsAfterRewind, atAfterRewind := -1, int64(-1)
	if cur != nil {
		stallsAfterRewind, atAfterRewind = cur.stalls, int64(cur.at)
	}
	s.liveAudit.retryMu.Unlock()
	if stallsAfterRewind != liveAuditStallTicks || atAfterRewind != int64(stalledID) {
		t.Fatalf("after the rewind: stalls=%d at=%d, want stalls=%d at the stalled id %d — the budget must carry, not restart",
			stallsAfterRewind, atAfterRewind, liveAuditStallTicks, stalledID)
	}

	// And the skip fires once ticks resume — without needing any fresh ten-tick budget. The
	// window is generous because the sweep loop is synchronous behind a real audit batch; the
	// assertion above is the carried-budget fact, this one is that the sweep does give up.
	// The window must survive a real audit batch: the tick that follows the rewind can be
	// blocked behind the previous batch's AuditSession (the sweep loop is synchronous), so
	// the bound is a full audit-worth of time, not merely stallTicks × the interval. Carried
	// means "no fresh ten-tick budget": the skip fires as soon as ticks resume, well before a
	// restarted budget would have.
	fastDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(fastDeadline) && s.liveAudit.Skipped() == 0 {
		time.Sleep(sweepTick / 2)
	}
	if s.liveAudit.Skipped() == 0 {
		t.Errorf("the rewind did not carry the stall budget: no skip within %d extra ticks — a fresh ten-tick budget was silently granted",
			liveAuditStallTicks+4)
	}
}

func TestARetryRequestedWhileNotStalledIsA409(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	// No sweep started, nothing stalled.
	rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false, "retry_stalled": true})
	if rec.Code != http.StatusConflict {
		t.Errorf("retry while not stalled = %d, want 409 — a silent 200 would leave the operator inferring the stall cleared from a stalled_at that never appears", rec.Code)
	}
}
