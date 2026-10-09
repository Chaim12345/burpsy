package web

// The operator rewind against a tick in flight (burpsy-react-ui-h68z). RetryStalled rewinds the
// sweep's cursor from the API goroutine while the sweep goroutine may be mid-tick; before the
// cursor was serialized, the tick's unlocked cursor writes raced the rewind (a -race failure in
// CI) and, worse, a tick that had snapshotted the position before the rewind overwrote it after —
// the operator's retry silently lost. These tests land the rewind deterministically INSIDE a
// tick, through the midTickHook seam (which runs with retryMu not held, between the tick's cursor
// snapshot and its commit), and pin that the rewind wins in both shapes a tick can take: the
// give-up tick and the progress tick.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// rewindMidTick arms a one-shot hook that performs the operator's RetryStalled from ANOTHER
// goroutine while the next tick is between its snapshot and its commit, and returns a pointer to
// the retry's answer. The tick blocks until the retry completes, so the rewind is guaranteed to
// land inside the tick's work phase — not before it, not after it.
func rewindMidTick(s *Server) *bool {
	answered := new(bool)
	s.liveAudit.midTickHook = func() {
		s.liveAudit.midTickHook = nil // one-shot; read and cleared on the tick goroutine only
		done := make(chan bool)
		go func() { done <- s.liveAudit.RetryStalled() }()
		*answered = <-done
	}
	return answered
}

func stalledCursorServer(t *testing.T) (*Server, *liveAuditRun, core.ExchangeID) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	t.Cleanup(target.Close)
	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)
	reqID, err := s.store.Put([]byte("GET /mid-tick HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Response: nil,
		Host: host, Port: port, Method: "GET", Path: "/mid-tick",
		Source: core.SourceProxy,
	})
	_, total := s.store.Count()
	s.liveAudit.SetEnabled(true)
	run := &liveAuditRun{}
	s.liveAudit.attachRun(&run.cursor)
	return s, run, core.ExchangeID(total - 1)
}

func cursorUnderLock(s *Server, run *liveAuditRun) liveAuditCursor {
	return s.liveAudit.readCursor(&run.cursor)
}

func TestAnOperatorRetryRewindLandingInsideAGiveUpTickIsNotOverwritten(t *testing.T) {
	s, run, stalledID := stalledCursorServer(t)
	ctx := context.Background()

	// Tick 0 walks the two seeded exchanges and parks on /mid-tick; ticks 1..stallTicks-1 each
	// add a stall. The next tick is the give-up tick.
	for i := 0; i < liveAuditStallTicks; i++ {
		s.liveAuditTick(ctx, run)
	}
	if c := cursorUnderLock(s, run); c.at != stalledID || c.stalls != liveAuditStallTicks-1 {
		t.Fatalf("control case: cursor at=%d stalls=%d, want parked at %d with %d stalls (the next tick gives up)",
			c.at, c.stalls, stalledID, liveAuditStallTicks-1)
	}

	retried := rewindMidTick(s)
	s.liveAuditTick(ctx, run) // would give up, but the operator rewinds while it works
	if !*retried {
		t.Fatal("RetryStalled mid-tick answered false: the sweep was visibly stalled, the rewind must happen")
	}
	c := cursorUnderLock(s, run)
	if c.at != stalledID || c.stalls != liveAuditStallTicks {
		t.Fatalf("after a rewind inside the give-up tick: at=%d stalls=%d, want the rewound at=%d stalls=%d — the tick's stale give-up overwrote the operator's retry",
			c.at, c.stalls, stalledID, liveAuditStallTicks)
	}
	if got := s.liveAudit.Skipped(); got != 0 {
		t.Fatalf("skipped = %d, want 0: the tick recorded a give-up on an exchange the operator just asked the sweep to wait on", got)
	}
	if id, waiting := s.liveAudit.StalledAt(); !waiting || id != uint64(stalledID) {
		t.Fatalf("StalledAt = %d,%v, want still waiting on %d", id, waiting, stalledID)
	}

	// The budget carried: the very next tick gives up, with no fresh ten-tick wait.
	s.liveAuditTick(ctx, run)
	if got := s.liveAudit.Skipped(); got != 1 {
		t.Fatalf("skipped = %d after the tick following the rewind, want 1 — the carried budget gives up immediately", got)
	}
	if c := cursorUnderLock(s, run); c.at != stalledID+1 || c.stalls != 0 {
		t.Fatalf("after the give-up: at=%d stalls=%d, want past the stall at %d", c.at, c.stalls, stalledID+1)
	}
}

func TestAnOperatorRetryRewindLandingInsideAProgressTickIsNotOverwritten(t *testing.T) {
	s, run, stalledID := stalledCursorServer(t)
	ctx := context.Background()

	s.liveAuditTick(ctx, run) // walks the seeded pair, parks on /mid-tick
	s.liveAuditTick(ctx, run) // first stall
	if _, waiting := s.liveAudit.StalledAt(); !waiting {
		t.Fatal("control case: the sweep is not showing a stall")
	}

	// The response lands, so the next tick walks past the stalled id — and the operator's retry,
	// issued against the stall the pane still shows, lands while that tick is working.
	resp, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nlanded"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex, err := s.store.GetExchange(stalledID)
	if err != nil {
		t.Fatalf("get stalled exchange: %v", err)
	}
	ex.Response = &resp

	retried := rewindMidTick(s)
	s.liveAuditTick(ctx, run)
	if !*retried {
		t.Fatal("RetryStalled mid-tick answered false: the stall was still standing when it was issued")
	}
	if c := cursorUnderLock(s, run); c.at != stalledID || c.stalls != liveAuditStallTicks || c.rewinds != 1 {
		t.Fatalf("after a rewind inside a progress tick: at=%d stalls=%d rewinds=%d, want at=%d stalls=%d rewinds=1 — the tick's stale advance overwrote the rewind",
			c.at, c.stalls, c.rewinds, stalledID, liveAuditStallTicks)
	}

	// The rewound cursor then moves normally: the response is there, so the walk passes it.
	s.liveAuditTick(ctx, run)
	if c := cursorUnderLock(s, run); c.at != stalledID+1 || c.stalls != 0 {
		t.Fatalf("after the tick following the rewind: at=%d stalls=%d, want past %d with no stalls", c.at, c.stalls, stalledID)
	}
	if got := s.liveAudit.Skipped(); got != 0 {
		t.Fatalf("skipped = %d, want 0: the exchange got its response and was never given up on", got)
	}
	if _, waiting := s.liveAudit.StalledAt(); waiting {
		t.Fatal("still reporting a stall after the cursor moved past it")
	}
}
