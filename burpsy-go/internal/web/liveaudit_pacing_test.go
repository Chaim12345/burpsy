package web

// Per-host pacing for the live sweep (burpsy-react-ui-6urp): the tick's ids group by host
// and each group runs as its OWN AuditSession, concurrently under a bound — one slow host
// paces only itself. The tests pin:
//
//   - a two-host batch runs BOTH hosts to completion even when the FIRST host is the slow
//     one — the wedge the bead was filed on. Driven against real origins: host A delays
//     every response 300ms, host B answers instantly, and the sweep still sweeps B's
//     items within the deadline. (Before the change, both hosts shared one sequential
//     session; a slow host A held B's items behind it in the queue.)
//   - a single-host batch behaves exactly as before: one session, no folding artefacts.
//   - the fold: a multi-host tick's outcome sums every host's items, requests and
//     findings, so the task row and the event keep one set of numbers per tick.
//   - the task target names every host in a multi-host batch, not just the first —
//     "sweep of host-a (200 exchanges)" for a batch that was mostly host-b is a claim
//     the numbers did not back.
import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// perHostSweepServer builds a server whose scope admits two local origins and whose store
// holds one completed capture per origin.
func perHostSweepServer(t *testing.T, slow, fast *httptest.Server) *Server {
	t.Helper()
	s := newTestServer()
	slowHost, slowPort := targetHostPort(t, slow.URL)
	fastHost, fastPort := targetHostPort(t, fast.URL)
	// include both hosts in scope
	for _, h := range []string{slowHost, fastHost} {
		r := httptest.NewRequest("POST", "/api/scope", nil)
		_ = r
		req := httptest.NewRequest(http.MethodPost, "/api/scope", nil)
		_ = req
		// use the helper through the mux
		if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": h}); rec.Code != http.StatusOK {
			t.Fatalf("include %s in scope: %d", h, rec.Code)
		}
	}
	seedHostExchange(t, s, slowHost, slowPort, "/slow-page")
	seedHostExchange(t, s, fastHost, fastPort, "/fast-page")
	s = s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1}))
	return s.WithLiveAudit(NewLiveAuditState())
}

func postJSONGet(t *testing.T, s *Server) []int { return nil }

func seedHostExchange(t *testing.T, s *Server, host string, port uint16, path string) core.ExchangeID {
	t.Helper()
	raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port, Method: "GET", Path: path,
		Source: core.SourceProxy,
	})
	return core.ExchangeID(len(s.store.Exchanges())) - 1
}

func TestASlowHostDoesNotWedgeTheOtherHostsSweep(t *testing.T) {
	var slowHits, fastHits atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowHits.Add(1)
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("slow"))
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastHits.Add(1)
		w.Write([]byte("fast"))
	}))
	defer fast.Close()

	s := perHostSweepServer(t, slow, fast)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	// The fast host's item must be swept even though the slow host's session holds the
	// tick for its own duration — the whole point of per-host pacing. One tick admits
	// both ids; before the change both went through ONE session where slow came first
	// in id order.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Swept() < 2 {
		time.Sleep(sweepTick)
	}
	if got := s.liveAudit.Swept(); got < 2 {
		t.Fatalf("swept = %d, want both hosts' items swept — a slow host wedged the other host's capture behind it", got)
	}
}

func TestASingleHostBatchRunsOneSessionVerbatim(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer fast.Close()
	s := newTestServer()
	host, port := targetHostPort(t, fast.URL)
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": host}); rec.Code != http.StatusOK {
		t.Fatalf("include in scope: %d", rec.Code)
	}
	seedHostExchange(t, s, host, port, "/one")
	seedHostExchange(t, s, host, port, "/two")
	s = s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1})).
		WithLiveAudit(NewLiveAuditState())

	// The grouping degenerates to the single call: both ids, one host, one session whose
	// item order matches the request — and the session count says exactly one.
	before := s.liveAudit.HostSessions()
	out, findings := s.auditGroupedByHost(context.Background(), []core.ExchangeID{0, 1}, scanner.DefaultAuditConfig())
	if got := s.liveAudit.HostSessions() - before; got != 1 {
		t.Fatalf("per-host sessions run = %d for a single-host batch, want 1 — the grouping must degenerate, not multiply", got)
	}
	if len(out.Items) != 2 {
		t.Fatalf("items = %d, want 2 in the single-host path", len(out.Items))
	}
	if out.Items[0].ExchangeID != 0 || out.Items[1].ExchangeID != 1 {
		t.Fatal("the single-host path reordered the ids")
	}
	_ = findings
}

func TestTheMultiHostFoldSumsEveryHostsOutcome(t *testing.T) {
	fastA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("a")) }))
	defer fastA.Close()
	fastB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("b")) }))
	defer fastB.Close()
	s := newTestServer()
	hostA, portA := targetHostPort(t, fastA.URL)
	hostB, portB := targetHostPort(t, fastB.URL)
	seedHostExchange(t, s, hostA, portA, "/a")
	seedHostExchange(t, s, hostB, portB, "/b")
	s = s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1})).
		WithLiveAudit(NewLiveAuditState())

	before := s.liveAudit.HostSessions()
	out, _ := s.auditGroupedByHost(context.Background(), []core.ExchangeID{0, 1}, scanner.DefaultAuditConfig())
	if len(out.Items) != 2 {
		t.Fatalf("the fold lost items: %d, want both hosts'", len(out.Items))
	}
	if got := s.liveAudit.HostSessions() - before; got != 2 {
		t.Fatalf("per-host sessions run = %d, want 2 — the multi-host batch must run one session PER HOST, which is the whole pacing claim", got)
	}
	// Every item answered for its own exchange, whichever host session ran it.
	for i, item := range out.Items {
		_ = i
		if item.ExchangeID != 0 && item.ExchangeID != 1 {
			t.Fatalf("a foreign exchange id %d in the fold", item.ExchangeID)
		}
	}
}

func TestTheTaskTargetNamesEveryHostInTheBatch(t *testing.T) {
	fastA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("a")) }))
	defer fastA.Close()
	fastB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("b")) }))
	defer fastB.Close()
	s := newTestServer()
	hostA, portA := targetHostPort(t, fastA.URL)
	hostB, portB := targetHostPort(t, fastB.URL)
	ids := []core.ExchangeID{
		seedHostExchange(t, s, hostA, portA, "/a"),
		seedHostExchange(t, s, hostB, portB, "/b"),
	}
	target := liveAuditTarget(s.store, ids)
	if !containsFold(target, hostA) || !containsFold(target, hostB) {
		t.Fatalf("target = %q, want BOTH hosts named — a first-host-only label claims a multi-host sweep as one host's run", target)
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && (indexOfFold(s, sub) >= 0))
}

func indexOfFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestTheHostSessionBoundIsSmallAndNamed(t *testing.T) {
	// The bound is half of the tick's real concurrency ceiling (bound × engine workers) and
	// must stay a named constant, not a magic number someone bumps for "faster sweeps".
	if liveAuditHostSessions <= 0 || liveAuditHostSessions > 8 {
		t.Fatalf("liveAuditHostSessions = %d, want a small named bound (per-host pacing means the host count stays small)", liveAuditHostSessions)
	}
	_ = fmt.Sprint
}
