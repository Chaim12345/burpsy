package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
	"io"
	"strconv"
	"strings"
	"time"
)

// The web audit paths must close the stored lifecycle themselves (gxbk). The engine's FinishScan
// re-fetch + pending-claim machinery existed, was tested in isolation, and had no production
// caller — so a stored claim deferred by a web-launched audit stayed undecided forever, and no
// second look ever happened. This test asserts the wiring end to end: an operator audit of the
// vulnapp stored pair settles its claim within the same request, and a scan that planted nothing
// (an ordinary audit of a static page) never sends second-pass traffic at all.
func TestAWEBLaunchedAuditSettlesItsStoredClaimsInTheSameRequest(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)
	host, portStr, ok := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if !ok {
		t.Fatalf("cannot split %q", srv.URL)
	}
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store := core.NewTrafficStore()
	var ids []core.ExchangeID
	for _, path := range []string{"/comment?comment=hello", "/comments", "/safe/comments"} {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		raw0, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		body := string(raw0)

		raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		reqID, err := store.Put([]byte(raw), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put request: %v", err)
		}
		respRaw := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		respID, err := store.Put([]byte(respRaw), core.DirectionResponse)
		if err != nil {
			t.Fatalf("put response: %v", err)
		}
		ex := &core.Exchange{Request: reqID, Response: &respID,
			Host: host, Port: uint16(port), TLS: false, Method: "GET", Path: path}
		store.AddExchange(ex)
		ids = append(ids, ex.ID)
	}

	active := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithStoredLedger(scanner.NewStoredLedger()).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckStored: true,
			PendingDeadline: 2 * time.Second})
	// NewServer takes the store the exchanges were seeded into; WithScanner attaches the
	// stored-capable scanner the audit paths share.
	s := NewServer(store, core.NewScope()).WithScanner(active)

	// The bulk audit path is asynchronous by design (202 + task row), so the settlement is
	// observed where it lands: the finding store and the pending registry. Bounded wait — the
	// audit of three exchanges over a loopback vulnapp settles in seconds when the wiring is
	// there, and never when it is not.
	rec := postJSON(t, s, "/api/audit/selected", map[string]any{"exchange_ids": ids})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("bulk audit = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var settled bool
	for i := 0; i < 150 && !settled; i++ {
		if active.PendingCount() == 0 && s.findings.Count() > 0 {
			settled = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !settled {
		// Diagnose rather than guess: name what the registry holds, so the failure tells the
		// next reader which half broke — claims that never registered vs a deferred phase that
		// never ran vs a re-fetch that could not see the canary.
		outs := active.Pending().Outstanding()
		rows := make([]string, 0, len(outs))
		for _, o := range outs {
			rows = append(rows, o.Row)
		}
		t.Fatalf("the stored claim never settled: pending=%d findings=%d rows=%v. Before gxbk "+
			"FinishScan had no web caller, so a web-launched bulk audit left its deferred claims "+
			"outstanding forever", active.PendingCount(), s.findings.Count(), rows)
	}
	// The settled claim must be the stored finding itself, recorded on the store rather than
	// computed and dropped: vulnapp /comments renders every submitted comment unescaped, so a
	// canary planted at /comment surfaces there on the re-fetch.
	for _, f := range s.findings.All() {
		if strings.Contains(strings.ToLower(f.Name), "stored") {
			return
		}
	}
	t.Fatalf("pending drained but no stored finding recorded; the deferred phase ran without " +
		"landing its findings on the store")
}

// The single-item path is synchronous, so its reply can and must carry the deferred phase's
// accounting where the bulk path's 202 cannot (gxbk).
func TestASingleItemAuditReplyCarriesTheDeferredPhase(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)
	host, portStr, ok := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if !ok {
		t.Fatalf("cannot split %q", srv.URL)
	}
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store := core.NewTrafficStore()
	var commentID core.ExchangeID
	for _, path := range []string{"/comment?comment=hello", "/comments"} {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		raw0, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		body := string(raw0)
		raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		reqID, err := store.Put([]byte(raw), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put request: %v", err)
		}
		respRaw := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		respID, err := store.Put([]byte(respRaw), core.DirectionResponse)
		if err != nil {
			t.Fatalf("put response: %v", err)
		}
		ex := &core.Exchange{Request: reqID, Response: &respID,
			Host: host, Port: uint16(port), TLS: false, Method: "GET", Path: path}
		store.AddExchange(ex)
		if path == "/comment?comment=hello" {
			commentID = ex.ID
		}
	}

	active := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithStoredLedger(scanner.NewStoredLedger()).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckStored: true,
			PendingDeadline: 2 * time.Second})
	s := NewServer(store, core.NewScope()).WithScanner(active)

	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(commentID), 10), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("reply is not JSON: %v", err)
	}
	if _, ok := parsed["deferred"]; !ok {
		t.Fatalf("the synchronous audit reply carries no deferred block; the stored claim was " +
			"registered and FinishScan must settle it before the reply (gxbk)")
	}
	if active.PendingCount() != 0 {
		t.Fatalf("pending registry still holds %d claims after the synchronous reply",
			active.PendingCount())
	}
}

// The guard half: an audit that registered no claim must not pay the second-pass traffic. A
// static page cannot plant a canary, so PendingCount stays zero and FinishScan must never run —
// the re-fetch pass is real requests to the target, and paying it with nothing to settle is
// traffic the operator never got value from.
func TestAnAuditThatPlantedNothingSendsNoSecondPassTraffic(t *testing.T) {
	s := newTestServer()
	reqID, err := s.store.Put([]byte("GET /shop HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put resp: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID,
		Host: "h.test", Port: 80, TLS: false, Method: "GET", Path: "/shop"}
	s.store.AddExchange(ex)

	before := s.activeScanner().PendingCount()
	if before != 0 {
		t.Fatalf("a fresh audit found %d pending claims, want 0; the fixture cannot assert the "+
			"guard if claims pre-exist", before)
	}
	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(ex.ID), 10), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if s.activeScanner().PendingCount() != 0 {
		t.Fatalf("claims appeared from a static audit; the guard would now pay second-pass traffic")
	}
	if strings.Contains(rec.Body.String(), `"deferred"`) {
		t.Fatalf("a claim-free audit ran a deferred phase: the re-fetch pass sent traffic with " +
			"nothing to settle (gxbk guard)")
	}
}
