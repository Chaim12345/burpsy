package proxy

// The proxy's capture sites, as a set: whatever traffic they are given, none of them may index a row
// that a consumer walking the exchange index in order would stop at.
//
// # What is actually being pinned, and why it is worth a test of its own
//
// internal/web/liveaudit.go sweeps history from a monotonic high-water cursor and breaks on the first
// exchange whose Response is nil. That break is correct — a row without a response yet may be an
// in-flight request whose answer is about to land, and skipping past it would lose that response from
// the sweep for good. What it cannot survive is a row that will *never* be completed: the cursor stops
// at that index for the life of the process while the sweep's own counters keep looking healthy.
//
// Every proxy capture site used to be able to mint one. Each stored its messages itself, built its own
// core.Exchange literal, and set Response unconditionally from a store.Put whose error it only logged
// — so a response the store rejected produced a row pointing at message 0, and the h2 relay indexed a
// row before its response existed and left it that way whenever the origin errored. They now all go
// through scanner.Capture.Record, which refuses an exchange it cannot complete, and these tests drive
// the sites through the failure modes a unit test of Record cannot reach: real connections and real
// origins that die mid-exchange, answer unparseably, upgrade, or get dropped by the operator.
//
// Three properties, in order: no capture may stall a cursor walking the index; a response the operator
// drops is still recorded and says so; and the CONNECT tunnel row is the one site that does not use the
// shared producer, asserted as such so the exception stays visible instead of quietly widening.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// walkLikeLiveAudit walks the exchange index exactly as the live-audit sweep does and reports how far
// it got. A stall is a row with no response: the walk stops there, permanently, and everything after it
// is never audited.
func walkLikeLiveAudit(t *testing.T, store *core.TrafficStore) (reached int, stalledAt *core.Exchange) {
	t.Helper()
	_, total := store.Count()
	for i := 0; i < total; i++ {
		ex, err := store.GetExchange(uint64(i))
		if err != nil {
			break
		}
		if ex.Response == nil {
			return i, ex
		}
		reached = i + 1
	}
	return reached, nil
}

// deadOrigin accepts a connection and closes it without answering, so the proxy's forward fails after
// the request has already been written. This is the shape that used to leave a stored request with no
// exchange, and — through the h2 relay — an indexed exchange with no response.
func deadOrigin(t *testing.T) (host string, port uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, uint16(n)
}

// malformedOrigin answers with a properly terminated head whose start line has too few tokens, so the
// response is readable off the wire and then rejected by the store's parser. That combination is the one
// the old capture sites mishandled: the store's rejection was logged and the row was indexed anyway,
// with Response pointing at message id 0 — which, on a fresh connection, is that exchange's own
// *request*.
func malformedOrigin(t *testing.T) (host string, port uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				// Terminated, so it reads off the wire cleanly; two tokens, so core.Parse refuses it.
				conn.Write([]byte("HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, uint16(n)
}

func TestNoProxyCaptureCanStallACursorWalkingTheIndex(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer good.Close()
	goodHost, goodPortStr, _ := net.SplitHostPort(strings.TrimPrefix(good.URL, "http://"))

	deadHost, deadPort := deadOrigin(t)
	malformedHost, malformedPort := malformedOrigin(t)
	wsHost, wsPort, wsReceived := startWsOrigin(t, nil)

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(core.NewFindingStore()))
	proxyAddr := startProxy(t, srv)

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		DisableKeepAlives: true,
	}}
	get := func(target string) {
		resp, err := client.Get(target)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	// One good exchange, then the two failure modes, then another good one. The order matters: the
	// failures sit *between* two captures, which is exactly where a stalling row does its damage — the
	// second good exchange is the one a stalled cursor would never reach.
	get(fmt.Sprintf("http://%s:%s/first", goodHost, goodPortStr))
	get(fmt.Sprintf("http://%s:%d/dead", deadHost, deadPort))
	get(fmt.Sprintf("http://%s:%d/malformed", malformedHost, malformedPort))

	// A WebSocket upgrade captures its handshake through the same producer, with the 101 head as the
	// response, so it must not stall the walk either.
	openWsThroughProxy(t, proxyAddr, wsHost, wsPort)
	awaitOrigin(t, wsReceived)

	get(fmt.Sprintf("http://%s:%s/last", goodHost, goodPortStr))

	// Wait for the last row: capture happens after the client has its bytes. This also checks every row
	// recorded so far for a stored response, which is the property the walk below depends on.
	awaitExchangeFor(t, store, "/last", "proxy")

	reached, stalled := walkLikeLiveAudit(t, store)
	if stalled != nil {
		t.Fatalf("the walk stopped at exchange %d (%s %s %s): a row with no response stalls the live-audit "+
			"cursor there for the life of the process",
			stalled.ID, stalled.Method, stalled.Host, stalled.Path)
	}
	_, total := store.Count()
	if reached != total {
		t.Fatalf("the walk reached %d of %d rows", reached, total)
	}
	if !hasPath(store, "/first") || !hasPath(store, "/last") {
		t.Fatalf("expected both good exchanges to be in history, got %v", pathsIn(store))
	}
	// The two failures are absent rather than half-recorded. Their reason is a log line, which is the
	// proxy's ledger; the crawler's equivalent is a skip record. Neither invents a row.
	if hasPath(store, "/dead") {
		t.Errorf("a forward that never got a response produced an exchange: %v", pathsIn(store))
	}
	if hasPath(store, "/malformed") {
		t.Errorf("a response the store could not parse produced an exchange: %v", pathsIn(store))
	}

	// Every row's message ids resolve, and resolve to messages of the right direction. This is the
	// assertion the old sites failed: a rejected store.Put left respID at its zero value and the row was
	// indexed with Response pointing at message 0, so a row could claim a request as its response.
	for _, ex := range store.Exchanges() {
		req, err := store.Get(ex.Request)
		if err != nil {
			t.Errorf("exchange %d (%s): its request id does not resolve: %v", ex.ID, ex.Path, err)
			continue
		}
		if req.Shape.Direction != core.DirectionRequest {
			t.Errorf("exchange %d (%s): its request id points at a %v", ex.ID, ex.Path, req.Shape.Direction)
		}
		resp, err := store.Get(*ex.Response)
		if err != nil {
			t.Errorf("exchange %d (%s): its response id does not resolve: %v", ex.ID, ex.Path, err)
			continue
		}
		if resp.Shape.Direction != core.DirectionResponse {
			t.Errorf("exchange %d (%s): its response id points at a %v", ex.ID, ex.Path, resp.Shape.Direction)
		}
	}
}

// A response the operator drops is still recorded, and the row says the client received nothing.
//
// This is a behaviour change, and it is the one place where collapsing the sites had to pick a winner
// rather than preserve both. The TLS path indexed its row before offering the response to the hold
// queue, so a dropped response was in history; the plain path stored the bytes and returned before
// creating a row, so it was not — the message was in the store with nothing indexing it. Recording it
// is the behaviour worth keeping: an operator who can drop a response and leave history showing a
// request that was never answered has a history that lies about the origin. The note is what keeps that
// row honest, because the bytes alone cannot say they were never delivered.
func TestADroppedResponseIsRecordedAndTheRowSaysTheClientNeverGotIt(t *testing.T) {
	const body = "<html><body>dropped</body></html>"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer origin.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	// Hold every response, unconditionally: an empty rule list on an active list is Burp's
	// "intercept everything", and it keeps this test about the drop rather than about rule matching.
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionResponse, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithIntercept(engine))
	proxyAddr := startProxy(t, srv)

	// The operator: drop the first response offered.
	dropped := make(chan struct{})
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction == intercept.DirectionResponse {
					if err := engine.Drop(held.ID, "not forwarding this"); err == nil {
						close(dropped)
						return
					}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		DisableKeepAlives: true,
	}}
	resp, err := client.Get(fmt.Sprintf("http://%s:%s/dropped", host, portStr))
	if err == nil {
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(got) == body {
			t.Fatal("the client received the response the operator dropped")
		}
	}
	select {
	case <-dropped:
	case <-time.After(5 * time.Second):
		t.Fatal("the response was never offered to the hold queue")
	}

	ex := awaitExchangeFor(t, store, "/dropped", "proxy")
	if ex.Notes == nil {
		t.Fatal("the row does not say the response was dropped, so history shows the client receiving bytes it never got")
	}
	if !strings.Contains(*ex.Notes, "dropped") {
		t.Errorf("the note does not name what happened: %q", *ex.Notes)
	}
	stored, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("stored response: %v", err)
	}
	if !strings.Contains(string(stored.Raw()), body) {
		t.Errorf("the recorded bytes are not the origin's answer: %q", stored.Raw())
	}
}

// The named exception, pinned so it cannot widen silently. A blind CONNECT tunnel records that it
// happened and nothing about its contents — there are no bytes, because nothing was decrypted — so it
// is the one row in the proxy that Record does not and cannot produce. It is also the one row that can
// stall the sweep, which is a fact about that cursor's break-on-nil rule and not about this capture
// path; see the comment at tunnelConnection.
func TestTheBlindTunnelRowIsTheOnlyCaptureNotMadeByTheSharedProducer(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(origin.Addr().String())

	store := core.NewTrafficStore()
	policy := NewTlsPolicy()
	policy.AddPassthrough(host)
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithLogger(zap.NewNop()))
	proxyAddr := startProxy(t, srv)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, portStr, host, portStr)
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read connect answer: %v", err)
	}

	awaitExchange(t, store)
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1 (the tunnel row)", len(exchanges))
	}
	tunnel := exchanges[0]
	if tunnel.Method != "CONNECT" {
		t.Fatalf("the recorded row is %s %s, not the tunnel", tunnel.Method, tunnel.Path)
	}
	if tunnel.Response != nil {
		t.Error("the tunnel row has a response: if a tunnel now records bytes, it should go through the " +
			"shared producer like everything else and this exception should be deleted")
	}
	if tunnel.Source != core.SourceProxy {
		t.Errorf("the tunnel row is attributed to %q, so history cannot say the proxy opened it", tunnel.Source)
	}
	// Messages, not just the row: this is what makes the exception real rather than a shortcut. There
	// are no bytes to give Record, because nothing was decrypted.
	if msgs, _ := store.Count(); msgs != 0 {
		t.Errorf("a blind tunnel stored %d messages; it has no plaintext to store", msgs)
	}
}

func pathsIn(store *core.TrafficStore) []string {
	var out []string
	for _, ex := range store.Exchanges() {
		out = append(out, ex.Method+" "+ex.Path)
	}
	return out
}

func hasPath(store *core.TrafficStore, path string) bool {
	for _, ex := range store.Exchanges() {
		if ex.Path == path {
			return true
		}
	}
	return false
}
