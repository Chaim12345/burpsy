package proxy

import (
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
	"go.uber.org/zap"
)

// ---- response modification rules across the scope boundary --------------------------------
//
// These tests pin two things that were wrong in opposite directions.
//
// `handleTLSResponse` has always applied the response rules *before* its `if inScope` check,
// so an out-of-scope HTTPS response was rewritten. The plaintext path returned early into
// `forwardOnly`, which wrote the origin's bytes to the client untouched, so an out-of-scope
// plaintext response was not. Same option, same scope verdict, opposite behaviour decided by
// whether the destination happened to use TLS.
//
// The direction of the fix is set by what these rules are. "Remove all JavaScript" is
// defensive — an operator turns it on to stop content reaching their browser — and a defence
// that silently lapses for part of the traffic is worse than one that is off, because the panel
// says it is on. It is also what `applyRequestRules` already documents for the request
// direction: rules run before the scope check so an out-of-scope forward sends exactly the
// bytes the recorded path would. Scope decides what is *retained*, never what is *rewritten*.
//
// The second wrong thing was the counting. An out-of-scope rewrite leaves no history row, so
// `responses_modified` included responses no history search could ever turn up, and the
// operator had no way to tell a counter bug from a scope decision. Hence
// `responses_modified_unrecorded`: Modified - ModifiedUnrecorded is the number findable in
// history, by construction.

// outOfScope returns a scope whose include list covers a host that is not the origin, so the
// origin falls outside it.
//
// Not `core.NewScope()` with no rules: `Scope.Contains` is **default-allow** — with no include
// rule at all, everything not explicitly excluded is in scope (`scope.go:253`). A bare
// NewScope() therefore puts the origin *in* scope and would make these tests pass for the
// wrong reason, which is exactly what the first draft of this file did.
//
// An include list that does not cover the destination is also the realistic shape of the bug:
// the operator scoped their engagement to a target, and this is the third-party traffic their
// browser makes alongside it. That is the traffic "remove all JavaScript" was silently failing
// to touch.
func outOfScope() *core.Scope {
	s := core.NewScope()
	s.AddInclude("scoped-target.test")
	return s
}

// scriptedOrigin serves one HTML page containing a <script> element, and reports its own
// host/port. HTML and a Content-Type of text/html both matter: ApplyResponse skips a response
// it cannot identify as HTML, and a test whose origin sent text/plain would pass while proving
// only that the skip counter works.
func scriptedOrigin(t *testing.T) (host string, port int, close func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><body>KEEPME<script>alert('DELETEME')</script></body></html>")
	}))
	h, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	p, _ := strconv.Atoi(portStr)
	return h, p, srv.Close
}

// driveThroughProxy runs one plaintext GET through a proxy server and returns the body the
// client received.
func driveThroughProxy(t *testing.T, srv *Server, host string, port int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/page", host, port))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// waitForExchanges polls until the store holds `want` exchanges, or fails.
//
// Necessary because the record is not ordered with respect to the client's read.
// `completeResponse` writes the response to the client and only *then* calls `s.record`
// (proxy.go: `clientConn.Write(responseData)` precedes `s.record(...)`), so
// driveThroughProxy returns as soon as io.ReadAll finishes — which can be before the
// recording goroutine has run at all.
//
// Asserting immediately therefore passed in isolation and failed under load, which is
// exactly what a full-suite run reported: "recorded 0 exchanges, want 1". The fix belongs
// in the test rather than in the proxy: the write-then-record order is deliberate (the
// client must not wait on bookkeeping), so the observable event the test can synchronise
// on is the store's contents, not the response body.
func waitForExchanges(t *testing.T, store *core.TrafficStore, want int) []*core.Exchange {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got []*core.Exchange
	for time.Now().Before(deadline) {
		got = store.Exchanges()
		if len(got) >= want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("after 5s the store holds %d exchanges, want %d", len(got), want)
	return nil
}

// settleThenCountExchanges gives any pending record a chance to land, then reports the count.
//
// The mirror of waitForExchanges, for the assertions that want *zero*. Those cannot
// false-fail on a slow record — they can false-*pass*, reporting success because the
// record had not happened yet rather than because it never will. A fixed settle is the
// honest way to assert an absence: there is no event to wait for when the correct
// behaviour is that nothing happens.
func settleThenCountExchanges(store *core.TrafficStore) int {
	time.Sleep(250 * time.Millisecond)
	return len(store.Exchanges())
}

// The defect, driven end to end: an out-of-scope plaintext response used to reach the browser
// with its JavaScript intact while the option said it had been removed.
func TestResponseRulesApplyToOutOfScopePlaintextTraffic(t *testing.T) {
	host, port, closeOrigin := scriptedOrigin(t)
	defer closeOrigin()

	options := NewOptions()
	// The retention these tests pin is the seeded one: dont_log_out_of_scope ON. Set
	// explicitly because NewOptions is all-off, and the unrecorded branch this file
	// exists to test only runs when the exchange is actually being dropped.
	if err := options.Set(OptDontLogOutOfScope, true); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := options.Set(OptRemoveAllJavaScript, true); err != nil {
		t.Fatalf("Set: %v", err)
	}

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(outOfScope()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	body := driveThroughProxy(t, srv, host, port)

	if strings.Contains(body, "DELETEME") {
		t.Errorf("the client received the script through an out-of-scope forward: %q\n"+
			"remove_all_javascript was on; scope must decide what is retained, not what is rewritten", body)
	}
	if !strings.Contains(body, "KEEPME") {
		t.Errorf("the rule removed more than the script: %q", body)
	}

	// And the rewrite is accounted for as unrecorded, because nothing was stored.
	c := options.Counters()
	if c.Modified != 1 {
		t.Errorf("Modified = %d, want 1", c.Modified)
	}
	if c.ModifiedUnrecorded != 1 {
		t.Errorf("ModifiedUnrecorded = %d, want 1 — an out-of-scope rewrite leaves no history row and must say so", c.ModifiedUnrecorded)
	}
	if got := settleThenCountExchanges(store); got != 0 {
		t.Errorf("out-of-scope traffic recorded %d exchanges, want 0", got)
	}
}

// The in-scope control. Same rule, same origin, scope now includes it: the rewrite still
// happens, it is still counted as Modified, but ModifiedUnrecorded stays zero because the
// exchange is in history where the operator can find it.
//
// Without this test the one above would pass if ModifiedUnrecorded were simply incremented on
// every modification.
func TestAnInScopeRewriteIsNotCountedAsUnrecorded(t *testing.T) {
	host, port, closeOrigin := scriptedOrigin(t)
	defer closeOrigin()

	options := NewOptions()
	if err := options.Set(OptRemoveAllJavaScript, true); err != nil {
		t.Fatalf("Set: %v", err)
	}

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	body := driveThroughProxy(t, srv, host, port)
	if strings.Contains(body, "DELETEME") {
		t.Errorf("an in-scope response kept its script: %q", body)
	}

	c := options.Counters()
	if c.Modified != 1 {
		t.Errorf("Modified = %d, want 1", c.Modified)
	}
	if c.ModifiedUnrecorded != 0 {
		t.Errorf("ModifiedUnrecorded = %d, want 0 — this exchange is in history, so the rewrite is findable", c.ModifiedUnrecorded)
	}
	recorded := waitForExchanges(t, store, 1)
	if len(recorded) != 1 {
		t.Fatalf("in-scope traffic recorded %d exchanges, want 1", len(recorded))
	}
	// The recorded bytes are the rewritten bytes: what history shows must be what the client
	// received. This is the existing invariant, asserted here because the new unrecorded branch
	// runs alongside it and must not have changed which bytes get stored.
	stored := recorded[0]
	if stored.Response == nil {
		t.Fatal("the recorded exchange has no response")
	}
	msg, err := store.Get(*stored.Response)
	if err != nil {
		t.Fatalf("Get recorded response: %v", err)
	}
	if strings.Contains(string(msg.Raw()), "DELETEME") {
		t.Error("history stored the pre-rewrite bytes; the client received the rewritten ones")
	}
}

// An out-of-scope response the rules were allowed to look at and did not change must not be
// counted as unrecorded. The counter is a subset of Modified, not a count of out-of-scope
// traffic, and this is the test that keeps it one.
func TestAnUnchangedOutOfScopeResponseIsNotCountedAsUnrecorded(t *testing.T) {
	srv0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// HTML with no script, no object tag and no hidden input: eligible, and nothing to do.
		io.WriteString(w, "<html><body>nothing to rewrite here</body></html>")
	}))
	defer srv0.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv0.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	options := NewOptions()
	// Seeded retention, set explicitly: see the comment in
	// TestResponseRulesApplyToOutOfScopePlaintextTraffic.
	if err := options.Set(OptDontLogOutOfScope, true); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := options.Set(OptRemoveAllJavaScript, true); err != nil {
		t.Fatalf("Set: %v", err)
	}

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(outOfScope()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	driveThroughProxy(t, srv, host, port)

	c := options.Counters()
	if c.Considered != 1 {
		t.Errorf("Considered = %d, want 1 — the rules were on, so this response was a candidate", c.Considered)
	}
	if c.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", c.Unchanged)
	}
	if c.ModifiedUnrecorded != 0 {
		t.Errorf("ModifiedUnrecorded = %d, want 0 — nothing was modified, so nothing can be an unrecorded modification", c.ModifiedUnrecorded)
	}
}

// With every rule off, an out-of-scope forward must be byte-identical to what the origin sent.
// This is the regression guard on the fix itself: routing forwardOnly's response through
// ApplyResponse must stay a no-op when no rule is enabled, or the fix would have made the proxy
// touch bytes it has no business touching.
func TestWithNoRulesOnAnOutOfScopeForwardIsUntouched(t *testing.T) {
	host, port, closeOrigin := scriptedOrigin(t)
	defer closeOrigin()

	options := NewOptions()
	// Seeded retention, set explicitly: see the comment in
	// TestResponseRulesApplyToOutOfScopePlaintextTraffic.
	if err := options.Set(OptDontLogOutOfScope, true); err != nil {
		t.Fatalf("Set: %v", err)
	}
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(outOfScope()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	body := driveThroughProxy(t, srv, host, port)
	if !strings.Contains(body, "DELETEME") || !strings.Contains(body, "KEEPME") {
		t.Errorf("an out-of-scope forward with no rules on altered the body: %q", body)
	}
	c := options.Counters()
	if c.Considered != 0 {
		t.Errorf("Considered = %d, want 0 — a response that arrived with every rule off was never a candidate", c.Considered)
	}
	if c.ModifiedUnrecorded != 0 {
		t.Errorf("ModifiedUnrecorded = %d, want 0", c.ModifiedUnrecorded)
	}
}

// A nil option set must not crash the out-of-scope path. A Server built without WithOptions has
// no rules, and forwardOnly now calls through the option set on every out-of-scope response, so
// this is the shape that would panic if the nil-tolerance were lost.
func TestOutOfScopeForwardingSurvivesANilOptionSet(t *testing.T) {
	host, port, closeOrigin := scriptedOrigin(t)
	defer closeOrigin()

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(outOfScope()).
		WithLogger(zap.NewNop()))

	body := driveThroughProxy(t, srv, host, port)
	if !strings.Contains(body, "DELETEME") {
		t.Errorf("a server with no option set altered the body: %q", body)
	}
}
