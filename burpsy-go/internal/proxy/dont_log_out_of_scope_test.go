package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- dont_log_out_of_scope: retention across the scope boundary ---------------------------
//
// Burp's proxy history panel offers three dispositions for out-of-scope items — don't log,
// ask each time, do nothing — and this engine has only ever had the first, hardcoded: every
// record site gates on the scope verdict and drops. burpsy-react-ui-am6 asks for the switch
// to exist. The seed is ON (see OptDontLogOutOfScope for why this diverges from Burp's
// default "do nothing": the store has never held out-of-scope rows, and flipping that on
// upgrade would silently retain third-party traffic), so the tests that matter are the two
// directions:
//
//   - ON, the seed: the drop must stay a drop, and now it is *counted* — an empty history
//     plus a rising exchanges_dropped_out_of_scope says "scope did that", where before the
//     operator could not tell a scope decision from a quiet target.
//   - OFF: the excluded exchange is recorded exactly as an in-scope one — the capability
//     the switch exists for. Its rewrites are then findable in history, which is why
//     ModifiedUnrecorded must stay zero: counting a recorded rewrite as unrecorded would
//     overstate what history cannot show.

// plainOrigin serves one HTML page and reports its host/port, mirroring scriptedOrigin from
// options_scope_test.go without the script-marker body: these tests are about retention, so
// the body content is deliberately inert.
func plainOrigin(t *testing.T) (host string, port int, close func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>retention probe</body></html>"))
	}))
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ = strconv.Atoi(p)
	return h, port, srv.Close
}

func scopeExcludingOrigin() *core.Scope {
	s := core.NewScope()
	s.AddInclude("scoped-target.test")
	return s
}

func setFlag(t *testing.T, o *Options, key OptionKey, value bool) {
	t.Helper()
	if err := o.Set(key, value); err != nil {
		t.Fatalf("Set(%s, %v): %v", key, value, err)
	}
}

// The seed: NewProxyConfig turns the switch on, and the option is editable through the API's
// known-key set. Seeded ON because the store has never held out-of-scope rows; the test keeps
// a change to that default from landing silently.
func TestDontLogOutOfScopeIsSeededOn(t *testing.T) {
	cfg := NewProxyConfig(core.NewTrafficStore())
	if !cfg.options.Get(OptDontLogOutOfScope) {
		t.Error("dont_log_out_of_scope seeded off; the store has always dropped out-of-scope exchanges and the seed must preserve that")
	}

	for _, k := range OptionKeys {
		if k == OptDontLogOutOfScope {
			return
		}
	}
	t.Error("dont_log_out_of_scope missing from OptionKeys; the API's PUT validates against that list and would reject the switch")
}

// Switch on (the seed): an out-of-scope exchange is forwarded and dropped, and the drop is
// counted. This is the existing behaviour plus the counter — the point of am6's second half.
func TestDontLogOutOfScopeCountsTheDrop(t *testing.T) {
	host, port, closeOrigin := plainOrigin(t)
	defer closeOrigin()

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(scopeExcludingOrigin()).
		WithLogger(zap.NewNop()))

	driveThroughProxy(t, srv, host, port)

	if got := settleThenCountExchanges(srv.config.store); got != 0 {
		t.Errorf("out-of-scope traffic recorded %d exchanges, want 0 with the switch on", got)
	}
	if got := srv.config.options.Counters().DroppedOutOfScope; got != 1 {
		t.Errorf("DroppedOutOfScope = %d, want 1 — a counted drop is what makes a mis-set scope visible", got)
	}
}

// Switch off: the same exchange is recorded — Burp's "do nothing" — and nothing is counted
// as a drop, because the operator asked for it to be kept.
func TestLogOutOfScopeWhenSwitchOff(t *testing.T) {
	host, port, closeOrigin := plainOrigin(t)
	defer closeOrigin()

	options := NewOptions()
	setFlag(t, options, OptDontLogOutOfScope, false)

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scopeExcludingOrigin()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	driveThroughProxy(t, srv, host, port)

	recorded := waitForExchanges(t, store, 1)
	if len(recorded) != 1 {
		t.Fatalf("out-of-scope traffic recorded %d exchanges, want 1 with the switch off", len(recorded))
	}
	if recorded[0].Response == nil {
		t.Fatal("the recorded out-of-scope exchange has no response")
	}
	if got := options.Counters().DroppedOutOfScope; got != 0 {
		t.Errorf("DroppedOutOfScope = %d, want 0 — the operator chose to keep this exchange", got)
	}
}

// Switch off with a rule on: the rewrite of an out-of-scope response lands in history, so it
// is findable — ModifiedUnrecorded must stay zero. The unrecorded counter exists to say what
// history cannot show; when the exchange IS in history, showing it would be a lie.
func TestRewriteOfALoggedOutOfScopeResponseIsNotCountedAsUnrecorded(t *testing.T) {
	// scriptedOrigin's body has a script to delete; plainOrigin's does not.
	shost, sport, closeOrigin := scriptedOrigin(t)
	defer closeOrigin()

	options := NewOptions()
	setFlag(t, options, OptDontLogOutOfScope, false)
	setFlag(t, options, OptRemoveAllJavaScript, true)

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scopeExcludingOrigin()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	body := driveThroughProxy(t, srv, shost, sport)

	if strings.Contains(body, "DELETEME") {
		t.Errorf("the rule did not run on a logged out-of-scope response: %q", body)
	}

	c := options.Counters()
	if c.Modified != 1 {
		t.Errorf("Modified = %d, want 1", c.Modified)
	}
	if c.ModifiedUnrecorded != 0 {
		t.Errorf("ModifiedUnrecorded = %d, want 0 — this rewrite is in history, so it is findable", c.ModifiedUnrecorded)
	}
	exchanges := waitForExchanges(t, store, 1)
	msg, err := store.Get(*exchanges[0].Response)
	if err != nil {
		t.Fatalf("Get recorded response: %v", err)
	}
	if strings.Contains(string(msg.Raw()), "DELETEME") {
		t.Error("history stored the pre-rewrite bytes; the client received the rewritten ones")
	}
}

// In-scope traffic is untouched by the switch in both positions: recorded either way, and
// never counted as a drop. The counter is "how many did the switch cost me", not a count of
// out-of-scope traffic.
func TestInScopeTrafficNeverCountsAsDropped(t *testing.T) {
	host, port, closeOrigin := scriptedOrigin(t)
	defer closeOrigin()

	for _, flagOn := range []bool{true, false} {
		options := NewOptions()
		setFlag(t, options, OptDontLogOutOfScope, flagOn)

		store := core.NewTrafficStore()
		srv := NewServer(NewProxyConfig(store).
			WithScope(testScope()).
			WithOptions(options).
			WithLogger(zap.NewNop()))

		driveThroughProxy(t, srv, host, port)
		waitForExchanges(t, store, 1)

		if got := options.Counters().DroppedOutOfScope; got != 0 {
			t.Errorf("flagOn=%v: DroppedOutOfScope = %d, want 0 — in-scope traffic is never a drop", flagOn, got)
		}
	}
}

// The TLS relay honours the switch too: off, an out-of-scope HTTPS exchange is decrypted,
// recorded, and its response rules run — matching what the plaintext path now does, instead
// of the two protocols disagreeing again the way they did before options_scope_test.go.
func TestLogOutOfScopeTLSExchangeWhenSwitchOff(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// A script to delete: proves the rules ran on a logged out-of-scope exchange,
		// not merely that the exchange was stored.
		_, _ = w.Write([]byte("<html><body>KEEPME<script>DELETEME</script></body></html>"))
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	target.StartTLS()
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))

	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)

	options := NewOptions()
	setFlag(t, options, OptDontLogOutOfScope, false)
	setFlag(t, options, OptRemoveAllJavaScript, true) // the rules must run on the logged exchange too

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scopeExcludingOrigin()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

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
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + net.JoinHostPort(thost, tportStr) + "/")
	if err != nil {
		t.Fatalf("https through proxy: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "KEEPME") || strings.Contains(string(b), "DELETEME") {
		t.Errorf("the rules did not run correctly on a logged out-of-scope TLS response: %q", b)
	}

	exchanges := awaitExchange(t, store)
	if !exchanges.TLS || exchanges.Method != "GET" {
		t.Errorf("exchange = %+v, want a recorded GET over TLS", exchanges)
	}
	c := options.Counters()
	if c.DroppedOutOfScope != 0 {
		t.Errorf("DroppedOutOfScope = %d, want 0 — the exchange was kept at the operator's request", c.DroppedOutOfScope)
	}
	if c.Modified != 1 {
		t.Errorf("Modified = %d, want 1 — the rules ran on a response that was then recorded", c.Modified)
	}
	if c.ModifiedUnrecorded != 0 {
		t.Errorf("ModifiedUnrecorded = %d, want 0 — the rewrite is in history", c.ModifiedUnrecorded)
	}
	stored, err := store.Get(*exchanges.Response)
	if err != nil {
		t.Fatalf("Get recorded response: %v", err)
	}
	if strings.Contains(string(stored.Raw()), "DELETEME") {
		t.Error("history stored the pre-rewrite bytes; the client received the rewritten ones")
	}
}

// And the TLS mirror of the counter test: on, an out-of-scope HTTPS exchange is decrypted
// and delivered but not recorded, and the drop is counted like any other.
func TestDontLogOutOfScopeCountsTheTLSDrop(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>tls drop probe</body></html>"))
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	target.StartTLS()
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))

	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)

	options := NewOptions()
	setFlag(t, options, OptDontLogOutOfScope, true)

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scopeExcludingOrigin()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

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
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + net.JoinHostPort(thost, tportStr) + "/")
	if err != nil {
		t.Fatalf("https through proxy: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "tls drop probe") {
		t.Errorf("the client received %q — the switch must never stop the delivery", b)
	}

	if got := settleThenCountExchanges(store); got != 0 {
		t.Errorf("out-of-scope TLS traffic recorded %d exchanges, want 0 with the switch on", got)
	}
	if got := options.Counters().DroppedOutOfScope; got != 1 {
		t.Errorf("DroppedOutOfScope = %d, want 1 — the TLS drop is counted like the plaintext one", got)
	}
}
