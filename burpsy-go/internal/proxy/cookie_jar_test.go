package proxy

// The proxy feeds the shared session cookie jar.
//
// Burp: "By default, the cookie jar is updated based on traffic from the Proxy." burpsy said the same
// thing in the Session page's empty state — "send authenticated traffic through the proxy" — while no
// code on the proxy path absorbed a Set-Cookie at all. The jar was fed only by login macros, the
// crawler's session gate and project recovery, so an operator who logged in through their browser had
// an empty jar and copy telling them their browsing should have filled it.
//
// These tests drive real traffic through a real listener, because that is the claim: not that a
// coordinator method works, but that browsing fills the jar.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// proxiedGet drives one plaintext GET through the listener and waits for its capture, so the assertions
// below run after the absorption that happens on the capture path.
func proxiedGet(t *testing.T, proxyAddr, target, path string, store *core.TrafficStore) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		DisableKeepAlives: true,
	}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s through the proxy: %v", target, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	awaitExchangeFor(t, store, path, "proxy")
}

func TestProxiedTrafficFillsTheSessionCookieJar(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two lines, deliberately. A real login sets a session cookie and a CSRF cookie, and the
		// coordinator's older map-shaped HandleResponse can carry exactly one of them — which is why
		// the proxy absorbs from the raw bytes instead.
		w.Header().Add("Set-Cookie", "sessid=abc123; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "csrf=deadbeef; Path=/")
		io.WriteString(w, "<html>logged in</html>")
	}))
	defer origin.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	coord := session.NewCoordinator(zap.NewNop())
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(core.NewFindingStore()).
		WithCookieJar(coord))
	proxyAddr := startProxy(t, srv)

	proxiedGet(t, proxyAddr, fmt.Sprintf("http://%s:%s/login", host, portStr), "/login", store)

	port := mustPort(t, portStr)
	got := coord.CookieHeader(host, port, false)
	if got == "" {
		t.Fatalf("the cookie jar for %s:%d is empty after a proxied response that set two cookies; "+
			"the Session page tells the operator this traffic fills it", host, port)
	}
	for _, want := range []string{"sessid=abc123", "csrf=deadbeef"} {
		if !strings.Contains(got, want) {
			t.Errorf("cookie header %q is missing %q", got, want)
		}
	}

	obs := coord.Observation()
	if len(obs.Sources) != 1 || obs.Sources[0] != session.SourceProxy {
		t.Errorf("absorption sources = %v, want [proxy]: the jar must be able to say what feeds it",
			obs.Sources)
	}
	if obs.SetCookiesAbsorbed != 2 {
		t.Errorf("set-cookies absorbed = %d, want 2", obs.SetCookiesAbsorbed)
	}
}

func TestAProxyWithNoCookieJarAbsorbsNothingAndSaysSo(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sessid=abc123")
		io.WriteString(w, "<html>ok</html>")
	}))
	defer origin.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	// No WithCookieJar: the wiring a server built without a session coordinator has.
	coord := session.NewCoordinator(zap.NewNop())
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(core.NewFindingStore()))
	proxyAddr := startProxy(t, srv)

	proxiedGet(t, proxyAddr, fmt.Sprintf("http://%s:%s/ok", host, portStr), "/ok", store)

	if h := coord.CookieHeader(host, mustPort(t, portStr), false); h != "" {
		t.Errorf("an unattached coordinator holds %q", h)
	}
	// The point of the assertion: the jar reports that nothing feeds it, so an empty table is not
	// reported as "no Set-Cookie yet". A nil jar must not read like a quiet one.
	if obs := coord.Observation(); len(obs.Sources) != 0 {
		t.Errorf("absorption sources = %v, want none", obs.Sources)
	}
}

// WithCookieJar(nil) must leave the config absorbing nothing rather than panicking on the response
// path — the same nil-tolerant shape WithOptions has.
func TestWithCookieJarNilIsANoOp(t *testing.T) {
	cfg := NewProxyConfig(core.NewTrafficStore())
	if cfg.WithCookieJar(nil).cookieJar != nil {
		t.Fatal("WithCookieJar(nil) installed something")
	}
}

func mustPort(t *testing.T, portStr string) uint16 {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(portStr, "%d", &n); err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return uint16(n)
}
