package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// This file is the other half of Unit 9's coverage claim. internal/sender's egress is tested in that
// package; this asserts the listener's own origin-facing leg, which is the half that is easy to forget
// and the one whose absence produces the worst outcome: an operator sets a corporate proxy, watches the
// scanner's traffic take it, and never learns that everything their browser drove through the listener
// went straight out.
//
// Five dial sites exist here — the intercepted TLS leg, the blind CONNECT tunnel, the plain-HTTP
// forward, the out-of-scope forward and the WebSocket relay's origin socket. The two reachable without
// a CA are driven below; all five share dialUpstream/dialUpstreamTLS, so the assertion is that the
// shared path is wired rather than that each caller re-implements it.

// upstreamOrigin starts a plain-HTTP origin and returns its host, port and authority.
func upstreamOrigin(t *testing.T) (host string, port uint16, authority string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("reached the origin"))
	}))
	t.Cleanup(server.Close)
	authority = strings.TrimPrefix(server.URL, "http://")
	h, p, _ := net.SplitHostPort(authority)
	n, _ := strconv.Atoi(p)
	return h, uint16(n), authority
}

// proxyThrough builds a listener whose upstream leg follows a policy pointing at proxyURL.
func proxyThrough(t *testing.T, proxyURL string) (*Server, *upstream.Policy) {
	t.Helper()
	policy := upstream.NewPolicy()
	if err := policy.SetDefault(proxyURL); err != nil {
		t.Fatalf("SetDefault(%q): %v", proxyURL, err)
	}
	config := NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScope()).
		WithUpstreamProxy(policy)
	return NewServer(config), policy
}

// forwardThrough drives one absolute-form GET through the listener and returns the response bytes.
func forwardThrough(t *testing.T, proxyAddr, authority string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial the listener: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority, authority)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		t.Fatalf("read response: %v", err)
	}
	return string(raw)
}

// The plain-HTTP forward — the listener's most-travelled leg — goes through the configured proxy.
func Test_the_listeners_plain_http_forward_traverses_the_upstream_proxy(t *testing.T) {
	_, _, authority := upstreamOrigin(t)
	proxy := upstreamtest.StartConnect(t, "", "")
	srv, _ := proxyThrough(t, "http://"+proxy.Addr())

	body := forwardThrough(t, startProxy(t, srv), authority)
	if !strings.Contains(body, "reached the origin") {
		t.Errorf("the origin's body did not come back through the listener; got %q", body)
	}
	if !proxy.Saw(authority) {
		t.Errorf("the upstream proxy was asked for %v, not %q — the listener's forward leg went out "+
			"direct, so a settings panel would be reporting coverage it does not have",
			proxy.Requests(), authority)
	}
	if errs := proxy.Errors(); len(errs) > 0 {
		t.Errorf("the upstream proxy could not parse what the listener sent: %v", errs)
	}
}

// The blind CONNECT tunnel — what a browser's HTTPS request becomes with no CA configured — also goes
// through the configured proxy, chaining CONNECT through CONNECT.
func Test_the_listeners_connect_tunnel_traverses_the_upstream_proxy(t *testing.T) {
	_, _, authority := upstreamOrigin(t)
	proxy := upstreamtest.StartConnect(t, "", "")
	srv, _ := proxyThrough(t, "http://"+proxy.Addr())
	proxyAddr := startProxy(t, srv)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial the listener: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read the tunnel's status line: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("the listener refused the tunnel: %q", status)
	}
	if !proxy.Saw(authority) {
		t.Errorf("the upstream proxy was asked for %v, not %q — the blind tunnel went out direct",
			proxy.Requests(), authority)
	}
}

// SOCKS5 carries the listener's leg too, through the same dialer the senders use.
func Test_the_listeners_forward_traverses_a_socks5_proxy(t *testing.T) {
	_, _, authority := upstreamOrigin(t)
	proxy := upstreamtest.StartSOCKS5(t, "operator", "s3cr3t")
	srv, _ := proxyThrough(t, "socks5://operator:s3cr3t@"+proxy.Addr())

	body := forwardThrough(t, startProxy(t, srv), authority)
	if !strings.Contains(body, "reached the origin") {
		t.Errorf("the origin's body did not come back through socks5; got %q", body)
	}
	if len(proxy.Requests()) == 0 {
		t.Fatal("the socks5 proxy was never asked for anything, so the listener went out direct")
	}
	if creds := proxy.Credentials(); len(creds) == 0 || creds[0] != "operator" {
		t.Errorf("the socks5 proxy saw credentials %v, want operator", creds)
	}
}

// A rule edited after the listener is running applies to the next connection.
//
// This is the reason the policy is held by reference rather than copied into the config: a restart is
// the wrong shape for a setting an operator changes while a browser is pointed at the proxy.
func Test_an_upstream_rule_added_after_startup_applies_to_the_next_connection(t *testing.T) {
	_, _, authority := upstreamOrigin(t)
	proxy := upstreamtest.StartConnect(t, "", "")

	// Start with an empty policy: the first forward goes direct.
	policy := upstream.NewPolicy()
	config := NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScope()).
		WithUpstreamProxy(policy)
	proxyAddr := startProxy(t, NewServer(config))

	if body := forwardThrough(t, proxyAddr, authority); !strings.Contains(body, "reached the origin") {
		t.Fatalf("the unproxied forward did not reach the origin; got %q", body)
	}
	if n := len(proxy.Requests()); n != 0 {
		t.Fatalf("the proxy saw %d request(s) before any rule was configured", n)
	}

	// Now add the rule, as /api/network/proxy would.
	if err := policy.SetDefault("http://" + proxy.Addr()); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	if body := forwardThrough(t, proxyAddr, authority); !strings.Contains(body, "reached the origin") {
		t.Fatalf("the proxied forward did not reach the origin; got %q", body)
	}
	if !proxy.Saw(authority) {
		t.Errorf("the proxy was asked for %v, not %q — a live edit did not reach the running listener",
			proxy.Requests(), authority)
	}
}

// A listener with no policy dials origins directly, so an unconfigured build is unchanged.
func Test_a_listener_with_no_upstream_policy_dials_directly(t *testing.T) {
	_, _, authority := upstreamOrigin(t)
	config := NewProxyConfig(core.NewTrafficStore()).WithScope(core.NewScope())
	body := forwardThrough(t, startProxy(t, NewServer(config)), authority)
	if !strings.Contains(body, "reached the origin") {
		t.Errorf("an unproxied listener did not reach the origin; got %q", body)
	}
}

// WithUpstreamProxy records the listener as a holder, which is what /api/network/proxy reports.
//
// Without this the panel could only say "a policy exists", not "it reaches the proxy listener" — and the
// difference between those two is the whole reason the `attached` field exists.
func Test_WithUpstreamProxy_registers_the_listener_as_a_holder(t *testing.T) {
	policy := upstream.NewPolicy()
	NewProxyConfig(core.NewTrafficStore()).WithUpstreamProxy(policy)
	if got := policy.Attached()["proxy"]; got != 1 {
		t.Errorf("the proxy surface registered %d times, want 1; the API would under-report coverage", got)
	}
}
