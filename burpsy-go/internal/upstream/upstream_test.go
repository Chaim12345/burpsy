package upstream_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// originServer is a target that answers a fixed body, and the host:port a proxy would be asked for.
func originServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("reached the origin"))
	}))
	t.Cleanup(server.Close)
	return server, strings.TrimPrefix(server.URL, "http://")
}

// fetchThrough opens a connection to authority through the dialer and runs one HTTP/1.1 exchange over
// it, returning the response body. It asserts on the *bytes*, so a "tunnel" that connected but relayed
// nothing fails here.
func fetchThrough(t *testing.T, dialer upstream.Dialer, authority string) string {
	t.Helper()
	conn, err := dialer.DialContext(context.Background(), "tcp", authority)
	if err != nil {
		t.Fatalf("dial %s: %v", authority, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		t.Fatalf("read response: %v", err)
	}
	return string(raw)
}

// Each proxy kind actually carries the bytes, and the proxy actually saw the destination.
//
// This is the test the whole unit turns on: not "the policy holds a rule" but "the proxy was asked for
// example:port and the origin's body came back through it".
func Test_every_proxy_kind_carries_the_connection_and_records_the_destination(t *testing.T) {
	_, authority := originServer(t)

	for _, tc := range []struct {
		name  string
		proxy func(t *testing.T) *upstreamtest.Proxy
		url   func(addr string) string
	}{
		{
			name:  "http CONNECT",
			proxy: func(t *testing.T) *upstreamtest.Proxy { return upstreamtest.StartConnect(t, "", "") },
			url:   func(addr string) string { return "http://" + addr },
		},
		{
			name:  "socks5",
			proxy: func(t *testing.T) *upstreamtest.Proxy { return upstreamtest.StartSOCKS5(t, "", "") },
			url:   func(addr string) string { return "socks5://" + addr },
		},
		{
			name:  "socks4",
			proxy: upstreamtest.StartSOCKS4,
			url:   func(addr string) string { return "socks4://" + addr },
		},
		{
			name:  "socks4a",
			proxy: upstreamtest.StartSOCKS4,
			url:   func(addr string) string { return "socks4a://" + addr },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := tc.proxy(t)
			policy := upstream.NewPolicy()
			if err := policy.SetDefault(tc.url(proxy.Addr())); err != nil {
				t.Fatalf("SetDefault: %v", err)
			}
			body := fetchThrough(t, upstream.Dialer{Policy: policy, Timeout: 5 * time.Second}, authority)
			if !strings.Contains(body, "reached the origin") {
				t.Errorf("the origin's body did not come back through the proxy; got %q", body)
			}
			if len(proxy.Requests()) == 0 {
				t.Fatal("the proxy was never asked for anything, so the connection went out direct")
			}
			if errs := proxy.Errors(); len(errs) > 0 {
				t.Errorf("the proxy could not parse what the client sent: %v", errs)
			}
			// socks4 resolves the destination locally to an IPv4 literal; socks4a hands over the name.
			// Both must name the same port, and the host must be one of the two forms — never empty.
			asked := proxy.Requests()[0]
			_, wantPort, _ := net.SplitHostPort(authority)
			gotHost, gotPort, err := net.SplitHostPort(asked)
			if err != nil {
				t.Fatalf("the proxy recorded %q, which is not host:port", asked)
			}
			if gotPort != wantPort {
				t.Errorf("the proxy was asked for port %s, want %s", gotPort, wantPort)
			}
			if gotHost == "" {
				t.Error("the proxy was asked for an empty host")
			}
		})
	}
}

// Credentials reach the proxy, on both the HTTP and the SOCKS5 path.
//
// Asserted by making the proxy *require* them: a client that stored the password without sending it
// gets a 407 or an auth failure, and the exchange fails rather than quietly succeeding.
func Test_credentials_reach_an_authenticated_proxy(t *testing.T) {
	_, authority := originServer(t)
	const user, pass = "operator", "s3cr3t"

	t.Run("http CONNECT", func(t *testing.T) {
		proxy := upstreamtest.StartConnect(t, user, pass)
		policy := upstream.NewPolicy()
		if err := policy.SetDefault("http://" + user + ":" + pass + "@" + proxy.Addr()); err != nil {
			t.Fatalf("SetDefault: %v", err)
		}
		body := fetchThrough(t, upstream.Dialer{Policy: policy, Timeout: 5 * time.Second}, authority)
		if !strings.Contains(body, "reached the origin") {
			t.Fatalf("the authenticated CONNECT did not reach the origin; got %q", body)
		}
		if got := proxy.Credentials(); len(got) == 0 || got[0] != user {
			t.Errorf("the proxy saw credentials %v, want %q offered", got, user)
		}
	})

	t.Run("socks5", func(t *testing.T) {
		proxy := upstreamtest.StartSOCKS5(t, user, pass)
		policy := upstream.NewPolicy()
		if err := policy.SetDefault("socks5://" + user + ":" + pass + "@" + proxy.Addr()); err != nil {
			t.Fatalf("SetDefault: %v", err)
		}
		body := fetchThrough(t, upstream.Dialer{Policy: policy, Timeout: 5 * time.Second}, authority)
		if !strings.Contains(body, "reached the origin") {
			t.Fatalf("the authenticated socks5 dial did not reach the origin; got %q", body)
		}
		if got := proxy.Credentials(); len(got) == 0 || got[0] != user {
			t.Errorf("the proxy saw credentials %v, want %q offered", got, user)
		}
	})
}

// A wrong password fails the dial rather than falling back to a direct connection.
//
// The failure mode this rules out is the worst one in the package: an authentication failure that
// degraded to "connect anyway" would send the operator's traffic straight to the target while the panel
// showed a configured proxy.
func Test_a_rejected_credential_fails_the_dial_rather_than_going_direct(t *testing.T) {
	_, authority := originServer(t)
	proxy := upstreamtest.StartConnect(t, "operator", "correct")
	policy := upstream.NewPolicy()
	if err := policy.SetDefault("http://operator:wrong@" + proxy.Addr()); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	_, err := upstream.Dialer{Policy: policy, Timeout: 5 * time.Second}.
		DialContext(context.Background(), "tcp", authority)
	if err == nil {
		t.Fatal("a rejected proxy credential produced a usable connection; traffic would go out direct")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Errorf("the error does not name the proxy's refusal: %v", err)
	}
	// And it does not leak the password it tried.
	if strings.Contains(err.Error(), "wrong") {
		t.Errorf("the dial error carries the password: %v", err)
	}
}

// Ordering: the first matching rule wins, and a `direct` rule above a broad one exempts its pattern.
func Test_the_first_matching_rule_wins_and_direct_exempts(t *testing.T) {
	policy := upstream.NewPolicy()
	if err := policy.SetDefault("http://default.test:3128"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	for _, r := range []struct{ pattern, proxy string }{
		{"api.example.com", "direct"},
		{"*.example.com", "socks5://socks.test:1080"},
	} {
		if _, err := policy.Set(r.pattern, r.proxy); err != nil {
			t.Fatalf("Set %s: %v", r.pattern, err)
		}
	}
	if !policy.For("api.example.com").IsDirect() {
		t.Error("the direct exemption above the wildcard did not win")
	}
	if got := policy.For("www.example.com").Kind(); got != upstream.KindSOCKS5 {
		t.Errorf("a subdomain resolved to %q, want socks5", got)
	}
	if got := policy.For("elsewhere.test").Kind(); got != upstream.KindHTTP {
		t.Errorf("an unmatched host resolved to %q, want the http default", got)
	}
	// ForAddr strips the port before matching, so a rule written for a host covers all its ports.
	if got := policy.ForAddr("www.example.com:8443").Kind(); got != upstream.KindSOCKS5 {
		t.Errorf("ForAddr resolved to %q, want socks5", got)
	}
}

// A nil policy, and an empty one, dial directly — so an unconfigured build behaves exactly as before.
func Test_an_unconfigured_policy_dials_directly(t *testing.T) {
	_, authority := originServer(t)
	for name, dialer := range map[string]upstream.Dialer{
		"nil policy":   {Timeout: 5 * time.Second},
		"empty policy": {Policy: upstream.NewPolicy(), Timeout: 5 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			body := fetchThrough(t, dialer, authority)
			if !strings.Contains(body, "reached the origin") {
				t.Errorf("a direct dial did not reach the origin; got %q", body)
			}
		})
	}
}

// Parse refuses what it cannot use, and never quotes a password back in the error.
func Test_parse_refuses_unusable_proxy_urls_without_leaking_credentials(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1:8080",
		"http://127.0.0.1",
		"gopher://127.0.0.1:70",
		"http://127.0.0.1:0",
		"http://127.0.0.1:70000",
		"http://:3128",
		"socks5://127.0.0.1:1080/path",
	} {
		if _, err := upstream.Parse(raw); err == nil {
			t.Errorf("Parse(%q) succeeded; an unusable proxy must be refused rather than becoming a "+
				"direct connection at dial time", raw)
		}
	}

	// A refused URL with a password in it must not put the password in the error, which reaches the API
	// response and the log.
	_, err := upstream.Parse("gopher://operator:s3cr3t@127.0.0.1:70")
	if err == nil {
		t.Fatal("an unknown scheme was accepted")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("the parse error carries the password: %v", err)
	}

	// socks4 has no password field on the wire, so a password with it is refused rather than dropped.
	if _, err := upstream.Parse("socks4://u:p@127.0.0.1:1080"); err == nil {
		t.Error("socks4 with a password was accepted; the password would have been silently dropped")
	}

	// Empty and "direct" are the direct proxy, which is how a rule exempts a destination.
	for _, raw := range []string{"", "direct", "DIRECT", "  "} {
		p, err := upstream.Parse(raw)
		if err != nil {
			t.Errorf("Parse(%q): %v", raw, err)
		}
		if !p.IsDirect() {
			t.Errorf("Parse(%q) is not the direct proxy", raw)
		}
	}
}

// Display and String redact; Raw does not. Raw exists only for the durable store.
func Test_display_redacts_and_raw_round_trips(t *testing.T) {
	p, err := upstream.Parse("socks5://operator:s3cr3t@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.Contains(p.Display(), "s3cr3t") || strings.Contains(p.String(), "s3cr3t") {
		t.Errorf("Display/String emit the password: %q / %q", p.Display(), p.String())
	}
	if !p.HasCredentials() {
		t.Error("HasCredentials is false for a proxy with a username")
	}
	// Raw is what persistence writes, so it must round-trip to an equivalent proxy.
	again, err := upstream.Parse(p.Raw())
	if err != nil {
		t.Fatalf("re-parsing Raw(): %v", err)
	}
	if again.Display() != p.Display() || !again.HasCredentials() {
		t.Errorf("Raw() does not round-trip: %q vs %q", again.Display(), p.Display())
	}
}

// Attach records holders, which is what /api/network/proxy reports rather than implying coverage.
func Test_attach_reports_the_surfaces_holding_the_policy(t *testing.T) {
	policy := upstream.NewPolicy()
	if len(policy.AttachedSurfaces()) != 0 {
		t.Error("a fresh policy claims an attached surface")
	}
	policy.Attach("sender")
	policy.Attach("proxy")
	policy.Attach("sender")
	surfaces := policy.AttachedSurfaces()
	if strings.Join(surfaces, ",") != "proxy,sender" {
		t.Errorf("AttachedSurfaces = %v, want a sorted [proxy sender]", surfaces)
	}
	if policy.Attached()["sender"] != 2 {
		t.Errorf("sender holder count = %d, want 2", policy.Attached()["sender"])
	}
}

// An HTTP proxy's own address is dialled directly, not through the policy.
//
// net/http hands Transport.DialContext the *proxy's* address once Transport.Proxy returns a URL. Without
// the guard, a policy whose rules happened to match the proxy's own hostname would tunnel the proxy
// connection through another proxy — a chain nobody asked for, produced by a coincidence of names.
func Test_a_proxys_own_address_is_not_itself_proxied(t *testing.T) {
	_, authority := originServer(t)
	proxy := upstreamtest.StartConnect(t, "", "")
	policy := upstream.NewPolicy()
	// A catch-all rule that also covers the proxy's own host (127.0.0.1).
	if _, err := policy.Set("*", "http://"+proxy.Addr()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	dialer := upstream.Dialer{Policy: policy, Timeout: 5 * time.Second}
	// Dialling the proxy itself must be direct; if it were proxied it would loop.
	conn, err := dialer.DialContext(context.Background(), "tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("dialling the proxy's own address: %v", err)
	}
	conn.Close()
	if n := len(proxy.Requests()); n != 0 {
		t.Errorf("dialling the proxy's own address produced %d CONNECT(s) through it", n)
	}
	// And an ordinary destination still goes through it.
	if body := fetchThrough(t, dialer, authority); !strings.Contains(body, "reached the origin") {
		t.Errorf("the ordinary destination did not traverse the proxy; got %q", body)
	}
}

// A destination the proxy cannot reach is an error naming the proxy, not a silent direct connection.
func Test_a_proxy_refusal_is_reported_rather_than_bypassed(t *testing.T) {
	proxy := upstreamtest.StartConnect(t, "", "")
	policy := upstream.NewPolicy()
	if err := policy.SetDefault("http://" + proxy.Addr()); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	// Port 1 on loopback: nothing listens, so the proxy answers 502.
	_, err := upstream.Dialer{Policy: policy, Timeout: 5 * time.Second}.
		DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("a destination the proxy could not reach produced a usable connection")
	}
	if !strings.Contains(err.Error(), proxy.Addr()) {
		t.Errorf("the error does not name the proxy that refused: %v", err)
	}
}

// A policy snapshot round-trips through Restore, and a snapshot that does not parse is refused whole.
func Test_snapshot_and_restore_refuse_a_partial_policy(t *testing.T) {
	policy := upstream.NewPolicy()
	if err := policy.SetDefault("http://127.0.0.1:3128"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	if _, err := policy.Set("*.internal", "socks5://127.0.0.1:1080"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	restored := upstream.NewPolicy()
	if err := restored.Restore(policy.Snapshot()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(restored.Rules()) != 1 || restored.Default().Kind() != upstream.KindHTTP {
		t.Fatal("the snapshot did not round-trip")
	}

	// One unusable entry stops the whole restore: a half-restored proxy policy is the one state an
	// operator must not be left silently holding.
	target := upstream.NewPolicy()
	if _, err := target.Set("*.kept", "http://127.0.0.1:3128"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	err := target.Restore(upstream.Snapshot{
		Default: "http://127.0.0.1:3128",
		Rules: []upstream.SnapshotRule{
			{Pattern: "*.good", Proxy: "socks5://127.0.0.1:1080"},
			{Pattern: "*.bad", Proxy: "gopher://127.0.0.1:70"},
		},
	})
	if err == nil {
		t.Fatal("a snapshot with an unusable rule restored without complaint")
	}
	rules := target.Rules()
	if len(rules) != 1 || rules[0].Pattern != "*.kept" {
		t.Errorf("the refused restore still mutated the policy: %v", rules)
	}
}
