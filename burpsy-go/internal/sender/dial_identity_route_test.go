package sender

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// Prior-semantics pins for the predial-vs-dial fix, from the integrator's review of the first
// cut: the freeze must not change WHAT the dial consumes, only WHEN it is read.

// The upstream policy has always been resolved against the address actually dialled — the
// hostname-resolution override's answer, not the original host — because rules match IPs as
// often as names (Dialer.DialContext resolves ForAddr of the address it is handed). A freeze
// keyed on the original host would route a host behind an override around the rule its
// resolved address matches. The override maps example.test onto the origin's loopback
// address; the only rule matches that IP literal; the send must be carried by the proxy the
// IP rule names — proven by the proxy observing the CONNECT, not by the send merely
// succeeding (a direct dial succeeds too, which is exactly the wrong answer).
func TestTheUpstreamRuleResolvesAgainstTheDialledAddress(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(okHandler))
	defer origin.Close()
	_, port, err := hostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	proxy := upstreamtest.StartConnect(t, "", "")

	policy := upstream.NewPolicy()
	if _, err := policy.Set("127.0.0.1", "http://"+proxy.Addr()); err != nil {
		t.Fatal(err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.Timeout = 5 * time.Second
	s := NewSender(config)
	n := s.Network()
	n.Resolution.Overrides = []HostOverride{{Host: "example.test", Address: "127.0.0.1", Enabled: true}}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	resp, err := s.SendRaw(context.Background(), "example.test", port, false, raw)
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if !strings.HasSuffix(string(resp), "ok") {
		t.Fatalf("the origin did not answer: %q", resp)
	}
	if want := "127.0.0.1:" + strings.TrimPrefix(origin.URL, "http://127.0.0.1:"); !proxy.Saw(want) {
		t.Errorf("the rule for the dialled address did not carry the dial: proxy saw %v, want a CONNECT for %q "+
			"(the freeze resolved the policy for the original host instead of the dialled address)",
			proxy.Requests(), want)
	}
}

// A send that takes a pooled connection, watches the exchange fail, and dials fresh is one
// send but two dial decisions: the retry has always read the configuration live, so an
// operator change landing during the failed exchange governs the redial. Freezing the
// identity at send entry would let the retry dial a route, carrier or certificate the
// operator just replaced. The handler answers the first request (the connection pools),
// flips the policy to an unreachable proxy when the second arrives on the pooled connection,
// and closes the TLS connection cleanly without answering — the retryable-fresh shape
// (staleReuse + idempotent GET). The retry must fail against the new route, not succeed on
// the old one; a retry reaching the origin proves it dialled the pre-flip capture, and the
// handler answers it to make exactly that visible.
func TestARetryAfterAFailedPooledExchangeDialsTheCurrentConfiguration(t *testing.T) {
	policy := upstream.NewPolicy()
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.TLSVerify = false
	config.Timeout = 5 * time.Second
	s := NewSender(config)
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.HTTP2 = &HTTP2Settings{EnableHTTP2: false}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) != 2 {
			_, _ = w.Write([]byte("ok"))
			return
		}
		// The operator change lands mid-send: after this send's pool take, before its retry
		// dial. The clean close after the hijack is the TLS-level EOF of an idle close.
		if _, err := policy.Set("*", "http://127.0.0.1:1"); err != nil {
			t.Errorf("flipping the policy mid-send: %v", err)
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijacking the pooled connection: %v", err)
			return
		}
		_ = conn.Close()
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	defer srv.Close()
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.SendRaw(context.Background(), host, port, true, rawGet(host, port)); err != nil {
		t.Fatalf("first send: %v", err)
	}
	resp, err := s.SendRaw(context.Background(), host, port, true, rawGet(host, port))
	if err == nil {
		t.Fatalf("the retry dialled the configuration captured before the failed exchange instead of "+
			"the operator's new route: %q", resp)
	}
}

// A pool hit must not resolve the host again. Before the dial identity existed a take read
// only the live route state — no DNS — and the one lookup a family filter needs happened at
// the dial. The first cut of the capture resolved the dial address for the TAKE's stamp too,
// so every pooled send under a family filter paid a lookup the dial had already paid. The
// take now re-evaluates the candidate's own stored dial address, which never resolves. The
// resolver below counts its calls: two sends, the second a pooled hit, must leave the count
// at one — and the IP-literal rule matching the resolver's answer must still be the rule
// that carried the dial, proving the take's re-evaluation did not trade the lookup away for
// hostname-keyed matching (which would never match an IP rule and silently pool nothing).
func TestAPoolHitDoesNoDNSLookupWhenAFamilyFilterMakesResolutionLive(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(okHandler))
	defer origin.Close()
	_, port, err := hostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	proxy := upstreamtest.StartConnect(t, "", "")

	policy := upstream.NewPolicy()
	if _, err := policy.Set("127.0.0.1", "http://"+proxy.Addr()); err != nil {
		t.Fatal(err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.Timeout = 5 * time.Second
	s := NewSender(config)
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.Resolution.Family = FamilyIPv4
	var lookups atomic.Int32
	n.Resolution.Lookup = func(_ context.Context, host string) ([]string, error) {
		lookups.Add(1)
		return []string{"127.0.0.1"}, nil
	}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if _, err := s.SendRaw(context.Background(), "example.test", port, false, raw); err != nil {
		t.Fatalf("first SendRaw: %v", err)
	}
	if _, err := s.SendRaw(context.Background(), "example.test", port, false, raw); err != nil {
		t.Fatalf("second SendRaw: %v", err)
	}
	// Under a family filter every fresh dial resolves the host, so a count of one after two
	// sends is itself the proof the second send rode the pool; the re-pooled connection below
	// is the corroboration. (SendOutcome.ConnectionReused reports only h2 reuse - protocol.go.)
	if got := lookups.Load(); got != 1 {
		t.Errorf("two sends, the second pooled, resolved %d times, want 1 (the dial's) - a take must not resolve the host again", got)
	}
	if n := s.pool.idleCount(); n != 1 {
		t.Errorf("after two sends %d connection(s) sit pooled, want 1 (the first send's, ridden and returned by the second)", n)
	}
	target := "127.0.0.1:" + strings.TrimPrefix(origin.URL, "http://127.0.0.1:")
	if !proxy.Saw(target) {
		t.Errorf("the rule for the resolver's answer did not carry the dial: proxy saw %v, want a CONNECT for %q",
			proxy.Requests(), target)
	}
}
