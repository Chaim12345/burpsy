package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// The proxy leg and the sender leg must read ONE streaming configuration. This is the test that
// holds them to it, because the failure it guards against is invisible from either side: the
// Settings panel shows a host list, the sender honours it, the proxy does not, and the only symptom
// is an event stream that arrives empty in a browser (burpsy-react-ui-wet3).
//
// Before this wiring the proxy had no access to the setting at all, so the panel described a list
// that only applied to Repeater sends.
func TestTheStreamingHostsReachTheProxyLegAndNotOnlyTheSender(t *testing.T) {
	store := core.NewTrafficStore()
	policy := proxy.NewStreamingPolicy()
	proxyServer := proxy.NewServer(
		proxy.NewProxyConfig(store).
			WithScope(core.NewScopeAllowEverything()).
			WithStreaming(policy).
			WithLogger(zap.NewNop()).
			WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))

	s := NewServer(store, core.NewScopeAllowEverything()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithProxyServer(proxyServer)

	rec := putNetworkSettings(t, s, `{"streaming": {"hosts": ["events.example.com", "*.sse.test"], "timeout_ms": 45000}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// The sender's half — which already worked before this change, and must keep working.
	if got := s.sender.Network().Streaming.Hosts; len(got) != 2 {
		t.Errorf("sender streaming hosts = %v, want the two the operator set", got)
	}

	// The proxy's half, which is what this test exists for.
	if !policy.IsStreaming("events.example.com") {
		t.Error("the proxy does not consider events.example.com open-ended: the Settings panel says it is, and a browser's event stream on that host would still be buffered to a hang")
	}
	if !policy.IsStreaming("api.sse.test") {
		t.Error("the proxy does not honour the *.sse.test pattern; the sender's matching rule is a wildcard suffix and the two must agree")
	}
	if policy.IsStreaming("elsewhere.test") {
		t.Error("the proxy considers an undeclared host open-ended")
	}
	if got := policy.Window(); got != 45*time.Second {
		t.Errorf("proxy streaming window = %v, want 45s — the proxy must use the operator's window, not its own default", got)
	}
}

// The window is bounded, and saying so is better than accepting a value that pins a connection. The
// sender has its own ceiling; the proxy's must not be looser or the same console config would behave
// differently depending on which tool sent the request.
func TestTheProxyWindowIsBoundedLikeTheSenders(t *testing.T) {
	policy := proxy.NewStreamingPolicy()
	if err := policy.Set(nil, 100*time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := policy.Window(); got > proxy.MaxStreamingWindow {
		t.Errorf("window = %v, over the %v ceiling; a config that pins a proxy connection for a hundred hours is not one the sender would also accept", got, proxy.MaxStreamingWindow)
	}
}

// A negative window is refused rather than clamped. A window that has already passed would stream
// nothing at all, which looks exactly like the bug this whole path fixes.
func TestANegativeStreamingWindowIsRefusedRatherThanClamped(t *testing.T) {
	policy := proxy.NewStreamingPolicy()
	err := policy.Set(nil, -time.Second)
	if err == nil {
		t.Fatal("a negative window was accepted; it would end every stream before the first byte")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("error = %q, want it to say the window is negative", err)
	}
	// And the previous value stands — a refusal changes nothing.
	if got := policy.Window(); got != proxy.DefaultStreamingWindow {
		t.Errorf("window = %v after a refused Set, want the default unchanged at %v", got, proxy.DefaultStreamingWindow)
	}
}

// The host matching has to be the sender's rule exactly, or one console config would behave
// differently in Repeater and through the proxy.
func TestHostMatchingHandlesPortsBracketsAndCase(t *testing.T) {
	policy := proxy.NewStreamingPolicy()
	if err := policy.Set([]string{"API.Example.com", "*.events.test"}, 0); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
		why  string
	}{
		{"api.example.com", true, "an exact match, case-insensitively"},
		{"API.EXAMPLE.COM", true, "case is not the operator's distinction"},
		{"api.example.com:8443", true, "a port is not part of the hostname"},
		{"stream.events.test", true, "the wildcard suffix covers a subdomain"},
		{"events.test", false, "the wildcard does not cover the bare domain — the sender's rule, kept identical"},
		{"notevents.test", false, "a suffix that is not a domain boundary does not match"},
		{"", false, "an empty host matches nothing"},
	}
	for _, tc := range cases {
		if got := policy.IsStreaming(tc.host); got != tc.want {
			t.Errorf("IsStreaming(%q) = %v, want %v (%s)", tc.host, got, tc.want, tc.why)
		}
	}
}
