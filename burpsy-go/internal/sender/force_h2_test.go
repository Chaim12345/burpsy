package sender

import (
	"context"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
)

// ProtocolPreferenceForceH2 (burpsy-react-ui-745): the opposite pin to HTTP1. A carriable request
// to a target that negotiates h2 goes out as h2; the same request to a target whose ALPN chooses
// http/1.1 goes out as HTTP/1.1 with the downgrade named — an h2-only offer would abort the
// handshake at exactly the target an operator is probing for h2-downgrade behaviour, which is the
// target this pin exists for.

// A carriable request over a dual-protocol target under force goes out as h2, even though ALPN
// could have chosen http/1.1 — the pin requires h2 where auto might cache either.
func TestForceH2SendsOverHTTP2WhenTheRequestIsCarriable(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2, alpn.HTTP11}, true)
	s := testSender()
	// First teach the cache http/1.1, the state that would make auto fall back: a pinned send
	// from a fresh sender is the state force must override.
	if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceHTTP1); err != nil {
		t.Fatalf("setup send: %v", err)
	}

	resp, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceForceH2)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if outcome.Protocol != core.ProtocolHTTP2 {
		t.Fatalf("forced send went out as %v, want h2", outcome.Protocol)
	}
	if !strings.HasPrefix(string(resp), "HTTP/2 200") {
		t.Fatalf("response over h2 should render as HTTP/2 200, got %q", string(resp[:min(40, len(resp))]))
	}
}

// The target that declines h2 at ALPN — the case the issue names — gets the request as HTTP/1.1
// and the downgrade names what happened, rather than the connection failing.
func TestForceH2AtAnHTTP11TargetDowngradesAndNamesIt(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	s := testSender()

	resp, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceForceH2)
	if err != nil {
		t.Fatalf("send must not fail at the handshake: %v", err)
	}
	if outcome.Protocol != core.ProtocolHTTP1 {
		t.Fatalf("went out as %v, want http/1.1 after the target declined", outcome.Protocol)
	}
	if outcome.Downgrade == nil || outcome.Downgrade.Reason != DowngradeNegotiatedHTTP11 {
		t.Fatalf("downgrade = %+v, want DowngradeNegotiatedHTTP11 — the pin that did not happen must be named", outcome.Downgrade)
	}
	if !strings.HasPrefix(string(resp), "HTTP/1.1 200") {
		t.Fatalf("expected an HTTP/1.1 response, got %q", string(resp[:min(40, len(resp))]))
	}
}

// A request h2 cannot carry (smuggled framing) is NOT re-encoded by the force pin: it goes out as
// HTTP/1.1 with the construct named. Re-encoding would send something the operator did not write.
func TestForceH2CannotCarryAnUnrepresentableRequest(t *testing.T) {
	srv := startRecordingServer(t, []string{alpn.H2, alpn.HTTP11})
	s := testSender()
	raw := "POST /smuggle HTTP/1.1\r\nHost: " + formatHostPort(srv.host, srv.port) +
		"\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

	resp, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true, []byte(raw), ProtocolPreferenceForceH2)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if outcome.Protocol != core.ProtocolHTTP1 {
		t.Fatalf("went out as %v, want http/1.1 — force must not mangle an uncarriable request onto h2", outcome.Protocol)
	}
	if outcome.Downgrade == nil || outcome.Downgrade.Reason != DowngradeTransferEncoding {
		t.Fatalf("downgrade = %+v, want the construct reason; got %v", outcome.Downgrade, outcome.Downgrade)
	}
	srv.mu.Lock()
	wire := strings.Join(srv.got, "")
	srv.mu.Unlock()
	if !strings.Contains(wire, "Transfer-Encoding: chunked") {
		t.Fatalf("the framing headers must reach the wire verbatim; got %q", wire)
	}
	_ = resp
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
