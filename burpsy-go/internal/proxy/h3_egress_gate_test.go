package proxy

// PR #363 review: an Alt-Svc-learned h3 endpoint is dialed directly over QUIC, so egress the
// operator configured - an upstream proxy or the SOCKS carrier - would be silently bypassed.
// With either in force the h3 attempt must not happen at all: no QUIC dial, and the h1 leg
// (which honors the egress) carries the request.

import (
	"testing"

	core "github.com/burpsy-go/burpsy/internal/core"
	upstreamproxy "github.com/burpsy-go/burpsy/internal/upstream"
	"go.uber.org/zap"
)

func TestH3EgressPossibleWithNoEgressConfigured(t *testing.T) {
	s := NewServer(NewProxyConfig(core.NewTrafficStore()).WithLogger(zap.NewNop()))
	if !s.h3EgressPossible() {
		t.Fatal("no upstream and no carrier: h3 egress should be possible")
	}
}

func TestH3EgressPossibleRefusedWithUpstreamProxy(t *testing.T) {
	policy := upstreamproxy.NewPolicy()
	if _, err := policy.Set("*", "http://127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	s := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithUpstreamProxy(policy).
		WithLogger(zap.NewNop()))
	if s.h3EgressPossible() {
		t.Fatal("an upstream proxy is configured: the h3 leg would bypass it")
	}
}

func TestH3EgressPossibleRefusedWithCarrier(t *testing.T) {
	carrier := upstreamproxy.NewCarrier()
	if err := carrier.SetSocks("socks5://127.0.0.1:1080", nil, false); err != nil {
		t.Fatal(err)
	}
	s := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithUpstreamCarrier(carrier).
		WithLogger(zap.NewNop()))
	if s.h3EgressPossible() {
		t.Fatal("a SOCKS carrier is configured: the h3 leg would bypass it")
	}
}

// A bare NewCarrier with no SOCKS set is no carrier: it must not shut the h3 leg off.
func TestH3EgressPossibleWithEmptyCarrier(t *testing.T) {
	s := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithUpstreamCarrier(upstreamproxy.NewCarrier()).
		WithLogger(zap.NewNop()))
	if !s.h3EgressPossible() {
		t.Fatal("an empty carrier is no carrier; the h3 leg must stay available")
	}
}
