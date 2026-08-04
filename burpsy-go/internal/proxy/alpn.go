package proxy

import (
	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
)

// The proxy's ALPN policy. The negotiation vocabulary itself moved to internal/alpn, because
// internal/sender needs the same offer list and the same wire-value-to-protocol mapping, and two
// copies of an offer list is how a tool ends up testing a target over one protocol and relaying it
// over another. What stays here is the one decision that is the *proxy's* and not a general one:
// interception forces http/1.1.

const (
	alpnH2     = alpn.H2
	alpnHTTP11 = alpn.HTTP11
)

// AlpnOffer filters the client's ALPN list to protocols this proxy can carry.
//
// When interception is enabled only http/1.1 is offered, because the hold queue is HTTP/1-shaped: an
// intercepted request is held, shown and possibly edited as HTTP/1 bytes, so offering h2 upstream
// would negotiate a protocol the intercept path cannot represent. This is the proxy's policy, which is
// why it lives here rather than in internal/alpn — a sender's egress leg has no hold queue and makes
// the opposite choice.
func AlpnOffer(clientOffer []string, interceptionEnabled bool) []string {
	return alpn.Filter(clientOffer, !interceptionEnabled)
}

// NegotiatedProtocol maps the wire ALPN value to a core.Protocol.
func NegotiatedProtocol(negotiated string) (core.Protocol, error) {
	return alpn.Protocol(negotiated)
}

// ClientALPNProtos returns the single protocol the client leg should offer after
// the upstream has chosen, so both legs speak the same protocol.
func ClientALPNProtos(negotiated string) []string {
	return alpn.Single(negotiated)
}
