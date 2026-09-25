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

// DowngradeNote returns the history note for a client whose ALPN offer included HTTP/2 but was
// carried over HTTP/1.1 because interception is on, and "" when no downgrade happened.
//
// # Why the protocol column alone is not enough
//
// The protocol field answers "what carried this exchange", and after a downgrade the truthful
// answer is HTTP/1.1. That is correct and useless: a target that only ever speaks HTTP/1.1 and an
// h2-first site that interception moved to HTTP/1.1 produce identical rows, so an operator reading
// history cannot tell that the protocol under test was never exercised. The note is what carries
// the second fact — that the client asked for h2 and the interception switch is why it did not get
// it — and it is the only place that fact exists anywhere.
//
// The wording names the cause rather than the effect. "HTTP/1.1" alone reads as a property of the
// target; "client offered HTTP/2; interception carried this over HTTP/1.1" reads as something the
// tool did, which is what an operator needs in order to decide whether to turn interception off.
func DowngradeNote(clientOffer []string, carried string) string {
	// alpn.Filter is the offer's own membership test, used as one: a list that gains an entry when
	// h2 is allowed and loses it when h2 is refused contained h2. Writing a second Contains in this
	// package would be the copy that drifts from the filter's idea of the vocabulary.
	offeredH2 := len(alpn.Filter(clientOffer, true)) > len(alpn.Filter(clientOffer, false))
	if carried == alpn.HTTP11 && offeredH2 {
		return "client offered HTTP/2; interception carried this over HTTP/1.1"
	}
	return ""
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
