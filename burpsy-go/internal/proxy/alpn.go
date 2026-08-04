package proxy

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/core"
)

const (
	alpnH2     = "h2"
	alpnHTTP11 = "http/1.1"
)

// AlpnOffer filters the client's ALPN list to protocols this proxy can carry.
// When interception is enabled only http/1.1 is offered, because the hold queue
// is HTTP/1-shaped.
func AlpnOffer(clientOffer []string, interceptionEnabled bool) []string {
	if len(clientOffer) == 0 {
		return nil
	}
	if interceptionEnabled {
		var out []string
		for _, p := range clientOffer {
			if p == alpnHTTP11 {
				out = append(out, p)
			}
		}
		return out
	}
	var out []string
	for _, p := range clientOffer {
		if p == alpnH2 || p == alpnHTTP11 {
			out = append(out, p)
		}
	}
	return out
}

// NegotiatedProtocol maps the wire ALPN value to a core.Protocol.
func NegotiatedProtocol(alpn string) (core.Protocol, error) {
	switch alpn {
	case "", alpnHTTP11:
		return core.ProtocolHTTP1, nil
	case alpnH2:
		return core.ProtocolHTTP2, nil
	default:
		return core.ProtocolHTTP1, fmt.Errorf("unrecognised ALPN %q", alpn)
	}
}

// ClientALPNProtos returns the single protocol the client leg should offer after
// the upstream has chosen, so both legs speak the same protocol.
func ClientALPNProtos(negotiated string) []string {
	if negotiated == "" {
		return []string{alpnHTTP11}
	}
	return []string{negotiated}
}
