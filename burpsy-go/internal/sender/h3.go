package sender

import (
	"context"
	"crypto/tls"
	"fmt"

	core "github.com/burpsy-go/burpsy/internal/core"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// sendH3 implements ProtocolPreferenceHTTP3 (burpsy-react-ui-0hgx): one request re-expressed as
// HTTP/3 over QUIC. HTTP/3 has no wire form an HTTP/1 byte string can be poured into, so the
// request is re-expressed — :method/:path/:authority plus the header fields — the same model the
// h2 leg uses, because RFC 9114's pseudo-headers are RFC 9113's. Every re-expression is reported
// on the outcome (Rewrites, and Rendered as the HTTP/1-shaped rendering of what was sent), exactly
// as an h2 send reports its own.
//
// The pin is strict. Nothing here downgrades: a plaintext target, a request QUIC has nowhere to
// put, or an endpoint that does not answer QUIC is an error that names the cause. Silently falling
// back under an explicit protocol choice would put bytes on a carrier the caller ruled out while
// the report still said h3 — the dishonesty the Downgrade record exists to prevent.
func (s *Sender) sendH3(ctx context.Context, host string, port uint16, useTLS bool, raw []byte) ([]byte, SendOutcome, error) {
	if !useTLS {
		return nil, SendOutcome{}, fmt.Errorf("HTTP/3 runs over QUIC and QUIC is always encrypted: a plaintext target cannot carry it, and silently falling back to cleartext HTTP/1.1 would send on a protocol the caller did not ask for")
	}
	// The carriability bar is planH2's. h3's request model is h2's with QPACK standing in for
	// HPACK, so any construct h2 has nowhere to put — a smuggled Transfer-Encoding, a hop-by-hop
	// field — h3 has nowhere to put either. Under an explicit pin the refusal is an error naming
	// the construct, never a fallback.
	plan, down := planH2(raw)
	if down != nil {
		return nil, SendOutcome{}, fmt.Errorf("HTTP/3 cannot carry this request (%s), and silently falling back to another protocol would send something the operator did not write", down)
	}

	settings := s.Network()
	// QUIC embeds TLS 1.3, but the policy inputs are the sender's own: the operator's verification
	// setting, trust roots, minimum version floor and per-host client certificate all apply here
	// exactly as they do on the TCP legs.
	verify, roots, minVersion := s.tlsPolicy(settings)
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !verify,
		RootCAs:            roots,
		MinVersion:         minVersion,
		NextProtos:         []string{"h3"},
	}
	if sni := sniOverride(ctx); sni != "" {
		tlsConfig.ServerName = sni
	}
	if s.config.ClientCerts != nil {
		if cert := s.config.ClientCerts.For(host); cert != nil {
			tlsConfig.Certificates = []tls.Certificate{*cert}
		}
	}

	// The re-expression itself lives in httputil (vln3): one path for the sender's explicit pin
	// and the proxy's Alt-Svc leg, so the mechanics are reviewed once. An endpoint that does not
	// answer QUIC surfaces as a dial or handshake failure here - the strict answer, because the
	// caller asked for h3 and h3 did not happen.
	resp, err := httputil.RoundTripH3(ctx, tlsConfig, fmt.Sprintf("%s:%d", host, port), plan.Authority, plan.Method, plan.Path, plan.Headers, plan.Body)
	if err != nil {
		return nil, SendOutcome{}, err
	}

	outcome := SendOutcome{
		Protocol:   core.ProtocolHTTP3,
		Negotiated: "h3",
		Rewrites:   plan.Rewrites,
		Rendered:   burpsyhttp2.RenderRequest(plan.Method, plan.Path, plan.Authority, plan.Headers, plan.Body),
	}
	return resp, outcome, nil
}

// H3Plan is what an HTTP/1.1 byte string becomes when it is carried over HTTP/3: the
// pseudo-header model h2 and h3 share, with the hop-by-hop fields h3 has nowhere to put already
// refused or accounted for.
type H3Plan struct {
	Method    string
	Path      string
	Authority string
	// Headers are in the order the request wrote them, with the Host header removed (it became
	// Authority) and hop-by-hop fields dropped. Names are lowercased.
	Headers []burpsyhttp2.Header
	Body    []byte
}

// PlanH3 applies the carriability bar to raw HTTP/1.1 bytes for an HTTP/3 carry
// (burpsy-react-ui-vln3 ruling B). The bar is planH2's, because RFC 9114's request model is RFC
// 9113's: any construct h2 has nowhere to put, h3 has nowhere to put either, and one planner
// means the two legs can never drift apart on what they refuse. The error names the refused
// construct; what the caller does with a refusal is its own policy (the sender's explicit pin
// errors, the proxy's Alt-Svc leg falls back and says so).
func PlanH3(raw []byte) (H3Plan, error) {
	plan, down := planH2(raw)
	if down != nil {
		return H3Plan{}, fmt.Errorf("HTTP/3 cannot carry this request: %s", down)
	}
	return H3Plan{
		Method:    plan.Method,
		Path:      plan.Path,
		Authority: plan.Authority,
		Headers:   plan.Headers,
		Body:      plan.Body,
	}, nil
}
