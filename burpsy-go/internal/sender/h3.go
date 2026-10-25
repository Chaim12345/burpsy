package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/quic-go/quic-go/http3"

	core "github.com/burpsy-go/burpsy/internal/core"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
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

	transport := &http3.Transport{TLSClientConfig: tlsConfig}
	defer transport.Close()

	target, err := h2RequestURL(fmt.Sprintf("%s:%d", host, port), plan.Path)
	if err != nil {
		return nil, SendOutcome{}, fmt.Errorf("HTTP/3 request target: %w", err)
	}
	httpReq := &http.Request{
		Method: plan.Method,
		URL:    target,
		// The authority is what the request wrote in its Host field, not the dial address: the two
		// differ whenever Repeater sends to one host under another's name.
		Host:   plan.Authority,
		Header: make(http.Header),
	}
	if len(plan.Body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(plan.Body))
		httpReq.ContentLength = int64(len(plan.Body))
	}
	httpReq = httpReq.WithContext(ctx)
	for _, h := range plan.Headers {
		httpReq.Header.Add(h.Name, h.Value)
	}

	httpResp, err := transport.RoundTrip(httpReq)
	if err != nil {
		// An endpoint that does not answer QUIC surfaces here as a dial or handshake failure. That
		// is the strict answer: the caller asked for h3 and h3 did not happen.
		return nil, SendOutcome{}, fmt.Errorf("HTTP/3 round trip: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, SendOutcome{}, fmt.Errorf("HTTP/3 read body: %w", err)
	}

	outcome := SendOutcome{
		Protocol:   core.ProtocolHTTP3,
		Negotiated: "h3",
		Rewrites:   plan.Rewrites,
		Rendered:   burpsyhttp2.RenderRequest(plan.Method, plan.Path, plan.Authority, plan.Headers, plan.Body),
	}
	return burpsyhttp2.RenderResponse(httpResp.StatusCode, burpsyhttp2.HeadersFromHTTP(httpResp.Header), respBody), outcome, nil
}
