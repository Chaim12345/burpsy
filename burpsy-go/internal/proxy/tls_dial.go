package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/alpn"
	upstreamproxy "github.com/burpsy-go/burpsy/internal/upstream"
)

// This file is the proxy's upstream leg: every connection this package opens towards an origin.
//
// # Why they are all here
//
// There are five of them — the intercepted TLS leg, the blind CONNECT tunnel, the plain-HTTP forward,
// the out-of-scope forward and the WebSocket relay's origin socket — and until now each called
// net.Dial itself. That is why upstream-proxy support could not simply be "add a field": a policy
// wired into one of five dial sites is a settings panel that works for some of an operator's traffic
// and silently not for the rest. They now all come through dialUpstream / dialUpstreamTLS, so a proxy
// rule either covers this package or does not, and there is one place to read to find out which.
//
// # The upstream proxy carries bytes, never the TLS session
//
// dialUpstreamTLS hands the tunnel to alpn.Dialer as its carrier, so the TLS handshake still runs
// end-to-end with the origin: the ALPN this leg reports is the origin's, and the certificate is the
// origin's. That matters here more than in a plain HTTP client, because the negotiated protocol
// decides what the *client* leg is then offered — a proxy answering for the origin's ALPN would make
// burpsy relay h2 to a client whose origin never agreed to it.

// upstreamPolicy is the configured upstream proxy policy, or nil. A method rather than a direct field
// read so a Server built by a test with no config cannot nil-dereference here.
func (s *Server) upstreamPolicy() *upstreamproxy.Policy {
	if s == nil || s.config == nil {
		return nil
	}
	return s.config.upstream
}

// upstreamDialer is the dialer every leg in this file uses.
//
// No timeout of its own: the relay legs here have never had a dial timeout — they rely on the OS
// connect timeout, the same as the net.Dial calls this replaced — and inventing one now would change
// when a slow origin gives up on a path unrelated to proxying.
func (s *Server) upstreamDialer() upstreamproxy.Dialer {
	return upstreamproxy.Dialer{Policy: s.upstreamPolicy()}
}

// dialUpstream opens a TCP connection to host:port, through whatever upstream proxy the configured
// policy resolves for that host. With no policy configured this is net.Dial, exactly as before.
//
// context.Background() is not used here: the caller's context bounds the dial, and the relay legs that
// have no context of their own pass context.Background() explicitly so the absence is visible at the
// call site rather than buried in this helper.
func (s *Server) dialUpstream(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return s.dialUpstreamAddr(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// dialUpstreamAddr is dialUpstream for a caller that already holds a host:port string — the blind
// CONNECT tunnel, whose target is the client's own CONNECT line.
func (s *Server) dialUpstreamAddr(ctx context.Context, addr string) (net.Conn, error) {
	return s.upstreamDialer().DialContext(ctx, "tcp", addr)
}

// dialUpstreamTLS opens a TLS connection to the origin, offering exactly the ALPN
// list derived from the client's own offer. Returns the negotiated protocol.
//
// Certificate verification is off on this leg deliberately: the proxy exists to reach targets whose
// certificate an operator cannot fix, and the client leg is presented with burpsy's own CA anyway. A
// sender's egress leg follows SenderConfig.TLSVerify instead, which is why the choice is a field on
// alpn.Dialer rather than a constant inside it.
func (s *Server) dialUpstreamTLS(serverName, addr string, alpnOffer []string) (*tls.Conn, string, error) {
	dialer := alpn.Dialer{InsecureSkipVerify: true}
	if policy := s.upstreamPolicy(); policy != nil && !policy.Empty() {
		dialer.Carry = s.upstreamDialer().DialContext
	}
	return dialer.Dial(context.Background(), serverName, addr, alpnOffer)
}
