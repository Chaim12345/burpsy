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

// clientCertSource is the per-host client-certificate source, or nil when none was configured.
//
// Nil-tolerant for the same reason upstreamPolicy is: this is reached from a dial that a test may
// drive against a Server built without a full config, and a nil source is a supported state that
// means "present no certificate" rather than an error.
func (s *Server) clientCertSource() alpn.ClientCertSource {
	if s == nil || s.config == nil {
		return nil
	}
	return s.config.clientCerts
}

// upstreamDialer is the dialer every leg in this file uses.
//
// No timeout of its own: the relay legs here have never had a dial timeout — they rely on the OS
// connect timeout, the same as the net.Dial calls this replaced — and inventing one now would change
// when a slow origin gives up on a path unrelated to proxying.
func (s *Server) upstreamDialer() upstreamproxy.Dialer {
	return upstreamproxy.Dialer{
		Policy: s.upstreamPolicy(),
		// The global SOCKS layer, applied beneath whatever the policy resolved — the layer that makes
		// an HTTP upstream proxy reachable only through a SOCKS hop expressible, and that carries a
		// direct dial too because the setting says every outbound connection
		// (burpsy-react-ui-mr83 part 3). Nil on a proxy built without one, which is the behaviour
		// every leg here had before the layer existed.
		Carrier: s.carrier(),
	}
}

// carrier is the global SOCKS layer, or nil. A method so every leg in this file reads it the same
// way and a nil Server is the same answer as a Server with no carrier.
func (s *Server) carrier() *upstreamproxy.Carrier {
	if s == nil || s.config == nil {
		return nil
	}
	return s.config.upstreamCarrier
}

// dialUpstream opens a TCP connection to host:port, through whatever upstream proxy the configured
// policy resolves for that host. With no policy configured this is net.Dial, exactly as before.
//
// context.Background() is not used here: the caller's context bounds the dial, and the relay legs that
// have no context of their own pass context.Background() explicitly so the absence is visible at the
// call site rather than buried in this helper.
func (s *Server) dialUpstream(ctx context.Context, host string, port uint16) (net.Conn, error) {
	// The address comes from the shared network settings when the console handed them over, so a
	// hostname override or an address-family preference applies to proxied traffic exactly as it
	// applies to a Repeater send (burpsy-react-ui-o1eu). Without them the name is dialled as given,
	// which is what this leg did for its whole life before the wiring.
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if n := s.config.network; n != nil {
		addr = n.Resolution.DialAddress(ctx, host, port)
	}
	return s.dialUpstreamAddr(ctx, addr)
}

// dialUpstreamAddr is dialUpstream for a caller that already holds a host:port string — the blind
// CONNECT tunnel, whose target is the client's own CONNECT line.
func (s *Server) dialUpstreamAddr(ctx context.Context, addr string) (net.Conn, error) {
	return s.upstreamDialer().DialContext(ctx, "tcp", addr)
}

// dialUpstreamTLS opens a TLS connection to the origin, offering exactly the ALPN
// list derived from the client's own offer. Returns the negotiated protocol.
//
// Certificate verification follows the proxy's TLSPolicy, which defaults to ON (burpsy-react-ui-f365).
// It used to be hardcoded off here, on the reasoning that "the proxy exists to reach targets whose
// certificate an operator cannot fix" — which is a real need, but it is answered by a custom CA or by
// the explicit do-not-verify switch, both of which the operator chooses and can see. A proxy that
// cannot verify anything cannot be told to, so an operator comparing two builds of the same app could
// not tell from burpsy whether the certificate had changed.
//
// The client leg is presented with burpsy's own CA regardless, which is a separate fact and does not
// bear on this one: the certificate verified HERE is the origin's, on a session burpsy opened itself.
// clientCerts is the per-host client-certificate source, or nil. This is the leg that makes TLS
// client authentication work through the proxy at all: the browser's own certificate cannot reach the
// origin, because the browser is talking to burpsy's leaf and burpsy is opening a separate connection
// onward. Before this existed, an app requiring a client certificate could only be reached by putting
// its host on the TLS passthrough list — which is to say by giving up interception entirely, which is
// the one thing the operator was using this tool to do.
//
// A method rather than a free function because the upstream proxy policy lives on the Server: both
// legs of this dial — which proxy carries it, and which certificate it presents — are per-server
// state, and threading either as a parameter would let one call site forget it.
func (s *Server) dialUpstreamTLS(serverName, addr string, alpnOffer []string) (*tls.Conn, string, error) {
	policy := s.config.TLS()
	dialer := alpn.Dialer{
		InsecureSkipVerify: !policy.Verify(),
		ClientCerts:        s.clientCertSource(),
	}
	// The pool and the protocol floor come from the same policy as the verify switch, so an operator
	// who turned verification off and then on again has not silently lost the custom CA they added.
	policy.applyTo(&dialer)
	if policy := s.upstreamPolicy(); policy != nil && !policy.Empty() {
		dialer.Carry = s.upstreamDialer().DialContext
	}
	conn, negotiated, err := dialer.Dial(context.Background(), serverName, addr, alpnOffer)
	if err == nil && s.config.serverCerts != nil {
		if _, portText, perr := net.SplitHostPort(addr); perr == nil {
			if port, cerr := strconv.Atoi(portText); cerr == nil {
				s.config.serverCerts.Record(serverName, uint16(port), conn.ConnectionState().PeerCertificates)
			}
		}
	}
	return conn, negotiated, err
}
