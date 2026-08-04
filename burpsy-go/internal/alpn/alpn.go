// The one place that decides which HTTP version a TLS connection will carry.
//
// # Why this is its own package
//
// This logic was internal/proxy's, and correctly so: the proxy is where ALPN first mattered, because a
// man-in-the-middle has to make both legs speak the same protocol or it corrupts the exchange it is
// relaying. But the proxy is not the only surface that dials a target. internal/sender dials one for
// every scanner probe, every intruder payload and every repeater resend, and it did so with no ALPN
// offer at all — so a target that speaks HTTP/2 got HTTP/1.1 from us and nothing anywhere said so
// (H2-04).
//
// The fix needs the negotiation vocabulary in both places, and the one thing it must not be is two
// copies: an offer list that drifts between the proxy leg and the egress leg means the tool tests a
// target over one protocol and relays it over another, which is precisely the class of silent
// disagreement burpsy exists to expose rather than commit. So the vocabulary moved here and both
// callers reach it. internal/proxy/alpn.go keeps the proxy's *policy* — interception forces
// http/1.1, because the hold queue is HTTP/1-shaped — because that is a proxy decision and belongs
// where a reader of the proxy will find it.
//
// # What this package deliberately does not decide
//
// Whether a request *may* be sent. That is sender.AuthorisedSender's gate on the bytes about to go on
// the wire (HARD-03), and it runs before any dial here. Dial opens a connection to an address the
// caller has already authorised; it has no scope handle and must never grow one, because a second
// place that can say yes to an egress is a second place that can be wrong about it.
//
// # h2c is not here
//
// Plaintext HTTP has no ALPN, so there is nothing for this package to negotiate on a cleartext
// connection and nothing here pretends otherwise: a plaintext target is HTTP/1.1 as far as ALPN is
// concerned. Prior-knowledge h2c (RFC 9113 §3.3) is reachable without negotiation — you simply write
// the preface — which is why sender's frame-program path allows it and sender's *request* path does
// not. Both decisions are stated where they are taken.
package alpn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

const (
	// H2 is the ALPN identifier for HTTP/2 over TLS, RFC 9113 §3.1.
	H2 = "h2"
	// HTTP11 is the ALPN identifier for HTTP/1.1, RFC 7301.
	HTTP11 = "http/1.1"
)

// Filter keeps the protocols this tool can actually carry, in the order the peer offered them, and
// drops the rest.
//
// The caller's order is preserved rather than re-sorted into a preference of our own: on the proxy's
// upstream leg the list being filtered is the *client's* offer, and its order is the client's
// preference. Re-ordering it would make the origin negotiate something the client did not ask for
// first, which is a difference the client cannot see and did not choose.
//
// An empty offer stays empty — nil, not a default list. A peer that sent no ALPN extension has not
// asked for anything, and inventing an offer on its behalf would put a protocol on the wire that
// nothing in the exchange requested.
func Filter(offer []string, allowH2 bool) []string {
	if len(offer) == 0 {
		return nil
	}
	var out []string
	for _, p := range offer {
		if p == HTTP11 || (allowH2 && p == H2) {
			out = append(out, p)
		}
	}
	return out
}

// EgressOffer is the offer for a connection this tool originates, rather than relays.
//
// When h2 is wanted, both protocols are offered and h2 is listed first. Offering h2 *alone* would be
// the wrong shape of strict: a server that does not speak it aborts the handshake with
// no_application_protocol, so a scan of an HTTP/1.1-only host would fail at the TLS layer rather than
// run over HTTP/1.1 and say so. Offering both means the target chooses, we find out what it chose, and
// a downgrade is reported instead of a connection error — see sender.Downgrade.
func EgressOffer(wantH2 bool) []string {
	if wantH2 {
		return []string{H2, HTTP11}
	}
	return []string{HTTP11}
}

// Protocol maps the negotiated wire value to a core.Protocol.
//
// An empty value is HTTP/1.1 with no error: it means the handshake carried no ALPN extension, which is
// what a peer that never heard of ALPN does, and HTTP/1.1 is what such a connection carries. An
// unrecognised value is an error *and* HTTP/1.1, so a caller that ignores the error still gets the
// conservative answer rather than a zero value that happened to mean something else.
func Protocol(negotiated string) (core.Protocol, error) {
	switch negotiated {
	case "", HTTP11:
		return core.ProtocolHTTP1, nil
	case H2:
		return core.ProtocolHTTP2, nil
	default:
		return core.ProtocolHTTP1, fmt.Errorf("unrecognised ALPN %q", negotiated)
	}
}

// Single is the one-protocol offer a second leg must make so both legs speak the same protocol — the
// proxy's client leg, after the upstream has already chosen.
func Single(negotiated string) []string {
	if negotiated == "" {
		return []string{HTTP11}
	}
	return []string{negotiated}
}

// Dialer opens TLS connections and reports what ALPN chose.
//
// A struct rather than a function with six arguments, because the two knobs are properties of the
// caller (a proxy that must reach a target whose certificate it cannot validate, a sender whose
// operator asked for verification) and not of an individual dial.
type Dialer struct {
	// InsecureSkipVerify skips certificate verification. True for the proxy's upstream leg, which
	// exists to reach targets with certificates an operator cannot fix; a sender follows its own
	// SenderConfig.TLSVerify.
	InsecureSkipVerify bool
	// Timeout bounds the whole dial including the handshake. Zero means no timeout of its own — the
	// context is then the only bound, which is what the proxy relies on.
	Timeout time.Duration
}

// Dial connects to addr, offering exactly the protocols in offer, and returns the connection with the
// protocol the handshake settled on.
//
// The returned string is the raw wire value, not a core.Protocol: the caller needs to tell "the peer
// chose http/1.1" from "the peer sent no ALPN at all", and Protocol collapses those two into the same
// answer. Both mean the connection carries HTTP/1.1; only one of them means the peer was asked and
// declined, which is the difference a downgrade report is made of.
//
// An empty offer sends no ALPN extension at all, rather than a default one — see Filter.
func (d Dialer) Dial(ctx context.Context, serverName, addr string, offer []string) (*tls.Conn, string, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.InsecureSkipVerify,
	}
	if len(offer) > 0 {
		cfg.NextProtos = offer
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: d.Timeout}, Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// Unreachable through tls.Dialer, which returns *tls.Conn by construction. Closed and
		// reported rather than asserted, because a type assertion that panics in a tool an operator
		// is running mid-engagement is a worse outcome than an error naming what happened.
		conn.Close()
		return nil, "", fmt.Errorf("tls dial to %s returned a %T, not a TLS connection", addr, conn)
	}
	return tlsConn, tlsConn.ConnectionState().NegotiatedProtocol, nil
}
