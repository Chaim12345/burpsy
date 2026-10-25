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
	"crypto/x509"
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

// ClientCertSource supplies the TLS client certificate to present to one host, or nil when no
// identity is bound to it.
//
// An interface with one method rather than a dependency on internal/netauth, which is where the
// bindings and the PKCS#12 parsing actually live. This package is deliberately stdlib-only (see
// AGENTS.md) because it sits underneath both the sender and the proxy: importing the credential
// store here would drag PKCS#12 decoding into the dial path of every TLS connection burpsy makes,
// and would invert the dependency direction — netauth is a policy holder, alpn is a transport
// detail. The parsed certificate arrives ready to use; nothing here knows where it came from.
type ClientCertSource interface {
	// For returns the certificate bound to host, or nil. Called once per dial that requests one.
	For(host string) *tls.Certificate
}

// Dialer opens TLS connections and reports what ALPN chose.
//
// A struct rather than a function with six arguments, because the two knobs are properties of the
// caller (a proxy that must reach a target whose certificate it cannot validate, a sender whose
// operator asked for verification) and not of an individual dial.
type Dialer struct {
	// InsecureSkipVerify skips certificate verification. It is a CALLER's policy, not a package
	// decision: the sender follows its own SenderConfig.TLSVerify and the proxy follows its
	// TLSPolicy, both of which default to verifying (burpsy-react-ui-f365). This field is the last
	// place the two legs could have drifted, because it is where the value becomes a tls.Config.
	InsecureSkipVerify bool
	// RootCAs is the pool the origin's certificate is verified against. Nil means the system pool,
	// which is what both legs used before a custom CA was configurable.
	//
	// It belongs here rather than being loaded per Dial because the pool is expensive to build and
	// because a per-dial load would mean reading a file on the handshake path — which is the hot path
	// for every intercepted connection.
	RootCAs *x509.CertPool
	// MinVersion is the lowest TLS version accepted. Zero means Go's default, which is the floor Go
	// itself considers safe; a caller lowering it is working around a legacy target and is saying so
	// explicitly.
	MinVersion uint16
	// Timeout bounds the whole dial including the handshake. Zero means no timeout of its own — the
	// context is then the only bound, which is what the proxy relies on.
	Timeout time.Duration
	// Resolver is the resolver the underlying TCP dial uses to turn addr's host into an address. Nil
	// means the system resolver, which is what every caller wanted until network settings gained a
	// lookup policy (see sender.ResolutionSettings).
	//
	// It is a property of the caller rather than of the dial for the same reason the two knobs above
	// are: a sender whose operator named a resolver must use it for every dial it makes, and a proxy
	// leg that never had one must keep not having one.
	Resolver *net.Resolver
	// Carry, when set, opens the TCP connection the TLS handshake runs over. Nil dials the address
	// directly, which is what every caller did before upstream proxying existed.
	//
	// This is how an upstream proxy is reached without weakening anything: the TLS session stays
	// end-to-end with the origin — the proxy carries opaque bytes and never sees the handshake — so
	// certificate verification, ALPN and the negotiated protocol all mean exactly what they meant on a
	// direct dial. A proxy applied *inside* the handshake would be a second man in the middle whose
	// certificate the caller would then have to decide about, which is a different feature.
	Carry func(ctx context.Context, network, addr string) (net.Conn, error)
	// ClientCerts, when set, is consulted for a client certificate to present when the peer asks for
	// one. Nil — the default — means no certificate is ever offered, which is the behaviour every
	// caller had before client TLS authentication existed.
	//
	// Per-Dialer rather than per-Dial because tls.CertificateRequestInfo does not carry the server
	// name: crypto/tls hands the callback the acceptable CAs and signature schemes and nothing that
	// identifies the peer, so the only place the host is still known is out here, where Dial was
	// given it. A single shared tls.Config physically cannot do per-host selection for that reason.
	ClientCerts ClientCertSource
	// SNI, when set, is the server name sent in the ClientHello instead of Dial's serverName — Burp
	// Repeater's "Override SNI" (burpsy-react-ui-k011), used to reproduce an SNI-based external
	// service interaction with a Collaborator domain in the SNI. It changes only that one field of the
	// handshake: the certificate is still verified against serverName (the authority actually
	// dialled), and a client certificate is still chosen for serverName, because the override is a
	// probe value aimed at the server's SNI handling, not a claim about who the peer is.
	SNI string
	// Fingerprint, when set, presents a browser-like ClientHello (utls) instead of Go's own —
	// see fingerprint.go. Empty is Go's hello and the default. Every other field keeps its
	// meaning under a fingerprint; the hello's bytes are the only thing that changes.
	Fingerprint Fingerprint
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
func (d Dialer) Dial(ctx context.Context, serverName, addr string, offer []string) (net.Conn, string, error) {
	if d.Fingerprint != FingerprintGo {
		return d.dialFingerprinted(ctx, serverName, addr, offer)
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.InsecureSkipVerify,
		RootCAs:            d.RootCAs,
		MinVersion:         d.MinVersion,
	}
	if d.SNI != "" && d.SNI != serverName {
		cfg.ServerName = d.SNI
		if !d.InsecureSkipVerify {
			// crypto/tls verifies against ServerName, which is now the probe value. Verification is
			// therefore done here, against the authority dialled, with the same roots — skipping the
			// built-in check is what lets the ClientHello carry a name the certificate was not issued for
			// without dropping verification altogether.
			cfg.InsecureSkipVerify = true
			cfg.VerifyConnection = verifyAgainst(serverName, d.RootCAs)
		}
	}
	if len(offer) > 0 {
		cfg.NextProtos = offer
	}
	if d.ClientCerts != nil {
		// GetClientCertificate rather than cfg.Certificates: it is only consulted when the peer
		// actually sends a CertificateRequest, so a host with no binding costs one nil map lookup on
		// the handshakes that ask and nothing at all on the ones that do not.
		//
		// Declining returns an empty tls.Certificate, never an error. A server may request a
		// certificate from every client and still accept those that send none, so failing the
		// handshake here would break targets that work fine today — an empty Certificate message is
		// the TLS-level way to say "I have none", which is exactly what this dialler sent before
		// client certificates existed.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if found := d.ClientCerts.For(serverName); found != nil {
				return found, nil
			}
			return &tls.Certificate{}, nil
		}
	}
	if d.Carry != nil {
		// The carrier is dialled first, then the handshake runs on top of it. HandshakeContext rather
		// than Handshake so a cancelled context still aborts, which tls.Dialer would have given us for
		// free on the direct path.
		carrier, err := d.Carry(ctx, "tcp", addr)
		if err != nil {
			return nil, "", err
		}
		tlsConn := tls.Client(carrier, cfg)
		handshakeCtx := ctx
		if _, hasDeadline := ctx.Deadline(); !hasDeadline && d.Timeout > 0 {
			var cancel context.CancelFunc
			handshakeCtx, cancel = context.WithTimeout(ctx, d.Timeout)
			defer cancel()
		}
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			carrier.Close()
			return nil, "", err
		}
		return tlsConn, tlsConn.ConnectionState().NegotiatedProtocol, nil
	}

	// The direct path keeps the caller's resolver: a carrier was not supplied, so this dial is the
	// one that has to honour a hostname-resolution override.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: d.Timeout, Resolver: d.Resolver},
		Config:    cfg,
	}
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

// verifyAgainst verifies a handshake's certificate chain for name, with roots (nil = the system pool):
// what crypto/tls would have done had ServerName been name.
func verifyAgainst(name string, roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("tls: the server presented no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       name,
			Roots:         roots,
			Intermediates: intermediates,
		})
		return err
	}
}
