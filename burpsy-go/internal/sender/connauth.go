package sender

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/netauth"
)

// Connection-bound platform authentication: NTLM, in the NTLM header or as raw NTLM inside
// Negotiate, v2 by default and v1 only for a rule that opts into it (burpsy-react-ui-sel6).
//
// # The shape, and why the typed transport cannot carry it
//
// NTLM's three legs — NEGOTIATE, CHALLENGE (in a 401), AUTHENTICATE — authenticate one TCP
// connection: the server keeps its challenge in that connection's state, verifies the answer only
// there, and from then on treats the connection as the authenticated party. The typed path's
// http.Client pools connections across every request the sender makes, and so it can neither
// promise the AUTHENTICATE rides the connection that was challenged nor stop the authenticated
// connection from carrying the next request — someone else's, under another rule or none.
//
// So an NTLM exchange gets its own client, built per exchange from the same settings (resolution,
// upstream proxy, client certificate, timeouts, TLS verification):
//
//   - HTTP/1.1 only. h2 is not offered at all; over h2 the legs would be streams of a multiplexed
//     connection, which NTLM servers refuse (IIS answers HTTP_1_1_REQUIRED).
//   - One connection, ever. A dial guard refuses a second dial, so if the server closes the
//     connection after its challenge the AUTHENTICATE is not sent on a fresh one where it cannot
//     verify — it is not sent at all, and the 401 is the answer.
//   - Verified, not assumed: each leg's connection is read back through httptrace, and an
//     AUTHENTICATE that rode any connection but the challenged one is reported as a failure.
//   - Discarded afterwards. The authenticated connection is closed when the exchange returns, so it
//     never reaches the shared pool and never authenticates a request it was not opened for.
//
// The cost is one handshake per send to an NTLM host (two round trips on a fresh connection). It is
// the honest price of the protocol; caching authenticated connections per rule is a possible later
// optimisation and would need its own invalidation story.
//
// # What it does not touch
//
// The raw-bytes paths (SendRawOutcome, the ry5n keep-alive pool, pipelining) present no platform
// credential at all — their contract is the caller's bytes verbatim — so NTLM never enters the
// keep-alive pool those paths share. The proxy leg still uses the host-keyed
// Authorization/Learn flow; gaps.md records that it is not connection-bound.

// ConnectionBoundAuth is implemented by a PlatformAuth that can answer for a connection-bound
// scheme. Satisfied by *netauth.Credentials. Kept separate from PlatformAuth so a source with
// only header-shaped schemes need not grow a method it cannot honour.
type ConnectionBoundAuth interface {
	// BeginConnectionAuth starts one handshake for host, or reports false when the host's rule is
	// not connection-bound (or there is none).
	BeginConnectionAuth(host string) (*netauth.NTLMExchange, bool)
}

// errSecondDial is what the dial guard answers once the exchange's one connection is gone.
var errSecondDial = errors.New("the NTLM handshake's connection closed; a new connection cannot carry a handshake the server bound to the old one")

// connectionHandshake begins a connection-bound handshake for this request, when its host's rule
// asks for one and the caller did not supply its own Authorization header (the caller's header
// always wins, as on the per-request path).
func (s *Sender) connectionHandshake(req *Request, target *url.URL) (*netauth.NTLMExchange, bool) {
	source, ok := s.config.PlatformAuth.(ConnectionBoundAuth)
	if !ok || source == nil {
		return nil, false
	}
	for name := range req.Headers {
		if strings.EqualFold(name, "Authorization") {
			return nil, false
		}
	}
	host, _, _, err := authorityOf(target.String())
	if err != nil {
		return nil, false
	}
	return source.BeginConnectionAuth(host)
}

// legConn records which connection one leg rode.
type legConn struct {
	conn   net.Conn
	reused bool
}

// sendConnectionBound performs one request as an NTLM exchange on one dedicated connection.
//
// It returns the response the exchange ended on: the first leg's when the server did not
// challenge (or challenged with nothing this build can answer, or closed the connection), the
// AUTHENTICATE leg's otherwise. A refused AUTHENTICATE is recorded as a platform-authentication
// failure; the credential is presented once and never retried.
func (s *Sender) sendConnectionBound(ctx context.Context, req *Request, target *url.URL, exchange *netauth.NTLMExchange) (*Response, error) {
	client := s.connectionBoundClient()
	defer client.CloseIdleConnections()

	negotiateLeg := &legConn{}
	first, challenges, err := s.exchangeOn(withLegTrace(ctx, negotiateLeg), client, req, target, exchange.Negotiate(), true)
	if err != nil {
		return nil, err
	}
	if first.StatusCode == http.StatusUnauthorized && exchange.SwitchToNegotiate(challenges) {
		// The server ignored the NTLM header and offers Negotiate: the same NEGOTIATE goes again, as
		// raw NTLM in the Negotiate header, on the same connection (the dial guard holds that).
		retried, retriedChallenges, err := s.exchangeOn(withLegTrace(ctx, negotiateLeg), client, req, target, exchange.Negotiate(), true)
		if err != nil {
			exchange.Rejected(challenges)
			return first, nil
		}
		first, challenges = retried, retriedChallenges
	}
	if first.StatusCode != http.StatusUnauthorized {
		// No challenge: the server did not ask for NTLM on this request (or let it through on the
		// NEGOTIATE alone). Nothing was presented beyond the credential-free type-1 message.
		return first, nil
	}
	answer, err := exchange.Authenticate(challenges)
	if err != nil {
		// A bare offer, a non-NTLM challenge, a SPNEGO/Kerberos Negotiate token, an NTLMv1-only
		// server under an ntlmv2 rule (never answered with v1): the credential cannot be presented,
		// and the 401 is the honest answer.
		exchange.Rejected(challenges)
		return first, nil
	}

	authenticateLeg := &legConn{}
	final, finalChallenges, err := s.exchangeOn(withLegTrace(ctx, authenticateLeg), client, req, target, answer, true)
	if err != nil {
		// Typically the dial guard: the server closed the challenged connection, so the
		// AUTHENTICATE had nowhere it could verify and was not sent. The first response is real and
		// already read, so it is returned, as Send does when its own retry fails at the transport.
		exchange.Rejected(challenges)
		return first, nil
	}
	if authenticateLeg.conn != negotiateLeg.conn || !authenticateLeg.reused {
		// Unreachable while the dial guard stands, and checked anyway: an AUTHENTICATE on another
		// connection is one the server cannot verify, and whatever it answered is not the result
		// of this handshake. Reported as the failure it is.
		exchange.Rejected(finalChallenges)
		return final, nil
	}
	if final.StatusCode == http.StatusUnauthorized {
		exchange.Rejected(finalChallenges)
	}
	return final, nil
}

// withLegTrace records the connection a leg is sent on.
func withLegTrace(ctx context.Context, leg *legConn) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			leg.conn, leg.reused = info.Conn, info.Reused
		},
	})
}

// connectionBoundClient builds the per-exchange client: this sender's settings, with HTTP/2 off,
// one connection per host, and a dial guard that allows exactly one connection for its lifetime.
func (s *Sender) connectionBoundClient() *http.Client {
	s.mu.RLock()
	config, settings, carrier := s.config, s.net, s.carrier
	s.mu.RUnlock()

	h2 := HTTP2Settings{}
	if settings.HTTP2 != nil {
		h2 = *settings.HTTP2
	}
	h2.EnableHTTP2 = false
	settings.HTTP2 = &h2

	client := buildClient(config, settings, carrier)
	transport := client.Transport.(*http.Transport)
	// An empty, non-nil TLSNextProto is net/http's documented switch for "no HTTP/2 on this
	// transport", independent of ALPN: belt to buildClient's braces of not offering h2.
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1

	var once sync.Mutex
	dialed := false
	guard := func(next func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			once.Lock()
			if dialed {
				once.Unlock()
				return nil, errSecondDial
			}
			dialed = true
			once.Unlock()
			return next(ctx, network, addr)
		}
	}
	// Exactly one of the two is used for a given target — DialTLSContext for an https target when
	// it is set, DialContext otherwise — and both share the one flag.
	if transport.DialContext != nil {
		transport.DialContext = guard(transport.DialContext)
	}
	if transport.DialTLSContext != nil {
		transport.DialTLSContext = guard(transport.DialTLSContext)
	}
	return client
}
