package sender

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// ScopeChecker is the per-request gate an AuthorisedSender asks about the exact bytes about to be
// written. Both core.Scope and core.SharedScope implement it; the interface keeps sender free of
// a concrete core type.
type ScopeChecker interface {
	AuthoriseRaw(host string, port uint16, isTLS bool, raw []byte) error
}

// AuthorisedResult is one authorised send's outcome.
type AuthorisedResult struct {
	Raw      []byte
	Duration time.Duration
	Status   *int
	// Outcome is which protocol carried the send, and why it was not HTTP/2 when it was not.
	//
	// Carried on the result rather than left to Sender.Protocols, because a caller that ran one payload
	// needs to know what that payload travelled over — an intruder run whose findings are all "no
	// difference" reads very differently once you know every request went out as HTTP/1.1 at an h2 front
	// end. See protocol.go.
	Outcome SendOutcome
}

// AuthorisedSender is a sender bound to one named target whose scope is checked against the
// request bytes actually about to go on the wire — not the target string the operator typed.
// This is the sender half of the intruder guarantee: a payload spliced into a path position can
// rewrite the request line, and only the bytes about to be written can be trusted. The scope
// check happens before the dial, so an out-of-scope request never reaches the transport.
//
// Ports burpsy-sender's AuthorisedSender contract: the scope handle is bound at construction,
// every send is checked individually, a refusal is counted and returned as the send's error,
// and the transport is never reached on refusal.
//
// # Two entry points, one gate
//
// Send takes raw bytes; SendRequest takes a *Request. Both run AuthoriseRaw on the request line
// before the dial and both feed the same Sent/Refused counters. That symmetry is the point: for a
// while the raw path was gated and the typed path was not, and Sender.Send was reachable by anyone
// holding the underlying *Sender — so session macros left the process with no scope decision made
// about them at all. A surface that holds an AuthorisedSender now has no unauthorised way out.
type AuthorisedSender struct {
	scope   ScopeChecker
	net     *Sender
	host    string
	port    uint16
	tls     bool
	sent    atomic.Int64
	refused atomic.Int64
}

// NewAuthorisedSender binds a scope gate and a raw sender to one named target.
func NewAuthorisedSender(scope ScopeChecker, net *Sender, host string, port uint16, tls bool) *AuthorisedSender {
	return &AuthorisedSender{scope: scope, net: net, host: host, port: port, tls: tls}
}

// Send checks the request bytes against the scope, then — and only then — writes them.
// The refused count includes requests refused on scope, readability or wrong-authority grounds; a
// request that fails to send at the transport is neither sent nor refused, and is reported by the
// caller.
func (a *AuthorisedSender) Send(ctx context.Context, raw []byte) (AuthorisedResult, error) {
	return a.SendAs(ctx, raw, ProtocolPreferenceAuto)
}

// SendAs is Send with the protocol choice made explicit, for a caller that needs the bytes on the wire to
// be exactly the bytes it wrote.
//
// A preference is not a scope waiver and cannot become one: the same AuthoriseRaw gate runs on the same
// bytes, bound to the same authority, and the only thing pref changes is whether those bytes may be
// re-expressed as h2 first. ProtocolPreferenceHTTP1 is still reported as a downgrade, so pinning shows up
// in the coverage report rather than being knowable only to whoever passed the flag.
func (a *AuthorisedSender) SendAs(ctx context.Context, raw []byte, pref ProtocolPreference) (AuthorisedResult, error) {
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
		a.refused.Add(1)
		return AuthorisedResult{}, err
	}
	start := time.Now()
	resp, outcome, err := a.net.SendRawOutcome(ctx, a.host, a.port, a.tls, raw, pref)
	if err != nil {
		return AuthorisedResult{}, err
	}
	a.sent.Add(1)
	return AuthorisedResult{
		Raw:      resp,
		Duration: time.Since(start),
		Status:   httputil.ResponseStatus(resp),
		Outcome:  outcome,
	}, nil
}

// SendRequest is the typed half of the chokepoint: the same AuthoriseRaw gate as Send, for a caller
// that holds a *Request rather than raw bytes. It is the entry point every request-originating
// surface should reach for; Sender.Send authorises nothing.
//
// The request is rendered to bytes and those bytes are what the gate reads, so a path assembled from
// interpolated values — a session macro's {{token}} spliced into a URL is the live case — is checked
// as the request line it produces rather than as the template it came from. The transport then writes
// an equivalent request with the stdlib's own transport headers added; what is byte-identical, and
// what the scope decision is actually made of, is the method, the request target and the authority.
// effectiveTarget computes the gate's view and the dialled URL from one parse, and redirects are
// never followed, so the authority reached is the bound one.
//
// The authority is always this sender's bound target. A Request naming a different host, port or
// scheme is refused rather than quietly rewritten: a caller that named another authority is asking
// for something this sender was not authorised to do, and silently sending it somewhere else would
// answer a question nobody asked.
func (a *AuthorisedSender) SendRequest(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, errors.New("refused: there is no request to send")
	}
	bound, err := a.bind(req)
	if err != nil {
		a.refused.Add(1)
		return nil, err
	}
	raw, err := a.net.Render(bound)
	if err != nil {
		// Counted as a refusal for the same reason an unreadable request line is: nothing was sent,
		// and a request the sender cannot even render is not a transport failure to report upwards.
		a.refused.Add(1)
		return nil, fmt.Errorf("refused: %w", err)
	}
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
		a.refused.Add(1)
		return nil, err
	}
	resp, err := a.net.Send(ctx, bound)
	if err != nil {
		return nil, err
	}
	a.sent.Add(1)
	return resp, nil
}

// bind returns a copy of req addressed at this sender's bound target, refusing any request that
// names a different authority.
//
// The scheme is only checked when the request names an authority at all: Request.TLS is a bool, so
// an unset field is indistinguishable from a deliberate "plaintext", and refusing every caller who
// simply left the authority to the bound sender would make the safe call the awkward one. When a
// host or port *is* named, the scheme is part of that authority and must match — a silent downgrade
// to plaintext would put a macro's credentials on the wire in clear.
func (a *AuthorisedSender) bind(req *Request) (*Request, error) {
	out := *req
	if out.URL != "" {
		host, port, isTLS, err := authorityOf(out.URL)
		if err != nil {
			return nil, fmt.Errorf("refused: %w", err)
		}
		if host != a.host || port != a.port || isTLS != a.tls {
			return nil, fmt.Errorf("refused: this sender is authorised for %s, and the request names %s",
				formatAuthority(a.host, a.port, a.tls), formatAuthority(host, port, isTLS))
		}
		return &out, nil
	}
	named := out.Host != "" || out.Port != 0
	if out.Host != "" && out.Host != a.host {
		return nil, fmt.Errorf("refused: this sender is authorised for host %s, and the request names %s", a.host, out.Host)
	}
	if out.Port != 0 && out.Port != a.port {
		return nil, fmt.Errorf("refused: this sender is authorised for port %d, and the request names %d", a.port, out.Port)
	}
	if named && out.TLS != a.tls {
		return nil, fmt.Errorf("refused: this sender is authorised for %s, and the request names %s",
			formatAuthority(a.host, a.port, a.tls), formatAuthority(a.host, a.port, out.TLS))
	}
	out.Host, out.Port, out.TLS = a.host, a.port, a.tls
	return &out, nil
}

// authorityOf reads host, port and scheme out of an absolute URL. A URL with no explicit port takes
// the scheme's default, so https://h and https://h:443 name the same authority rather than one that
// matches a bound target and one that does not.
func authorityOf(raw string) (host string, port uint16, isTLS bool, err error) {
	parsed, perr := url.Parse(raw)
	if perr != nil {
		return "", 0, false, fmt.Errorf("unusable target %q: %w", raw, perr)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		isTLS = true
	case "http":
		isTLS = false
	default:
		return "", 0, false, fmt.Errorf("target %q names no http scheme this sender can dial", raw)
	}
	host = parsed.Hostname()
	if host == "" {
		return "", 0, false, fmt.Errorf("target %q names no host", raw)
	}
	if p := parsed.Port(); p != "" {
		n, cerr := strconv.ParseUint(p, 10, 16)
		if cerr != nil {
			return "", 0, false, fmt.Errorf("target %q names an unusable port: %w", raw, cerr)
		}
		port = uint16(n)
	} else if isTLS {
		port = 443
	} else {
		port = 80
	}
	return host, port, isTLS, nil
}

// formatAuthority renders one authority the way a refusal message should name it.
func formatAuthority(host string, port uint16, isTLS bool) string {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// Sent counts the requests that cleared the gate and reached the transport.
func (a *AuthorisedSender) Sent() int64 { return a.sent.Load() }

// Refused counts the requests the scope stopped before the dial.
func (a *AuthorisedSender) Refused() int64 { return a.refused.Load() }
