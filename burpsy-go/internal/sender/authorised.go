package sender

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

// SendFailure names why one authorised send produced no response, as a kind rather than a
// string, so a caller reporting an unproven check can tell "the target never saw the bytes"
// apart from "the bytes were never allowed to leave" without matching on message text.
type SendFailure int

const (
	// SendFailureNone marks a send that reached the transport and answered.
	SendFailureNone SendFailure = iota
	// SendFailureScope marks bytes the scope gate refused. Kept distinct from a pacing
	// decline: the operator fixes one with a scope rule and the other with a pool.
	SendFailureScope
	// SendFailurePacing marks a group the pacer declined to admit atomically. A synchronized
	// group that cannot go out together must not trickle out one paced send at a time -
	// staggered "simultaneous" sends report a race that was never run.
	SendFailurePacing
	// SendFailureTransport marks a send that reached the wire and failed there.
	SendFailureTransport
)

// AuthorisedResult is one authorised send's outcome.
type AuthorisedResult struct {
	Raw      []byte
	Duration time.Duration
	Status   *int
	// Err is why this send produced no usable response, nil when it did. Carried on the
	// result so a group's per-member failures keep their member's index.
	Err error
	// Failure classifies Err; SendFailureNone when Err is nil.
	Failure SendFailure
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
	pace    Pacer
	sent    atomic.Int64
	refused atomic.Int64
}

// Pacer bounds how fast and how concurrently sends leave this sender.
//
// # Why the interface lives here and the implementation does not
//
// The one limiter in this tree is intruder.RateLimiter, and package intruder imports this one — so
// this package cannot import it back. An interface with a single method is the whole fix: the
// limiter grows a Pace method of this shape (see intruder.RateLimiter.Pace) and satisfies this
// without either package learning about the other. What must not happen is a second limiter written
// here to avoid the import; two limiters of one shape drift, and the one that drifts is always the
// one nobody's tests measure.
//
// # Why an AuthorisedSender is the right place for it
//
// The audit path has no driver loop. An intruder attack has one place that decides to send the next
// request, so a limiter goes there; the scanner has dozens of checks each calling
// ActiveScanner.probeGate(...).Send(...) directly, and there is no single line that would bound them
// all. But every one of those calls goes through an AuthorisedSender built at one construction
// point, which makes *this* the chokepoint — the same argument that put the scope check here.
// Pacing and authorising are then the same unforgettable step rather than two conventions.
type Pacer interface {
	// Pace blocks until this send may go out, returning the function that gives the slot back. It
	// returns an error only when ctx ends first, and on error nothing must be released — a caller
	// that got an error never held a slot.
	Pace(ctx context.Context) (release func(), err error)
}

// GroupPacer is the optional second contract a Pacer can satisfy: one atomic reservation for
// a whole synchronized group. SendSynchronizedGroup type-asserts for it, and a Pacer without
// it declines synchronized groups rather than pacing them one send at a time - per-send
// acquires would stagger the releases the group exists to align, and N-1 of the members
// would also go uncounted against the rate budget. intruder.RateLimiter and
// pool.ContextPacer satisfy it; a custom Pacer that predates the contract declines groups
// loudly instead of sending them wrong.
type GroupPacer interface {
	// PaceN reserves n slots and spends n rate tokens atomically: the caller holds the whole
	// group or nothing, and the one release gives every slot back. An error means nothing was
	// held.
	PaceN(ctx context.Context, n int) (release func(), err error)
}

// NewAuthorisedSender binds a scope gate and a raw sender to one named target.
func NewAuthorisedSender(scope ScopeChecker, net *Sender, host string, port uint16, tls bool) *AuthorisedSender {
	return &AuthorisedSender{scope: scope, net: net, host: host, port: port, tls: tls}
}

// WithPace bounds every send that leaves this sender by a resource pool's limits, and returns the
// sender so it reads as one expression at the construction point.
//
// nil is a supported state and the default: with no pacer, `pacing` below is one nil check and every
// code path behaves exactly as it did before this existed. That is deliberate — the repeater, the
// session macro runner and the intruder all keep their current behaviour (the intruder because it
// already paces itself in its driver loop, and pacing it twice would apply one pool's delay per
// request and then again per send).
func (a *AuthorisedSender) WithPace(p Pacer) *AuthorisedSender {
	a.pace = p
	return a
}

// pacing acquires this send's slot, returning a release function that is always safe to call.
//
// It is called *after* the scope decision and before the dial, which is the only correct order: a
// refused request is not traffic, so it must not spend a pool's budget or wait for a slot, and a
// pool with one concurrent request would otherwise let a stream of out-of-scope requests serialise
// behind each other for no reason.
func (a *AuthorisedSender) pacing(ctx context.Context) (func(), error) {
	if a.pace == nil {
		return func() {}, nil
	}
	release, err := a.pace.Pace(ctx)
	if err != nil {
		return nil, err
	}
	if release == nil {
		return func() {}, nil
	}
	return release, nil
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
	release, err := a.pacing(ctx)
	if err != nil {
		return AuthorisedResult{}, err
	}
	defer release()
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

// SendSynchronizedGroup sends raws as one synchronized race group: HTTP/1.1, every request's
// final byte withheld until every member is holding its own, then released together. It is
// the scanner's single-packet race surface (burpsy-react-ui-0vzb.8), mirroring the Repeater
// orchestration in internal/web/api_repeater_group.go through this sender's two gates.
//
// Scope: every member's bytes are authorised before anything is written, and the first
// refusal refuses the whole group with the refusal counted like a Send refusal - a partial
// race group is not a smaller measurement, it is a different one. Pacing: the group acquires
// once, atomically, through the pacer's GroupPacer contract; a pacer that cannot do that, or
// a pool that cannot admit the group, declines with SendFailurePacing on every member.
// A nil pacer paces nothing, exactly as Send.
//
// The returned slice is in member order, one entry per raw, each with its own outcome or its
// own error and failure kind; Sent moves only for members whose bytes actually left. The
// group error is non-nil only when the group as a whole never ran - scope refusal or pacing
// decline - never because one member failed on the wire, which is that member's result.
func (a *AuthorisedSender) SendSynchronizedGroup(ctx context.Context, raws [][]byte) ([]AuthorisedResult, error) {
	if len(raws) == 0 {
		return nil, errors.New("refused: a synchronized group has no members")
	}
	for _, raw := range raws {
		if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
			a.refused.Add(1)
			return nil, err
		}
	}
	release := func() {}
	if a.pace != nil {
		gp, ok := a.pace.(GroupPacer)
		if !ok {
			err := errors.New("declined: pacing cannot admit the group atomically (the configured pacer has no group contract)")
			return declinedGroup(len(raws), err), err
		}
		r, err := gp.PaceN(ctx, len(raws))
		if err != nil {
			wrapped := fmt.Errorf("declined: pacing cannot admit %d at once: %w", len(raws), err)
			return declinedGroup(len(raws), wrapped), wrapped
		}
		if r != nil {
			release = r
		}
	}
	defer release()

	ready := make(chan struct{}, len(raws))
	released := make(chan struct{})
	barrier := SyncPoints{Ready: ready, Release: released}

	results := make([]AuthorisedResult, len(raws))
	var wg sync.WaitGroup
	for i, raw := range raws {
		wg.Add(1)
		go func(i int, raw []byte) {
			defer wg.Done()
			start := time.Now()
			resp, outcome, err := a.net.SendSynchronized(ctx, a.host, a.port, a.tls, raw, barrier)
			if err != nil {
				results[i] = AuthorisedResult{Err: err, Failure: SendFailureTransport, Outcome: outcome}
				return
			}
			a.sent.Add(1)
			results[i] = AuthorisedResult{
				Raw:      resp,
				Duration: time.Since(start),
				Status:   httputil.ResponseStatus(resp),
				Outcome:  outcome,
			}
		}(i, raw)
	}
	// Every member signals readiness exactly once, failure included, so len(raws) signals
	// fill the barrier. The ctx branch only covers a member cancelled before it could
	// signal; the senders' own holds select on ctx.Done regardless.
	var releaseOnce sync.Once
	go func() {
		defer releaseOnce.Do(func() { close(released) })
		for range raws {
			select {
			case <-ready:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	return results, nil
}

// declinedGroup marks every member of a group that never ran with the one decline, so the
// caller's per-member report reads "unproven: pacing" for each rather than one bare error
// detached from the members it stopped.
func declinedGroup(n int, err error) []AuthorisedResult {
	results := make([]AuthorisedResult, n)
	for i := range results {
		results[i] = AuthorisedResult{Err: err, Failure: SendFailurePacing}
	}
	return results
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
	release, err := a.pacing(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
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
