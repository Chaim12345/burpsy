package web

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// The send half of an Intruder attack (burpsy-react-ui-xixe.1, Phase 1).
//
// handleIntruderRun used to build its send closure inline: the session jar, the redirect policy, the
// per-attempt timeout and the authorising sender, captured from a 600-line function. Every attack
// setting that changes how a request reaches the wire — a response timeout, connection reuse, an HTTP
// version pin, Host-header sync — lands here, so it is one function that resolves the settings from the
// request (refusing a bad one before anything is sent) and one method that sends. A later "request this
// item again" reuses the same plan rather than reconstructing the closure.

// intruderSendPlan is one attack's resolved send settings and the state its sends share.
type intruderSendPlan struct {
	host string
	port uint16
	tls  bool

	// auth is the one authorising sender for the whole attack. The scope decision still happens once
	// per spliced request — which is what matters, because a payload landing in a path position
	// rewrites the request line, so the request that goes out may address something a host-level
	// check never saw.
	auth *sender.AuthorisedSender

	// timeout is the total per-attempt deadline (timeout_ms), covering a redirect chain as a whole.
	timeout time.Duration
	// responseTimeout is each request's own read bound (response_timeout_ms, mmca), carried on the
	// send's context as sender.SendOptions. Zero is the standing network read timeout.
	responseTimeout time.Duration

	// redirectPolicy is Burp's "Follow redirections" (tirx), resolved before any request goes out.
	redirectPolicy sender.RedirectSettings

	// jarHeader is the session cookie jar's Cookie header for the target, resolved once: an attack must
	// ask the same question of every payload, and a jar that changed mid-attack would make the buckets
	// incomparable. exemptCookies are the cookie names this attack is fuzzing, which the jar does not
	// overwrite. See intruder_cookies.go.
	jarHeader     string
	exemptCookies map[string]bool

	// redirectsFollowed counts every hop this attack actually sent, across every attempt — the
	// report's own proof that the setting did something. Atomic because every attempt's send runs on
	// its own goroutine (engine.go's driver loop), all writing through one plan.
	redirectsFollowed atomic.Int64
}

// buildIntruderSendPlan resolves req's send settings for an attack on host:port. Every error is a
// refusal of the request as written (a 400), returned before any request is sent.
func (s *Server) buildIntruderSendPlan(
	req intruderRunReq, selected []intruder.InsertionPoint, host string, port uint16, tls bool,
) (*intruderSendPlan, error) {
	timeout := time.Duration(intruderDefaultTimeoutMS) * time.Millisecond
	if req.TimeoutMS != nil {
		timeout = time.Duration(*req.TimeoutMS) * time.Millisecond
	}
	// Burp's "Follow redirections" (tirx): resolved here, so a bad mode is refused before any request
	// goes out rather than discovered on the first 30x.
	redirectPolicy, err := intruderRedirectPolicy(req.FollowRedirects, s.sender.Network().Redirects)
	if err != nil {
		return nil, err
	}
	var responseTimeout time.Duration
	if rt := req.ResponseTimeoutMS; rt != nil {
		if err := sender.ValidateResponseTimeoutMS("response_timeout_ms", *rt); err != nil {
			return nil, err
		}
		if req.TimeoutMS != nil && *req.TimeoutMS > 0 && uint64(*rt) > *req.TimeoutMS {
			return nil, fmt.Errorf("response_timeout_ms (%d) is longer than timeout_ms (%d), the total "+
				"per-attempt deadline, so the response timeout could never apply", *rt, *req.TimeoutMS)
		}
		responseTimeout = time.Duration(*rt) * time.Millisecond
	}
	return &intruderSendPlan{
		host:            host,
		port:            port,
		tls:             tls,
		auth:            sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls),
		timeout:         timeout,
		responseTimeout: responseTimeout,
		redirectPolicy:  redirectPolicy,
		// The session cookie jar, applied to every spliced request. Burp's jar "is shared between all
		// of Burp's tools"; before this it reached only the Repeater, so an attack against an
		// authenticated endpoint reported the login wall instead of the endpoint.
		jarHeader:     s.cookieHeaderFor(host, port, tls, targetPathOf(req.Target)),
		exemptCookies: exemptCookieNames(selected),
	}, nil
}

// close releases what the plan holds once the attack is over.
func (p *intruderSendPlan) close() {}

// sendFn is the engine's SendFn for this plan, bound to the attack's context.
func (p *intruderSendPlan) sendFn(ctx context.Context) intruder.SendFn {
	return func(raw []byte) (intruder.Sent, error) {
		return p.send(ctx, raw)
	}
}

// send puts one spliced request on the wire.
func (p *intruderSendPlan) send(ctx context.Context, raw []byte) (intruder.Sent, error) {
	sendStarted := time.Now()
	sctx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		sctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	if p.responseTimeout > 0 {
		// On the context, so it bounds every request this attempt makes — a followed redirect hop
		// included — and never touches the shared NetworkSettings (sendopts.go).
		sctx = sender.WithSendOptions(sctx, sender.SendOptions{ResponseTimeout: p.responseTimeout})
	}
	// After the splice, never before: insertion points are byte spans into the base request, and a
	// header added to the base would shift every span after it.
	raw = applyJarCookies(raw, p.jarHeader, p.exemptCookies)
	res, err := p.auth.Send(sctx, raw)
	if err != nil {
		return intruder.Sent{}, err
	}
	respRaw, status := res.Raw, res.Status
	if p.redirectPolicy.Mode != sender.RedirectNever {
		// Every hop re-authorised on its own rendered bytes through the same AuthorisedSender the first
		// send used — the intruder.go file header's whole point: "if an attack ever needs to follow a
		// redirect it must do so per hop, re-authorising the new authority through the scope chokepoint,
		// because a 30x is exactly how a target steers an attack somewhere nobody authorised." A chain
		// FollowRedirectsAfterPolicy could not evaluate, or that the policy or scope refused past the
		// first hop, leaves respRaw as the 30x itself — result.Final is always that response in that
		// case, never a fabrication (see FollowRedirectsAfterPolicy's own doc), which is exactly what an
		// operator who asked to follow and got refused should see.
		if result, ferr := p.auth.FollowRedirectsAfterPolicy(sctx, raw, res.Raw, p.redirectPolicy); ferr == nil && result.Final != nil {
			// Final.Raw is always set on this entry point (FollowRedirectsAfterPolicy builds Final from
			// responseFromRaw or a followed hop's own wire bytes, never the typed transport path that has
			// none — see FollowResult.Final's own doc), so this is the response the engine's grep,
			// reflection and bucketing will actually see.
			respRaw = result.Final.Raw
			status = &result.Final.StatusCode
			if result.Sent > 1 {
				p.redirectsFollowed.Add(int64(result.Sent - 1))
			}
		}
	}
	// Timed across the whole send, not just the first hop's res.Duration: once redirects are being
	// followed, "how long this attempt took" means the whole chain, the same way Burp's own timing
	// describes what an operator waited for, not the first response of several.
	return intruder.Sent{Raw: respRaw, Duration: time.Since(sendStarted), Status: status}, nil
}
