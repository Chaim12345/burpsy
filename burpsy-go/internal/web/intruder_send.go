package web

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
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

	// pref is the attack's HTTP version (http_version, xhqr), applied to every first-hop send.
	pref sender.ProtocolPreference
	// reuse is "HTTP/1 connection reuse" (xhqr); pool is its pool, built by startPool once the
	// attack's concurrency is final and closed by close. Nil pool means one connection per request.
	reuse bool
	pool  *sender.ConnPool

	// hostValue is the Host header every request is rewritten to ("Update Host header to match
	// target", ety8), or "" when the setting is off or was skipped; hostSkipped says why it was
	// skipped. hostUntouched counts requests a payload left with other than one Host header.
	hostValue     string
	hostSkipped   string
	hostUntouched atomic.Int64
}

// buildIntruderSendPlan resolves req's send settings for an attack on host:port. Every error is a
// refusal of the request as written (a 400), returned before any request is sent.
func (s *Server) buildIntruderSendPlan(
	req intruderRunReq, base []byte, selected []intruder.InsertionPoint, host string, port uint16, tls bool,
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
	pref, err := intruderHTTPVersion(req.HTTPVersion)
	if err != nil {
		return nil, err
	}
	reuse := req.HTTP1ConnectionReuse != nil && *req.HTTP1ConnectionReuse
	if reuse && req.SetConnectionClose != nil && *req.SetConnectionClose {
		return nil, fmt.Errorf("http1_connection_reuse and set_connection_close are both on: every request " +
			"would say Connection: close, and a connection that said it is never reused, so the attack would " +
			"ask for reuse and never get any. Turn one of them off")
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
	hostValue, hostSkipped := "", ""
	if req.UpdateHostHeader != nil && *req.UpdateHostHeader {
		hostValue, hostSkipped = hostHeaderPlan(base, selected, host, port, tls)
	}
	return &intruderSendPlan{
		hostValue:       hostValue,
		hostSkipped:     hostSkipped,
		host:            host,
		port:            port,
		tls:             tls,
		auth:            sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls),
		timeout:         timeout,
		responseTimeout: responseTimeout,
		redirectPolicy:  redirectPolicy,
		pref:            pref,
		reuse:           reuse,
		// The session cookie jar, applied to every spliced request. Burp's jar "is shared between all
		// of Burp's tools"; before this it reached only the Repeater, so an attack against an
		// authenticated endpoint reported the login wall instead of the endpoint.
		jarHeader:     s.cookieHeaderFor(host, port, tls, targetPathOf(req.Target)),
		exemptCookies: exemptCookieNames(selected),
	}, nil
}

// intruderHTTPVersion maps http_version onto the sender's protocol preference.
func intruderHTTPVersion(v *string) (sender.ProtocolPreference, error) {
	if v == nil {
		return sender.ProtocolPreferenceAuto, nil
	}
	switch *v {
	case "":
		return sender.ProtocolPreferenceAuto, nil
	case "http1":
		return sender.ProtocolPreferenceHTTP1, nil
	case "http2":
		return sender.ProtocolPreferenceForceH2, nil
	}
	return sender.ProtocolPreferenceAuto, fmt.Errorf(
		"http_version: unknown version %q (want http1, http2, or empty to negotiate)", *v)
}

// startPool builds the connection pool when reuse was asked for, bounded at the attack's
// concurrency. Called once, after the attack's limits are final and before the first send.
func (p *intruderSendPlan) startPool(maxInFlight int) {
	if p.reuse && p.pool == nil {
		p.pool = sender.NewConnPool(maxInFlight)
	}
}

// connectionsOpened and connectionsReused report the pool's counts, or nil when reuse was off.
func (p *intruderSendPlan) connectionsOpened() *int64 {
	if p.pool == nil {
		return nil
	}
	n := p.pool.Opened()
	return &n
}

func (p *intruderSendPlan) connectionsReused() *int64 {
	if p.pool == nil {
		return nil
	}
	n := p.pool.Reused()
	return &n
}

// close releases what the plan holds once the attack is over: the pool's idle connections.
func (p *intruderSendPlan) close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

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
	// Same place and same reason as the jar: after the splice, so no span offset moves.
	if p.hostValue != "" {
		if rewritten, ok := rewriteHostHeader(raw, p.hostValue); ok {
			raw = rewritten
		} else {
			p.hostUntouched.Add(1)
		}
	}
	// One gate either way: SendReusing authorises every request exactly as SendAs does, and only then
	// decides whether an idle connection carries it.
	var res sender.AuthorisedResult
	var err error
	if p.pool != nil {
		res, err = p.auth.SendReusing(sctx, p.pool, raw, p.pref)
	} else {
		res, err = p.auth.SendAs(sctx, raw, p.pref)
	}
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

// targetAuthority is the Host header value for an attack's target: the default port omitted, an IPv6
// literal bracketed, and the name the operator typed — never an address it resolved to, because a
// resolution override changes where the socket goes and not what the request names.
func targetAuthority(host string, port uint16, tls bool) string {
	if (tls && port == 443) || (!tls && port == 80) {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// headerLine is one header line in a request head: [start, end) excludes the CRLF.
type headerLine struct{ start, end int }

// hostHeaderLines returns every Host header line in raw's head, by byte range.
func hostHeaderLines(raw []byte) []headerLine {
	headEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headEnd < 0 {
		return nil
	}
	var out []headerLine
	// Skip the request line: a request target can contain "Host:" and is not a header.
	pos := bytes.Index(raw, []byte("\r\n"))
	for pos >= 0 && pos < headEnd {
		start := pos + 2
		end := start + bytes.Index(raw[start:], []byte("\r\n"))
		if end < start {
			break
		}
		line := raw[start:end]
		if i := bytes.IndexByte(line, ':'); i > 0 && strings.EqualFold(string(line[:i]), "Host") {
			out = append(out, headerLine{start, end})
		}
		pos = end
	}
	return out
}

// hostHeaderPlan decides, once from the base request, whether "Update Host header to match target"
// can apply: the value to write, or "" and the reason it cannot.
//
// Skipped when a selected position overlaps the Host header line — the same rule exemptCookieNames
// applies to the jar: the position being fuzzed is the question, and overwriting it would send the
// same request every time. Skipped too when the base request carries no Host header (there is no
// header to keep in step) or more than one (a duplicated-Host probe, where rewriting either would
// change what is being tested).
func hostHeaderPlan(base []byte, selected []intruder.InsertionPoint, host string, port uint16, tls bool) (string, string) {
	lines := hostHeaderLines(base)
	switch {
	case len(lines) == 0:
		return "", "the base request has no Host header to update"
	case len(lines) > 1:
		return "", fmt.Sprintf("the base request carries %d Host headers; rewriting one would change what a duplicated-Host request tests", len(lines))
	}
	line := lines[0]
	for _, p := range selected {
		// Inclusive at both ends, so a zero-length position at the line's edge counts as covering it.
		if p.Span.Offset <= line.end && line.start <= p.Span.Offset+p.Span.Len {
			return "", fmt.Sprintf("position %q covers the Host header, and the position being fuzzed is not overwritten", p.Label)
		}
	}
	return targetAuthority(host, port, tls), ""
}

// rewriteHostHeader sets the value of raw's one Host header, keeping the name's spelling and the
// whitespace after the colon. ok is false, and raw is returned unchanged, when the request does not
// carry exactly one Host header.
func rewriteHostHeader(raw []byte, value string) ([]byte, bool) {
	lines := hostHeaderLines(raw)
	if len(lines) != 1 {
		return raw, false
	}
	line := lines[0]
	colon := line.start + bytes.IndexByte(raw[line.start:line.end], ':')
	valueStart := colon + 1
	for valueStart < line.end && (raw[valueStart] == ' ' || raw[valueStart] == '\t') {
		valueStart++
	}
	out := make([]byte, 0, len(raw)-(line.end-valueStart)+len(value))
	out = append(out, raw[:valueStart]...)
	out = append(out, value...)
	out = append(out, raw[line.end:]...)
	return out, true
}
