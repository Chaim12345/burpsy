package sender

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RedirectHop is one 30x this chain reached, and what was decided about it.
//
// Recorded even when the hop was not followed, because "the chain stopped here and this is why" is the
// answer an operator needs. A follower that returned only the final response would make a chain
// stopped by policy indistinguishable from one that ended in a 200, which is the same class of lie as a
// skipped check reporting as a pass.
type RedirectHop struct {
	// From is the absolute URL that produced this 30x.
	From string `json:"from"`
	// Status is the redirect status.
	Status int `json:"status"`
	// Location is the raw Location header, exactly as the peer sent it — relative or absolute.
	Location string `json:"location"`
	// To is the absolute URL Location resolves to, or empty when it could not be resolved.
	To string `json:"to,omitempty"`
	// Followed says whether a request was actually sent to To.
	Followed bool `json:"followed"`
	// Reason names why an unfollowed hop was not followed: the policy that filtered it, the scope that
	// refused it, the budget that ran out, or the Location that could not be read. Empty when Followed.
	Reason string `json:"reason,omitempty"`
	// Protocol is what carried a followed hop ("HTTP/1.1" or "HTTP/2"), empty when it was not sent —
	// the fact an operator enforcing a protocol on cross-domain hops (adkx) has to be able to check.
	Protocol string `json:"protocol,omitempty"`

	// RequestRaw and ResponseRaw capture what this hop put on the wire and what came back, set when the
	// hop was followed and nil when it was not — a hop that was never sent has no bytes, and inventing
	// either half would misdescribe what happened. Tagged out of this type's JSON because byte images
	// are engine state, not wire shape: the web layer maps them onto its own view and decides what a
	// browser sees, the same division that keeps FollowResult.Final out of the JSON.
	RequestRaw  []byte `json:"-"`
	ResponseRaw []byte `json:"-"`
}

// FollowResult is a redirect-following send: the last response actually received, and every hop.
type FollowResult struct {
	// Final is the last response received. Never nil when the error is nil, and it is the 30x itself
	// when the chain was stopped at one — the operator sees the redirect rather than nothing. Final.Raw
	// carries the exact response bytes whenever they are known: the caller's own bytes on the
	// AfterPolicy entry points, the hop's wire bytes on every followed hop. Only the typed entry
	// point's first response has no bytes to attach — SendRequest returns a transport view — and a
	// caller of that entry holds the bytes it sent, not bytes it can show for the response.
	//
	// This is the fix for a real gap: Final was tagged out of the JSON and nothing else carried the
	// body, so the operator who set "follow redirections" got a status number and no bytes.
	Final *Response `json:"-"`
	// Hops is every 30x reached, in order.
	Hops []RedirectHop `json:"hops"`
	// Sent counts the requests this call put on the wire, the first one included.
	Sent int `json:"sent"`
	// Complete is false when the chain was still redirecting when it stopped — a hop filtered by
	// policy, refused by scope, exhausted by the budget or caught looping. The distinction matters:
	// Final is then a 30x, not the resource.
	Complete bool `json:"complete"`
}

// FollowRedirects sends req and follows the chain the settings permit, re-authorising every hop.
//
// # Why this is a method here and not a transport option
//
// NewSender's transport refuses to follow 30x and has no knob to switch it on, and that stays true:
// a follow inside the transport dials the next hop with no gate in front of it, which is the "hostile
// target steers you at an internal service" escape. This function is the opposite construction. Each
// hop is a fresh AuthorisedSender bound to the new authority and sharing this one's scope handle, so
// the next request is authorised the way a first request is — the scope decides about the bytes about
// to be written, for the authority they are about to be written to. There is no path through here that
// reaches a socket without that gate, which is why following redirects can be offered at all.
//
// # Why it is opt-in and off by default
//
// Because not following is the truthful default. A 30x *is* the response: it is what the target said,
// and an operator auditing a login flow needs to see the redirect and its Set-Cookie rather than the
// page three hops later. Following also multiplies traffic — a scan of N requests against a target
// that redirects everything becomes 2N or 3N requests at the client's expense — and it hides findings,
// because a redirect to an error page reads as a clean 200. Burp's Repeater defaults to not following
// for the same reasons. So the default is RedirectNever, every mode above it is something the operator
// asked for by name, and the hop count is bounded even then.
//
// # What a caller gets
//
// The error return is for a request that could not be sent at all, exactly as SendRequest's is. A hop
// that was refused or filtered is not an error: it is a Hop with Followed=false and a Reason, and
// FollowResult.Complete is false. A caller that ignores everything but Final still gets the response
// this sender actually received, never a fabricated one.
func (a *AuthorisedSender) FollowRedirects(ctx context.Context, req *Request) (*FollowResult, error) {
	target, err := effectiveTarget(req)
	if err != nil {
		return nil, err
	}
	resp, err := a.SendRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	result := &FollowResult{Sent: 1, Final: resp}
	a.followChain(ctx, result, a, req, target, resp, a.net.Network().Redirects)
	return result, nil
}

// FollowRedirectsAfter follows the chain that begins at a response the caller already has.
//
// # Why the caller keeps its own first send
//
// Repeater's contract is that the bytes the operator typed are the bytes that go out, and its scope
// gate is deliberately host-level because it does not parse the request line — the operator owns it.
// An entry point that did the first send itself would have to choose one of those for every caller and
// would quietly change the other. So this takes the request bytes and the response bytes of a send that
// already happened, and decides only what comes next.
//
// Every hop it does send goes through a fresh AuthorisedSender bound to that hop's authority, so the
// hops are gated on their rendered bytes even though the first request was not. That asymmetry is the
// right way round: the first request is the operator's own, and a hop is a request a possibly-hostile
// Location asked for.
//
// FollowResult.Sent counts the caller's send as the first, so it is the total this exchange put on the
// wire rather than the number this function added. When the policy is RedirectNever, no hop is sent and
// the result is one unfollowed hop naming the policy — which is what makes wiring this in safe.
func (a *AuthorisedSender) FollowRedirectsAfter(ctx context.Context, raw, rawResp []byte) (*FollowResult, error) {
	return a.FollowRedirectsAfterPolicy(ctx, raw, rawResp, a.net.Network().Redirects)
}

// FollowRedirectsAfterPolicy is FollowRedirectsAfter with the policy made explicit, for a caller whose
// override lives outside the network settings — Repeater's per-send redirect-mode choice, which must
// not have to mutate the global table (and be raced by every other sender in the process) to take
// effect on one send. The rules are the caller's; the authorisation per hop never leaves this file.
func (a *AuthorisedSender) FollowRedirectsAfterPolicy(
	ctx context.Context,
	raw, rawResp []byte,
	policy RedirectSettings,
) (*FollowResult, error) {
	resp, err := responseFromRaw(rawResp)
	if err != nil {
		// The bytes came back but cannot be read as a response, so there is no status to decide from.
		// Returned as an error rather than as a complete chain: the caller already holds the response it
		// is going to show, and a silent "complete" here would claim this function looked and found
		// nothing to follow when in fact it could not look.
		return nil, fmt.Errorf("the response cannot be read well enough to decide a redirect from: %w", err)
	}
	result := &FollowResult{Sent: 1, Final: resp}

	// Answered before the request bytes are parsed, because this runs on every send a caller makes and
	// the overwhelming majority are not redirects. redirectLocation is the one place that decides what
	// counts as one, so short-circuiting here reuses that decision rather than restating it.
	if _, isRedirect := redirectLocation(resp, policy.EffectiveTypes()); !isRedirect {
		result.Complete = true
		return result, nil
	}

	req, rerr := requestFromRaw(raw, a)
	if rerr != nil {
		if location, isRedirect := redirectLocation(resp, policy.EffectiveTypes()); isRedirect {
			result.Hops = append(result.Hops, RedirectHop{
				From:     formatAuthority(a.host, a.port, a.tls),
				Status:   resp.StatusCode,
				Location: location,
				Reason: "the request bytes cannot be read well enough to build the next hop from them: " +
					rerr.Error(),
			})
			return result, nil
		}
		result.Complete = true
		return result, nil
	}
	target, terr := effectiveTarget(req)
	if terr != nil {
		return nil, terr
	}
	a.followChain(ctx, result, a, req, target, resp, policy)
	return result, nil
}

// followChain is the hop loop both entry points share: it is handed the response to the request already
// sent, and decides and performs every hop after it.
//
// Shared rather than duplicated because every rule in here is a security rule — the scope gate per hop,
// the budget, the loop key, the credential drop — and two copies would be two places for one of them to
// go missing. `current` and `next` describe the request that produced `resp`.
func (a *AuthorisedSender) followChain(
	ctx context.Context,
	result *FollowResult,
	current *AuthorisedSender,
	next *Request,
	target *url.URL,
	resp *Response,
	policy RedirectSettings,
) {

	// Where we have already been, so a chain that cycles is named as a loop rather than reported as a
	// budget that ran out. Keyed on a canonical authority-and-path rather than on the URL string,
	// because `http://h:80/a` and `http://h/a` are the same place and a loop between the two spellings
	// is still a loop — comparing the strings would miss exactly the cycle a hostile Location can build
	// out of alternating spellings.
	visited := make(map[string]struct{}, policy.MaxHops+1)
	visited[visitKey(current.host, current.port, current.tls, target.RequestURI())] = struct{}{}

	for {
		from := absoluteURL(current, target)
		location, isRedirect := redirectLocation(resp, policy.EffectiveTypes())
		if !isRedirect {
			result.Complete = true
			return
		}

		// Whatever THIS response set is remembered before the next hop is built, so a login or SSO
		// flow that sets a cookie on its 302 can carry it onward. Burp exposes this as a setting and
		// burpsy had the absence documented in repeater_options.go; the operator who hit it saw a
		// login page come back and had no way to tell a missing cookie from a broken app
		// (burpsy-react-ui-mr83).
		absorbHopCookies(a.net.CookieJar(), policy.ReplayCookies, current.host, current.port, current.tls, resp)

		hop := RedirectHop{From: from, Status: resp.StatusCode, Location: location}

		if location == "" {
			hop.Reason = fmt.Sprintf("the %d names no Location, so there is no next hop to send",
				resp.StatusCode)
			result.Hops = append(result.Hops, hop)
			return
		}
		if policy.Mode == RedirectNever {
			hop.Reason = "redirects.mode is \"never\", so the 30x is the response"
			result.Hops = append(result.Hops, hop)
			return
		}
		if len(result.Hops) >= policy.MaxHops {
			hop.Reason = fmt.Sprintf("redirects.max_hops is %d and this chain has used them all",
				policy.MaxHops)
			result.Hops = append(result.Hops, hop)
			return
		}

		candidate, candidateURL, err := redirectRequest(next, target, resp.StatusCode, location)
		if err != nil {
			hop.Reason = err.Error()
			result.Hops = append(result.Hops, hop)
			return
		}
		hop.To = candidateURL.String()

		nextHost, nextPort, nextTLS, err := authorityOf(hop.To)
		if err != nil {
			hop.Reason = err.Error()
			result.Hops = append(result.Hops, hop)
			return
		}

		if _, seen := visited[visitKey(nextHost, nextPort, nextTLS, candidateURL.RequestURI())]; seen {
			hop.Reason = "this chain has already been to " + hop.To + ", so it is looping"
			result.Hops = append(result.Hops, hop)
			return
		}

		if reason := filterHop(policy.Mode, current, nextHost, nextPort, nextTLS); reason != "" {
			hop.Reason = reason
			result.Hops = append(result.Hops, hop)
			return
		}

		// The authoritative gate for this hop. A fresh AuthorisedSender bound to the new authority,
		// sharing this one's scope handle: its SendAs authorises the rendered bytes before any dial, so
		// the hop is authorised on the same terms as a first request. Reusing `current` would not work
		// and must not be made to — a request naming another authority is exactly what makes a
		// cross-authority hop deliberate, and the render below is where that naming becomes bytes.
		hopSender := NewAuthorisedSender(a.scope, a.net, nextHost, nextPort, nextTLS).WithPace(a.pace)

		// The hop's request is rendered exactly once: these bytes are what the scope gate reads and
		// what the transport writes, so the gate's decision and the wire cannot disagree. They are also
		// kept on the hop — a request a Location chose is worth reading as readily as the one the
		// operator wrote, which is Burp's own contract for a followed chain.
		rendered, rerr := a.net.Render(candidate)
		if rerr != nil {
			hop.Reason = "the next hop's request cannot be rendered to wire bytes: " + rerr.Error()
			result.Hops = append(result.Hops, hop)
			return
		}

		// Cookies go on AFTER the render and BEFORE the scope gate, so the bytes the gate authorises
		// are the bytes that go out — the same rule the operator's own platform credential follows on
		// the proxy leg. A hop that already carries a Cookie header keeps it: an operator who typed
		// one meant that one, and a jar replacing it would be the silent substitution that rule exists
		// to refuse.
		//
		// The path is the hop's own request target, because a cookie jar scopes by Path: a cookie set
		// with Path=/ does not go to /admin/secret, and asking for everything the host holds is the
		// opposite of what the Location said.
		rendered = applyHopCookies(rendered, a.net.CookieJar(), policy.ReplayCookies,
			nextHost, nextPort, nextTLS, requestPathOf(candidate))

		// Pre-flighting the same gate lets a refusal be reported as this hop's Reason rather than as an
		// error that loses the chain. It is not the check that protects anything — hopSender.SendAs
		// runs it again on these same bytes and is what actually stops the dial — so a disagreement
		// between the two costs a confusing message, never an ungated send.
		if serr := a.scope.AuthoriseRaw(nextHost, nextPort, nextTLS, rendered); serr != nil {
			hop.Reason = serr.Error()
			result.Hops = append(result.Hops, hop)
			// Counted on the sender the caller holds, so the chain's refusals show up in the same
			// counters every other refused request does. Not also on hopSender: that sender is
			// discarded on this path, so incrementing it would record the refusal nowhere.
			a.refused.Add(1)
			return
		}

		// The hop is sent here rather than at the top of the loop so the loop is entered with a response
		// already in hand — which is what lets a raw first send share this machinery.
		//
		// SendAs rather than SendRequest: the raw path is what the caller's own send used (Repeater
		// sends the operator's bytes), so a hop travels under the same rules as the request that started
		// the chain instead of the stdlib transport's — no injected User-Agent or Accept-Encoding, no
		// transparent gzip — and the bytes that come back are the bytes that arrived, which is the whole
		// point of following. The gate is unchanged: SendAs runs AuthoriseRaw on exactly these rendered
		// bytes for the authority it is bound to.
		// Each hop negotiates as normal unless the caller enforces its protocol on a hop to another
		// host (adkx) — "cross-domain" meaning a different host name than the request that started
		// the chain, which is the case Burp's setting names.
		hopPref := ProtocolPreferenceAuto
		if !strings.EqualFold(nextHost, a.host) {
			hopPref = policy.CrossDomainProtocol
		}
		hopRes, err := hopSender.SendAs(ctx, rendered, hopPref)
		if err != nil {
			// The hop cleared every gate and then failed at the transport. That is not a refusal and not
			// a completed chain: Final stays the 30x that named it, and the reason says what happened.
			hop.Reason = "the hop was authorised but could not be sent: " + err.Error()
			result.Hops = append(result.Hops, hop)
			return
		}
		hop.Followed = true
		hop.Protocol = hopRes.Outcome.Protocol.VersionToken()
		hop.RequestRaw = rendered
		hop.ResponseRaw = hopRes.Raw
		parsed, perr := responseFromRaw(hopRes.Raw)
		if perr != nil {
			// The hop's bytes arrived but cannot be read as a response, so the chain cannot be decided
			// further from them. The hop stays followed and keeps its bytes; the chain stops here rather
			// than guessing what the bytes meant, and the reason names the stop.
			hop.Reason = "the hop was sent and answered, but its response cannot be read well enough to " +
				"continue the chain: " + perr.Error()
			result.Hops = append(result.Hops, hop)
			result.Sent++
			return
		}
		result.Hops = append(result.Hops, hop)
		result.Sent++
		result.Final = parsed

		nextTarget, terr := effectiveTarget(candidate)
		if terr != nil {
			// Unreachable: candidate's URL was built by redirectRequest and already parsed by
			// authorityOf above. Handled rather than ignored because the alternative is a nil deref on
			// the next iteration.
			return
		}
		visited[visitKey(nextHost, nextPort, nextTLS, nextTarget.RequestURI())] = struct{}{}
		current, next, target, resp = hopSender, candidate, nextTarget, parsed
	}
}

// responseFromRaw parses raw response bytes into the view the redirect decision needs, keeping the
// bytes themselves on Response.Raw — the parsed view flattens headers and never reads the body, so
// the raw image is the only complete copy and a caller that wants to show the response reads it
// there rather than reconstructing one.
//
// http.ReadResponse rather than a hand-rolled split: the status line and header folding rules are
// exactly where a hand-rolled parser gets a hostile response wrong, and this decides whether another
// request is sent. Headers are flattened to the map sender.Response carries; a repeated header keeps
// the first value, matching redirectLocation's own "first Location wins" reading.
func responseFromRaw(raw []byte) (*Response, error) {
	// An h2 response is stored in the HTTP/1-shaped rendering, whose status line says "HTTP/2" —
	// which net/http's parser refuses as a malformed version ("HTTP/2.0" is the form it reads). Read
	// through a copy with that one token widened; Raw below stays the bytes as rendered. Without this
	// every h2 send reported "the response cannot be read well enough to decide a redirect from", and
	// a chain stopped at its first h2 hop (found by adkx's cross-domain tests).
	parseable := raw
	if bytes.HasPrefix(raw, []byte("HTTP/2 ")) {
		parseable = append([]byte("HTTP/2.0 "), raw[len("HTTP/2 "):]...)
	}
	parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(parseable)), nil)
	if err != nil {
		return nil, err
	}
	defer parsed.Body.Close()
	headers := make(map[string]string, len(parsed.Header))
	for name, values := range parsed.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}
	return &Response{
		StatusCode: parsed.StatusCode,
		Status:     parsed.Status,
		Headers:    headers,
		Version:    parsed.Proto,
		Raw:        raw,
	}, nil
}

// requestFromRaw reads the request the operator's raw bytes describe, so a hop can be built from it.
//
// Only ever used to construct the *next* hop — the raw bytes themselves are sent verbatim by
// FollowRedirectsRaw. The authority comes from the bound sender rather than from the bytes: a raw
// request carries a Host header and an origin-form target, which together do not say whether the
// connection was TLS or what port it used, and the sender is bound to the authority that answered.
func requestFromRaw(raw []byte, a *AuthorisedSender) (*Request, error) {
	parsed, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, err
	}
	defer parsed.Body.Close()
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if a.tls {
		scheme = "https"
	}
	headers := make(map[string]string, len(parsed.Header))
	for name, values := range parsed.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}
	return &Request{
		Method:  parsed.Method,
		URL:     scheme + "://" + hostPortFor(a.host, a.port, a.tls) + parsed.URL.RequestURI(),
		Host:    a.host,
		Port:    a.port,
		TLS:     a.tls,
		Path:    parsed.URL.RequestURI(),
		Headers: headers,
		Body:    body,
	}, nil
}

// filterHop applies the policy arm that is not the scope check, returning the reason to stop or "".
//
// RedirectInScope and RedirectAlways both return "" here: the scope check that follows is the filter
// for both of them, and it is the same check. They differ in what an operator is told, not in what is
// sent — see RedirectAlways's own doc comment on why "always" cannot mean "unauthorised".
func filterHop(mode RedirectMode, from *AuthorisedSender, host string, port uint16, isTLS bool) string {
	if mode != RedirectOnSite {
		return ""
	}
	if host == from.host && port == from.port && isTLS == from.tls {
		return ""
	}
	return fmt.Sprintf("redirects.mode is %q and %s is not the same site as %s",
		RedirectOnSite, formatAuthority(host, port, isTLS),
		formatAuthority(from.host, from.port, from.tls))
}

// redirectLocation reports the Location header and whether the status is one this follower treats as a
// redirect.
//
// 301, 302, 303, 307 and 308 only. A 300 Multiple Choices is deliberately not followed: it means the
// server has several representations and is not nominating one, so picking its Location — which is
// optional there and merely "preferred" — would be this tool choosing a resource the operator did not.
// A 304 Not Modified is not a redirect at all despite living in the same century of status codes.
//
// Which responses count beyond the 30x is Burp's "Allowed redirect types" (types, z9zi): any status
// with a Location header, the Refresh header, and the meta refresh tag in an HTML body. A Refresh or
// meta-refresh hop is followed as a bodiless GET, as a browser navigates it.
func redirectLocation(resp *Response, types RedirectTypes) (string, bool) {
	header := func(want string) (string, bool) {
		for name, value := range resp.Headers {
			if strings.EqualFold(name, want) {
				return strings.TrimSpace(value), true
			}
		}
		return "", false
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		if types.Understand3xx {
			loc, _ := header("Location")
			return loc, true
		}
	}
	// The other kinds name their target or they are not redirects at all: a 300 or a 304 is never
	// one, and a response without the header or tag is just a response.
	if resp.StatusCode != http.StatusMultipleChoices && resp.StatusCode != http.StatusNotModified {
		if types.UnderstandAnyLocation {
			if loc, ok := header("Location"); ok && loc != "" {
				return loc, true
			}
		}
		if types.UnderstandRefreshHeader {
			if v, ok := header("Refresh"); ok {
				if target, ok := httputil.RefreshTarget(v); ok {
					return target, true
				}
			}
		}
		if types.UnderstandMetaRefresh {
			if ct, _ := header("Content-Type"); strings.Contains(strings.ToLower(ct), "html") {
				if target, ok := httputil.MetaRefreshTarget(resp.Body); ok {
					return target, true
				}
			}
		}
	}
	return "", false
}

// redirectRequest builds the next hop's request from the one that produced the 30x.
//
// # Method and body follow the status, not convenience
//
// 307 and 308 preserve the method and the body — that is what they exist to mean, and rewriting a POST
// to a GET there would send a different request than the target asked for. 301, 302 and 303 become a
// bodiless GET, which is what every browser and the Go standard library do: the entity headers are
// dropped with the body, because a Content-Length or Content-Type describing a body that is no longer
// there is a malformed request.
//
// # Credentials do not cross an authority boundary
//
// Authorization, Cookie and Proxy-Authorization are dropped when the hop changes authority. A target
// that can emit a Location can choose where those headers go, so forwarding them means a redirect is
// enough to make this tool hand an engagement's session cookie to a host of the target's choosing.
// The standard library strips them across a domain change for the same reason. They survive a
// same-authority hop, which is the ordinary /login -> /dashboard case and is where they are needed.
func redirectRequest(prev *Request, prevURL *url.URL, status int, location string) (*Request, *url.URL, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, nil, fmt.Errorf("Location %q cannot be read as a URL: %v", location, err)
	}
	resolved := prevURL.ResolveReference(parsed)
	switch strings.ToLower(resolved.Scheme) {
	case "http", "https":
	default:
		return nil, nil, fmt.Errorf("Location %q resolves to %q, which names no http scheme this sender can dial",
			location, resolved.String())
	}
	if resolved.Hostname() == "" {
		return nil, nil, fmt.Errorf("Location %q resolves to %q, which names no host",
			location, resolved.String())
	}

	host, port, isTLS, err := authorityOf(resolved.String())
	if err != nil {
		return nil, nil, err
	}
	sameAuthority := host == prevURL.Hostname() && isTLS == (strings.EqualFold(prevURL.Scheme, "https"))
	if sameAuthority {
		// Ports have to agree too, and prevURL may state its port implicitly.
		prevHost, prevPort, prevTLS, perr := authorityOf(prevURL.String())
		sameAuthority = perr == nil && host == prevHost && port == prevPort && isTLS == prevTLS
	}

	keepMethodAndBody := status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect

	out := &Request{
		Method: prev.Method,
		URL:    resolved.String(),
		// The Host header names the hop's authority, port included when the scheme's default does not
		// apply. Burp's own rendering is the specification here: Zxrb.Zv(Zp42) writes host only for
		// https/443 and http/80 and host:port otherwise, and Zx9i.ZH writes that exact string into
		// :authority when a cross-domain hop is rebuilt — so a followed hop to :8080 advertises
		// host:8080, the way the target's virtual-host routing expects to be addressed. The hostname
		// alone that used to be set here addressed the right socket but the wrong service.
		Host: hostPortFor(host, port, isTLS),
		Path: resolved.RequestURI(),
		TLS:  isTLS,
		Port: port,
	}
	if !keepMethodAndBody {
		out.Method = http.MethodGet
	} else {
		out.Body = prev.Body
	}

	out.Headers = make(map[string]string, len(prev.Headers))
	for name, value := range prev.Headers {
		lower := strings.ToLower(name)
		// Host is derived from the authority above; carrying the previous one would address the new
		// host and name the old one.
		if lower == "host" {
			continue
		}
		if !sameAuthority && (lower == "authorization" || lower == "cookie" || lower == "proxy-authorization") {
			continue
		}
		if !keepMethodAndBody &&
			(lower == "content-length" || lower == "content-type" || lower == "transfer-encoding") {
			continue
		}
		out.Headers[name] = value
	}
	return out, resolved, nil
}

// absoluteURL is the URL a hop should be reported as having come from.
//
// effectiveTarget already produces the URL that will be dialled, but a Request that named only a path
// leaves it relative; the bound sender's authority is what completes it. Reported rather than derived
// at read time so a chain reads as a list of absolute URLs.
func absoluteURL(a *AuthorisedSender, target *url.URL) string {
	if target.IsAbs() && target.Host != "" {
		return target.String()
	}
	scheme := "http"
	if a.tls {
		scheme = "https"
	}
	out := &url.URL{Scheme: scheme, Host: hostPortFor(a.host, a.port, a.tls), Path: target.Path, RawQuery: target.RawQuery}
	return out.String()
}

// hostPortFor renders an authority, eliding the port when it is the scheme's default so two spellings
// of one authority produce one string. A bare IPv6 literal is bracketed first, mirroring Burp's
// Zxrb.Zv (its Zhq_.ZK check): "::1:8080" is unparseable as an authority, "[::1]:8080" is the address.
func hostPortFor(host string, port uint16, isTLS bool) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if (isTLS && port == 443) || (!isTLS && port == 80) {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// visitKey is the identity the loop check compares: scheme, host, port and request target, with the
// port always explicit so no two spellings of one place can differ.
//
// The query string is part of it, because `/next?page=2` is a different resource from `/next?page=1`
// and a paginating redirect chain is not a loop. The fragment is not, because it never goes on the wire.
func visitKey(host string, port uint16, isTLS bool, requestURI string) string {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, strings.ToLower(host), port, requestURI)
}
