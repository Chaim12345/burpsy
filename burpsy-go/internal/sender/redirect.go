package sender

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
}

// FollowResult is a redirect-following send: the last response actually received, and every hop.
type FollowResult struct {
	// Final is the last response received. Never nil when the error is nil, and it is the 30x itself
	// when the chain was stopped at one — the operator sees the redirect rather than nothing.
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
	a.followChain(ctx, result, a, req, target, resp)
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
	if _, isRedirect := redirectLocation(resp); !isRedirect {
		result.Complete = true
		return result, nil
	}

	req, rerr := requestFromRaw(raw, a)
	if rerr != nil {
		if location, isRedirect := redirectLocation(resp); isRedirect {
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
	a.followChain(ctx, result, a, req, target, resp)
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
) {
	policy := a.net.Network().Redirects

	// Where we have already been, so a chain that cycles is named as a loop rather than reported as a
	// budget that ran out. Keyed on a canonical authority-and-path rather than on the URL string,
	// because `http://h:80/a` and `http://h/a` are the same place and a loop between the two spellings
	// is still a loop — comparing the strings would miss exactly the cycle a hostile Location can build
	// out of alternating spellings.
	visited := make(map[string]struct{}, policy.MaxHops+1)
	visited[visitKey(current.host, current.port, current.tls, target.RequestURI())] = struct{}{}

	for {
		from := absoluteURL(current, target)
		location, isRedirect := redirectLocation(resp)
		if !isRedirect {
			result.Complete = true
			return
		}

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
		// sharing this one's scope handle: its SendRequest renders the request and runs AuthoriseRaw on
		// those bytes before any dial, so the hop is authorised on the same terms as a first request.
		// Reusing `current` would not work and must not be made to — bind() refuses a request naming
		// another authority, which is precisely the check that makes a cross-authority hop deliberate.
		hopSender := NewAuthorisedSender(a.scope, a.net, nextHost, nextPort, nextTLS)

		// Pre-flighting the same gate lets a refusal be reported as this hop's Reason rather than as an
		// error that loses the chain. It is not the check that protects anything — hopSender.SendRequest
		// runs it again on its own bytes and is what actually stops the dial — so a disagreement between
		// the two costs a confusing message, never an ungated send.
		if raw, rerr := a.net.Render(candidate); rerr == nil {
			if serr := a.scope.AuthoriseRaw(nextHost, nextPort, nextTLS, raw); serr != nil {
				hop.Reason = serr.Error()
				result.Hops = append(result.Hops, hop)
				// Counted on the sender the caller holds, so the chain's refusals show up in the same
				// counters every other refused request does. Not also on hopSender: that sender is
				// discarded on this path, so incrementing it would record the refusal nowhere.
				a.refused.Add(1)
				return
			}
		}

		// The hop is sent here rather than at the top of the loop so the loop is entered with a response
		// already in hand — which is what lets a raw first send share this machinery.
		hopResp, err := hopSender.SendRequest(ctx, candidate)
		if err != nil {
			// The hop cleared every gate and then failed at the transport. That is not a refusal and not
			// a completed chain: Final stays the 30x that named it, and the reason says what happened.
			hop.Reason = "the hop was authorised but could not be sent: " + err.Error()
			result.Hops = append(result.Hops, hop)
			return
		}
		hop.Followed = true
		result.Hops = append(result.Hops, hop)
		result.Sent++
		result.Final = hopResp

		nextTarget, terr := effectiveTarget(candidate)
		if terr != nil {
			// Unreachable: candidate's URL was built by redirectRequest and already parsed by
			// authorityOf above. Handled rather than ignored because the alternative is a nil deref on
			// the next iteration.
			return
		}
		visited[visitKey(nextHost, nextPort, nextTLS, nextTarget.RequestURI())] = struct{}{}
		current, next, target, resp = hopSender, candidate, nextTarget, hopResp
	}
}

// responseFromRaw parses raw response bytes into the view the redirect decision needs.
//
// http.ReadResponse rather than a hand-rolled split: the status line and header folding rules are
// exactly where a hand-rolled parser gets a hostile response wrong, and this decides whether another
// request is sent. Headers are flattened to the map sender.Response carries; a repeated header keeps
// the first value, matching redirectLocation's own "first Location wins" reading.
func responseFromRaw(raw []byte) (*Response, error) {
	parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
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
func redirectLocation(resp *Response) (string, bool) {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return "", false
	}
	for name, value := range resp.Headers {
		if strings.EqualFold(name, "Location") {
			return strings.TrimSpace(value), true
		}
	}
	return "", true
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
		Host:   host,
		Path:   resolved.RequestURI(),
		TLS:    isTLS,
		Port:   port,
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
// of one authority produce one string.
func hostPortFor(host string, port uint16, isTLS bool) string {
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
