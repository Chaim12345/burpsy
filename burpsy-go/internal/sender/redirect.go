package sender

import (
	"context"
	"fmt"
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
	settings := a.net.Network()
	policy := settings.Redirects

	current := a
	next := req
	result := &FollowResult{}

	// Where we have already been, so a chain that cycles is named as a loop rather than reported as a
	// budget that ran out. Keyed on a canonical authority-and-path rather than on the URL string,
	// because `http://h:80/a` and `http://h/a` are the same place and a loop between the two spellings
	// is still a loop — comparing the strings would miss exactly the cycle a hostile Location can build
	// out of alternating spellings.
	visited := make(map[string]struct{}, policy.MaxHops+1)

	for {
		target, err := effectiveTarget(next)
		if err != nil {
			return nil, err
		}
		from := absoluteURL(current, target)
		visited[visitKey(current.host, current.port, current.tls, target.RequestURI())] = struct{}{}

		resp, err := current.SendRequest(ctx, next)
		if err != nil {
			return nil, err
		}
		result.Sent++
		result.Final = resp

		location, isRedirect := redirectLocation(resp)
		if !isRedirect {
			result.Complete = true
			return result, nil
		}

		hop := RedirectHop{From: from, Status: resp.StatusCode, Location: location}

		if location == "" {
			hop.Reason = fmt.Sprintf("the %d names no Location, so there is no next hop to send",
				resp.StatusCode)
			result.Hops = append(result.Hops, hop)
			return result, nil
		}
		if policy.Mode == RedirectNever {
			hop.Reason = "redirects.mode is \"never\", so the 30x is the response"
			result.Hops = append(result.Hops, hop)
			return result, nil
		}
		if len(result.Hops) >= policy.MaxHops {
			hop.Reason = fmt.Sprintf("redirects.max_hops is %d and this chain has used them all",
				policy.MaxHops)
			result.Hops = append(result.Hops, hop)
			return result, nil
		}

		candidate, candidateURL, err := redirectRequest(next, target, resp.StatusCode, location)
		if err != nil {
			hop.Reason = err.Error()
			result.Hops = append(result.Hops, hop)
			return result, nil
		}
		hop.To = candidateURL.String()

		nextHost, nextPort, nextTLS, err := authorityOf(hop.To)
		if err != nil {
			hop.Reason = err.Error()
			result.Hops = append(result.Hops, hop)
			return result, nil
		}

		if _, seen := visited[visitKey(nextHost, nextPort, nextTLS, candidateURL.RequestURI())]; seen {
			hop.Reason = "this chain has already been to " + hop.To + ", so it is looping"
			result.Hops = append(result.Hops, hop)
			return result, nil
		}

		if reason := filterHop(policy.Mode, current, nextHost, nextPort, nextTLS); reason != "" {
			hop.Reason = reason
			result.Hops = append(result.Hops, hop)
			return result, nil
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
				// Counted as a refusal on the sender that would have sent it, so the chain's refusals
				// show up in the same counters every other refused request does.
				hopSender.refused.Add(1)
				a.refused.Add(1)
				return result, nil
			}
		}

		hop.Followed = true
		result.Hops = append(result.Hops, hop)
		current, next = hopSender, candidate
	}
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
