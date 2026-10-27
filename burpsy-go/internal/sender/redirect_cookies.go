package sender

import (
	"bufio"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// This file is the cookie replay a followed redirect chain needs, and the option that turns it off.
//
// # The gap
//
// Burp's Repeater setting is explicit about the shape: "If you enable this setting, Burp resubmits any
// cookies set in the redirect response when it follows the redirection target" (settings/tools/
// repeater.html:143-145). burpsy's follower built each hop from the previous REQUEST only, so a
// login or SSO flow that sets a cookie on a 302 arrived at the destination unauthenticated — the
// redirect was followed, the cookie was not sent, and the destination answered with its login page.
// To an operator that reads as an application failure rather than a missing cookie, which is the
// single most common redirect shape in an authenticated tool (burpsy-react-ui-mr83).
//
// The help text already said the absence plainly (internal/web/repeater_options.go), so nothing on
// screen was wrong. This is the capability, and the option Burp exposes alongside it.
//
// # Why it is an interface, and why it is per-hop
//
// The jar is internal/session's Coordinator, and internal/session already imports internal/sender —
// so a direct import here would be a cycle. The seam is therefore two small methods, which the
// Coordinator already satisfies in shape (CookieHeader, AbsorbResponseCookies) and which any other
// store can too.
//
// Per-hop rather than per-chain is the deliberate choice. A cookie is scoped to the authority that set
// it: a 302 from auth.example.com to app.example.com sets a cookie for auth.example.com, and replaying
// it to app.example.com would hand one host's credential to another. The hop's own authority decides
// which cookies the next request carries, which is also what a browser does and what the stdlib's own
// jar does.

// CookieJar is the redirect chain's view of a cookie store: which cookies to send to one authority,
// and what to remember from a response.
//
// An interface for the reason above, and because a caller that only wants replay OFF must not be forced
// to have a jar at all — nil is a valid CookieJar and means "no cookies are ever replayed", which is
// what an operator who turned the setting off gets.
type CookieJar interface {
	// CookieHeader returns the Cookie header value to present to one request, and whether there is
	// one. False is an ordinary answer: most authorities have no cookies.
	//
	// path is the request's path, and it is a parameter rather than an empty string because a cookie
	// jar scopes by Path: a cookie set with Path=/ does not go to /admin/secret, and asking for
	// "everything this host holds" is the opposite of what the hop's URL says.
	CookieHeader(host string, port uint16, tls bool, path string) (string, bool)
	// AbsorbResponseCookies records the Set-Cookie values a response carried, so a LATER hop to the
	// same authority can present them.
	//
	// The values, not the response and not a re-serialised header block. Handing over bytes would
	// mean every implementation re-parsing them back into the same values, and getting that wrong is
	// silent: a jar that looked for a name the follower had stripped would simply remember nothing,
	// which is the defect this whole path exists to fix (burpsy-react-ui-mr83).
	AbsorbResponseCookies(host string, port uint16, tls bool, setCookie []string)
}

// SetCookieReplay turns cookie replay on or off for every send this sender makes.
//
// Burp's setting is a Repeater preference, and this is where burpsy keeps that preference: on the
// sender, because a send is where the choice is observable, and on RedirectSettings because a chain
// that does not follow redirects has no hop to replay into.
//
// Default is OFF. That is the opposite of a browser's, and it is right here: burpsy is a tool that
// sends what an operator wrote, and a cookie the target set mid-chain is not something the operator
// asked to send. A chain that suddenly carries a credential the operator did not type is the surprise
// this setting exists to prevent, so it is opt-in like Burp's.
func (n *NetworkSettings) SetCookieReplay(on bool) *NetworkSettings {
	n.Redirects.ReplayCookies = on
	return n
}

// cookieHeaderFor builds the Cookie header for one hop's authority from the jar, or "" when there is
// no jar, no setting, or nothing to send.
//
// The three absences are all ordinary answers rather than errors, and keeping them in one function is
// what stops the hop loop from growing a nil check per hop for a case that is the common one.
func cookieHeaderFor(jar CookieJar, replay bool, host string, port uint16, tls bool, path string) string {
	if jar == nil || !replay {
		return ""
	}
	value, ok := jar.CookieHeader(host, port, tls, path)
	if !ok {
		return ""
	}
	return value
}

// applyHopCookies adds the jar's cookies for the hop's authority to the rendered hop request.
//
// It edits the header block in place rather than re-rendering the request, for the same reason the
// proxy's platform-auth insert does: the hop's bytes were already rendered once and the scope gate
// read those exact bytes, so anything that changes them afterwards must be a header the gate can see.
// Here the cookie is added BEFORE the gate — applyHopCookies runs on `candidate` and the render happens
// after — so the authorised bytes and the wire bytes still agree.
//
// A hop that already carries a Cookie header keeps it. An operator who put a cookie in the request by
// hand meant that cookie, and a jar replacing it would be the same silent substitution the proxy's
// platform-auth rule refuses.
func applyHopCookies(rendered []byte, jar CookieJar, replay bool, host string, port uint16, tls bool, path string) []byte {
	header := cookieHeaderFor(jar, replay, host, port, tls, path)
	if header == "" {
		return rendered
	}
	if hasCookieHeader(rendered) {
		return rendered
	}
	return insertHeaderBeforeTerminator(rendered, "Cookie: "+header)
}

// absorbHopCookies records what a hop's response set, so the NEXT hop to the same authority can carry
// it. A jar that is nil, or a chain that arrived with replay off, remembers nothing — the setting
// governs the whole chain rather than each hop, because a chain that replayed nothing on hop one has
// no business replaying on hop three.
//
// The Set-Cookie values are extracted from the parsed Response rather than from its raw bytes, and
// that is not a shortcut. The typed transport path has no byte image to read — core.Response.Raw
// says so itself ("nil here means ask whoever sent it") — so a follower that absorbed from Raw would
// work on the raw-bytes entry point and silently remember nothing on the typed one. The typed
// headers are the fact both paths agree on.
func absorbHopCookies(jar CookieJar, replay bool, host string, port uint16, tls bool, resp *Response) {
	if jar == nil || !replay || resp == nil {
		return
	}
	var values []string
	for name, value := range resp.Headers {
		if strings.EqualFold(name, "Set-Cookie") {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return
	}
	// Map order is not stable, so the values are sorted into a deterministic order before they are
	// handed over. A jar that records "what it was told" would otherwise produce a different order run
	// to run, and a test asserting on that would flake for a reason that has nothing to do with the
	// behaviour under test.
	sort.Strings(values)
	jar.AbsorbResponseCookies(host, port, tls, values)
}

// hasCookieHeader reports whether the rendered request already carries a Cookie header, in any case.
func hasCookieHeader(rendered []byte) bool {
	for _, line := range strings.Split(string(rendered), "\n") {
		field, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(field), "Cookie") {
			return true
		}
		// The head ends at the blank line; a body that happens to contain "Cookie:" is not a header.
		if strings.TrimSpace(line) == "" {
			return false
		}
	}
	return false
}

// insertHeaderBeforeTerminator adds one header line immediately before the blank line that ends the
// head, matching the head's own line ending.
//
// The same operation the proxy's credential insert performs, and for the same reason it is not a text
// replace: the insert point is where the BODY starts, which is not where a header goes, and a header
// spliced at the wrong index lands at the front of the body.
func insertHeaderBeforeTerminator(rendered []byte, header string) []byte {
	eol := "\r\n"
	if strings.Contains(string(rendered), "\n") && !strings.Contains(string(rendered), "\r\n") {
		eol = "\n"
	}
	insertAt := -1
	if head, _, _, ok := httputil.SplitHeadBody([]byte(rendered)); ok {
		insertAt = len(head)
	}
	if insertAt < 0 {
		return rendered
	}
	out := make([]byte, 0, len(rendered)+len(header)+2*len(eol))
	out = append(out, rendered[:insertAt]...)
	out = append(out, []byte(eol+header)...)
	out = append(out, rendered[insertAt:]...)
	return out
}

// httpCookies is the stdlib's shape of the same idea, kept so a caller holding an http.CookieJar can
// satisfy CookieJar without an adapter of its own.
//
// Exported because the Repeater holds a stdlib jar in some wiring and the alternative is a conversion
// in every caller — a conversion that would have to re-implement the attribute rules the stdlib
// already gets right, which is how a Domain=host cookie ends up on a sibling.
type HTTPCookieJar struct {
	Jar http.CookieJar
}

// CookieHeader implements CookieJar.
func (h HTTPCookieJar) CookieHeader(host string, port uint16, tls bool, path string) (string, bool) {
	if h.Jar == nil {
		return "", false
	}
	u := &url.URL{Scheme: schemeFor(tls), Host: hostPortFor(host, port, tls), Path: path}
	cookies := h.Jar.Cookies(u)
	if len(cookies) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), true
}

// AbsorbResponseCookies implements CookieJar.
//
// Each value is turned back into a full response and read with the stdlib's own cookie parser rather
// than parsed here. That is not a roundabout way to reach http.ParseSetCookie: it is the same parse,
// and it is the one that decides whether a Domain or Path attribute makes a cookie eligible for a
// given authority. A hand-written reader would have to re-implement those rules to get scoping right,
// and a scoping bug in a cookie store hands one host's credential to another.
func (h HTTPCookieJar) AbsorbResponseCookies(host string, port uint16, tls bool, setCookie []string) {
	if h.Jar == nil || len(setCookie) == 0 {
		return
	}
	u := &url.URL{Scheme: schemeFor(tls), Host: hostPortFor(host, port, tls)}
	cookies := make([]*http.Cookie, 0, len(setCookie))
	for _, value := range setCookie {
		parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(
			"HTTP/1.1 200 OK\r\nSet-Cookie: "+value+"\r\nContent-Length: 0\r\n\r\n")), nil)
		if err != nil {
			continue
		}
		cookies = append(cookies, parsed.Cookies()...)
	}
	if len(cookies) == 0 {
		return
	}
	h.Jar.SetCookies(u, cookies)
}

func schemeFor(tls bool) string {
	if tls {
		return "https"
	}
	return "http"
}

// requestPathOf is the hop's request target — path plus query — for a cookie jar's Path scoping.
//
// A cookie set with Path=/admin does not go to /other, and a jar asked about "" takes that as "no path
// given" and answers with everything the host holds. So the hop's own target is threaded through
// rather than dropped, and the query rides along because a jar is free to scope on it.
func requestPathOf(req *Request) string {
	if req == nil {
		return "/"
	}
	if req.URL != "" {
		if parsed, err := url.Parse(req.URL); err == nil && parsed.RequestURI() != "" {
			return parsed.RequestURI()
		}
	}
	if req.Path != "" {
		return req.Path
	}
	return "/"
}
