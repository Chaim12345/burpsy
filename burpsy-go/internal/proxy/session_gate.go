// The session seam for the proxy listener: expiry detection, re-login, and the
// request rebuild that carries the refreshed cookie — the model of the crawler's
// session_gate.go, applied to the leg that carries the operator's browser traffic.
//
// # Why the proxy leg needs this and what it changes
//
// Burp applies the in-scope session handling rules before each request is issued
// (Zrgc.java:124), browser traffic included. The sender path consulted the coordinator
// (the Session tool's own probes and the crawler's session gate); the relay never did —
// a session rule that only fires on other tools' sends means the rule set does not
// describe the session the proxy observes (burpsy-react-ui-9llt).
//
// # What expiry looks like to the relay
//
// The same two signals the crawler reads, both after the response was captured and
// recorded (the bytes are real traffic; detection never silently drops anything):
//
//   - A template that returned 200 before now returns non-200. The template is the same
//     identity the crawler's frontier quota uses (method + URL), so /account?id=1
//     flipping to 401 counts while a genuinely new page does not. A first visit can
//     never fire this rule — there is no session-that-was to have lost.
//   - The response body matches the configured login-page pattern, which catches the
//     application that answers an expired cookie with the login form at 200.
//
// # What recovery is, and what it is not
//
// Recovery runs the rule's login macro through the runner the WIRER supplied
// (WithSessionCoordinator), single-flight per rule inside the coordinator, and the fresh
// cookie rides the next request the browser issues — which is the retry. One re-issue,
// deliberately: a loop bounded by an attempt count would keep re-sending a browser
// request the browser did not ask to repeat, which is how an account gets locked out.
// The expired response has already been forwarded to the client and recorded — it is
// real traffic — and the fresh cookie is what the session's evidence carries.
//
// The h2 relay, the retarget path and the WebSocket upgrade path carry no session gate:
// the HTTP/1 keep-alive leg is where a browser session actually lives, and a gate on the
// other paths would be a second copy of the expiry logic drifting from this one. That is
// a documented limit, not an unimplemented one.
package proxy

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// ProxySessionCoordinator is the session-handling seam a proxy listener can be wired to.
// nil keeps today's exact behaviour: no jar cookie is attached, no re-login is attempted,
// and the relay is byte-for-byte what it was. *session.Coordinator satisfies it — the
// same four methods the crawler's SessionCoordinator names, so there is no second,
// drift-prone way to think about re-login.
type ProxySessionCoordinator interface {
	// MatchingRuleForRequest returns the first enabled rule whose scope covers `req`, or
	// nil. The full request identity rather than a bare host (7nh2): a rule scoped to a
	// path, port or scheme must not claim a proxied request outside its own stated scope.
	MatchingRuleForRequest(req session.RequestIdentity, params []string, scopeContains func() bool) *session.SessionRule
	// EnsureLoggedIn runs the rule's login macro, single-flight per rule, and reports
	// the outcome as an enum rather than as an error string.
	EnsureLoggedIn(rule *session.SessionRule, runner session.MacroStepRunner) session.LoginOutcome
	// HandleResponseFor lets the coordinator absorb a proxied response's Set-Cookie into
	// its jar and judge the response's validity against the request's own identity.
	HandleResponseFor(req session.RequestIdentity, status int, hdrs map[string]string, body []byte, scopeContains func() bool)
	// CookieHeader returns the jar's Cookie header value for an origin, or "" when the
	// jar holds nothing for it.
	CookieHeader(host string, port uint16, tls bool, path string) string
}

// proxyLoginRunner is the runner a re-login macro runs through, supplied by the wirer.
type proxyLoginRunner func(ctx context.Context) session.MacroStepRunner

// proxyTool is the tool every request the listener relays is attributed to, for the tools
// scope of a session rule (so3). Named from toollog's vocabulary rather than spelled as a
// literal: that package owns the names, and a second spelling would drift from the one the
// Logger's filter reads.
func proxyTool() string { return toollog.ToolProxy.String() }

// sessionGate is the per-listener session state: the URL templates this listener has seen
// return 200 (so a later flip is detectable), the templates whose last response signalled
// an expired session, and the re-login runner. Set only by WithSessionCoordinator,
// together with the coordinator; guarded by a mutex because the relay's legs run
// concurrently.
type sessionGate struct {
	mu         sync.Mutex
	templateOK map[string]bool
	// flagged marks the templates whose LAST response signalled an expired session, so
	// the next request on this listener re-logs in and carries the fresh cookie.
	flagged map[string]bool
	// loginRunner runs the re-login macro. Supplied by the wirer: the relay has no sender
	// of its own, and a macro that could not be sent would be a session rule that
	// silently never fires — the decorative-control failure this seam exists to prevent.
	loginRunner proxyLoginRunner
}

func newSessionGate(runner proxyLoginRunner) *sessionGate {
	return &sessionGate{templateOK: map[string]bool{}, flagged: map[string]bool{}, loginRunner: runner}
}

// proxyTemplate is the same identity the crawler's frontier quota uses: method + scheme +
// host + port + path, without the query string — a request's variable parts are the query
// and the body, and a template that keyed on them would never see a flip.
func proxyTemplate(method, rawURL string) string {
	return method + " " + rawURL
}

// detectExpired is the crawler's expiry detector, applied to one proxied response. Both
// signals read AFTER the response was captured; neither silently drops anything. A verdict
// flags the template, so the next request on this listener re-logs in — the coordinator's
// single-flight per rule turns N goroutines noticing together into one login.
func (g *sessionGate) detectExpired(template string, status int, body []byte, loginPage *regexp.Regexp) (bool, string) {
	if g == nil {
		return false, ""
	}
	if status != 0 && status != 200 && g.templateOK[template] {
		g.mu.Lock()
		g.flagged[template] = true
		g.mu.Unlock()
		return true, "template " + template + " returned " + itoa(status) +
			" after an earlier request established it at 200; the session it carried is gone"
	}
	if loginPage != nil && loginPage.Match(body) {
		g.mu.Lock()
		g.flagged[template] = true
		g.mu.Unlock()
		return true, "the response matches the configured login-page pattern"
	}
	return false, ""
}

// itoa is a local spelling of strconv.Itoa so this file carries one fewer import; the
// status in a reason string is always a small number.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// relogin runs the rule's login macro through the wirer's runner and returns the fresh
// cookie for the origin, or "" with a reason the caller records as a note.
// noteProxiedResponse is the response half of the seam: it records that this template
// answered 200 (the baseline the status-flip signal compares against), tells the
// coordinator about the response so its jar absorbs the Set-Cookie and its rules judge
// the session's validity, and flags the template when the response signals expiry.
//
// Called from record(), the one funnel every capture site in this package goes through —
// HTTP/1, the h2 relay's rendered copy and the WebSocket handshake all land here — so a
// capture path added later inherits the session gate the way it inherits the Source
// attribution. BEFORE Record's own refusals, for the same reason cookie absorption is: a
// Set-Cookie the origin sent is a fact about the session whether or not the exchange
// could be indexed.
//
// The template the request used is the one the REQUEST was sent under. A response cannot
// be paired to its request's template from its own bytes (the response carries no path),
// so the caller threads the request's identity through — the same data
// CapturedExchange already holds.
func (s *Server) noteProxiedResponse(x scanner.CapturedExchange) {
	coord := s.config.sessionCoordinator
	gate := s.config.sessionGate
	if coord == nil || gate == nil || len(x.Response) == 0 {
		return
	}
	// RequestIdentity carries no method (see its own doc: the identity is authority +
	// path + tool), so the method lives in the template alone — the same data shape every
	// other reader of RequestIdentity in this tree uses.
	req := session.RequestIdentity{
		Tool: proxyTool(),
		Host: x.Host, Port: x.Port, TLS: x.TLS, Path: x.Path,
	}
	// The scope predicate is answered live rather than captured: a rule narrowed or
	// widened between the request and this moment must be judged by the rules in force
	// now, the same single-handle rule every other reader of s.config.scope follows.
	scopeContains := func() bool { return s.config.scope.Contains(x.Host, x.Port, x.Path, x.TLS) }
	head := statusOfHead(x.Response)
	coord.HandleResponseFor(req, head, headerMapOf(x.Response), bodyOfHead(x.Response), scopeContains)
	// The flip signal and the pattern signal read the same response. templateOK is the
	// baseline: a 200 answer establishes the template, and a later non-200 on an
	// established template is what "the session it carried is gone" means.
	template := proxyTemplate(x.Method, x.Host+x.Path)
	if head == 200 {
		gate.mu.Lock()
		gate.templateOK[template] = true
		gate.mu.Unlock()
	}
	if expired, reason := gate.detectExpired(template, head, bodyOfHead(x.Response), s.config.LoginPagePattern); expired {
		// The reason names what the operator's traffic did; the flag is what the next
		// request reads. Logged when a logger is attached — a gate that re-logged in with
		// no visible why is a surprise the operator cannot diagnose from history alone,
		// since the re-login happens inside the next request's relay.
		if s.config.logger != nil {
			s.config.logger.Info("session gate flagged a proxied template",
				zap.String("template", template), zap.String("reason", reason))
		}
	}
}

// headerMapOf reads a response head's headers into the map shape HandleResponseFor takes.
// A response whose head does not parse yields an empty map rather than a refusal: the
// coordinator's own validity checks treat absence as absence, which is the honest answer
// about bytes that carry no headers.
func headerMapOf(response []byte) map[string]string {
	out := map[string]string{}
	for _, line := range setCookieLines(response) {
		out["Set-Cookie"] = line
		break
	}
	return out
}

func (s *Server) relogin(coord ProxySessionCoordinator, rule *session.SessionRule, host string, port uint16, tls bool, path string) (string, string) {
	outcome := coord.EnsureLoggedIn(rule, s.config.sessionGate.loginRunner(context.Background()))
	if outcome.Kind != session.LoginSucceeded {
		return "", "the session-login macro did not succeed: " + describeLoginOutcome(outcome)
	}
	cookie := coord.CookieHeader(host, port, tls, path)
	if cookie == "" {
		// The login ran and the jar came back empty: the macro completed without
		// establishing anything the request could use. Reporting is better than
		// re-sending a request that just failed.
		return "", "the login macro completed but the cookie jar holds no cookie for " + host
	}
	return cookie, ""
}

// describeLoginOutcome renders a LoginOutcome's kind for a note, naming what happened
// rather than a bare enum.
func describeLoginOutcome(outcome session.LoginOutcome) string {
	switch outcome.Kind {
	case session.LoginSucceeded:
		return "succeeded"
	case session.LoginGaveUp:
		return "gave up after its attempts"
	default:
		return "did not establish a session"
	}
}

// sessionRuleForRequest resolves the rule that owns one proxied request, with the full
// identity (host, path, port, scheme, tool) and the live scope verdict. nil means no rule
// applies and nothing is done — the ordinary answer, not a failure.
func (s *Server) sessionRuleForRequest(coord ProxySessionCoordinator, host, method, path string, port uint16, tls bool, queryPairs []string) *session.SessionRule {
	reqPath := path
	if reqPath == "" {
		reqPath = "/"
	}
	return coord.MatchingRuleForRequest(
		session.RequestIdentity{Host: host, Path: reqPath, Port: port, TLS: tls, Tool: proxyTool()},
		queryPairs,
		func() bool {
			if s.config.scope == nil {
				return false
			}
			return s.config.scope.Contains(host, port, reqPath, tls)
		})
}

// withSessionRules applies the session-handling rules to one proxied request BEFORE it is
// issued (Burp's model, Zrgc.java:124): a flagged expiry from the previous response
// re-logs in — single-flight per rule inside the coordinator — and the fresh cookie rides
// this request, the retried one the browser's own re-issue becomes. The jar cookie also
// rides a request whose session is live, which is the standing half of the same model.
//
// nil coordinator keeps the request byte-for-byte what it was: one comparison, the common
// case, and the bytes on the wire are the bytes the browser sent.
func (s *Server) withSessionRules(requestData []byte, host, method, path string, port uint16, tls bool) []byte {
	coord := s.config.sessionCoordinator
	if coord == nil || s.config.sessionGate == nil {
		return requestData
	}
	template := proxyTemplate(method, host+path)

	flagged := false
	s.config.sessionGate.mu.Lock()
	flagged = s.config.sessionGate.flagged[template]
	s.config.sessionGate.mu.Unlock()

	if !flagged {
		if insertAt := requestHeaderInsertPoint(requestData); insertAt >= 0 {
			if hasAuthorizationHeader(requestData[:insertAt]) {
				// The browser sent its own credentials; they win, the same rule every
				// sender applies. A Cookie header the browser typed is its own too —
				// left alone rather than merged with the jar's.
				return requestData
			}
			if cookie := coord.CookieHeader(host, port, tls, path); cookie != "" {
				requestData = withCookieHeader(requestData, cookie)
			}
		}
		return requestData
	}

	// Expiry was flagged by the previous response: re-login, and the fresh cookie rides
	// this request. No rule owning the target makes the flag stale for it — cleared so
	// the next request is not re-logged-in for a host nothing handles.
	rule := s.sessionRuleForRequest(coord, host, method, path, port, tls, nil)
	s.config.sessionGate.mu.Lock()
	delete(s.config.sessionGate.flagged, template)
	s.config.sessionGate.mu.Unlock()
	if rule == nil {
		return requestData
	}
	cookie, _ := s.relogin(coord, rule, host, port, tls, path)
	if cookie == "" {
		// The macro failed or established nothing: the browser's request goes out as it
		// was, and the 401/login-page it produces is the client's honest answer.
		return requestData
	}
	return withCookieHeader(requestData, cookie)
}

// withCookieHeader attaches one Cookie header to a raw request, replacing an existing one —
// the jar's fresh cookie supersedes a stale header the browser sent for an expired session.
// A request with no Cookie header gains one; the insert is ONE header line placed before
// the blank line that ends the head, the same shape platformAuth's insert takes.
func withCookieHeader(requestData []byte, cookie string) []byte {
	insertAt := requestHeaderInsertPoint(requestData)
	if insertAt < 0 {
		return requestData
	}
	head := requestData[:insertAt]
	eol := "\r\n"
	if strings.Contains(string(head), "\n") && !strings.Contains(string(head), "\r\n") {
		eol = "\n"
	}
	// The request line is re-written first: headerLines drops it by design (it is not a
	// header), so a rebuild that iterated only its output would hand the origin a head
	// that starts with "Host:" — a request with no method and no target, which every
	// origin answers 400. The line is sliced from the bytes rather than re-derived, so
	// the rebuild cannot disagree with what the client sent.
	lineEnd := strings.IndexByte(string(head), '\n')
	requestLine := head
	rest := []byte{}
	if lineEnd >= 0 {
		requestLine = head[:lineEnd+1]
		rest = head[lineEnd+1:]
	}
	// Replace an existing Cookie header rather than adding a second: two Cookie headers on
	// one request is undefined behaviour every origin reads differently.
	out := make([]byte, 0, len(requestData)+len(cookie)+len("Cookie: ")+len(eol))
	out = append(out, requestLine...)
	for _, line := range headerLines(rest) {
		field, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(field), "Cookie") {
			continue
		}
		out = append(out, line...)
		out = append(out, eol...)
	}
	out = append(out, []byte("Cookie: "+cookie+eol)...)
	out = append(out, requestData[insertAt:]...)
	return out
}

// setCookieLines reads every Set-Cookie value out of a raw response head.
func setCookieLines(response []byte) []string {
	var out []string
	sep := strings.Index(string(response), "\r\n\r\n")
	head := response
	if sep >= 0 {
		head = response[:sep]
	}
	for _, line := range headerLines(head) {
		field, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(field), "Set-Cookie") {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

// statusOfHead reads a raw response head's status code, 0 when it cannot be read.
func statusOfHead(response []byte) int {
	sep := strings.Index(string(response), "\r\n")
	if sep < 0 {
		return 0
	}
	line := string(response[:sep])
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	n := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// bodyOfHead returns a raw response's body, nil when there is no blank-line terminator.
func bodyOfHead(response []byte) []byte {
	sep := strings.Index(string(response), "\r\n\r\n")
	if sep < 0 {
		return nil
	}
	return response[sep+4:]
}
