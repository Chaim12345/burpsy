// The session seam for an authenticated crawl: expiry detection, re-login, and the
// per-crawl budget that binds sequential waves of expiry.
//
// # Why this is an interface, not a *session.Coordinator field
//
// *session.Coordinator satisfies the interface, and a nil field keeps today's exact
// static-Headers behaviour — that is the backwards-compatibility argument, and it has
// to be provable rather than assumed. Every test that runs a crawl without a
// coordinator runs the same code paths a coordinator-less production crawl runs.
//
// # What expiry looks like to this package
//
// Two signals, both read *after* the response was captured and scanned (CRAWL-02 has
// already stored the bytes; detection never silently drops anything):
//
//   - A template that returned 200 before now returns non-200. "Template" is the same
//     identity the frontier quota uses (urlTemplate), so /account?id=1 flipping to
//     401 counts while a genuinely new page does not. A first visit can never fire
//     this rule — there is no session-that-was to have lost.
//   - The response body matches Config.LoginPagePattern. This catches the application
//     that answers an expired cookie with the login form *at 200*, which the status
//     rule cannot see.
//
// # What recovery is, and what it is not
//
// Recovery runs the rule's login macro (single-flight per rule inside the coordinator,
// so N crawler goroutines noticing expiry together fire one login), then rebuilds the
// original request carrying the refreshed jar's cookie and sends it exactly once more
// through the same AuthorisedSender — the retried bytes are re-authorised like any
// other. The retried response then travels the ordinary pipeline: capture, scan,
// fingerprint, admit links. The expired response stays in history (it is real traffic
// and CRAWL-02 captured it) but is not fingerprinted as a location and its links are
// not followed — it is a login page, not application content.
//
// # The re-login budget
//
// Every successful re-login costs the target traffic and every failure costs repeated
// login-page fetches, so both are bounded by Limits.MaxRelogins. The budget is a
// generation counter on the Crawler — sequential waves of expiry (login expires,
// relogin, expires again) count the same as concurrent ones. Running out is a
// StopReason (StopReloginBudget) like every other bound: the crawl is truncated, the
// frontier stays non-empty, and Report says which bound did it.
package crawler

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// crawlTool is the tool every request this crawl makes is attributed to, for the tools scope of a
// session rule (so3). Named from toollog's vocabulary rather than spelled as a literal here: that
// package owns the names, and a second spelling would drift from the one the Logger's filter and the
// rule editor both offer.
func crawlTool() string { return toollog.ToolCrawler.String() }

// SessionCoordinator is the session-handling seam a crawl can be wired to. nil keeps
// the static-Headers behaviour unchanged; *session.Coordinator satisfies it.
//
// The methods are the four the recovery path needs, the same four the web surface
// already uses — a coordinator wired for proxied traffic is wired for the crawl the
// same way, so there is no second, drift-prone way to think about re-login.
type SessionCoordinator interface {
	// MatchingRuleForRequest returns the first enabled rule whose URL scope covers `req`, or
	// nil. The request identity rather than a bare host (7nh2): a rule scoped to a path, port
	// or scheme must not claim a crawl item outside its own stated scope, and a host-only
	// lookup cannot tell the difference. params is nil here — a crawl item has a method and a
	// URL, not a parsed parameter set, and MatchParams reads nil as "unknown" rather than as
	// "carries none".
	MatchingRuleForRequest(req session.RequestIdentity, params []string, scopeContains func() bool) *session.SessionRule
	// EnsureLoggedIn runs the rule's login macro, single-flight per rule, and reports
	// the outcome as an enum rather than as an error string.
	EnsureLoggedIn(rule *session.SessionRule, runner session.MacroStepRunner) session.LoginOutcome
	// HandleResponseFor lets the coordinator absorb a macro step's Set-Cookie into its
	// jar, exactly as the web surface's runner does, and judge the step's validity against
	// the step's own request identity — path, port, scheme and the tool that sent it (so3) —
	// rather than its host alone.
	HandleResponseFor(req session.RequestIdentity, status int, hdrs map[string]string, body []byte, scopeContains func() bool)
	// CookieHeader returns the jar's Cookie header value for an origin, or "" when
	// the jar holds nothing for it.
	CookieHeader(host string, port uint16, tls bool, path string) string
}

// loggedOut is the expiry detector's verdict for one response.
type loggedOut struct {
	yes    bool
	reason string
}

// detectExpired decides whether a captured response tells this crawl that the session
// it authenticates with is gone.
//
// Rule 1 (template flip): `template` has previously been seen at 200 and this response
// to the same template is not 200. A first-visit non-200 is never reported as expiry.
//
// Rule 2 (login page): cfg.LoginPagePattern is set and matches `body`. The pattern is
// compiled in New, so a malformed one is a construction error, never a per-URL surprise.
func (c *Crawler) detectExpired(template string, status int, body []byte) loggedOut {
	if c.cfg.SessionCoordinator == nil {
		return loggedOut{yes: false}
	}
	if status != 0 && status != 200 && c.templateOK[template] {
		return loggedOut{yes: true, reason: fmt.Sprintf(
			"template %q returned %d after an earlier request established it at 200; the session it carried is gone", template, status)}
	}
	if c.loginPage != nil && c.loginPage.Match(body) {
		return loggedOut{yes: true, reason: "the response matches the configured login-page pattern"}
	}
	return loggedOut{yes: false}
}

// recoverResult is the outcome of one recovery attempt. It is an enum rather than a
// bool so the caller can record the right skip reason — a spent budget and a failed
// macro read very differently in a report — without inspecting a detail string.
type recoverResult int

const (
	// recovered means the login macro succeeded and raw is the request rebuilt to carry
	// the refreshed cookie, ready to retry through the chokepoint.
	recovered recoverResult = iota
	// reloginBudgetSpent means MaxRelogins attempts are already used; no macro was run
	// this time and StopReloginBudget has been recorded. The crawl is truncated.
	reloginBudgetSpent
	// reloginFailed means a recovery was attempted and could not restore the session:
	// no rule covers the host, the macro failed, or it succeeded but the jar stayed
	// empty. Nothing was refused — a recovery was tried and did not take.
	reloginFailed
)

// recoverSession restores the session for one item and rebuilds the request to retry.
//
// On recovered it returns the rebuilt request bytes, which the caller sends through the
// same AuthorisedSender as the original — the retried bytes are re-authorised like any
// other request, so a refreshed cookie cannot widen the crawl's scope. On the two
// failure results raw is nil and detail is the one-line reason for the skip ledger.
//
// The budget is checked, and the attempt counted, before the macro runs: the counter
// is a generation counter (Crawler.relogins), so sequential waves of expiry — login
// dies, relogin, dies again — draw down the same MaxRelogins budget as concurrent ones
// would, and running out records StopReloginBudget so the crawl reports as truncated
// rather than as quietly unauthenticated.
func (c *Crawler) recoverSession(ctx context.Context, item frontierItem, lim *LimitReport) (raw []byte, result recoverResult, detail string) {
	host := item.url.Hostname()
	// The full identity, not the hostname: a rule scoped to a path or port must not be the rule
	// that fires a login macro for a crawl item its own editor excludes (7nh2). The suite-scope
	// verdict is this crawl's own scope handle, read live.
	// The tool too (so3): these are the crawler's own requests, so a rule the operator restricted
	// to another tool must not re-login on the crawl's behalf — and one restricted to the crawler
	// must, even though it names no host.
	rule := c.cfg.SessionCoordinator.MatchingRuleForRequest(
		session.RequestIdentity{
			Host: host,
			Path: item.url.EscapedPath(),
			Port: portOf(item.url),
			TLS:  strings.EqualFold(item.url.Scheme, "https"),
			Tool: crawlTool(),
		},
		nil,
		func() bool {
			if c.cfg.Scope == nil {
				return false
			}
			return c.cfg.Scope.Contains(host, portOf(item.url), item.url.EscapedPath(), strings.EqualFold(item.url.Scheme, "https"))
		})
	if rule == nil {
		return nil, reloginFailed, "no session rule covers " + item.url.String()
	}
	if c.relogins >= c.limits.MaxRelogins {
		lim.record(StopReloginBudget)
		return nil, reloginBudgetSpent, fmt.Sprintf(
			"the re-login budget of %d is spent; this request cannot be retried with a fresh session", c.limits.MaxRelogins)
	}
	c.relogins++
	outcome := c.cfg.SessionCoordinator.EnsureLoggedIn(rule, c.crawlSessionRunner(ctx))
	if outcome.Kind != session.LoginSucceeded {
		return nil, reloginFailed, "the session-login macro did not succeed: " + describeLogin(outcome)
	}

	tls := strings.EqualFold(item.url.Scheme, "https")
	cookie := c.cfg.SessionCoordinator.CookieHeader(host, portOf(item.url), tls, item.url.Path)
	if cookie == "" {
		// The login ran and the jar came back empty: the macro completed without
		// establishing anything the request could use. Retrying with no cookie is
		// retrying a request that just failed; reporting is better than looping.
		return nil, reloginFailed, "the login macro completed but the cookie jar holds no cookie for " + host
	}
	rebuilt := c.buildRequestWithCookie(item, cookie)
	return rebuilt, recovered, ""
}

// handleExpired reacts to a captured response the detector judged to be a login page.
//
// It attempts one recovery and, on success, re-sends the original request with the
// refreshed cookie through the ordinary pipeline (perform), where the retry is captured,
// scanned, fingerprinted and traversed like any first attempt. If the retry is itself a
// login page — the session died again the instant it was restored — detection fires once
// more inside that perform call and draws down the same re-login budget, so a target that
// keeps logging the crawl out is bounded by MaxRelogins rather than looping.
//
// On the two give-up results nothing is retried and the login page's links stay
// unfollowed: a spent budget is SkipSessionExpired (the crawl is now unauthenticated and
// StopReloginBudget already names the truncation), and a failed recovery is
// SkipReloginFailed (a macro-level reason the operator can act on). Every path records
// exactly one skip, so a login page is never silently dropped.
func (c *Crawler) handleExpired(ctx context.Context, item frontierItem, verdict loggedOut, rep *Report, lim *LimitReport) {
	rebuilt, result, detail := c.recoverSession(ctx, item, lim)
	// The consecutive authentication-failure streak the pause policy reads (o0c5): a failed re-login
	// extends it, a restored session ends it. A spent budget is not counted — the crawl did not try.
	switch result {
	case recovered:
		c.noteAuth(true)
	case reloginFailed:
		c.noteAuth(false)
	}
	switch result {
	case recovered:
		c.perform(ctx, item, rebuilt, rep, lim)
	case reloginBudgetSpent:
		c.skips.record(SkipRecord{
			Reason: SkipSessionExpired, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt, Detail: verdict.reason + "; " + detail,
		})
	case reloginFailed:
		c.skips.record(SkipRecord{
			Reason: SkipReloginFailed, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt, Detail: verdict.reason + "; " + detail,
		})
	}
}

// describeLogin renders a LoginOutcome as one line for the skip ledger.
func describeLogin(o session.LoginOutcome) string {
	switch o.Kind {
	case session.LoginSucceeded:
		return fmt.Sprintf("succeeded in %d attempts", o.Attempts)
	case session.LoginGaveUp:
		return fmt.Sprintf("gave up after %d attempts", o.Attempts)
	case session.LoginMacroFailed:
		if o.Failure != nil {
			return o.Failure.String()
		}
		return "the macro failed"
	}
	return "unknown outcome"
}

// crawlSessionRunner is the session package's MacroStepRunner seam bound to this
// crawl's own scope and sender: it sends one macro step through an AuthorisedSender
// for that step's authority and absorbs Set-Cookie into the coordinator's jar.
//
// Mirrors the web surface's runner (internal/web/api_session.go) for exactly the
// reason that one documents: the login probe, the recovery macro it triggers and the
// manual "run macro" button must behave identically, and the crawl is a fourth
// surface with the same requirement. Every step leaves through the chokepoint, so a
// macro pointed outside the engagement — by a typo or a stale saved rule — is refused
// before the dial, and the refusal surfaces as a failed login rather than as
// credentials sent to the wrong host.
func (c *Crawler) crawlSessionRunner(ctx context.Context) session.MacroStepRunner {
	return func(step session.MacroStep) (*session.StepResult, error) {
		u, err := url.Parse(step.URL)
		if err != nil {
			return nil, err
		}
		host := u.Hostname()
		tls := strings.EqualFold(u.Scheme, "https")
		port := portOf(u)
		path := u.RequestURI()
		if path == "" {
			path = "/"
		}
		req := &sender.Request{
			Method:  step.Method,
			Host:    host,
			Path:    path,
			Headers: map[string]string{"Host": host},
			Body:    []byte(step.Body),
			TLS:     tls,
			Port:    port,
		}
		for k, v := range step.Headers {
			req.Headers[k] = v
		}
		// The coordinator attaches the jar's cookie to a step it owns; only fill one in
		// when the step did not carry one, matching the web runner.
		if _, has := req.Headers["Cookie"]; !has {
			if cookie := c.cfg.SessionCoordinator.CookieHeader(host, port, tls, req.Path); cookie != "" {
				req.Headers["Cookie"] = cookie
			}
		}
		// The engagement scope, not this crawl's narrower prefixes (501u): a login page outside the
		// directory being crawled must still be reachable to restore the session.
		resp, err := sender.NewAuthorisedSender(engagementScope(c.cfg.Scope), c.cfg.Sender, host, port, tls).SendRequest(ctx, req)
		if err != nil {
			return nil, err
		}
		hdrs := make(map[string]string, len(resp.Headers))
		for k, v := range resp.Headers {
			hdrs[k] = v
			if strings.EqualFold(k, "Set-Cookie") {
				c.cfg.SessionCoordinator.HandleResponseFor(
					session.RequestIdentity{Host: host, Path: stepPath(step.URL), Port: port, TLS: tls, Tool: crawlTool()},
					resp.StatusCode, map[string]string{"Set-Cookie": v}, resp.Body, nil)
			}
		}
		return &session.StepResult{Status: resp.StatusCode, Headers: hdrs, Body: resp.Body}, nil
	}
}

// stepPath is the path a macro step's URL names, for the URL-scope axes the coordinator matches a
// step's response on (7nh2).
//
// "/" when the URL states no path — that is what an absent path means in HTTP, and it means a rule
// scoped to "/api" does not claim a step that names the bare origin. A URL that will not parse
// yields "/" for the same reason: the honest answer is "this step's path is unknown", and an
// unknown path must not satisfy a path-scoped rule.
func stepPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// buildRequestWithCookie is buildRequest with one addition: a Cookie header written
// after the operator headers, replacing any static Cookie among them. Used for the
// retry after a re-login, where the refreshed jar's cookie is the whole point of the
// new request.
func (c *Crawler) buildRequestWithCookie(item frontierItem, cookie string) []byte {
	raw := c.buildRequest(item)
	if cookie == "" {
		return raw
	}
	lines := strings.Split(string(raw), "\r\n")
	var out strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "cookie:") {
			continue
		}
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	// Rebuild the head so the injected header lands before the blank line. Simpler and
	// just as correct: strip any existing Cookie (done above), then splice the fresh
	// one before the final blank line, which is where buildRequest's own operators
	// headers live.
	return []byte(strings.Replace(strings.TrimSuffix(out.String(), "\r\n"), "\r\n\r\n", "\r\nCookie: "+cookie+"\r\n\r\n", 1))
}
