package crawler

// The recorded-login seam (burpsy-react-ui-xhtk): a crawl that logs in by replaying a browser
// sequence before its first fetch, carries the session that replay earned on every request, keeps it
// current from the responses, and replays again when the session is lost.
//
// # Why this is not the SessionCoordinator
//
// The coordinator logs in with an HTTP macro and hands back one Cookie header for the retried
// request; ordinary requests never carry it (buildRequest attaches only the operator's static
// Headers). A browser login earns a cookie JAR — several cookies, several domains, path-scoped — and
// the whole point is that every request after it is authenticated. So this seam owns a real jar
// (net/http/cookiejar: RFC 6265 domain, path and Secure matching, the same rules the replay browser
// applied), attaches it in buildRequest, absorbs Set-Cookie from every captured response so a session
// the application rotates is not stranded, and re-runs the replay through the existing expiry
// detection and MaxRelogins budget rather than through a parallel path.
//
// Burp: "You cannot use both authentication methods on a single application", and a recorded login
// replaces the crawl's credential-based login. When both a coordinator and a BrowserLogin are wired,
// recovery uses the BrowserLogin; the coordinator is not consulted for re-login.

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
)

// BrowserLogin replays a recorded login sequence.
type BrowserLogin interface {
	// Label names the sequence for the report.
	Label() string
	// Login replays it and reports the outcome. Called once before the first fetch and once per
	// detected session loss, within Limits.MaxRelogins.
	Login(ctx context.Context) LoginAttempt
}

// LoginCookie is one cookie the replay earned, as the browser stored it.
type LoginCookie struct {
	Name   string
	Value  string
	Domain string
	// HostOnly is a cookie set without a Domain attribute: it goes back to exactly Domain and not to
	// its subdomains. CDP spells this as a Domain without a leading dot.
	HostOnly bool
	Path     string
	Secure   bool
	HTTPOnly bool
}

// LoginAttempt is one replay's outcome.
type LoginAttempt struct {
	Succeeded bool
	// Reason is why it did not succeed — the failed step, the refused status check, the blocked host.
	Reason   string
	FinalURL string
	Cookies  []LoginCookie
	// Blocked are the requests the replay's scope gate refused.
	Blocked []string
}

// LoginReport is the Report's account of a recorded login.
type LoginReport struct {
	// Method is "recorded": the only login this block describes today.
	Method string `json:"method"`
	Label  string `json:"label"`
	// Authenticated is whether the replay before the first fetch logged in. False means the whole
	// crawl ran logged out, and Limits carries StopLoginFailed.
	Authenticated bool `json:"authenticated"`
	// Attempts counts every replay — the initial login plus each re-login.
	Attempts  int `json:"attempts"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	// Relogins counts the replays run because the session was detected as lost.
	Relogins    int    `json:"relogins"`
	LastFailure string `json:"last_failure,omitempty"`
	FinalURL    string `json:"final_url,omitempty"`
	// CookieNames are the names of the cookies the last successful replay earned. Names only: the
	// values are the session.
	CookieNames []string `json:"cookie_names"`
	// Blocked are the requests the replay's scope gate refused, across all attempts (bounded).
	Blocked []string `json:"blocked"`
	// RequestsWithSession counts the crawl requests that carried the login's cookies.
	RequestsWithSession int `json:"requests_with_session"`
}

// maxLoginBlockedReported bounds LoginReport.Blocked.
const maxLoginBlockedReported = 50

// loginState is the crawl's side of a recorded login.
type loginState struct {
	login  BrowserLogin
	jar    *cookiejar.Jar
	report LoginReport
}

// newLoginStateOrNil is nil for a crawl with no recorded login, so every loginState method's nil
// receiver is the "no login" case and the call sites need no branch.
func newLoginStateOrNil(l BrowserLogin) *loginState {
	if l == nil {
		return nil
	}
	return newLoginState(l)
}

func newLoginState(l BrowserLogin) *loginState {
	return &loginState{login: l, report: LoginReport{
		Method: "recorded", Label: l.Label(), CookieNames: []string{}, Blocked: []string{},
	}}
}

// attempt runs one replay and, on success, replaces the jar with what it earned. A failed re-login
// keeps the previous jar: it is no worse than nothing, and the expired response that triggered the
// re-login is already recorded as such.
func (s *loginState) attempt(ctx context.Context, relogin bool) LoginAttempt {
	a := s.login.Login(ctx)
	s.report.Attempts++
	if relogin {
		s.report.Relogins++
	}
	for _, b := range a.Blocked {
		if len(s.report.Blocked) >= maxLoginBlockedReported {
			break
		}
		if !loginHasString(s.report.Blocked, b) {
			s.report.Blocked = append(s.report.Blocked, b)
		}
	}
	if !a.Succeeded {
		s.report.Failed++
		s.report.LastFailure = a.Reason
		return a
	}
	s.report.Succeeded++
	s.report.FinalURL = a.FinalURL
	jar, _ := cookiejar.New(nil)
	names := make([]string, 0, len(a.Cookies))
	for _, c := range a.Cookies {
		domain := strings.TrimPrefix(c.Domain, ".")
		if domain == "" {
			continue
		}
		scheme := "http"
		if c.Secure {
			scheme = "https"
		}
		hc := &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Secure: c.Secure, HttpOnly: c.HTTPOnly}
		if !c.HostOnly {
			hc.Domain = domain
		}
		jar.SetCookies(&url.URL{Scheme: scheme, Host: domain, Path: "/"}, []*http.Cookie{hc})
		if !loginHasString(names, c.Name) {
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	s.jar = jar
	s.report.CookieNames = names
	return a
}

// cookieFor is the Cookie header value the jar holds for u, or "".
func (s *loginState) cookieFor(u *url.URL) string {
	if s == nil || s.jar == nil {
		return ""
	}
	cookies := s.jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// absorb takes the Set-Cookie headers of one captured response into the jar, so a session the
// application rotates on every response stays current. rawResponse is the whole response as captured;
// only its head is parsed.
func (s *loginState) absorb(u *url.URL, rawResponse []byte) {
	if s == nil || s.jar == nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rawResponse)), nil)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	if cookies := resp.Cookies(); len(cookies) > 0 {
		s.jar.SetCookies(u, cookies)
	}
}

func loginHasString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// loginBeforeCrawl runs the initial replay. A failure is recorded as StopLoginFailed and the crawl
// proceeds unauthenticated, as Burp's does.
func (c *Crawler) loginBeforeCrawl(ctx context.Context, rep *Report, lim *LimitReport) {
	if c.login == nil {
		return
	}
	a := c.login.attempt(ctx, false)
	c.login.report.Authenticated = a.Succeeded
	if !a.Succeeded {
		lim.record(StopLoginFailed)
	}
}

// reloginWithBrowser is recoverSession's recorded-login branch: one replay within the budget, and the
// item's request rebuilt from the refreshed jar.
func (c *Crawler) reloginWithBrowser(ctx context.Context, item frontierItem, lim *LimitReport) ([]byte, recoverResult, string) {
	if c.relogins >= c.limits.MaxRelogins {
		lim.record(StopReloginBudget)
		return nil, reloginBudgetSpent, "the re-login budget is spent; this request cannot be retried with a fresh session"
	}
	c.relogins++
	a := c.login.attempt(ctx, true)
	if !a.Succeeded {
		return nil, reloginFailed, "the recorded login did not log in again: " + a.Reason
	}
	if c.login.cookieFor(item.url) == "" {
		return nil, reloginFailed, "the recorded login succeeded but earned no cookie for " + item.url.Host
	}
	return c.buildRequest(item), recovered, ""
}
