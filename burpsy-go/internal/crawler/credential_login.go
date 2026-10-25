package crawler

// Application-login credentials (burpsy-react-ui-uzil). Burp's login-functions model: the crawl
// discovers the application's own login form — an input type=password with a non-empty name —
// and logs in with each provided username/password pair in turn, then crawls the content behind
// the login carrying the session it earned.
//
// # Why this rides the frontier instead of a side channel
//
// A credential login IS a form submission: same urlencoded POST, same scope gate, same rate
// limit, same capture (CRAWL-02). Building it as frontier items keeps every one of those
// properties and gives the run's history one honest account of what was sent. What differs from
// an ordinary submission is three things:
//
//   - The values are the configured credentials, not the placeholder fill an ordinary form gets.
//   - The response's Set-Cookie is harvested into the crawl's session jar, the same jar a
//     recorded login maintains, so every later request carries the session (buildRequest).
//   - The STORED exchange masks the credential values (maskValues on the item): the bytes on the
//     wire carry them, the bytes history keeps do not. This is the bead's "never logged/stored
//     beyond the run's need" condition applied to the exchange store, on the HeadersWithheld
//     precedent — the secret reaches the target and nothing else.
//
// # Sequential credentials, one crawl
//
// With several credentials the login form is submitted once per credential, in order, inside
// the one crawl; each successful login's jar replaces the previous one, so the frontier drains
// under each session in turn. What this is NOT: per-credential frontier isolation (which pages
// were reached under which session). That is its own follow-up bead, deliberately — the
// bookkeeping it needs (per-session frontiers) is a larger change than the login itself.
//
// # What session loss does
//
// A credential session installs the same loginState a recorded login does, with a formLogin as
// its BrowserLogin: the session-expiry detector's re-login re-sends the form submission through
// the ordinary send-and-capture path and harvests the fresh cookie. One pipeline, one report.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// maskedPlaceholder is what the stored exchange carries in place of each credential value. The
// tool's own name, like the form filler: an operator who finds it in history knows what wrote it.
const maskedPlaceholder = "burpsy-masked"

// maskStoredValues returns the request bytes as history may keep them: every occurrence of each
// secret — raw and urlencoded, since a urlencoded body carries the encoded form — replaced by
// the placeholder. The wire bytes are built from the unmasked item; only the stored copy passes
// through here.
func maskStoredValues(raw []byte, secrets []string) []byte {
	if len(secrets) == 0 {
		return raw
	}
	out := raw
	for _, s := range secrets {
		if s == "" {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(s), []byte(maskedPlaceholder))
		if enc := url.QueryEscape(s); enc != s {
			out = bytes.ReplaceAll(out, []byte(enc), []byte(maskedPlaceholder))
		}
	}
	return out
}

// admitCredentialLogins enqueues one login submission per configured credential for a form the
// discovery pass identified as a login form, in place of the ordinary placeholder submission.
// Every refusal the ordinary path already made (method, enctype, destructive intent, scope at
// enqueue) still applies: this runs after those checks, and enqueue applies its own.
func (c *Crawler) admitCredentialLogins(f discoveredForm, base, u *url.URL, depth int, rep *Report, lim *LimitReport) {
	if f.method == "GET" {
		// A GET submission puts the form data set in the URL, and the URL is in every log,
		// history row and Referer the request ever touches. Credentials do not go in URLs.
		c.skips.record(SkipRecord{
			Reason: SkipFormNotSubmittable, URL: u.String(), Method: f.method, Text: f.label,
			FoundAt: base.String(),
			Detail:  "a login form that submits GET would place the credentials in the URL; not submitted",
		})
		return
	}
	for i, cred := range c.cfg.LoginCredentials {
		values := url.Values{}
		mappedUser, mappedPass := false, false
		for _, fl := range f.fields {
			v := fl.value
			switch fl.name {
			case f.passwordField:
				v = cred.Password
				mappedPass = true
			case f.usernameField:
				v = cred.Username
				mappedUser = true
			}
			values.Add(fl.name, v)
		}
		if !mappedPass {
			// Discovery marked the form on a named password input, so this cannot happen; if a
			// future edit breaks that invariant, sending the password nowhere is the safe answer.
			c.skips.record(SkipRecord{
				Reason: SkipFormNotSubmittable, URL: u.String(), Method: f.method, Text: f.label,
				FoundAt: base.String(),
				Detail:  "login form has no named password field to carry the credential",
			})
			return
		}
		if !mappedUser && f.usernameField == "" && cred.Username != "" {
			// No text field accompanies the password one (a password-only form, e.g. a PIN
			// gate). The password still maps; the username has nowhere to go and is not sent.
			c.skips.record(SkipRecord{
				Reason: SkipFormNotSubmittable, URL: u.String(), Method: f.method, Text: f.label,
				FoundAt: base.String(),
				Detail: fmt.Sprintf("credential %d's username has no text field to map onto; "+
					"only the password was sent", i+1),
			})
			// Not a refusal of the submission itself: the password still maps.
		}
		item := frontierItem{
			url: u, method: f.method, depth: depth, foundAt: base.String(), text: f.label,
			body:        []byte(values.Encode()),
			contentType: "application/x-www-form-urlencoded",
			// The stored copy of this request masks both values; the wire copy carries them.
			maskValues: []string{cred.Username, cred.Password},
			loginCred:  cred.Username,
		}
		for _, fl := range f.fields {
			item.fieldNames = append(item.fieldNames, fl.name)
		}
		if c.enqueue(item, base.String(), lim) {
			rep.FormsSubmitted++
		}
	}
}

// completeCredentialLogin harvests the session a login submission earned. Called from perform
// after the exchange is captured, so a failed login's exchange is still history (CRAWL-02) and
// only the session accounting lives here.
func (c *Crawler) completeCredentialLogin(item frontierItem, rawResponse []byte, rep *Report, lim *LimitReport) {
	cookies := cookiesFromRawResponse(item.url, rawResponse)
	st := c.login
	if st == nil || st.report.Method != "credentials" {
		// The first credential login of this crawl. Replaces any recorded-login state only in a
		// configuration that has both — one auth method per scan, Burp's own rule, and Config's
		// BrowserLogin wins by having run first; a crawl with both is a configuration error New
		// refuses, so this branch is the credentials-only case.
		st = &loginState{report: LoginReport{Method: "credentials", CookieNames: []string{}, Blocked: []string{}, RenderBlocked: []string{}}}
		c.login = st
		c.credLoginLocationBase = len(c.locations)
	}
	st.report.Attempts++
	if len(cookies) == 0 {
		st.report.Failed++
		st.report.LastFailure = "the login response set no session cookie"
		return
	}
	st.report.Succeeded++
	st.report.Authenticated = true
	st.report.Label = item.loginCred
	// The session swap: this credential's jar replaces the previous credential's, so the
	// frontier drains under each session in turn (the sequential model the file docs describe).
	jar, _ := cookiejar.New(nil)
	hc := make([]*http.Cookie, 0, len(cookies))
	names := make([]string, 0, len(cookies))
	for _, lc := range cookies {
		hc = append(hc, &http.Cookie{Name: lc.Name, Value: lc.Value, Path: lc.Path})
		if !loginHasString(names, lc.Name) {
			names = append(names, lc.Name)
		}
	}
	jar.SetCookies(&url.URL{Scheme: item.url.Scheme, Host: item.url.Host, Path: "/"}, hc)
	st.jar = jar
	st.report.CookieNames = names
	st.report.FinalURL = item.url.String()
	// Session loss after a credential login re-sends this same submission: the formLogin is the
	// BrowserLogin the session gate's re-login path already knows how to run.
	st.login = &formLogin{
		label: item.loginCred,
		send:  c.credentialLoginSend(item, rep, lim),
	}
}

// formLogin is the BrowserLogin a credential session re-logs-in through: its "replay" is the
// form submission, sent again through the same chokepoint and capture as any crawl request.
type formLogin struct {
	label string
	send  func(ctx context.Context) LoginAttempt
}

func (f *formLogin) Label() string { return f.label }

func (f *formLogin) Login(ctx context.Context) LoginAttempt { return f.send(ctx) }

// credentialLoginSend re-sends one credential submission and reports the outcome as a
// LoginAttempt, so loginState.attempt's jar refill and counters work unchanged. The re-send is
// captured like the original (masked); a capture failure does not fail the login — the session
// the target granted is real whether or not history could keep the exchange — but it counts
// against the run's Failed total, as any uncaptured fetch does.
func (c *Crawler) credentialLoginSend(item frontierItem, rep *Report, lim *LimitReport) func(ctx context.Context) LoginAttempt {
	return func(ctx context.Context) LoginAttempt {
		raw := c.buildRequest(item)
		as := c.senderFor(item.url)
		global := c.limiter.Acquire()
		host := c.limiterFor(item.url).Acquire()
		res, err := as.Send(ctx, raw)
		host.Release()
		global.Release()
		if err != nil {
			return LoginAttempt{Reason: "the login re-send failed: " + err.Error()}
		}
		if len(res.Raw) > c.limits.MaxCaptureBytes {
			rep.NotCaptured++
			lim.record(StopCaptureBytes)
		} else if _, cerr := c.cfg.Capture.Record(scanner.CapturedExchange{
			Host:     item.url.Hostname(),
			Port:     portOf(item.url),
			TLS:      strings.EqualFold(item.url.Scheme, "https"),
			Method:   item.method,
			Path:     item.url.RequestURI(),
			Request:  maskStoredValues(raw, item.maskValues),
			Response: res.Raw,
			Started:  time.Now().Add(-res.Duration),
			Duration: res.Duration,
			Protocol: core.ProtocolHTTP1,
			ServerIP: res.Outcome.ServerIP,
			Source:   c.captureSource(),
		}); cerr != nil {
			rep.Failed++
		} else {
			rep.Fetched++
		}
		cookies := cookiesFromRawResponse(item.url, res.Raw)
		if len(cookies) == 0 {
			return LoginAttempt{Reason: "the login response set no session cookie"}
		}
		return LoginAttempt{Succeeded: true, Cookies: cookies, FinalURL: item.url.String()}
	}
}

// cookiesFromRawResponse parses the Set-Cookie headers of one raw response into LoginCookies,
// defaulting the absent Domain to the serving host (host-only, RFC 6265) and the absent Path to
// "/" — close to the RFC's default-path rule for the login endpoints this sees, which answer at
// their own path or redirect from it.
func cookiesFromRawResponse(u *url.URL, rawResponse []byte) []LoginCookie {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rawResponse)), nil)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()
	set := resp.Cookies()
	if len(set) == 0 {
		return nil
	}
	out := make([]LoginCookie, 0, len(set))
	for _, sc := range set {
		lc := LoginCookie{
			Name: sc.Name, Value: sc.Value, Domain: sc.Domain,
			Path: sc.Path, Secure: sc.Secure, HTTPOnly: sc.HttpOnly,
		}
		if lc.Domain == "" {
			lc.Domain = u.Hostname()
			lc.HostOnly = true
		} else {
			lc.Domain = strings.TrimPrefix(lc.Domain, ".")
		}
		if lc.Path == "" {
			lc.Path = "/"
		}
		out = append(out, lc)
	}
	return out
}
