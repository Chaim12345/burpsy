package session

// What a run-macro action does to the current request once the macro has run (burpsy-react-ui-8gk8),
// Burp's "Run a macro" editor (session-handling-rules.html, "Run a macro to obtain a new valid
// session"):
//
//	"Once the macro has run, you can select whether Burp should update the current request with
//	parameters matched from the final macro response. You can also select whether Burp should
//	update the current request with cookies from the session handling cookie jar. Burp can either
//	update the request using specific parameters and cookies, or update using all parameters and
//	cookies except those specified."
//
// and "Tolerate URL mismatch when matching parameters": normally a parameter derived from the final
// response is matched by name AND by the URL the response points it at (the form's action, the
// link's target); tolerating the mismatch matches by name alone, for a CSRF token that is valid
// anywhere in the application.
//
// Parameters are derived from the final response's HTML: every named field of every form (input,
// textarea, select) against that form's action, and every query parameter of every link (a, link,
// area href; form action) against the link's target. Only parameters the current request already
// carries are updated, in the query string and in an application/x-www-form-urlencoded body; the
// request's shape is never extended.
//
// Cookies are a filter on the jar for the re-sent request only. Macro steps keep the whole jar,
// which is what a login flow needs.

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

const (
	matchAllParamsExcept   = "all_params_except"
	matchSpecifiedParams   = "specified_params"
	matchAllCookiesExcept  = "all_cookies_except"
	matchSpecifiedCookies  = "specified_cookies"
	maxDerivedParamBodyLen = 1 << 20
)

// validateMacroUpdate refuses run-macro update fields that are malformed, or set on any other kind.
func validateMacroUpdate(a *Action, path string) error {
	set := a.UpdateWithParams || a.MatchParams != "" || len(a.Params) > 0 || a.TolerateURLMismatch ||
		a.UpdateWithCookies != nil || a.MatchCookies != "" || len(a.Cookies) > 0
	if !set {
		return nil
	}
	if a.Kind != ActionRunMacro {
		return fmt.Errorf("%s (%s): update_with_params, match_params, params, tolerate_url_mismatch, "+
			"update_with_cookies, match_cookies and cookies belong to a run-macro action", path, ActionKindLabel(a.Kind))
	}
	switch a.MatchParams {
	case "", matchAllParamsExcept, matchSpecifiedParams:
	default:
		return fmt.Errorf("%s (%s): match_params must be %s or %s, got %q",
			path, ActionKindLabel(a.Kind), matchAllParamsExcept, matchSpecifiedParams, a.MatchParams)
	}
	switch a.MatchCookies {
	case "", matchAllCookiesExcept, matchSpecifiedCookies:
	default:
		return fmt.Errorf("%s (%s): match_cookies must be %s or %s, got %q",
			path, ActionKindLabel(a.Kind), matchAllCookiesExcept, matchSpecifiedCookies, a.MatchCookies)
	}
	for _, list := range [][]string{a.Params, a.Cookies} {
		for _, name := range list {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("%s (%s): a parameter or cookie name in the list is empty", path, ActionKindLabel(a.Kind))
			}
		}
	}
	return nil
}

// nameAllowed applies an only/except list: specified mode allows exactly the names listed, the
// default allows every name not listed.
func nameAllowed(name, mode, specified string, list []string) bool {
	listed := false
	for _, n := range list {
		if n == name {
			listed = true
			break
		}
	}
	if mode == specified {
		return listed
	}
	return !listed
}

// cookieScope is a run-macro action's jar-cookie choice for the re-sent request.
type cookieScope struct {
	// off is "Update current request with cookies from session handling cookie jar" turned off: the
	// request keeps its own Cookie header and gets nothing from the jar.
	off   bool
	mode  string
	names []string
}

// scopeFor is the action's cookie choice, or nil when the action states none (the whole jar).
func scopeFor(a *Action) *cookieScope {
	if a.UpdateWithCookies != nil && !*a.UpdateWithCookies {
		return &cookieScope{off: true}
	}
	if a.MatchCookies == matchSpecifiedCookies || len(a.Cookies) > 0 {
		return &cookieScope{mode: a.MatchCookies, names: a.Cookies}
	}
	return nil
}

// updateFromMacro applies the run-macro action's update choices after a successful macro.
func (w *actionWalk) updateFromMacro(a *Action, outcome LoginOutcome) {
	if scope := scopeFor(a); scope != nil {
		w.cookieScope = scope
	} else {
		w.cookieScope = nil
	}
	if !a.UpdateWithParams {
		return
	}
	if outcome.Final == nil {
		w.record(a.Kind, "no final macro response to derive parameters from", false)
		return
	}
	base := outcome.Final.FinalURL
	if base == "" {
		base = outcome.FinalStepURL
	}
	derived := deriveParams(outcome.Final.Body, base)
	before := cloneMacroStep(w.request)
	next, updated := updateRequestParams(w.request, derived, a)
	w.request = next
	if len(updated) == 0 {
		w.record(a.Kind, fmt.Sprintf("updated no parameters: %d derived from the final macro response, none matched "+
			"a parameter of this request that the action allows", len(derived)), false)
		return
	}
	w.record(a.Kind, "updated parameter(s) from the final macro response: "+strings.Join(updated, ", "),
		!sameMacroStep(before, w.request))
}

// derivedParam is one parameter the final response names, with the location it belongs to.
type derivedParam struct {
	name, value string
	// where is host and path of the URL the parameter is sent to; empty when it could not be read.
	where string
}

func locationOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Host) + u.EscapedPath()
}

// deriveParams reads form fields and link query parameters out of an HTML body.
func deriveParams(body []byte, base string) []derivedParam {
	if len(body) > maxDerivedParamBodyLen {
		body = body[:maxDerivedParamBodyLen]
	}
	baseURL, _ := url.Parse(base)
	resolve := func(ref string) *url.URL {
		if baseURL == nil {
			u, err := url.Parse(ref)
			if err != nil {
				return nil
			}
			return u
		}
		u, err := baseURL.Parse(strings.TrimSpace(ref))
		if err != nil {
			return nil
		}
		return u
	}
	var out []derivedParam
	addQuery := func(u *url.URL) {
		if u == nil {
			return
		}
		for name, values := range u.Query() {
			for _, v := range values {
				out = append(out, derivedParam{name: name, value: v, where: locationOf(u)})
			}
		}
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	formWhere := ""
	inForm := false
	var textarea *derivedParam
	var selectName string
	selectChosen := false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		tok := z.Token()
		attr := func(key string) (string, bool) {
			for _, at := range tok.Attr {
				if strings.EqualFold(at.Key, key) {
					return at.Val, true
				}
			}
			return "", false
		}
		switch tt {
		case html.TextToken:
			if textarea != nil {
				textarea.value += tok.Data
			}
		case html.EndTagToken:
			switch tok.DataAtom.String() {
			case "form":
				inForm, formWhere = false, ""
			case "textarea":
				if textarea != nil {
					out = append(out, *textarea)
					textarea = nil
				}
			case "select":
				selectName, selectChosen = "", false
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			switch tok.DataAtom.String() {
			case "form":
				inForm = true
				action, ok := attr("action")
				target := resolve(action)
				if !ok || strings.TrimSpace(action) == "" {
					target = baseURL
				}
				formWhere = locationOf(target)
				addQuery(target)
			case "input":
				name, ok := attr("name")
				if !ok || name == "" || !inForm {
					continue
				}
				value, _ := attr("value")
				out = append(out, derivedParam{name: name, value: value, where: formWhere})
			case "textarea":
				if name, ok := attr("name"); ok && name != "" && inForm {
					textarea = &derivedParam{name: name, where: formWhere}
				}
			case "select":
				if name, ok := attr("name"); ok && name != "" && inForm {
					selectName, selectChosen = name, false
				}
			case "option":
				if selectName == "" || selectChosen {
					continue
				}
				value, _ := attr("value")
				_, selected := attr("selected")
				if selected {
					// A selected option wins over the first one recorded earlier.
					for i := len(out) - 1; i >= 0; i-- {
						if out[i].name == selectName && out[i].where == formWhere {
							out = append(out[:i], out[i+1:]...)
							break
						}
					}
					selectChosen = true
				} else {
					for _, p := range out {
						if p.name == selectName && p.where == formWhere {
							goto nextToken
						}
					}
				}
				out = append(out, derivedParam{name: selectName, value: value, where: formWhere})
			case "a", "link", "area":
				if href, ok := attr("href"); ok {
					addQuery(resolve(href))
				}
			}
		}
	nextToken:
	}
	return out
}

// updateRequestParams rewrites the values of the request's own query and urlencoded body parameters
// that a derived parameter names, as the action allows. It returns the request and the names updated.
func updateRequestParams(req MacroStep, derived []derivedParam, a *Action) (MacroStep, []string) {
	if len(derived) == 0 {
		return req, nil
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return req, nil
	}
	where := locationOf(u)
	// The value for a name: the last derived occurrence at this request's location, or anywhere when
	// tolerating a URL mismatch.
	lookup := func(name string) (string, bool) {
		value, found := "", false
		for _, p := range derived {
			if p.name != name {
				continue
			}
			if !a.TolerateURLMismatch && p.where != where {
				continue
			}
			value, found = p.value, true
		}
		return value, found
	}
	var updated []string
	rewrite := func(encoded string) (string, bool) {
		if encoded == "" {
			return encoded, false
		}
		parts := strings.Split(encoded, "&")
		changed := false
		for i, part := range parts {
			rawName, rawValue, hasEq := strings.Cut(part, "=")
			name, err := url.QueryUnescape(rawName)
			if err != nil || name == "" || !nameAllowed(name, a.MatchParams, matchSpecifiedParams, a.Params) {
				continue
			}
			value, ok := lookup(name)
			if !ok {
				continue
			}
			if old, err := url.QueryUnescape(rawValue); err == nil && old == value && hasEq {
				continue
			}
			parts[i] = rawName + "=" + url.QueryEscape(value)
			changed = true
			updated = append(updated, name)
		}
		return strings.Join(parts, "&"), changed
	}
	if q, changed := rewrite(u.RawQuery); changed {
		u.RawQuery = q
		req.URL = u.String()
	}
	if isURLEncodedBody(req.Headers) {
		if body, changed := rewrite(req.Body); changed {
			req.Body = body
			req.Headers = copyHeaders(req.Headers)
			for k := range req.Headers {
				if strings.EqualFold(k, "Content-Length") {
					req.Headers[k] = strconv.Itoa(len(body))
				}
			}
		}
	}
	return req, updated
}

func isURLEncodedBody(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			return strings.Contains(strings.ToLower(v), "application/x-www-form-urlencoded")
		}
	}
	return false
}

// sendCurrentRequest re-sends the request a rule's actions arrived at. With no cookie scope it is the
// whole-jar send every rule has always made; with one, the jar's cookies are filtered for this
// request only.
func (c *Coordinator) sendCurrentRequest(runner MacroStepRunner, step MacroStep, overrides []CookieOverride, scope *cookieScope) (*StepResult, error) {
	if scope == nil {
		return c.sendWithJarAnd(runner, step, overrides)
	}
	effective := c.applyJarScoped(step, overrides, scope)
	resp, err := runner(effective)
	if err != nil {
		return nil, err
	}
	host, port, tls := authorityOf(step.URL)
	c.absorb.attach(SourceMacro)
	c.absorb.responses.Add(1)
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			c.jarMgr.AbsorbSetCookie(host, port, tls, v)
			c.absorb.cookies.Add(1)
		}
	}
	return resp, nil
}

// applyJarScoped merges the jar into the request's own Cookie header, cookie by cookie, as the scope
// allows: an allowed jar cookie replaces or joins the request's, a disallowed one leaves the request's
// value (or its absence) alone. With the update off nothing comes from the jar. Overrides apply last.
func (c *Coordinator) applyJarScoped(step MacroStep, overrides []CookieOverride, scope *cookieScope) MacroStep {
	step.Headers = copyHeaders(step.Headers)
	if step.Headers == nil {
		step.Headers = map[string]string{}
	}
	cookieKey, own := "Cookie", ""
	for k, v := range step.Headers {
		if strings.EqualFold(k, "Cookie") {
			cookieKey, own = k, v
		}
	}
	cookie := own
	if !scope.off {
		host, port, tls := authorityOf(step.URL)
		for _, pair := range strings.Split(c.jarMgr.CookieHeader(host, port, tls, pathOf(step.URL)), ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || name == "" || !nameAllowed(name, scope.mode, matchSpecifiedCookies, scope.names) {
				continue
			}
			cookie = setCookiePair(cookie, name, value)
		}
	}
	for _, o := range overrides {
		cookie = setCookiePair(cookie, o.Name, o.Value)
	}
	if cookie == "" {
		delete(step.Headers, cookieKey)
	} else {
		step.Headers[cookieKey] = cookie
	}
	return step
}
