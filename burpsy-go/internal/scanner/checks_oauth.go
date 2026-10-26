package scanner

// OAuth/OIDC authorization-server checks (burpsy-react-ui-0vzb.9).
//
// Burp's catalogue has no OAuth rows: PortSwigger documents OAuth attacks as an Academy topic
// tested by hand. Four burpsy rows, one captured authorize request:
//
//   - Passive, from the captured exchange alone (the finding is about the SERVER accepting the
//     weak request, so each requires its 302 proof): implicit flow answered with the token in
//     the fragment; a code grant honoured with no state parameter (login CSRF); a code grant
//     honoured with no PKCE or a plain challenge.
//   - Active: redirect_uri manipulation. Other-host, attacker subdomain, userinfo and
//     traversal spellings of the registered callback, plus a duplicate-parameter pair, are
//     replayed through the probe gate; the row stands when the endpoint 302s to the
//     manipulated URI.
//
// The active probes replay a login initiation, which changes no server state, but the row is
// off by default with the rest of the OAuth bundle behind CheckOAuth.

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// Burpsy's own rows; see BurpsyNativeRows.
const (
	IssueOAuthImplicitFlow      = "OAuth implicit flow"
	IssueOAuthStateMissing      = "OAuth state parameter missing"
	IssueOAuthPKCEAbsentOrPlain = "OAuth PKCE absent or downgraded"
	IssueOAuthRedirectURIBypass = "OAuth redirect_uri validation bypass" //nolint:gosec // G101: an issue name, not a credential
)

// oauthEnabled is the bundle's own switch.
func oauthEnabled(c *ScanConfig) bool { return c != nil && c.CheckOAuth }

// oauthCanaryHost is the attacker host every bypass spelling aims at.
const oauthCanaryHost = "attacker.burpsy.invalid"

// oauthAuthorizeShape parses the captured request's query and reports whether it is an OAuth
// authorize request: response_type, client_id and redirect_uri all present.
func oauthAuthorizeShape(raw string) (url.Values, bool) {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	line, _, _ := strings.Cut(head, "\r\n")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, false
	}
	parts := strings.SplitN(fields[1], "?", 2)
	if len(parts) != 2 {
		return nil, false
	}
	q, err := url.ParseQuery(parts[1])
	if err != nil {
		return nil, false
	}
	if q.Get("response_type") == "" || q.Get("client_id") == "" || q.Get("redirect_uri") == "" {
		return nil, false
	}
	return q, true
}

// checkOAuthPassive runs the implicit-flow and PKCE rows against one captured authorize request.
func checkOAuthPassive(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	q, ok := oauthAuthorizeShape(raw)
	if !ok {
		return nil, nil
	}
	resp := responseRaw(cc.Scanner, cc.Exchange)
	if !strings.HasPrefix(resp, "HTTP/1.1 302") && !strings.HasPrefix(resp, "HTTP/1.0 302") && !strings.HasPrefix(resp, "HTTP/2 302") {
		return nil, nil
	}
	loc := headerValue(resp, "Location")
	if loc == "" {
		return nil, nil
	}
	var out []*Finding
	rt := q.Get("response_type")
	// Implicit flow: the server answered a token grant with the token in the fragment.
	if (rt == "token" || rt == "id_token" || strings.Contains(rt, "token")) && strings.Contains(loc, "#access_token=") {
		out = append(out, buildHeaderFinding(cc, IssueOAuthImplicitFlow, "medium", "firm",
			fmt.Sprintf("response_type=%s answered 302 with Location fragment #access_token=...", rt),
			"The authorization server still honours the implicit flow: a response_type="+rt+
				" request was answered with the access token in the redirect fragment, where browser "+
				"history, referrer leakage and client-side scripts can reach it. The code flow with PKCE "+
				"is the current guidance for every client type."))
	}
	// PKCE absent or downgraded: a code grant honoured without S256.
	if rt == "code" && q.Get("code_challenge_method") != "S256" && strings.Contains(loc, "code=") {
		kind := "no code_challenge at all"
		if q.Get("code_challenge") != "" {
			kind = "code_challenge_method=" + q.Get("code_challenge_method")
		}
		out = append(out, buildHeaderFinding(cc, IssueOAuthPKCEAbsentOrPlain, "medium", "firm",
			fmt.Sprintf("response_type=code with %s answered 302 with a code", kind),
			"The authorization server issued a code for a request with "+kind+
				": without S256 PKCE a intercepted code redeems without the verifier, which is the "+
				"interception attack PKCE exists to close."))
	}
	return out, nil
}

// oauthRedirectVariants are the spellings of the registered callback a weak validator accepts.
func oauthRedirectVariants(registered string) []string {
	u, err := url.Parse(registered)
	if err != nil || u.Host == "" {
		return nil
	}
	return []string{
		"https://" + oauthCanaryHost + "/cb",
		u.Scheme + "://" + u.Host + "." + oauthCanaryHost + u.Path,
		registered + "/../cb-burpsy-canary",
		u.Scheme + "://" + u.Host + "@" + oauthCanaryHost + u.Path,
	}
}

// checkOAuthRedirectBypass replays the captured authorize request with manipulated
// redirect_uri values; a 302 to the manipulated URI is the finding.
func checkOAuthRedirectBypass(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	q, ok := oauthAuthorizeShape(raw)
	if !ok {
		return nil, nil
	}
	registered := q.Get("redirect_uri")
	variants := oauthRedirectVariants(registered)
	if len(variants) == 0 {
		return nil, nil
	}
	gate := cc.Scanner.probeGate(ctx, cc.Exchange)
	if gate == nil {
		return nil, fmt.Errorf("oauth redirect_uri: no authorised sender: %w", errCapabilityMissing)
	}
	if _, ok := oauthWithRedirectURI(raw, variants[0], false); !ok {
		// Sending the request unchanged five times would read as "validated" when nothing was tested.
		return nil, fmt.Errorf("oauth redirect_uri: the parameter could not be located in the request target")
	}
	var hits []string
	// Variant 1-4: substitute the value. Variant 5: duplicate the parameter - the first value
	// is the registered callback, the second the attacker's.
	probes := append([]string{}, variants...)
	for _, v := range probes {
		mutated, _ := oauthWithRedirectURI(raw, v, false)
		res, err := gate.Send(ctx, []byte(mutated))
		if err != nil || res.Err != nil || res.Status == nil {
			continue
		}
		if *res.Status == 302 && oauthLocationTargets(string(res.Raw), v) {
			hits = append(hits, v)
		}
	}
	// Parameter pollution: registered first, attacker second.
	dup := "https://" + oauthCanaryHost + "/cb"
	mutated, _ := oauthWithRedirectURI(raw, dup, true)
	res, err := gate.Send(ctx, []byte(mutated))
	if err == nil && res.Err == nil && res.Status != nil && *res.Status == 302 &&
		oauthLocationTargets(string(res.Raw), dup) {
		hits = append(hits, "duplicate redirect_uri parameter")
	}
	if len(hits) == 0 {
		return nil, nil
	}
	evidence := fmt.Sprintf("registered redirect_uri %s; the endpoint 302-redirected to %d manipulated spelling(s):\n- %s",
		registered, len(hits), strings.Join(hits, "\n- "))
	detail := "The authorization server validates redirect_uri weakly (prefix or first-value-only): " +
		"it redirected the flow to a manipulated spelling of the registered callback, delivering the " +
		"victim's code or token to an attacker-controlled URI - one-click account takeover."
	return []*Finding{buildHeaderFinding(cc, IssueOAuthRedirectURIBypass, "high", "firm", evidence, detail)}, nil
}

// oauthWithRedirectURI returns the raw request with redirect_uri's value replaced (or
// duplicated, when duplicate is set: the captured pair first, value second). The pair is found by
// its decoded name in the request target's query, whatever spelling the client used for the value
// (unencoded, lowercase escapes, %20); ok is false when there is no such pair to rewrite.
func oauthWithRedirectURI(raw, value string, duplicate bool) (string, bool) {
	line, rest, _ := strings.Cut(raw, "\r\n")
	fields := strings.SplitN(line, " ", 3)
	if len(fields) != 3 {
		return raw, false
	}
	target, query, hasQuery := strings.Cut(fields[1], "?")
	if !hasQuery {
		return raw, false
	}
	pairs := strings.Split(query, "&")
	for i, p := range pairs {
		name, _, _ := strings.Cut(p, "=")
		if n, err := url.QueryUnescape(name); err != nil || n != "redirect_uri" {
			continue
		}
		repl := "redirect_uri=" + url.QueryEscape(value)
		if duplicate {
			repl = p + "&" + repl
		}
		pairs[i] = repl
		fields[1] = target + "?" + strings.Join(pairs, "&")
		return strings.Join(fields, " ") + "\r\n" + rest, true
	}
	return raw, false
}

// oauthLocationTargets reports whether a 302 response's Location IS this variant's manipulated
// redirect: an absolute URL on the variant's host and path (for the traversal variant, a path that
// ends in the canary segment once dot segments are resolved). The canary merely appearing in the
// Location - a login bounce or an error page echoing redirect_uri in its own query - is not a
// redirect to the attacker.
func oauthLocationTargets(respRaw, variant string) bool {
	lu, err := url.Parse(headerValue(respRaw, "Location"))
	if err != nil || !lu.IsAbs() {
		return false
	}
	vu, err := url.Parse(variant)
	if err != nil || !strings.EqualFold(lu.Hostname(), vu.Hostname()) || lu.Port() != vu.Port() {
		return false
	}
	if strings.Contains(variant, "cb-burpsy-canary") {
		return strings.HasSuffix(path.Clean(lu.Path), "/cb-burpsy-canary")
	}
	return lu.Path == vu.Path
}

// oauthLocationGrant reports whether a Location carries an issued grant (a code, an access token
// or an id token in its query or fragment) and no error: RFC 6749 section 4.1.2.1 answers a
// rejected authorize request with a 302 too, carrying error=.
func oauthLocationGrant(loc string) bool {
	lu, err := url.Parse(loc)
	if err != nil {
		return false
	}
	q := lu.Query()
	if f, err := url.ParseQuery(lu.Fragment); err == nil {
		for k, v := range f {
			q[k] = append(q[k], v...)
		}
	}
	if q.Get("error") != "" {
		return false
	}
	return q.Get("code") != "" || q.Get("access_token") != "" || q.Get("id_token") != ""
}

// checkOAuthStateMissing runs the state row against one captured authorize request. It rides the
// "Cross-site request forgery" descriptor: the attack is login CSRF.
func checkOAuthStateMissing(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	q, ok := oauthAuthorizeShape(raw)
	if !ok || q.Get("state") != "" {
		return nil, nil
	}
	resp := responseRaw(cc.Scanner, cc.Exchange)
	if !strings.Contains(strings.SplitN(resp, "\r\n", 2)[0], " 302") {
		return nil, nil
	}
	if !oauthLocationGrant(headerValue(resp, "Location")) {
		return nil, nil // a refusal (error=...) or a login bounce, not a grant
	}
	return []*Finding{buildHeaderFinding(cc, IssueOAuthStateMissing, "medium", "firm",
		"authorize request carried no state parameter and the server answered 302 with a grant",
		"The authorization server honoured an authorize request that carried no state parameter: "+
			"an attacker can initiate a flow and deliver the resulting redirect to a victim, binding "+
			"the attacker's grant to the victim's session (login cross-site request forgery).")}, nil
}

// withOAuthState adds the state row to the runner of the "Cross-site request forgery" descriptor.
func withOAuthState(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		innerF, innerErr := inner(ctx, cc)
		if !oauthEnabled(cc.Config) {
			return innerF, innerErr
		}
		stF, stErr := checkOAuthStateMissing(ctx, cc)
		out := append(innerF, stF...)
		switch {
		case len(stF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case stErr != nil:
			return innerF, stErr
		}
		return out, nil
	}
}

// withOAuth adds the OAuth bundle to the runner of the descriptor it rides.
func withOAuth(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		innerF, innerErr := inner(ctx, cc)
		if !oauthEnabled(cc.Config) {
			return innerF, innerErr
		}
		passiveF, passiveErr := checkOAuthPassive(ctx, cc)
		activeF, activeErr := checkOAuthRedirectBypass(ctx, cc)
		out := append(innerF, passiveF...)
		out = append(out, activeF...)
		switch {
		case len(passiveF)+len(activeF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case passiveErr != nil:
			return innerF, passiveErr
		case activeErr != nil:
			return innerF, activeErr
		}
		return out, nil
	}
}
