package vulnapp

// OAuth/OIDC authorization-server fixtures (burpsy-react-ui-0vzb.9), for
// internal/scanner/checks_oauth.go.
//
// The vulnerable server models the classic authorization-endpoint mistakes: it validates
// redirect_uri by string prefix, so the registered "https://client.example/callback" is
// bypassed by an attacker subdomain (https://client.example.attacker.example/callback), a
// userinfo spelling (https://client.example@attacker.example/callback), a traversal
// (https://client.example/callback/../x), or a duplicate parameter whose first value passes
// the check while the last is honoured. It also still answers response_type=token with the
// token in the fragment (implicit flow), enforces no state parameter, and asks for no PKCE
// on the code flow. The safe twin exact-matches redirect_uri, rejects duplicate parameters,
// requires state, and requires S256 PKCE on the code flow, answering 400 otherwise.

import (
	"net/http"
	"strings"
)

// oauthRegisteredRedirect is the one registered callback.
const oauthRegisteredRedirect = "https://client.example/callback"

func oauthAuthorize(w http.ResponseWriter, r *http.Request, safe bool) {
	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirects, hasRedirect := q["redirect_uri"]
	if responseType == "" || clientID == "" || !hasRedirect || redirects[0] == "" {
		oauthError(w, "invalid_request")
		return
	}
	if safe {
		if len(redirects) != 1 || redirects[0] != oauthRegisteredRedirect {
			oauthError(w, "invalid_request: redirect_uri")
			return
		}
		if q.Get("state") == "" {
			oauthError(w, "invalid_request: state required")
			return
		}
		if responseType == "code" && q.Get("code_challenge_method") != "S256" {
			oauthError(w, "invalid_request: PKCE S256 required")
			return
		}
		if responseType == "token" || responseType == "id_token" {
			oauthError(w, "unsupported_response_type")
			return
		}
	} else {
		// The weak check: a string prefix. Every spelling that starts with the registered
		// origin passes - subdomains of it, userinfo tricks, traversals under it.
		if !strings.HasPrefix(redirects[0], "https://client.example") {
			oauthError(w, "invalid_request: redirect_uri")
			return
		}
	}
	// The vulnerable server validates the first redirect_uri but honours the last; the safe
	// twin already rejected a duplicate above.
	redirect := redirects[len(redirects)-1]
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	loc := redirect
	if responseType == "token" || responseType == "id_token" {
		// Implicit flow: the token leaves in the fragment.
		loc += "#access_token=demo-access-token&token_type=bearer"
	} else {
		loc += sep + "code=demo-auth-code"
	}
	if st := q.Get("state"); st != "" {
		loc += sep + "state=" + st
	}
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

func oauthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	// 200, not the RFC's 400: the bundled Spring4Shell bcheck treats any endpoint whose base
	// answer is 400 as a candidate (400 on the poisoned parameter, then a differential), and a
	// fixture that 400s every weak request by design trips it. The scanner checks read the
	// redirect, not the refusal status, so the refusal carries no signal either way.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`)) //nolint:gosec // G705: application/json naming a fixed refusal reason; the fixture is deliberately weak, not this line
}

func oauthEndpoints() []Endpoint {
	registered := "https%3A%2F%2Fclient.example%2Fcallback"
	return []Endpoint{
		{Path: "/oauth/authorize?response_type=token&client_id=demo&redirect_uri=" + registered,
			Method: http.MethodGet, Row: "OAuth implicit flow",
			Note: "authorization server still answers response_type=token with the token in the fragment"},
		{Path: "/oauth/safe/authorize?response_type=token&client_id=demo&redirect_uri=" + registered + "&state=seedstate",
			Method: http.MethodGet, Row: "OAuth implicit flow", Safe: true,
			Note: "the same server refusing implicit flow outright"},
		{Path: "/oauth/authorize?response_type=code&client_id=demo&redirect_uri=" + registered,
			Method: http.MethodGet, Row: "OAuth state parameter missing",
			Note: "code flow accepted with no state parameter - login CSRF"},
		{Path: "/oauth/safe/authorize?response_type=code&client_id=demo&redirect_uri=" + registered + "&code_challenge=abc&code_challenge_method=S256",
			Method: http.MethodGet, Row: "OAuth state parameter missing", Safe: true,
			Note: "the same server requiring state"},
		{Path: "/oauth/authorize?response_type=code&client_id=demo&redirect_uri=" + registered + "&state=seedstate&code_challenge=abc&code_challenge_method=plain",
			Method: http.MethodGet, Row: "OAuth PKCE absent or downgraded",
			Note: "code flow accepting plain PKCE"},
		{Path: "/oauth/safe/authorize?response_type=code&client_id=demo&redirect_uri=" + registered + "&state=seedstate&code_challenge=abc&code_challenge_method=plain",
			Method: http.MethodGet, Row: "OAuth PKCE absent or downgraded", Safe: true,
			Note: "the same server requiring S256"},
		{Path: "/oauth/authorize?response_type=code&client_id=demo&redirect_uri=" + registered + "&state=seedstate&code_challenge=abc&code_challenge_method=S256",
			Method: http.MethodGet, Row: "OAuth redirect_uri validation bypass",
			Note: "redirect_uri validated by string prefix - subdomain, userinfo, traversal and duplicate-parameter spellings all pass"},
		{Path: "/oauth/safe/authorize?response_type=code&client_id=demo&redirect_uri=" + registered + "&state=seedstate&code_challenge=abc&code_challenge_method=S256",
			Method: http.MethodGet, Row: "OAuth redirect_uri validation bypass", Safe: true,
			Note: "the same server exact-matching the registered redirect"},
	}
}

func registerOAuth(mux *http.ServeMux) {
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) { oauthAuthorize(w, r, false) })
	mux.HandleFunc("/oauth/safe/authorize", func(w http.ResponseWriter, r *http.Request) { oauthAuthorize(w, r, true) })
}
