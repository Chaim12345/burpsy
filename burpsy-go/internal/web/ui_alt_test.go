package web

import (
	"net/http"
	"strings"
	"testing"
)

// The alternative console (altui, Map / Probe / Prove) is the landing page, and the original console
// stays reachable at /legacy. Both are static assets served by uiHandler, behind the same credential
// gate as everything else.

func TestTheAlternativeConsoleIsTheLandingPage(t *testing.T) {
	s := newAuthServer(t)
	rec := authDoReq(s, http.MethodGet, "/", "burpsy.example.com", authBasic("u", testAuthToken), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-view="probe"`) || !strings.Contains(body, "workbench") {
		t.Fatalf("GET / is not the alternative console")
	}
	for _, want := range []string{`href="/alt/app.css"`, `src="/alt/app.js"`, `href="/legacy"`} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page lacks %s", want)
		}
	}
	if strings.Contains(body, `href="/app.css"`) || strings.Contains(body, `src="/app.js"`) {
		t.Errorf("landing page still points at root assets, which belong to the original console")
	}
}

func TestTheOriginalConsoleStaysReachableAtLegacy(t *testing.T) {
	s := newAuthServer(t)
	hdr := authBasic("u", testAuthToken)
	rec := authDoReq(s, http.MethodGet, "/legacy", "burpsy.example.com", hdr, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app.js") {
		t.Fatalf("GET /legacy = %d, want the original index", rec.Code)
	}
	// Its own assets are unchanged at the root.
	for _, p := range []string{"/app.js", "/style.css"} {
		if r := authDoReq(s, http.MethodGet, p, "burpsy.example.com", hdr, ""); r.Code != http.StatusOK {
			t.Errorf("GET %s = %d, the original console's asset moved", p, r.Code)
		}
	}
}

func TestAltAssetsAreServedWithTheRightTypeAndBehindTheCredential(t *testing.T) {
	s := newAuthServer(t)
	hdr := authBasic("u", testAuthToken)
	cases := map[string]string{
		"/alt/app.js":         "javascript",
		"/alt/api.js":         "javascript",
		"/alt/components.js":  "javascript",
		"/alt/views/map.js":   "javascript",
		"/alt/views/probe.js": "javascript",
		"/alt/views/prove.js": "javascript",
		"/alt/views/tools.js": "javascript",
		"/alt/app.css":        "text/css",
	}
	for p, typ := range cases {
		if r := authDoReq(s, http.MethodGet, p, "burpsy.example.com", nil, ""); r.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d, want 401", p, r.Code)
		}
		r := authDoReq(s, http.MethodGet, p, "burpsy.example.com", hdr, "")
		if r.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, r.Code)
			continue
		}
		if ct := r.Header().Get("Content-Type"); !strings.Contains(ct, typ) {
			t.Errorf("GET %s Content-Type = %q, want %q", p, ct, typ)
		}
		if r.Body.Len() == 0 {
			t.Errorf("GET %s is empty", p)
		}
	}
	// HEAD is behind the gate too.
	if r := authDoReq(s, http.MethodHead, "/alt/app.js", "burpsy.example.com", nil, ""); r.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated HEAD /alt/app.js = %d, want 401", r.Code)
	}
}

func TestAltPathsCannotEscapeTheEmbeddedTree(t *testing.T) {
	s := newAuthServer(t)
	hdr := authBasic("u", testAuthToken)
	for _, p := range []string{
		"/alt/../server.mjs", "/alt/%2e%2e/server.mjs", "/alt/..%2fserver.mjs", "/alt/views/../../README.md",
		"/alt/server.mjs", "/alt/test-proxy.mjs", "/alt/README.md", "/alt/nope.js", "/alt//etc/passwd",
	} {
		r := authDoReq(s, http.MethodGet, p, "burpsy.example.com", hdr, "")
		if r.Code == http.StatusOK {
			t.Errorf("GET %s = 200; only the SPA's own files may be served under /alt/", p)
		}
		if strings.Contains(r.Body.String(), "createServer") || strings.Contains(r.Body.String(), "BURPSY_BACKEND") {
			t.Errorf("GET %s leaked the Node proxy source", p)
		}
	}
}

func TestAltUIIsNotServedForMutatingVerbs(t *testing.T) {
	s := newAuthServer(t)
	hdr := authBasic("u", testAuthToken)
	hdr["Origin"] = "https://burpsy.example.com"
	for _, p := range []string{"/alt/app.js", "/legacy"} {
		r := authDoReq(s, http.MethodPost, p, "burpsy.example.com", hdr, "{}")
		if r.Code == http.StatusOK {
			t.Errorf("POST %s = 200", p)
		}
	}
}
