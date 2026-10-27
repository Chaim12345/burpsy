package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A console bound beyond loopback has no credential at all (api_sameorigin.go says so). These tests
// pin the credential that closes that: one shared token, checked on EVERY route before anything else
// runs, reads included, because the credential-class GETs (session cookies, login macros, scanner
// secrets, config export) are reads.
//
// Every test drives s.guarded, the handler ListenAndServe serves, for the reason api_sameorigin_test.go
// gives. The tokens below are throwaway test values.

const testAuthToken = "unit-test-token-0123456789abcdef"

func newAuthServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer()
	if err := s.SetAuthToken(testAuthToken); err != nil {
		t.Fatalf("SetAuthToken refused a valid token: %v", err)
	}
	return s
}

func authDoReq(s *Server, method, path, host string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	return rec
}

func authBasic(user, pass string) map[string]string {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth(user, pass)
	return map[string]string{"Authorization": r.Header.Get("Authorization")}
}

func TestWithATokenSetAnUnauthenticatedReadIsRefused(t *testing.T) {
	s := newAuthServer(t)
	for _, path := range []string{"/", "/api/stats", "/api/session/cookies", "/api/scanner/secrets", "/api/config/export", "/api/proxy/ca"} {
		rec := authDoReq(s, http.MethodGet, path, "burpsy.example.com", nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without credentials = %d, want 401", path, rec.Code)
		}
		if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Fatalf("GET %s 401 lacks a Basic challenge, so a browser cannot prompt: %q", path, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestWrongCredentialsAreRefused(t *testing.T) {
	s := newAuthServer(t)
	for name, hdr := range map[string]map[string]string{
		"wrong password":           authBasic("u", "nope-nope-nope-nope"),
		"empty password":           authBasic("u", ""),
		"token with a suffix":      authBasic("u", testAuthToken+"x"),
		"token with a prefix cut":  authBasic("u", testAuthToken[1:]),
		"wrong bearer":             {"Authorization": "Bearer nope-nope-nope-nope"},
		"bearer with empty token":  {"Authorization": "Bearer "},
		"unknown scheme":           {"Authorization": "Digest " + testAuthToken},
		"token in the wrong place": {"X-Burpsy-Token": testAuthToken},
	} {
		t.Run(name, func(t *testing.T) {
			rec := authDoReq(s, http.MethodGet, "/api/stats", "burpsy.example.com", hdr, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestTheRightTokenIsAcceptedAsBasicPasswordOrBearer(t *testing.T) {
	s := newAuthServer(t)
	for name, hdr := range map[string]map[string]string{
		"basic, any username": authBasic("operator", testAuthToken),
		"basic, empty user":   authBasic("", testAuthToken),
		"bearer":              {"Authorization": "Bearer " + testAuthToken},
	} {
		t.Run(name, func(t *testing.T) {
			rec := authDoReq(s, http.MethodGet, "/api/stats", "burpsy.example.com", hdr, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTheRefusalLeaksNeitherTheTokenNorTheRoute(t *testing.T) {
	s := newAuthServer(t)
	rec := authDoReq(s, http.MethodGet, "/api/session/cookies", "burpsy.example.com", authBasic("u", "wrong-wrong-wrong-1"), "")
	all := rec.Body.String() + rec.Header().Get("WWW-Authenticate")
	for _, leak := range []string{testAuthToken, "wrong-wrong-wrong-1", "cookies", "session"} {
		if strings.Contains(all, leak) {
			t.Fatalf("the 401 echoed %q: %s", leak, all)
		}
	}
}

func TestAnUnauthenticatedRequestNeverReachesItsHandler(t *testing.T) {
	s := newAuthServer(t)
	hit := 0
	s.mux.HandleFunc("/api/__auth_probe", func(w http.ResponseWriter, r *http.Request) { hit++ })
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, http.MethodHead} {
		authDoReq(s, m, "/api/__auth_probe", "burpsy.example.com", nil, "")
	}
	if hit != 0 {
		t.Fatalf("handler ran %d times for unauthenticated requests", hit)
	}
	authDoReq(s, http.MethodGet, "/api/__auth_probe", "burpsy.example.com", authBasic("u", testAuthToken), "")
	if hit != 1 {
		t.Fatalf("authenticated request did not reach the handler (hit=%d)", hit)
	}
}

func TestStreamsAndUpgradesAreBehindTheCredentialToo(t *testing.T) {
	s := newAuthServer(t)
	for name, hdr := range map[string]map[string]string{
		"websocket upgrade": {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
		"event stream":      {"Accept": "text/event-stream"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{"/api/events", "/api/crawl/live", "/api/scanner/live"} {
				rec := authDoReq(s, http.MethodGet, path, "burpsy.example.com", hdr, "")
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("%s %s = %d, want 401", name, path, rec.Code)
				}
			}
		})
	}
}

func TestEveryManifestRouteIsBehindTheCredential(t *testing.T) {
	s := newAuthServer(t)
	for pattern, rt := range manifest {
		path := concretePath(pattern, rt.subPath)
		for _, m := range rt.methods {
			rec := authDoReq(s, m, path, "burpsy.example.com", nil, "{}")
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s (%s) without credentials = %d, want 401", m, path, pattern, rec.Code)
			}
		}
	}
}

// The probe a platform health check needs, and the only unauthenticated path. It must say nothing
// about the instance, and it must not accept anything but a read.
func TestHealthzIsTheOnlyUnauthenticatedPathAndSaysNothing(t *testing.T) {
	s := newAuthServer(t)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := authDoReq(s, m, "/healthz", "burpsy.example.com", nil, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s /healthz = %d, want 200", m, rec.Code)
		}
		if m == http.MethodGet && strings.TrimSpace(rec.Body.String()) != "ok" {
			t.Fatalf("/healthz body = %q, want exactly \"ok\"", rec.Body.String())
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := authDoReq(s, m, "/healthz", "burpsy.example.com", nil, "")
		if rec.Code == http.StatusOK {
			t.Fatalf("%s /healthz answered 200 without credentials", m)
		}
	}
	for _, path := range []string{"/healthz/", "/healthz/x", "/healthzz", "/HEALTHZ", "/healthz%2F", "//healthz", "/./healthz/../api/stats"} {
		rec := authDoReq(s, http.MethodGet, path, "burpsy.example.com", nil, "")
		if rec.Code == http.StatusOK {
			t.Fatalf("GET %s answered 200 without credentials", path)
		}
	}
}

// The credential does not replace the cross-site gate. A correct token from a non-loopback Host the
// operator never named still cannot mutate, and a named Host still has to pass the Origin check.
func TestTheCredentialDoesNotReplaceTheCrossSiteGate(t *testing.T) {
	s := newAuthServer(t)
	hdr := authBasic("u", testAuthToken)
	hdr["Content-Type"] = "application/json"

	rec := authDoReq(s, http.MethodPost, "/api/scope", "burpsy.example.com", hdr, `{"add":["x.example"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("authenticated POST from an unnamed Host = %d, want 403", rec.Code)
	}

	s.WithAllowedHosts("burpsy.example.com")
	hdr["Origin"] = "https://evil.example"
	rec = authDoReq(s, http.MethodPost, "/api/scope", "burpsy.example.com", hdr, `{"add":["x.example"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("authenticated POST with a hostile Origin = %d, want 403", rec.Code)
	}

	hdr["Origin"] = "https://burpsy.example.com"
	hdr["Sec-Fetch-Site"] = "same-origin"
	rec = authDoReq(s, http.MethodPost, "/api/scope", "burpsy.example.com", hdr, `{"add":["x.example"]}`)
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("authenticated same-origin POST on a named Host = %d, want it to reach the handler", rec.Code)
	}
}

func TestACredentialThatCannotBeSetSafelyIsRefused(t *testing.T) {
	for name, tok := range map[string]string{
		"empty":            "",
		"spaces":           "                ",
		"short":            "short-token",
		"15 characters":    "123456789012345",
		"control chars":    "abcdefghijklmnop\x00",
		"surrounding ws":   " abcdefghijklmnopqrstuvwxyz ",
		"contains a colon": "abcdefghij:klmnopqrstuvwxyz",
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer()
			if err := s.SetAuthToken(tok); err == nil {
				t.Fatalf("SetAuthToken accepted %q", tok)
			}
		})
	}
	s := newTestServer()
	if err := s.SetAuthToken("0123456789abcdef"); err != nil {
		t.Fatalf("a 16 character token was refused: %v", err)
	}
}

// With no token the console is exactly what it was: loopback-bound, no credential. Nothing here
// changes the default.
func TestWithoutATokenNothingChanges(t *testing.T) {
	s := newTestServer()
	rec := authDoReq(s, http.MethodGet, "/api/stats", "127.0.0.1:8081", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/stats on a plain loopback console = %d, want 200", rec.Code)
	}
	if rec := authDoReq(s, http.MethodGet, "/healthz", "127.0.0.1:8081", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", rec.Code)
	}
}
