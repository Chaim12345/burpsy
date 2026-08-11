package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// HONEST-03.
//
// /api/session/cookies answered `{"wired": true, "cookies": []}` for every request, with a comment
// explaining that the coordinator's jar had no enumeration API. The statement was true about the
// code and false about the session: after any authenticated flow the coordinator holds cookies and
// attaches them to outgoing requests, so the operator's cookie table asserted "there are none"
// about cookies it was actively sending. The jar enumerates now, and this pins that the route reads
// it rather than reporting a constant.
func Test_the_cookie_route_enumerates_the_jar_rather_than_claiming_it_is_wired_HONEST_03(t *testing.T) {
	coordinator := session.NewCoordinator(zap.NewNop())
	s := newTestServer().WithSessionCoordinator(coordinator)

	// Two authorities, and deliberately the same hostname on both: a jar is keyed by (host, port,
	// tls), so this is the case that used to be unrepresentable on the wire — the old shape carried
	// only a bare host and would have rendered these as two identical rows.
	//
	// Absorbed through HandleResponse, the same entry point the proxy uses, rather than by reaching
	// into the jar: a test that populated the jar directly could pass while the production path that
	// fills it was broken.
	absorb := func(host string, port uint16, tls bool, setCookie string) {
		coordinator.HandleResponse(host, port, tls, 200, map[string]string{"Set-Cookie": setCookie}, nil)
	}
	absorb("app.test", 443, true, "SESSION=abc; Path=/")
	absorb("app.test", 443, true, "csrf=zz9")
	absorb("app.test", 8080, false, "SESSION=plain")

	rec := get(t, s, "/api/session/cookies")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/session/cookies: %d", rec.Code)
	}
	var body struct {
		Wired   bool   `json:"wired"`
		Hint    string `json:"hint"`
		Cookies []struct {
			Host    string `json:"host"`
			Port    uint16 `json:"port"`
			TLS     bool   `json:"tls"`
			Cookies []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"cookies"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !body.Wired {
		t.Error("wired = false with a coordinator attached")
	}
	if len(body.Cookies) != 2 {
		t.Fatalf("got %d jars, want 2 (same host, two authorities): %s", len(body.Cookies), rec.Body.String())
	}
	// Sorted by host then port numerically, so 443 precedes 8080.
	secure, plain := body.Cookies[0], body.Cookies[1]
	if plain.Host != "app.test:8080" || plain.Port != 8080 || plain.TLS {
		t.Errorf("first jar = %+v, want app.test:8080 without TLS", plain)
	}
	if secure.Host != "app.test:443" || secure.Port != 443 || !secure.TLS {
		t.Errorf("second jar = %+v, want app.test:443 with TLS", secure)
	}
	// Both cookies absorbed for the TLS authority are present, and in name order — the value an
	// operator came to this table to read has to actually be here.
	if len(secure.Cookies) != 2 ||
		secure.Cookies[0].Name != "SESSION" || secure.Cookies[0].Value != "abc" ||
		secure.Cookies[1].Name != "csrf" || secure.Cookies[1].Value != "zz9" {
		t.Errorf("TLS jar cookies = %+v, want SESSION=abc then csrf=zz9", secure.Cookies)
	}
	// Two authorities holding a cookie of the same name must not collapse into one another.
	if len(plain.Cookies) != 1 || plain.Cookies[0].Value != "plain" {
		t.Errorf("plain jar cookies = %+v, want the single SESSION=plain", plain.Cookies)
	}
}

// The two states the old constant could not tell apart. "Attached and empty" and "not attached at
// all" both used to render as wired-with-nothing; each now says which it is, because the UI shows a
// different thing for each and was previously choosing between them on a value that never varied.
func Test_the_cookie_route_distinguishes_an_empty_jar_from_no_jar_HONEST_03(t *testing.T) {
	empty := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	var body struct {
		Wired   bool   `json:"wired"`
		Hint    string `json:"hint"`
		Cookies []any  `json:"cookies"`
	}
	rec := get(t, empty, "/api/session/cookies")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !body.Wired || len(body.Cookies) != 0 || body.Hint == "" {
		t.Errorf("attached-and-empty answered %+v; want wired with no cookies and a hint saying so", body)
	}

	// NewServer always installs a coordinator, so the unwired case is constructed by clearing the
	// field. It is still worth pinning: every other optional dependency on Server is nil-safe with a
	// handler that says "unwired" rather than 500ing, and this route is now part of that set.
	unwired := newTestServer()
	unwired.sessionCoordinator = nil
	body.Wired, body.Hint, body.Cookies = true, "", nil
	rec = get(t, unwired, "/api/session/cookies")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Wired || body.Hint == "" {
		t.Errorf("unwired answered %+v; want wired=false and a hint naming the reason", body)
	}
}
