package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-z5z3: GET/POST /api/scope/check answers what the capture matcher answers.

func scopeCheckServer(t *testing.T, rules ...*core.ScopeRule) *Server {
	t.Helper()
	s := newTestServer()
	for _, r := range rules {
		s.scope.Add(r)
	}
	return s
}

func rule(t *testing.T, kind core.ScopeRuleKind, pattern string, path *string, port *uint16) *core.ScopeRule {
	t.Helper()
	r, err := core.NewScopeRuleFrom(kind, pattern, path, port, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScopeCheckAnswersWhatTheCaptureMatcherAnswers(t *testing.T) {
	admin := "/admin"
	p8443 := uint16(8443)
	s := scopeCheckServer(t,
		rule(t, core.ScopeInclude, "*.shop.test", nil, nil),
		rule(t, core.ScopeExclude, "www.shop.test", &admin, nil),
		rule(t, core.ScopeInclude, "api.test", nil, &p8443),
	)
	urls := []string{
		"https://www.shop.test/cart",       // include
		"https://www.shop.test/admin/user", // path exclude wins
		"http://api.test:8443/v1",          // port include
		"http://api.test/v1",               // wrong port
		"https://elsewhere.test/",          // no include matched
		"ftp://www.shop.test/",             // not http(s)
	}
	body, _ := json.Marshal(map[string]any{"urls": urls})
	req := httptest.NewRequest(http.MethodPost, "/api/scope/check", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST answered %d: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Results []struct {
			URL           string          `json:"url"`
			Error         string          `json:"error"`
			Host          string          `json:"host"`
			Port          uint16          `json:"port"`
			Path          string          `json:"path"`
			TLS           bool            `json:"tls"`
			InScope       bool            `json:"in_scope"`
			ProxyForwards bool            `json:"proxy_forwards"`
			Reason        string          `json:"reason"`
			MatchedRule   json.RawMessage `json:"matched_rule"`
		} `json:"results"`
		InScopeCount    int  `json:"in_scope_count"`
		InvalidURLCount int  `json:"invalid_url_count"`
		DropOutOfScope  bool `json:"drop_out_of_scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Results) != len(urls) {
		t.Fatalf("%d results for %d urls", len(view.Results), len(urls))
	}
	wantReason := []string{"included", "excluded", "included", "no_include_match", "no_include_match", ""}
	wantRule := []string{"*.shop.test", "www.shop.test", "api.test", "", "", ""}
	wantPort := []uint16{443, 443, 8443, 80, 443}
	for i, r := range view.Results {
		if i == len(urls)-1 {
			if r.Error == "" || r.InScope {
				t.Fatalf("ftp URL was not refused per-item: %+v", r)
			}
			continue
		}
		u, _ := url.Parse(urls[i])
		port := uint16(80)
		if r.TLS {
			port = 443
		}
		if u.Port() == "8443" {
			port = 8443
		}
		// The capture matcher's own answer, for the same host/port/path/scheme.
		want := s.scope.Contains(u.Hostname(), port, u.EscapedPath(), u.Scheme == "https")
		if r.Port != wantPort[i] || r.Port != port {
			t.Fatalf("%s: port %d, want %d (the scheme's default when the URL names none)", urls[i], r.Port, wantPort[i])
		}
		if r.InScope != want {
			t.Fatalf("%s: in_scope=%v, Contains says %v", urls[i], r.InScope, want)
		}
		if r.Reason != wantReason[i] {
			t.Fatalf("%s: reason %q, want %q", urls[i], r.Reason, wantReason[i])
		}
		if wantRule[i] == "" {
			if string(r.MatchedRule) != "null" {
				t.Fatalf("%s: matched_rule is %s, want null (marshalled, not omitted)", urls[i], r.MatchedRule)
			}
		} else if !strings.Contains(string(r.MatchedRule), `"pattern":"`+wantRule[i]+`"`) {
			t.Fatalf("%s: matched_rule %s does not name %s", urls[i], r.MatchedRule, wantRule[i])
		}
		// Drop switch off: the proxy forwards everything, in scope or not.
		if !r.ProxyForwards {
			t.Fatalf("%s: proxy_forwards false with the drop switch off", urls[i])
		}
	}
	if view.InScopeCount != 2 || view.InvalidURLCount != 1 || view.DropOutOfScope {
		t.Fatalf("counts in_scope=%d invalid=%d drop=%v", view.InScopeCount, view.InvalidURLCount, view.DropOutOfScope)
	}

	// With the drop switch on, an out-of-scope URL is not forwarded either.
	s.scope.SetDropOutOfScope(true)
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scope/check?url="+url.QueryEscape("https://elsewhere.test/"), nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"proxy_forwards":false`) || !strings.Contains(rec.Body.String(), `"drop_out_of_scope":true`) {
		t.Fatalf("GET with the drop switch on answered %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScopeCheckRefusesWhatItCannotRead(t *testing.T) {
	s := scopeCheckServer(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/scope/check", ""},
		{http.MethodGet, "/api/scope/check?url=notaurl", ""},
		{http.MethodPost, "/api/scope/check", `{"urls":[]}`},
		{http.MethodPost, "/api/scope/check", `{"urls":"x"}`},
	} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s %s answered %d: %s", tc.method, tc.path, tc.body, rec.Code, rec.Body.String())
		}
	}
	// No rules at all: default allow, and said so.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scope/check?url=http://any.test/", nil))
	if !strings.Contains(rec.Body.String(), `"in_scope":true`) || !strings.Contains(rec.Body.String(), `"reason":"no_include_rules"`) {
		t.Fatalf("an empty scope did not answer default-allow: %s", rec.Body.String())
	}
}
