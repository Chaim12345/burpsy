package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The scope API's rule identity includes the protocol arm: an http rule and an https rule on
// the same host:port coexist, and a toggle or remove naming one scheme must not touch the
// other. A call that names no protocol over such a pair is refused 409 rather than applied to
// whichever sibling came first - first-match could enable a broader rule than the operator
// named, which silently widens the engagement's authorised surface.
func TestScopeAPIProtocolIdentity(t *testing.T) {
	s := newTestServer()
	add := func(protocol string) {
		t.Helper()
		rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "127.0.0.1", "port": 18101, "protocol": protocol})
		if rec.Code != http.StatusOK {
			t.Fatalf("include %s = %d: %s", protocol, rec.Code, rec.Body.String())
		}
	}
	// Both insertion orders get the same identity behaviour.
	add("http")
	add("https")

	rules := func() []map[string]any {
		t.Helper()
		get := newRecorder()
		s.mux.ServeHTTP(get, newReq(http.MethodGet, "/api/scope"))
		var sc struct {
			Rules []map[string]any `json:"rules"`
		}
		if err := json.Unmarshal(get.Body.Bytes(), &sc); err != nil {
			t.Fatalf("scope view: %v", err)
		}
		return sc.Rules
	}
	byProto := func(rs []map[string]any, p string) map[string]any {
		t.Helper()
		for _, r := range rs {
			if r["protocol"] == p {
				return r
			}
		}
		t.Fatalf("no %s rule in %v", p, rs)
		return nil
	}
	if got := rules(); len(got) != 2 {
		t.Fatalf("rules after the pair = %v, want two protocol-differentiated siblings", got)
	}

	// Toggle with the protocol named: only the https rule flips.
	rec := postJSON(t, s, "/api/scope", map[string]any{"action": "toggle", "kind": "include", "pattern": "127.0.0.1", "port": 18101, "protocol": "https", "enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle https = %d: %s", rec.Code, rec.Body.String())
	}
	rs := rules()
	if on, _ := byProto(rs, "http")["enabled"].(bool); !on {
		t.Error("the http rule was disabled by a toggle aimed at the https rule - the first-match bug")
	}
	if on, _ := byProto(rs, "https")["enabled"].(bool); on {
		t.Error("the https rule did not take the disable")
	}

	// Toggle without the protocol: refused 409, nothing changes.
	rec = postJSON(t, s, "/api/scope", map[string]any{"action": "toggle", "kind": "include", "pattern": "127.0.0.1", "port": 18101, "enabled": true})
	if rec.Code != http.StatusConflict {
		t.Fatalf("toggle without protocol = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "protocol") {
		t.Errorf("the 409 does not tell the caller to name the protocol: %s", rec.Body.String())
	}
	rs = rules()
	if on, _ := byProto(rs, "https")["enabled"].(bool); on {
		t.Error("the ambiguous toggle changed the https rule")
	}

	// Remove with the protocol named: only the http rule goes.
	rec = postJSON(t, s, "/api/scope", map[string]any{"action": "remove", "kind": "include", "pattern": "127.0.0.1", "port": 18101, "protocol": "http"})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove http = %d: %s", rec.Code, rec.Body.String())
	}
	rs = rules()
	if len(rs) != 1 || rs[0]["protocol"] != "https" {
		t.Fatalf("rules after removing http = %v, want only the https sibling", rs)
	}

	// With one rule left the unnamed call is unambiguous and still applies (compatibility).
	rec = postJSON(t, s, "/api/scope", map[string]any{"action": "remove", "kind": "include", "pattern": "127.0.0.1", "port": 18101})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove of the now-unique rule = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rules(); len(got) != 0 {
		t.Fatalf("rules after the final remove = %v, want none", got)
	}
}

// The reverse insertion order resolves identically: the named protocol picks its own sibling.
func TestScopeAPIProtocolIdentityReverseOrder(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"https", "http"} {
		if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "app.test", "port": 443, "protocol": p}); rec.Code != http.StatusOK {
			t.Fatalf("include %s = %d", p, rec.Code)
		}
	}
	rec := postJSON(t, s, "/api/scope", map[string]any{"action": "remove", "kind": "include", "pattern": "app.test", "port": 443, "protocol": "http"})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove http = %d: %s", rec.Code, rec.Body.String())
	}
	get := newRecorder()
	s.mux.ServeHTTP(get, newReq(http.MethodGet, "/api/scope"))
	var sc struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &sc); err != nil {
		t.Fatalf("scope view: %v", err)
	}
	if len(sc.Rules) != 1 || sc.Rules[0]["protocol"] != "https" {
		t.Fatalf("rules = %v, want only the https sibling", sc.Rules)
	}
}
