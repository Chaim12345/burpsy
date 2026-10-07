package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
)

// burpsy-react-ui-q7f8: an access-control identity sourced from a session rule. The rule's login
// macro is run before the test, so a logged-in session the operator already holds becomes a role
// without pasting its cookie — and the cookie is fresh, not stale.
func TestAuthzIdentityFromSessionRule(t *testing.T) {
	// The target: /login hands out the admin cookie; everything else returns the privileged body only
	// to a request carrying it.
	srv := startTarget(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "role", Value: "admin", Path: "/"})
			fmt.Fprint(w, "logged in")
			return
		}
		if strings.Contains(r.Header.Get("Cookie"), "role=admin") {
			fmt.Fprintf(w, "SECRET admin dashboard for %s", r.URL.Path)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
	})
	host, port := srv.host, srv.port

	s := newTestServer()
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))
	s.scope.AddInclude("*")

	// A session rule whose login macro fetches /login (which sets role=admin). The access-control
	// identity references it instead of a pasted cookie.
	loginURL := fmt.Sprintf("http://%s:%d/login", host, port)
	ruleID, err := s.sessionCoordinator.AddRule(session.NewSessionRule("admin login", []string{host}, []session.MacroStep{{Method: "GET", URL: loginURL}}))
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	// The captured request under test carries no cookie of its own; the identities supply them.
	raw := fmt.Sprintf("GET /dash HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
	reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
	rspID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
	ex := &core.Exchange{Host: host, Port: port, Method: "GET", Path: "/dash", Request: core.MsgPtr(reqID), Response: &rspID}
	s.store.AddExchange(ex)

	// Baseline sources its admin cookie from the session rule; the no-auth row strips it.
	if rec := putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{
		{"label": "admin", "baseline": true, "session_rule_id": int64(ruleID)},
		{"label": "no-auth", "strip_cookie": true},
	}}); rec.Code != http.StatusOK {
		t.Fatalf("PUT identities = %d: %s", rec.Code, rec.Body.String())
	}

	rec := postJSON(t, s, "/api/authz/test", map[string]any{"exchange_id": uint64(ex.ID), "samples": 3})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST test = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Verdicts []authzVerdict `json:"verdicts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// The baseline logged in via the rule and saw the admin body; the no-auth row was denied, so the
	// control is Enforced. If the session cookie had not been resolved, the baseline itself would have
	// been denied and calibration would have failed (a 502) — so reaching Enforced proves the resolve.
	if b := verdictFor(t, resp.Verdicts, "admin"); b.Verdict != "Baseline" {
		t.Fatalf("admin verdict = %q, want Baseline", b.Verdict)
	}
	if na := verdictFor(t, resp.Verdicts, "no-auth"); na.Verdict != "Enforced" {
		t.Fatalf("no-auth verdict = %q, want Enforced (the session baseline must have gotten the admin body)", na.Verdict)
	}
}

// A reference to a rule that does not exist is refused at save time, not discovered at test time.
func TestAuthzRejectsAMissingSessionRuleAtSave(t *testing.T) {
	s := newTestServer()
	rec := putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{
		{"label": "admin", "baseline": true, "session_rule_id": int64(999)},
		{"label": "other", "cookie": "x=1"},
	}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "does not exist") {
		t.Fatalf("PUT with a bad rule ref = %d: %s", rec.Code, rec.Body.String())
	}
}

type target struct {
	host string
	port uint16
}

func startTarget(t *testing.T, h http.HandlerFunc) *target {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	return &target{host: host, port: port}
}
