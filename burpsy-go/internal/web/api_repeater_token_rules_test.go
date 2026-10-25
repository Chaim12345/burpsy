package web

// The capture half of xe82 at the repeater's capture point (recordRepeaterExchange): a Repeater
// response is observed traffic, attributed to the repeater so a rule's tools scope decides
// whether it may re-issue the rule's value.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

// repeaterTokenTarget serves one form whose csrf value identifies which response carried it.
func repeaterTokenTarget(t *testing.T, token string) (host string, port uint16, closeFn func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<form><input name="csrf" value="%s"></form>`, token)
	}))
	authority := strings.TrimPrefix(srv.URL, "http://")
	name, portStr, ok := strings.Cut(authority, ":")
	if !ok {
		srv.Close()
		t.Fatalf("test origin %q has no port", srv.URL)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		srv.Close()
		t.Fatalf("test origin port: %v", err)
	}
	return name, uint16(p), srv.Close
}

func sendOneRaw(t *testing.T, s *Server, host string, port uint16, path string) {
	t.Helper()
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n", path, host, port)
	if _, err := s.sendOneRepeaterRequest(context.Background(), repeaterSendSpec{
		Host: host, Port: port, Raw: []byte(raw), AsWritten: raw,
	}); err != nil {
		t.Fatalf("repeater send: %v", err)
	}
}

func tokenRuleWebTest(t *testing.T, tools ...string) *session.TokenRule {
	t.Helper()
	ex, err := session.NewExtraction("csrf", "body", `name="csrf" value="([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("build extraction: %v", err)
	}
	return &session.TokenRule{
		Name: "repeater csrf", Enabled: true, ScopeHosts: []string{"*"}, ScopeTools: tools,
		Extract: *ex, InjectHeader: "X-CSRF-Token", InjectValue: "{{csrf}}",
	}
}

func TestRepeaterResponseFeedsTokenCaptureWithRepeaterAttribution(t *testing.T) {
	host, port, closeFn := repeaterTokenTarget(t, "tok-from-repeater")
	defer closeFn()
	s := newTestServer()
	ruleID, err := s.sessionCoordinator.AddTokenRule(tokenRuleWebTest(t, "repeater"))
	if err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	sendOneRaw(t, s, host, port, "/form")

	if got, ok := s.sessionCoordinator.TokenValue(ruleID); !ok || got != "tok-from-repeater" {
		t.Errorf("the repeater response's token was not captured: %q, %v", got, ok)
	}
}

func TestRepeaterResponseDoesNotOverwriteARuleScopedAwayFromIt(t *testing.T) {
	host, port, closeFn := repeaterTokenTarget(t, "tok-from-repeater")
	defer closeFn()
	s := newTestServer()
	// The rule covers the proxy only: a hand-driven repeater response must not re-issue its value.
	ruleID, err := s.sessionCoordinator.AddTokenRule(tokenRuleWebTest(t, "proxy"))
	if err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	sendOneRaw(t, s, host, port, "/form")

	if got, ok := s.sessionCoordinator.TokenValue(ruleID); ok {
		t.Errorf("a proxy-scoped rule captured from a repeater response: %q", got)
	}
}

// The jar's monitored-source toggle governs COOKIES, not token rules: with the repeater switched
// off as a cookie source, a repeater-scoped rule still captures - the toggle is the jar's, and a
// token rule's own tools scope is what gates it.
func TestRepeaterTokenCaptureIgnoresTheCookieMonitorToggle(t *testing.T) {
	host, port, closeFn := repeaterTokenTarget(t, "tok-despite-toggle")
	defer closeFn()
	s := newTestServer()
	s.sessionCoordinator.SetMonitoredSources([]string{"proxy"})
	ruleID, err := s.sessionCoordinator.AddTokenRule(tokenRuleWebTest(t, "repeater"))
	if err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	sendOneRaw(t, s, host, port, "/form")

	if got, ok := s.sessionCoordinator.TokenValue(ruleID); !ok || got != "tok-despite-toggle" {
		t.Errorf("the cookie monitor toggle silenced a token rule: %q, %v", got, ok)
	}
}

// The bead's acceptance test (burpsy-react-ui-xe82), end to end over real HTTP: a rule is added
// through the API, a login response the repeater fetches carries the token, and a LATER repeater
// request - the operator's own bytes, carrying no token - arrives at the origin with the token
// injected. Nothing is pasted anywhere.
func TestAcceptanceLoginTokenFlowsIntoALaterRepeaterRequest(t *testing.T) {
	var got []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_, _ = fmt.Fprint(w, `<form><input name="csrf" value="tok-acceptance"></form>`)
		case "/transfer":
			got = append(got, r.Header.Get("X-CSRF-Token"))
			_, _ = fmt.Fprint(w, "ok")
		}
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "http://")
	host, portStr, _ := strings.Cut(authority, ":")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("test origin port: %v", err)
	}

	s := newTestServer()
	rec := postJSON(t, s, "/api/session/token-rules", map[string]any{
		"name": "acceptance", "enabled": true, "scope_hosts": []string{host}, "scope_tools": []string{"repeater"},
		"extract": map[string]any{
			"name": "csrf", "from": "body", "pattern": `name="csrf" value="([^"]+)"`, "group": 1,
		},
		"inject_header": "X-CSRF-Token", "inject_value": "{{csrf}}",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("add the rule over the API: %d %s", rec.Code, rec.Body)
	}

	// The login fetch, then the operator's own transfer request - which names no token.
	sendOneRaw(t, s, host, uint16(port), "/login")
	transfer := fmt.Sprintf("POST /transfer HTTP/1.1\r\nHost: %s\r\nContent-Length: 9\r\n\r\namount=10", authority)
	if _, err := s.sendOneRepeaterRequest(context.Background(), repeaterSendSpec{
		Host: host, Port: uint16(port), Raw: []byte(transfer), AsWritten: transfer,
	}); err != nil {
		t.Fatalf("the transfer send: %v", err)
	}

	if len(got) != 1 || got[0] != "tok-acceptance" {
		t.Fatalf("the origin saw X-CSRF-Token %v, want [tok-acceptance] injected without pasting", got)
	}
}
