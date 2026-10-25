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
		Name: "repeater csrf", Enabled: true, ScopeTools: tools,
		Extract: *ex, InjectHeader: "X-CSRF-Token", InjectValue: "{{csrf}}",
	}
}

func TestRepeaterResponseFeedsTokenCaptureWithRepeaterAttribution(t *testing.T) {
	host, port, closeFn := repeaterTokenTarget(t, "tok-from-repeater")
	defer closeFn()
	s := newTestServer()
	if _, err := s.sessionCoordinator.AddTokenRule(tokenRuleWebTest(t, "repeater")); err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	sendOneRaw(t, s, host, port, "/form")

	if got, ok := s.sessionCoordinator.TokenValue("csrf"); !ok || got != "tok-from-repeater" {
		t.Errorf("the repeater response's token was not captured: %q, %v", got, ok)
	}
}

func TestRepeaterResponseDoesNotOverwriteARuleScopedAwayFromIt(t *testing.T) {
	host, port, closeFn := repeaterTokenTarget(t, "tok-from-repeater")
	defer closeFn()
	s := newTestServer()
	// The rule covers the proxy only: a hand-driven repeater response must not re-issue its value.
	if _, err := s.sessionCoordinator.AddTokenRule(tokenRuleWebTest(t, "proxy")); err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	sendOneRaw(t, s, host, port, "/form")

	if got, ok := s.sessionCoordinator.TokenValue("csrf"); ok {
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
	if _, err := s.sessionCoordinator.AddTokenRule(tokenRuleWebTest(t, "repeater")); err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	sendOneRaw(t, s, host, port, "/form")

	if got, ok := s.sessionCoordinator.TokenValue("csrf"); !ok || got != "tok-despite-toggle" {
		t.Errorf("the cookie monitor toggle silenced a token rule: %q, %v", got, ok)
	}
}
