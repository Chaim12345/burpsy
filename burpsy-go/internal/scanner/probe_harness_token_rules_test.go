package scanner

// The injection half of xe82 at the scanner's probe template: a value a token rule captured is
// spliced into the request the harness derives every probe from.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// harnessWithTokenRule starts a server that records the named header of every request it sees,
// seeds an exchange for path, and returns the CheckContext (wired to a session coordinator
// carrying rule) plus the record.
func harnessWithTokenRule(t *testing.T, path, headerName string, rule *session.TokenRule) (*CheckContext, func() []string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get(headerName))
		_, _ = w.Write([]byte("seed"))
	}))
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	store := core.NewTrafficStore()
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n", path, host, port)
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port,
		TLS: false, Method: "GET", Path: path}
	store.AddExchange(ex)

	coord := session.NewCoordinator(zap.NewNop())
	if rule != nil {
		if _, err := coord.AddTokenRule(rule); err != nil {
			t.Fatalf("add token rule: %v", err)
		}
	}
	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil)).WithSessionCoordinator(coord)
	return NewCheckContext(s, ex, nil), func() []string { return seen }
}

func tokenRuleScannerTest(t *testing.T) *session.TokenRule {
	t.Helper()
	ex, err := session.NewExtraction("csrf", "body", `name="csrf" value="([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("build extraction: %v", err)
	}
	return &session.TokenRule{
		Name: "scanner csrf", Enabled: true,
		Extract: *ex, InjectHeader: "X-CSRF-Token", InjectValue: "{{csrf}}",
	}
}

func TestScannerProbesCarryTheCapturedToken(t *testing.T) {
	rule := tokenRuleScannerTest(t)
	cc, seen := harnessWithTokenRule(t, "/form", "X-CSRF-Token", rule)
	coord, err := cc.SessionCoordinator()
	if err != nil {
		t.Fatalf("session coordinator: %v", err)
	}
	// The value was lifted from observed traffic before the scan reached this exchange.
	coord.ObserveTokenResponse(session.RequestIdentity{Host: cc.Exchange.Host, Tool: "proxy"},
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-scanned"></form>`))

	if _, err := NewProbeHarness(context.Background(), cc, []string{"query"}); err != nil {
		t.Fatalf("build harness: %v", err)
	}
	if len(seen()) == 0 || seen()[0] != "tok-scanned" {
		t.Errorf("the baseline request did not carry the captured token: %v", seen())
	}
}

func TestScannerProbesStaySilentWithoutACapturedValue(t *testing.T) {
	cc, seen := harnessWithTokenRule(t, "/form", "X-CSRF-Token", tokenRuleScannerTest(t))
	if _, err := NewProbeHarness(context.Background(), cc, []string{"query"}); err != nil {
		t.Fatalf("build harness: %v", err)
	}
	if len(seen()) == 0 || seen()[0] != "" {
		t.Errorf("a header was injected with no value captured: %v", seen())
	}
}

func TestScannerProbesRunUnchangedWithoutACoordinator(t *testing.T) {
	// A scan configured without a session coordinator takes the path every scan took before
	// xe82: same bytes, no refusal.
	cc, seen := harnessWithTokenRule(t, "/form", "X-CSRF-Token", nil)
	if _, err := NewProbeHarness(context.Background(), cc, []string{"query"}); err != nil {
		t.Fatalf("build harness: %v", err)
	}
	if len(seen()) != 1 {
		t.Errorf("the baseline was not sent exactly once: %d requests", len(seen()))
	}
}
