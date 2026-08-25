package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ---- /api/proxy/options: Burp's Proxy → settings response-modification switches -----------------
//
// The engine (proxy.Options) is live-mutable by design — an operator turns "remove all
// JavaScript" on, views one page, turns it off — but the web package had no door to it, so the
// switches existed nowhere an operator could reach. These tests pin the contract: GET answers
// the full confirmed snapshot (one entry per key, plus the counters that say what the rules
// actually did), PUT takes a flat map of keys to booleans and returns the confirmed state, and
// an unknown key is a 400 that names it rather than a silent accept.

// newTestServerWithProxyOptions builds a server with a live proxy.Options attached — the
// same shape main.go builds, one set shared by the relay and the API.
func newTestServerWithProxyOptions(t *testing.T) *Server {
	t.Helper()
	return NewServer(core.NewTrafficStore(), core.NewScope()).WithProxyOptions(proxy.NewOptions())
}

func TestProxyOptionsGetReturnsEveryKeyAndCounters(t *testing.T) {
	ts := newTestServerWithProxyOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/api/proxy/options", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/proxy/options = %d, want 200", rec.Code)
	}
	var view struct {
		Options  map[string]bool   `json:"options"`
		Counters proxy.Counters    `json:"counters"`
		Keys     []proxy.OptionKey `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(view.Keys) != len(proxy.OptionKeys) {
		t.Errorf("keys lists %d entries, want all %d the engine defines", len(view.Keys), len(proxy.OptionKeys))
	}
	if len(view.Options) != len(proxy.OptionKeys) {
		t.Errorf("options has %d entries, want one per key (%d)", len(view.Options), len(proxy.OptionKeys))
	}
}

func TestProxyOptionsPutFlipsAKeyAndReportsConfirmedState(t *testing.T) {
	ts := newTestServerWithProxyOptions(t)
	// The body is the flat map of keys to booleans — the same shape the panel sends.
	req := httptest.NewRequest(http.MethodPut, "/api/proxy/options", strings.NewReader(`{"remove_all_javascript": true}`))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Options map[string]bool `json:"options"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !view.Options["remove_all_javascript"] {
		t.Error("PUT did not confirm the flip; the panel would show a state the relay is not in")
	}
}

func TestProxyOptionsPutRefusesAnUnknownKeyByName(t *testing.T) {
	ts := newTestServerWithProxyOptions(t)
	req := httptest.NewRequest(http.MethodPut, "/api/proxy/options", strings.NewReader(`{"no_such_switch": true}`))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT unknown key = %d, want 400; a silent accept is how a client ends up believing it enabled something", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no_such_switch") {
		t.Error("the 400 must name the key it refused")
	}
}
