package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Intruder send settings through POST /api/intruder/run (burpsy-react-ui-xixe.1, Phase 1) ------
//
// Every test here drives the real route against a real local listener and counts on the listener's
// side, because the settings are claims about what reached the wire.

// intruderSendFixture stores a base request and returns a server and the request's message id, with
// the payload position marked over "pha" in the query.
func intruderSendFixture(t *testing.T, raw string) (*Server, uint64, []map[string]int) {
	t.Helper()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, raw)
	start := strings.Index(raw, "pha")
	if start < 0 {
		t.Fatalf("fixture request has no \"pha\" to mark: %q", raw)
	}
	return srv, id, []map[string]int{{"start": start, "end": start + 3}}
}

// runView is the part of the report these tests read, decoded from the marshalled bytes.
type sendSettingsView struct {
	Report struct {
		Sent   int `json:"sent"`
		Failed int `json:"failed"`
	} `json:"report"`
	ConnectionsOpened *int64 `json:"connections_opened"`
	ConnectionsReused *int64 `json:"connections_reused"`
	HostHeaderUpdated bool   `json:"host_header_updated"`
	HostHeaderSkipped string `json:"host_header_skipped"`
}

// ---- mmca: response_timeout_ms --------------------------------------------------------------------

// Each request in the attack is bounded by response_timeout_ms, inside the attempt's total timeout_ms,
// and the shared network settings are untouched.
func TestAnIntruderResponseTimeoutBoundsEveryRequest(t *testing.T) {
	addr, accepts := silentListener(t)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	before := srv.sender.Network()
	rec, elapsed := postJSONWithin(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":              id,
		"target":              "http://" + addr,
		"mode":                "sniper",
		"manual_points":       points,
		"payload_sets":        [][]string{{"a", "b"}},
		"rps":                 1000,
		"max_in_flight":       2,
		"retries":             0,
		"timeout_ms":          5000,
		"response_timeout_ms": 200,
	}, 15*time.Second)
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d (%s)", rec.Code, rec.Body.String())
	}
	var view sendSettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Report.Failed != 2 || accepts.Load() != 2 {
		t.Fatalf("failed=%d accepts=%d, want both requests sent and both failed: %s", view.Report.Failed, accepts.Load(), rec.Body.String())
	}
	// Two requests at concurrency 2, each bounded at 200ms. timeout_ms (5s) is what a regression
	// falls back to.
	if elapsed > 3*time.Second {
		t.Fatalf("response_timeout_ms=200 did not bound the attack's requests: the run took %s", elapsed)
	}
	if !strings.Contains(rec.Body.String(), "response timeout") {
		t.Fatalf("the report's errors do not name the response timeout: %s", rec.Body.String())
	}
	if after := srv.sender.Network(); !reflect.DeepEqual(before, after) {
		t.Fatal("an attack's response timeout changed the shared network settings")
	}
}

// Two bounds where one can never apply are refused by name, before anything is sent.
func TestAnIntruderResponseTimeoutLongerThanTheTotalIsRefused(t *testing.T) {
	addr, accepts := silentListener(t)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	for _, tc := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"longer than timeout_ms", map[string]any{"timeout_ms": 1000, "response_timeout_ms": 2000}, "timeout_ms"},
		{"zero", map[string]any{"response_timeout_ms": 0}, "response_timeout_ms"},
	} {
		body := map[string]any{
			"msg_id": id, "target": "http://" + addr, "mode": "sniper",
			"manual_points": points, "payload_sets": [][]string{{"a"}},
		}
		for k, v := range tc.body {
			body[k] = v
		}
		rec := postJSON(t, srv, "/api/intruder/run", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: got %d (%s), want 400 naming %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatal("a refused attack reached the target")
	}
}
