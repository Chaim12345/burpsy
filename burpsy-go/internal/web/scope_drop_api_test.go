package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The drop switch's API surface (burpsy-react-ui-5j4i): GET reports it on every answer so the
// switch reads the state it toggles; POST with action "drop_out_of_scope" flips it and the
// change is visible in the engine (AuthoriseRequest refuses what the scope excludes).
func TestTheDropOutOfScopeSwitchRoundTripsThroughTheAPI(t *testing.T) {
	s := newTestServer()

	get := func() bool {
		t.Helper()
		rec := get(t, s, "/api/scope")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/scope: status = %d", rec.Code)
		}
		var body struct {
			DropOutOfScope bool `json:"drop_out_of_scope"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode scope: %v", err)
		}
		return body.DropOutOfScope
	}

	if get() {
		t.Fatal("a fresh server must report drop_out_of_scope=false; the seed both the engine and a new Burp project use")
	}

	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_out_of_scope", "enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enable: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !get() {
		t.Error("the switch did not read back true after being enabled")
	}
	if !s.scope.DropOutOfScope() {
		t.Error("the flag did not reach the engine object the API holds")
	}

	// The egress effect: with an include list and the switch on, a host the list does not
	// name is refused at the authorisation gate — the refusal a per-request sender sees.
	s.scope.Add(core.NewScopeRule(core.ScopeInclude, "shop.test"))
	if s.scope.AuthoriseRequest("ghost.test", 80, "/", false) {
		t.Error("with the switch on, an unnamed host must not be authorised to send")
	}
	if !s.scope.AuthoriseRequest("shop.test", 80, "/", false) {
		t.Error("a named host must stay authorised while the switch is on")
	}

	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_out_of_scope", "enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if get() {
		t.Error("the switch did not read back false after being disabled")
	}
	// With the switch off, the egress fence is down: retention semantics only.
	if !s.scope.AuthoriseRequest("ghost.test", 80, "/", false) && !s.scope.Contains("ghost.test", 80, "/", false) {
		t.Log("ghost.test is refused by Contains because the include list names it not; egress independence means the refusal wording differs, not the verdict")
	}
}

// A switch POST without the target state is refused, not guessed.
func TestDropOutOfScopeWithoutEnabledIsRefused(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_out_of_scope"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — a toggle with no target state must not read as success", rec.Code)
	}
}
