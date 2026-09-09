package web

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// Burp's "Default Proxy interception state" (burpsy-react-ui-7vy): whether the intercept
// switch reads on, off, or restored-from-last-session at server start. The endpoint is a
// preference about the NEXT start, not a live toggle; /api/intercept/enable stays the switch
// and records the live state beside it.

// newTestServerWithPersist builds a server with a fresh SQLite store attached.
func newTestServerWithPersist(t *testing.T) *Server {
	t.Helper()
	ps, err := persist.Open(filepath.Join(t.TempDir(), "startup.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open persist: %v", err)
	}
	return newTestServer().WithPersist(ps)
}

// restartedTestServerWithPersist builds a second server over the SAME database — the restart
// the restore mode is about — through the same WithPersist path production uses.
func restartedTestServerWithPersist(s *Server) *Server {
	return NewServer(s.store, s.scope).WithPersist(s.persist).WithIntercept(s.intercept)
}

func TestInterceptStartupModeRoundTrips(t *testing.T) {
	s := newTestServerWithPersist(t)

	getMode := func() string {
		t.Helper()
		rec := get(t, s, "/api/intercept/startup")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET startup: %d", rec.Code)
		}
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Mode
	}

	if mode := getMode(); mode != "off" {
		t.Fatalf("fresh store mode = %q, want off — a preference nobody wrote must not turn interception on", mode)
	}

	for _, mode := range []string{"on", "restore", "off"} {
		rec := postJSON(t, s, "/api/intercept/startup", map[string]any{"mode": mode})
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %q: %d (%s)", mode, rec.Code, rec.Body.String())
		}
		if got := getMode(); got != mode {
			t.Errorf("after POST %q, GET reads %q", mode, got)
		}
	}

	// An unrepresentable mode is refused, not coerced: silently accepting "maybe" would mean
	// the panel describes a state the startup path will never apply.
	if rec := postJSON(t, s, "/api/intercept/startup", map[string]any{"mode": "maybe"}); rec.Code != http.StatusBadRequest {
		t.Errorf("POST unknown mode answered %d, want 400", rec.Code)
	}
}

// The restore path end to end: toggle the live switch on, restart against the same database,
// and the switch comes back on — because the enable endpoint recorded the live state.
func TestRestoreStartupBringsBackTheLastLiveState(t *testing.T) {
	s := newTestServerWithPersist(t)

	// Preference: restore. Then the operator turns interception on live.
	if rec := postJSON(t, s, "/api/intercept/startup", map[string]any{"mode": "restore"}); rec.Code != http.StatusOK {
		t.Fatalf("POST restore: %d", rec.Code)
	}
	if rec := postJSON(t, s, "/api/intercept/enable", map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d", rec.Code)
	}

	// Simulate the restart: a fresh server over the same database applies the startup
	// preference through the same WithPersist path production uses.
	restarted := restartedTestServerWithPersist(s)
	if !restarted.intercept.Enabled() {
		t.Error("a server starting in restore mode with the last live state on must come up intercepting")
	}
}
