package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Proxy HTTP history is proxy traffic. A Repeater resend, an Intruder payload, or a Scanner probe
// that lands in the same store must not show up here — those belong in the tool log, the view
// whose whole subject is "requests burpsy itself made". Leaving them in makes HTTP history and
// Logger the same list with different columns, and turns "how many requests did I proxy" into a
// question history answers wrongly. That was the bug the e2e suite's "Proxy HTTP history holds
// proxy traffic only" test pinned as a deliberate red test; this is the unit-level guard.
func TestHistoryExcludesToolOriginatedExchanges(t *testing.T) {
	s := newTestServer()

	// One proxied exchange, one nobody claimed, and one of each tool kind. Unattributed stays:
	// hiding it would invent an attribution it never had, the same fail-safe direction the Source
	// type itself takes.
	addExchangeWithSource(t, s, "/proxied", core.SourceProxy)
	addExchangeWithSource(t, s, "/unattributed", core.SourceUnattributed)
	addExchangeWithSource(t, s, "/repeated", core.SourceRepeater)
	addExchangeWithSource(t, s, "/attacked", core.SourceIntruder)
	addExchangeWithSource(t, s, "/probed", core.SourceScanner)

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/history", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/history: status = %d, want 200", rec.Code)
	}

	var rows []ExchangeView
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode history %q: %v", rec.Body.String(), err)
	}

	if len(rows) != 2 {
		var paths []string
		for _, row := range rows {
			paths = append(paths, row.Path)
		}
		t.Fatalf("history returned %d rows %v, want exactly the proxied and unattributed ones", len(rows), paths)
	}
	// Newest first, so the unattributed row (added second) comes back ahead of the proxied one.
	if rows[0].Path != "/unattributed" || rows[1].Path != "/proxied" {
		t.Fatalf("history rows = [%s %s], want [/unattributed /proxied]", rows[0].Path, rows[1].Path)
	}
}

// addExchangeWithSource stores a minimal request and records an exchange attributed to source.
func addExchangeWithSource(t *testing.T, s *Server, path string, source core.Source) {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID),
		Host:    "h.test",
		Port:    80,
		Method:  "GET",
		Path:    path,
		Source:  source,
	})
}
