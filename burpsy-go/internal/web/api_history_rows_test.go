package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// historyRowCount reads GET /api/history through the whole chain and returns how many rows it lists.
func historyRowCount(t *testing.T, s *Server) int {
	t.Helper()
	rec := guarded(t, s, http.MethodGet, "/api/history", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/history = %d: %s", rec.Code, rec.Body.String())
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decoding history: %v", err)
	}
	return len(rows)
}

// confirmedDelete sends DELETE /api/history/rows through the whole chain carrying token.
func confirmedDelete(t *testing.T, s *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodDelete, "/api/history/rows", nil)
	} else {
		req = httptest.NewRequest(http.MethodDelete, "/api/history/rows", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	req.Header.Set(ConfirmHeader, token)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	return rec
}

// burpsy-react-ui-gf68: removing history rows discards the record an operator reports from, so it is
// gated like every other evidence-discarding route. Before the fix it was DELETE /api/history under
// that pattern's riskRead class, and an unconfirmed same-origin call emptied history.
func TestClearingHistoryNeedsAConfirmation(t *testing.T) {
	s := newTestServer()
	first := seedResponse(t, s, "HTTP/1.1 200 OK", "a")
	seedResponse(t, s, "HTTP/1.1 200 OK", "b")
	seedResponse(t, s, "HTTP/1.1 200 OK", "c")
	if n := historyRowCount(t, s); n != 3 {
		t.Fatalf("seeded 3 rows, history lists %d", n)
	}

	// Unconfirmed, both shapes: the clear-all (no body) and the named-ids removal.
	for _, body := range []string{"", fmt.Sprintf(`{"ids":[%d]}`, first)} {
		rec := guarded(t, s, http.MethodDelete, "/api/history/rows", body)
		if rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("an unconfirmed DELETE /api/history/rows (body %q) = %d, want 428: %s", body, rec.Code, rec.Body.String())
		}
		var refusal struct {
			Route string `json:"route"`
			Risk  string `json:"risk"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err != nil || refusal.Route != "/api/history/rows" || refusal.Risk != string(riskDestructive) {
			t.Fatalf("the refusal names %+v (err %v), want route /api/history/rows risk destructive", refusal, err)
		}
	}
	// The old spelling must not be a way around the gate: it answers 405 and removes nothing.
	if rec := guarded(t, s, http.MethodDelete, "/api/history", ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("DELETE /api/history = %d Allow=%q, want 405 Allow=GET: %s", rec.Code, rec.Header().Get("Allow"), rec.Body.String())
	}
	// A token minted for another destructive route does not spend here.
	if rec := confirmedDelete(t, s, confirm(t, s, "/api/sitemap"), ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("a /api/sitemap confirmation spent on /api/history/rows = %d, want 428", rec.Code)
	}
	if n := historyRowCount(t, s); n != 3 {
		t.Fatalf("after only refused deletes history lists %d rows, want all 3", n)
	}

	// Confirmed, named ids: exactly that row goes.
	token := confirm(t, s, "/api/history/rows")
	rec := confirmedDelete(t, s, token, fmt.Sprintf(`{"ids":[%d]}`, first))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"removed":1`) {
		t.Fatalf("a confirmed DELETE of one row = %d %s, want 200 removed 1", rec.Code, rec.Body.String())
	}
	if n := historyRowCount(t, s); n != 2 {
		t.Fatalf("after removing one row history lists %d, want 2", n)
	}
	// The token was one-time.
	if rec := confirmedDelete(t, s, token, ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("a replayed confirmation = %d, want 428", rec.Code)
	}
	if n := historyRowCount(t, s); n != 2 {
		t.Fatalf("a replayed token cleared history: %d rows left, want 2", n)
	}

	// Confirmed, no body: the whole capture clears.
	rec = confirmedDelete(t, s, confirm(t, s, "/api/history/rows"), "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"removed":2`) {
		t.Fatalf("a confirmed clear = %d %s, want 200 removed 2", rec.Code, rec.Body.String())
	}
	if n := historyRowCount(t, s); n != 0 {
		t.Fatalf("after a confirmed clear history lists %d rows, want 0", n)
	}
}
