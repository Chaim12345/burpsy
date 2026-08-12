package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// UX-15.
//
// core.Exchange carried Notes but nothing could write it, and there was no highlight field at all:
// "Add to Organizer" filed a *copy* of the row in a different tool instead of annotating the row
// itself. This adds PATCH /api/exchange/{id} — {"notes": string|null, "highlight": string}, both
// optional — as the one route that closes both gaps at once.

// patchJSON performs a PATCH of body to the server's mux and returns the response.
func patchJSON(t *testing.T, s *Server, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// addTestExchange puts a minimal request/response pair through the store and returns the resulting
// exchange's id.
func addTestExchange(t *testing.T, s *Server) core.ExchangeID {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET /x HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/x"}
	s.store.AddExchange(ex)
	return ex.ID
}

func TestPatchExchangeStoresHighlightAndNotes_UX15(t *testing.T) {
	s := newTestServer()
	id := addTestExchange(t, s)

	notes := "worth a second look"
	rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"notes": notes, "highlight": "cyan"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	var view ExchangeView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if view.Highlight != "cyan" {
		t.Errorf("response highlight = %q, want %q", view.Highlight, "cyan")
	}
	if view.Notes == nil || *view.Notes != notes {
		t.Errorf("response notes = %v, want %q", view.Notes, notes)
	}

	// The store itself, not just the echoed response.
	ex, err := s.store.GetExchange(id)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	if ex.Highlight != "cyan" {
		t.Errorf("stored highlight = %q, want %q", ex.Highlight, "cyan")
	}
	if ex.Notes == nil || *ex.Notes != notes {
		t.Errorf("stored notes = %v, want %q", ex.Notes, notes)
	}
}

func TestPatchExchangeRejectsAnUnknownHighlightColour_UX15(t *testing.T) {
	s := newTestServer()
	addTestExchange(t, s)

	for _, bad := range []string{"none", "purple", "RED", " red", ""} {
		if bad == "" {
			// "" is the wire spelling of "no highlight" and must be accepted, not rejected — tested
			// separately below via the omitted-field case. Skip it here.
			continue
		}
		t.Run(bad, func(t *testing.T) {
			rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"highlight": bad})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PATCH highlight=%q: status = %d (%s), want 400 — %q is not a member of "+
					"core.ValidHighlights and must never be coerced into one", bad, rec.Code, rec.Body.String(), bad)
			}
		})
		ex, err := s.store.GetExchange(0)
		if err != nil {
			t.Fatalf("GetExchange: %v", err)
		}
		if ex.Highlight != "" {
			t.Errorf("after a rejected PATCH(highlight=%q), stored highlight = %q, want unchanged (\"\")", bad, ex.Highlight)
		}
	}

	// The empty string ("none") is not in ValidHighlights but is the one value that must be accepted.
	rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"highlight": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf(`PATCH highlight="": status = %d (%s), want 200 — "" clears the highlight rather than being an unknown colour`,
			rec.Code, rec.Body.String())
	}
}

func TestPatchExchangeLeavesOmittedFieldsUnchanged_UX15(t *testing.T) {
	s := newTestServer()
	addTestExchange(t, s)

	notes := "keep me"
	if rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"notes": notes, "highlight": "green"}); rec.Code != http.StatusOK {
		t.Fatalf("seed PATCH: status = %d (%s)", rec.Code, rec.Body.String())
	}

	// An omitted highlight leaves the existing colour alone.
	rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"notes": "still here"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH notes only: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	ex, err := s.store.GetExchange(0)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	if ex.Highlight != "green" {
		t.Errorf("highlight after an omitted-highlight PATCH = %q, want unchanged %q", ex.Highlight, "green")
	}
	if ex.Notes == nil || *ex.Notes != "still here" {
		t.Errorf("notes = %v, want %q", ex.Notes, "still here")
	}

	// An omitted notes field leaves the existing note alone; an explicit null clears it.
	if rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"highlight": "blue"}); rec.Code != http.StatusOK {
		t.Fatalf("PATCH highlight only: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	ex, err = s.store.GetExchange(0)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	if ex.Notes == nil || *ex.Notes != "still here" {
		t.Errorf("notes after an omitted-notes PATCH = %v, want unchanged %q", ex.Notes, "still here")
	}

	if rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"notes": nil}); rec.Code != http.StatusOK {
		t.Fatalf("PATCH notes=null: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	ex, err = s.store.GetExchange(0)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	if ex.Notes != nil {
		t.Errorf("notes after PATCH notes=null = %v, want nil", ex.Notes)
	}
	if ex.Highlight != "blue" {
		t.Errorf("highlight after PATCH notes=null = %q, want unchanged %q", ex.Highlight, "blue")
	}
}

// The durable half: an annotation has to survive a restart the same way the traffic it is attached to
// does, or "the highlight didn't stick" becomes a bug report the moment burpsy is restarted.
func TestExchangeHighlightSurvivesAReload_UX15(t *testing.T) {
	p, err := persist.Open(filepath.Join(t.TempDir(), "highlight.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer p.Close()

	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	s := NewServer(store, core.NewScope())

	addTestExchange(t, s)
	notes := "survives a restart"
	if rec := patchJSON(t, s, "/api/exchange/0", map[string]any{"notes": notes, "highlight": "magenta"}); rec.Code != http.StatusOK {
		t.Fatalf("PATCH: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	restored := core.NewTrafficStore()
	if err := p.Restore(restored, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	ex, err := restored.GetExchange(0)
	if err != nil {
		t.Fatalf("GetExchange(0) after restore: %v", err)
	}
	if ex.Highlight != "magenta" {
		t.Errorf("restored highlight = %q, want %q", ex.Highlight, "magenta")
	}
	if ex.Notes == nil || *ex.Notes != notes {
		t.Errorf("restored notes = %v, want %q", ex.Notes, notes)
	}
}
