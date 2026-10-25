package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// burpsy-react-ui-wl94: the auditor is off with a fresh canary by default; the operator sets the
// canary and the switch; the extension's reports arrive and the console reads them; a repeat
// collapses onto its row.
func TestDomInvaderSetReportAndRead(t *testing.T) {
	s := newTestServer()

	g := get(t, s, "/api/dominvader")
	if !strings.Contains(g.Body.String(), `"enabled":false`) || !strings.Contains(g.Body.String(), "burpsyDI") {
		t.Fatalf("default view = %s", g.Body.String())
	}

	if rec := putJSON(t, s, "/api/dominvader", map[string]any{"canary": "myMark", "enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if !s.domInvader.Enabled() || s.domInvader.Canary() != "myMark" {
		t.Errorf("state not applied: enabled %v canary %q", s.domInvader.Enabled(), s.domInvader.Canary())
	}
	if rec := putJSON(t, s, "/api/dominvader", map[string]any{"canary": "  "}); rec.Code != http.StatusBadRequest {
		t.Errorf("an empty canary = %d, want 400", rec.Code)
	}

	// The extension reports two hits, the second a repeat of the first.
	hit := map[string]any{"kind": "sink", "sink": "innerHTML", "sources": []string{"location.hash"}, "excerpt": "<img src=x onerror=myMark>", "dedupe": "d1"}
	for i := 0; i < 2; i++ {
		if rec := postJSON(t, s, "/api/dominvader/hit", hit); rec.Code != http.StatusNoContent {
			t.Fatalf("POST hit = %d: %s", rec.Code, rec.Body.String())
		}
	}
	if rec := postJSON(t, s, "/api/dominvader/hit", map[string]any{"kind": "source", "sink": "postMessage", "dedupe": "d2"}); rec.Code != http.StatusNoContent {
		t.Fatalf("POST source hit = %d", rec.Code)
	}
	if rec := postJSON(t, s, "/api/dominvader/hit", map[string]any{"kind": "sink"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a hit without a sink name = %d, want 400", rec.Code)
	}

	g = get(t, s, "/api/dominvader")
	var view domInvaderView
	if err := json.Unmarshal(g.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Hits) != 2 {
		t.Fatalf("hits = %d, want 2 (the repeat collapsed)", len(view.Hits))
	}
	if view.Hits[0].Sink != "innerHTML" || view.Hits[0].Sources[0] != "location.hash" {
		t.Errorf("first hit = %+v", view.Hits[0])
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/dominvader/hits", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, del)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE hits = %d", rec.Code)
	}
	if g := get(t, s, "/api/dominvader"); !strings.Contains(g.Body.String(), `"hits":[]`) {
		t.Errorf("hits not cleared: %s", g.Body.String())
	}
}

func TestDomMessageWorkerRoutesRefuseMissingStaleAndWrongCapabilities(t *testing.T) {
	s := newTestServer()
	launch := s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	for _, path := range []string{"/api/dominvader/messages/register", "/api/dominvader/messages/report", "/api/dominvader/messages/poll"} {
		for _, capability := range []string{"", "wrong", launch.WorkerCapability} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("X-Burpsy-DOM-Worker", capability)
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("worker route %s accepted invalid capability: %d", path, rec.Code)
			}
		}
	}
}

func TestDomMessageWorkerRegistrationRequiresCapabilityAndDoesNotExposeItToConsole(t *testing.T) {
	s := newTestServer()
	launch := s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	req := httptest.NewRequest(http.MethodPost, "/api/dominvader/messages/register", strings.NewReader(`{"tab":4,"frame":"0"}`))
	req.Header.Set("X-Burpsy-DOM-Worker", launch.WorkerCapability)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized worker refused %d %s", rec.Code, rec.Body.String())
	}
	var frame struct {
		Token string `json:"frame_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Token == "" {
		t.Fatal("worker received empty frame session")
	}
	view := get(t, s, "/api/dominvader")
	if strings.Contains(view.Body.String(), launch.WorkerCapability) || strings.Contains(view.Body.String(), frame.Token) {
		t.Fatal("private capability leaked into console view")
	}
	for _, path := range []string{"/worker-config.js", "/api/dominvader/worker-config.js"} {
		rec := get(t, s, path)
		if strings.Contains(rec.Body.String(), launch.WorkerCapability) {
			t.Fatalf("worker capability served to page at %s", path)
		}
	}
}
