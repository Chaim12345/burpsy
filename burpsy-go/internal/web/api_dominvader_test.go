package web

import (
	"encoding/json"
	"github.com/burpsy-go/burpsy/internal/core"
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

// c67v: opting into probes requires an explicit technique and a bounded property
// vocabulary. A rejected combined update must not partly enable instrumentation.
func TestDomAuditorRefusesInvalidPollutionControlsBeforeChangingState(t *testing.T) {
	for _, pollution := range []map[string]any{
		{"enabled": true},
		{"enabled": true, "query": true, "properties": []string{"__proto__"}},
		{"enabled": true, "query": true, "properties": []string{"a.b"}},
	} {
		s := newTestServer()
		rec := putJSON(t, s, "/api/dominvader", map[string]any{"enabled": true, "canary": "changed", "pollution": pollution})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid pollution config accepted: %d %s", rec.Code, rec.Body.String())
		}
		if s.domInvader.Enabled() || s.domInvader.Canary() == "changed" {
			t.Fatal("refused update partly changed the auditor")
		}
	}
}

func TestDomAuditorPollutionPlanDefaultsOffAndRefusesAnOutOfScopeTarget(t *testing.T) {
	s := newTestServer()
	s.scope = core.NewScope()
	s.scope.AddInclude("allowed.example")
	if rec := get(t, s, "/api/dominvader"); !strings.Contains(rec.Body.String(), `"pollution":{"enabled":false`) {
		t.Fatalf("pollution must default off: %s", rec.Body.String())
	}
	rec := putJSON(t, s, "/api/dominvader", map[string]any{"enabled": true, "pollution": map[string]any{"enabled": true, "query": true, "target": "https://unrelated.example/a", "properties": []string{"transport_url"}}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope plan: %d %s", rec.Code, rec.Body.String())
	}
	if s.domInvader.Enabled() {
		t.Fatal("scope refusal partly enabled auditor")
	}
}

func TestDomAuditorPollutionRefusesUnconfiguredScopeAndAcceptsAnExplicitScope(t *testing.T) {
	s := newTestServer()
	body := map[string]any{"pollution": map[string]any{"enabled": true, "query": true, "hash": true, "json": true, "nested": true, "target": "https://allowed.example/a", "properties": []string{"transport_url", "html"}}}
	if rec := putJSON(t, s, "/api/dominvader", body); rec.Code != http.StatusForbidden {
		t.Fatalf("empty scope must not enable probes: %d %s", rec.Code, rec.Body.String())
	}
	s.scope.AddInclude("allowed.example")
	if rec := putJSON(t, s, "/api/dominvader", body); rec.Code != http.StatusOK {
		t.Fatalf("explicit scope refused: %d %s", rec.Code, rec.Body.String())
	}
	if !s.domInvader.Config("http://localhost/hit").Pollution.Enabled {
		t.Fatal("accepted plan never reached browser configuration")
	}
	// A malformed combined request does not change an existing plan.
	if rec := putJSON(t, s, "/api/dominvader", map[string]any{"canary": " ", "pollution": map[string]any{"enabled": false}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid canary accepted: %d", rec.Code)
	}
	if !s.domInvader.Pollution().Enabled {
		t.Fatal("invalid canary partly disabled probes")
	}
}

func TestDomAuditorScanRouteRefusesAnOffPlan(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/dominvader/scan", map[string]any{})
	if rec.Code != http.StatusConflict {
		t.Fatalf("off scan must refuse before browser allocation: %d %s", rec.Code, rec.Body.String())
	}
}
