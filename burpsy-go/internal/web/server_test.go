package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// newTestServer builds a server with a fresh store and scope, the minimal
// wiring every API test in this package shares.
func newTestServer() *Server {
	return NewServer(core.NewTrafficStore(), core.NewScope())
}

// postJSON performs a POST of body to the server's mux and returns the response.
func postJSON(t *testing.T, s *Server, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// scopeKinds decodes the GET /api/scope response (the TS ScopeInfo shape:
// {allow_all, rules:[{kind:"Include"|"Exclude", host}], empty}) into a
// lowercased kind -> pattern list.
func scopeKinds(t *testing.T, rec *httptest.ResponseRecorder) map[string][]string {
	t.Helper()
	var body struct {
		AllowAll bool `json:"allow_all"`
		Rules    []struct {
			Kind string  `json:"kind"`
			Host *string `json:"host"`
		} `json:"rules"`
		Empty bool `json:"empty"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode scope response %q: %v", rec.Body.String(), err)
	}
	out := map[string][]string{}
	for _, rule := range body.Rules {
		kind := strings.ToLower(rule.Kind)
		host := ""
		if rule.Host != nil {
			host = *rule.Host
		}
		out[kind] = append(out[kind], host)
	}
	return out
}

func TestScopePostRemoveTakesARuleOutOfScope(t *testing.T) {
	s := newTestServer()

	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": "a.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("add include: status = %d, want 200", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "exclude", "pattern": "b.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("add exclude: status = %d, want 200", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "remove", "pattern": "b.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("remove: status = %d, want 200", rec.Code)
	}

	kinds := scopeKinds(t, get(t, s, "/api/scope"))
	if len(kinds["exclude"]) != 0 {
		t.Errorf("excludes = %v, want none after remove", kinds["exclude"])
	}
	if len(kinds["include"]) != 1 || kinds["include"][0] != "a.example.com" {
		t.Errorf("includes = %v, want [a.example.com] after remove", kinds["include"])
	}
}

func TestScopePostClearLeavesNoRules(t *testing.T) {
	s := newTestServer()

	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": "a.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("add include: status = %d, want 200", rec.Code)
	}

	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "clear"}); rec.Code != http.StatusOK {
		t.Fatalf("clear: status = %d, want 200", rec.Code)
	}

	kinds := scopeKinds(t, get(t, s, "/api/scope"))
	if len(kinds["include"]) != 0 || len(kinds["exclude"]) != 0 {
		t.Errorf("scope after clear = %v, want empty", kinds)
	}
}

// With no WebSocket relay the connections and history endpoints honestly report an empty capture
// surface, so the WS History tab renders its empty state rather than fabricated rows.
func TestWSConnectionsAndHistoryReportEmptyCapture(t *testing.T) {
	s := newTestServer()

	var conns []map[string]interface{}
	if rec := get(t, s, "/api/ws/connections"); rec.Code != http.StatusOK {
		t.Fatalf("connections: status = %d, want 200", rec.Code)
	} else if err := json.Unmarshal(rec.Body.Bytes(), &conns); err != nil {
		t.Fatalf("decode connections: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("connections = %v, want empty", conns)
	}

	var history struct {
		Rows  []map[string]interface{} `json:"rows"`
		Total int                      `json:"total"`
	}
	if rec := get(t, s, "/api/ws/history"); rec.Code != http.StatusOK {
		t.Fatalf("history: status = %d, want 200", rec.Code)
	} else if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if history.Total != 0 || len(history.Rows) != 0 {
		t.Errorf("history = %+v, want empty rows/total", history)
	}

	if rec := get(t, s, "/api/ws/message/1"); rec.Code != http.StatusNotFound {
		t.Errorf("message: status = %d, want 404 (no WS traffic captured)", rec.Code)
	}
}

// Report exports produce valid documents in each requested format.
func TestReportExportsJSONAndSARIF(t *testing.T) {
	s := newTestServer()

	rec := get(t, s, "/api/report/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("json report: status = %d, want 200", rec.Code)
	}
	var doc struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("json report is not valid JSON: %v", err)
	}
	if doc.Total != 0 {
		t.Errorf("json report total = %d, want 0 (no findings)", doc.Total)
	}

	rec = get(t, s, "/api/report/sarif")
	if rec.Code != http.StatusOK {
		t.Fatalf("sarif report: status = %d, want 200", rec.Code)
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []map[string]interface{} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sarif); err != nil {
		t.Fatalf("sarif report is not valid JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", sarif.Version)
	}

	rec = get(t, s, "/api/report/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("html report: status = %d, want 200", rec.Code)
	}
	// Matched on the prefix, not on a literal "<html>": the document carries lang="en" (WCAG 3.1.1,
	// so a screen reader picks the right pronunciation) and a stylesheet, and an assertion that
	// pinned the exact opening tag would fail the report for getting better.
	body := rec.Body.String()
	for _, want := range []string{"<!DOCTYPE html>", "<html lang=", "<style>", "burpsy scan report"} {
		if !strings.Contains(body, want) {
			t.Errorf("html report is missing %q; it must be a complete, styled document: %q", want, body)
		}
	}
}
