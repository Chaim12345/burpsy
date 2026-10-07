package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// triageSeed puts two findings in the server's store and returns their ids. Every test here needs
// something to triage; the second finding exists so a test can prove the write is scoped to one
// row rather than the store.
func triageSeed(t *testing.T, s *Server) (uint64, uint64) {
	t.Helper()
	idA := s.findings.Add(core.NewFinding{
		Name:     "Reflected XSS",
		Severity: core.SeverityHigh,
		Target:   core.FindingTarget{Host: "app.test", Port: 80, Path: "/search"},
	})
	idB := s.findings.Add(core.NewFinding{
		Name:     "Missing header",
		Severity: core.SeverityLow,
		Target:   core.FindingTarget{Host: "app.test", Port: 80, Path: "/other"},
	})
	return idA, idB
}

// triagedView decodes the view of one finding out of GET /api/issues.
func triagedView(t *testing.T, s *Server, id uint64) map[string]interface{} {
	t.Helper()
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var body struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, f := range body.Findings {
		if uint64(f["id"].(float64)) == id {
			return f
		}
	}
	t.Fatalf("finding %d not in /api/issues response", id)
	return nil
}

func putIssue(t *testing.T, s *Server, id string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/issues/"+id, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// The PUT path: a severity override shows up as the effective severity, the engine's original
// rides alongside.
func TestIssueTriageSetsSeverityOverride(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	idA, _ := triageSeed(t, s)

	if rec := putIssue(t, s, "0", map[string]interface{}{"severity": "info"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/issues/0: %d %s", rec.Code, rec.Body.String())
	}

	view := triagedView(t, s, idA)
	if view["severity"] != "Informational" {
		t.Errorf("severity = %v, want Informational (the override)", view["severity"])
	}
	if view["original_severity"] != "High" {
		t.Errorf("original_severity = %v, want High (the engine's report)", view["original_severity"])
	}
	if view["severity_override"] != "Informational" {
		t.Errorf("severity_override = %v, want Informational", view["severity_override"])
	}
}

func TestIssueTriageCountsFollowOverrideAndExcludedFalsePositives(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	_, _ = triageSeed(t, s)

	// A: high -> informational; B: marked a false positive. The headline should now say one
	// informational finding and one excluded, with no high or low buckets left.
	if rec := putIssue(t, s, "0", map[string]interface{}{"severity": "informational"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT severity: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putIssue(t, s, "1", map[string]interface{}{"false_positive": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT false_positive: %d %s", rec.Code, rec.Body.String())
	}

	rec := get(t, s, "/api/issues")
	var body struct {
		Counts         map[string]int `json:"counts"`
		Counted        int            `json:"counted"`
		FalsePositives int            `json:"false_positives"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Counts["informational"] != 1 {
		t.Errorf("counts[informational] = %d, want 1 (override applied)", body.Counts["informational"])
	}
	if body.Counts["high"] != 0 || body.Counts["low"] != 0 {
		t.Errorf("counts = %v, want high and low empty (override + false positive)", body.Counts)
	}
	if body.FalsePositives != 1 {
		t.Errorf("false_positives = %d, want 1", body.FalsePositives)
	}
	if body.Counted != 1 {
		t.Errorf("counted = %d, want 1 (two findings, one excluded)", body.Counted)
	}
}

func TestIssueTriageFalsePositiveAndCommentRoundTrip(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	idA, _ := triageSeed(t, s)

	if rec := putIssue(t, s, "0", map[string]interface{}{
		"false_positive": true,
		"comment":        "parameter is not reflected on any live page",
	}); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}

	view := triagedView(t, s, idA)
	if view["false_positive"] != true {
		t.Errorf("false_positive = %v, want true", view["false_positive"])
	}
	if view["comment"] != "parameter is not reflected on any live page" {
		t.Errorf("comment = %v", view["comment"])
	}
}

func TestIssueTriageClearsOverrideWithEmptyString(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	idA, _ := triageSeed(t, s)

	putIssue(t, s, "0", map[string]interface{}{"severity": "low"})
	putIssue(t, s, "0", map[string]interface{}{"severity": ""})

	view := triagedView(t, s, idA)
	if view["severity"] != "High" {
		t.Errorf("severity = %v, want High (engine value restored)", view["severity"])
	}
	if _, ok := view["severity_override"]; ok {
		t.Errorf("severity_override = %v, want absent once cleared", view["severity_override"])
	}
}

func TestIssueTriageRejectsUnknownSeverityAndConfidence(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	_, _ = triageSeed(t, s)

	for _, tc := range []struct{ field, value string }{
		{"severity", "catastrophic"},
		{"confidence", "sure"},
	} {
		raw, err := json.Marshal(map[string]string{tc.field: tc.value})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPut, "/api/issues/0", bytes.NewReader(raw))
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s=%q: %d, want 400 — Parse* fallbacks must not reclassify silently", tc.field, tc.value, rec.Code)
		}
	}
}

func TestIssueTriageMissingIDIs404(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	_, _ = triageSeed(t, s)

	if rec := putIssue(t, s, "999", map[string]interface{}{"comment": "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("PUT /api/issues/999: %d, want 404", rec.Code)
	}
}

func TestIssueDeleteRemovesFinding(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	idA, idB := triageSeed(t, s)

	req := httptest.NewRequest(http.MethodDelete, "/api/issues/0", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /api/issues/0: %d, want 204", rec.Code)
	}

	if _, err := s.findings.Get(idA); err == nil {
		t.Error("finding 0 still in store after DELETE")
	}
	// The sibling is untouched: the write is one row.
	if _, err := s.findings.Get(idB); err != nil {
		t.Errorf("finding 1 missing after deleting 0: %v", err)
	}

	// Deleting again is 404, not a silent success.
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/issues/0", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("second DELETE: %d, want 404", rec.Code)
	}
}
