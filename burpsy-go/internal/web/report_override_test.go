package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// A report is the document triage exists to produce, so it must not be the one surface that
// ignores it (burpsy-react-ui-5qfr).
//
// api_capture.go's findingToIssueView has always used EffectiveSeverity/EffectiveConfidence, so
// the Issues page showed the operator's override while the export showed the engine's original.
// api_report_filter_test.go seeds raw severities only, so nothing failed.

func reportServerWithOverriddenFinding(t *testing.T) *Server {
	t.Helper()
	srv := NewServer(core.NewTrafficStore(), core.NewScope())
	// Added at the engine's severity, then triaged — the real sequence, rather than a finding
	// constructed already-overridden, so the test also proves Triage is what the export reads.
	id := srv.findings.Add(core.NewFinding{
		Name:       "raised by the operator",
		Severity:   core.SeverityLow,
		Confidence: core.ConfidenceTentative,
	})
	critical := core.SeverityCritical
	certain := core.ConfidenceCertain
	if !srv.findings.Triage(id, func(f *core.Finding) {
		f.SeverityOverride = &critical
		// Confidence is overridden too: both are read from the same struct by the same code, so
		// testing one and not the other would leave half the fix unpinned.
		f.ConfidenceOverride = &certain
	}) {
		t.Fatalf("setup: Triage did not find finding %d", id)
	}
	return srv
}

func reportJSON(t *testing.T, srv *Server, query string) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/report/json"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/report/json%s -> %d: %s", query, rec.Code, rec.Body.String())
	}
	var payload struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		// Some report shapes are a bare array; fall back rather than assume.
		var bare []map[string]any
		if err2 := json.Unmarshal(rec.Body.Bytes(), &bare); err2 != nil {
			t.Fatalf("decode report: %v / %v\n%s", err, err2, rec.Body.String())
		}
		return bare
	}
	return payload.Findings
}

func TestTheExportCarriesTheOperatorsSeverityNotTheEnginesOriginal(t *testing.T) {
	srv := reportServerWithOverriddenFinding(t)

	rows := reportJSON(t, srv, "")
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if got := strings.ToLower(asString(rows[0]["severity"])); got != "critical" {
		t.Errorf("severity = %q, want critical — the Issues page shows the override and the export must agree", got)
	}
	if got := strings.ToLower(asString(rows[0]["confidence"])); got != "certain" {
		t.Errorf("confidence = %q, want certain", got)
	}
}

// The filter is the half that fails in both directions, and it is the worse half: a report
// filtered to critical silently omitted the finding the operator had just raised to critical.
func TestTheExportsSeverityFilterSelectsOnTheOverride(t *testing.T) {
	srv := reportServerWithOverriddenFinding(t)

	if rows := reportJSON(t, srv, "?severity=critical"); len(rows) != 1 {
		t.Errorf("?severity=critical returned %d rows, want 1 — the override IS the severity", len(rows))
	}
	if rows := reportJSON(t, srv, "?severity=low"); len(rows) != 0 {
		t.Errorf("?severity=low returned %d rows, want 0 — the engine's original is no longer this finding's severity", len(rows))
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
