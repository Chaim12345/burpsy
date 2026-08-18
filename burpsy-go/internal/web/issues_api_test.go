package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

func TestIssuesReportsEnabledWhenBChecksLoaded(t *testing.T) {
	dir := t.TempDir()
	const src = `
metadata:
  language: v1-beta
  name: "noop"
given response then
  if {latest.response.body} contains "never" then
      report issue:
          severity: info
          confidence: certain
          detail: "nope"
  end if
`
	if err := os.WriteFile(filepath.Join(dir, "noop.bcheck"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	store := core.NewTrafficStore()
	scope := core.NewScope()
	ps, err := scanner.LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	s := newTestServer().WithPassiveScanner(ps).WithFindings(core.NewFindingStore())
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != true {
		t.Errorf("enabled = %v, want true", body["enabled"])
	}
	if loaded, _ := body["loaded"].(float64); loaded != 1 {
		t.Errorf("loaded = %v, want 1", body["loaded"])
	}
}

// /api/issues must not report that passive scanning is off while serving findings it produced.
//
// `enabled` used to be defined as "a BCheck corpus is loaded", but the UI reads it as "passive
// scanning is in force" — scanner.tsx renders a warning banner reading "passive scanning is not
// enabled" whenever it is false. The built-in passive checks run with or without a corpus, so a
// server started without --bchecks served that banner directly above a list of hundreds of real
// findings, telling the operator to go and enable the thing that had evidently already run.
//
// The two facts stay separate: `loaded` is still the exact corpus count (zero here), and the hint
// still says no corpus is loaded — it just no longer contradicts the findings beside it.
func TestIssuesDoesNotClaimScanningIsOffWhileServingFindings(t *testing.T) {
	findings := core.NewFindingStore()
	findings.Add(core.NewFinding{
		Name:       "Missing X-Frame-Options Header",
		Severity:   core.SeverityLow,
		Confidence: core.ConfidenceCertain,
	})

	// No passive scanner attached: exactly the shipped default, and the case that misreported.
	s := newTestServer().WithFindings(findings)
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	list, _ := body["findings"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("findings = %d, want 1", len(list))
	}
	if body["enabled"] != true {
		t.Errorf("enabled = %v while serving %d finding(s): the response contradicts itself",
			body["enabled"], len(list))
	}
	if loaded, _ := body["loaded"].(float64); loaded != 0 {
		t.Errorf("loaded = %v, want 0 — the corpus count must stay exact", body["loaded"])
	}
	if hint, _ := body["hint"].(string); strings.Contains(hint, "is not enabled") {
		t.Errorf("hint = %q, which still asserts scanning is off alongside real findings", hint)
	}
}

// With no findings and no corpus there is genuinely nothing running, and the response says so. The
// fix must not make `enabled` unconditionally true.
func TestIssuesStillReportsDisabledWhenNothingHasRun(t *testing.T) {
	s := newTestServer().WithFindings(core.NewFindingStore())
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != false {
		t.Errorf("enabled = %v, want false: no corpus and no findings", body["enabled"])
	}
	if hint, _ := body["hint"].(string); !strings.Contains(hint, "--bchecks") {
		t.Errorf("hint = %q, want it to name --bchecks", hint)
	}
}
