package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

// A merged finding must not lose the parameters it covers on the way to the UI. Five reflected-XSS
// hits on one endpoint become one row with five occurrences, and `params` is the field that keeps
// that row as actionable as the five separate rows it replaced.
func TestIssuesSurfacesMergedParams(t *testing.T) {
	findings := core.NewFindingStore()
	target := core.FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/search"}
	for i, p := range []string{"q", "sort", "page", "lang", "ref"} {
		findings.Add(core.NewFinding{
			Name:       "Cross-site scripting (reflected)",
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceFirm,
			Param:      p,
			Target:     target,
			Occurrences: []core.Occurrence{{
				ExchangeID: core.ExchangeID(i),
				Request:    core.MsgPtr(core.MsgId(i * 2)),
			}},
		})
	}

	s := newTestServer().WithFindings(findings)
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var body struct {
		Findings []struct {
			Params    []string `json:"params"`
			TimesSeen int      `json:"times_seen"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 merged row", len(body.Findings))
	}
	if body.Findings[0].TimesSeen != 5 {
		t.Errorf("times_seen = %d, want 5", body.Findings[0].TimesSeen)
	}
	want := []string{"q", "sort", "page", "lang", "ref"}
	if len(body.Findings[0].Params) != len(want) {
		t.Fatalf("params = %v, want %v", body.Findings[0].Params, want)
	}
	for i, p := range want {
		if body.Findings[0].Params[i] != p {
			t.Errorf("params[%d] = %q, want %q", i, body.Findings[0].Params[i], p)
		}
	}
}

// The list the console refetches on every issues event must not carry each finding's prose.
//
// A few thousand findings, each with its detail and a copy of the catalogue advisory, is a
// multi-megabyte document. The shell's issue badge is mounted on every page and the Issues tree
// only paints a window of rows, so both of those reads are a summary: the prose is GET
// /api/issues/{id}, fetched for the one row that is open. The count read is smaller still — the
// badge does not need a row per finding at all.
func TestTheIssueListSummaryOmitsProseAndTheCountSendsNoRows(t *testing.T) {
	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte("GET /admin HTTP/1.1\r\nHost: app.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: "app.test", Port: 80, Method: "GET", Path: "/admin",
	})
	const prose = "UNIQUE-DETAIL-the operator reads this on the open issue, not in the list"
	findings := core.NewFindingStore()
	id := findings.Add(core.NewFinding{
		Name:        "Admin panel",
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceCertain,
		Description: prose,
		Remediation: "UNIQUE-REMEDIATION-do not list this",
		Evidence:    "UNIQUE-EVIDENCE-do not list this",
		Occurrences: []core.Occurrence{{Request: core.MsgPtr(reqID), Response: &respID}},
	})
	s := NewServer(store, core.NewScope()).WithFindings(findings)

	summary := get(t, s, "/api/issues?summary=1")
	if summary.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", summary.Code, summary.Body.String())
	}
	raw := summary.Body.String()
	for _, leaked := range []string{prose, "UNIQUE-REMEDIATION", "UNIQUE-EVIDENCE"} {
		if strings.Contains(raw, leaked) {
			t.Errorf("summary list contains %q; that text belongs on the open issue, not the list", leaked)
		}
	}
	if !strings.Contains(raw, `"host":"app.test"`) || !strings.Contains(raw, `"path":"/admin"`) {
		t.Errorf("summary list lost the exchange it was observed on: %s", raw)
	}

	count := get(t, s, "/api/issues?count=1")
	if count.Code != http.StatusOK {
		t.Fatalf("count: %d %s", count.Code, count.Body.String())
	}
	var counted struct {
		Counted  int               `json:"counted"`
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(count.Body.Bytes(), &counted); err != nil {
		t.Fatal(err)
	}
	if counted.Counted != 1 {
		t.Errorf("counted = %d, want 1", counted.Counted)
	}
	if len(counted.Findings) != 0 {
		t.Errorf("count response has %d findings; the badge must not receive a row per issue", len(counted.Findings))
	}
	if strings.Contains(count.Body.String(), prose) {
		t.Errorf("count response contains the finding prose")
	}

	one := get(t, s, "/api/issues/"+strconv.FormatUint(id, 10))
	if one.Code != http.StatusOK {
		t.Fatalf("GET one: %d %s", one.Code, one.Body.String())
	}
	if !strings.Contains(one.Body.String(), prose) {
		t.Errorf("the open issue does not carry its detail: %s", one.Body.String())
	}
}
