package extscan

import (
	"os"
	"strings"
	"testing"
)

// The two testdata files are FIXTURES: real output captured from real ffuf
// 2.1.0-dev and nuclei v3.8.0 runs against a local throwaway HTTP server, saved
// so the parsers can be tested without a live target. They are evidence of what
// these tools emit, not evidence of any finding — nothing in this file scans
// anything. The live tests in live_test.go are what exercise the binaries.
const (
	ffufFixture   = "testdata/ffuf-real-output.json"
	nucleiFixture = "testdata/nuclei-real-output.jsonl"
)

func TestParseFFUFReadsRealOutput(t *testing.T) {
	doc, err := os.ReadFile(ffufFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, err := parseFFUF(doc)
	if err != nil {
		t.Fatalf("parseFFUF: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d discoveries, want 2", len(got))
	}
	byWord := map[string]Discovery{}
	for _, d := range got {
		byWord[d.Word] = d
	}
	admin, ok := byWord["admin"]
	if !ok {
		t.Fatalf("no discovery for the wordlist entry %q; got %v", "admin", byWord)
	}
	if admin.Status != 301 {
		t.Errorf("admin status = %d, want 301", admin.Status)
	}
	if admin.Path != "/admin" {
		t.Errorf("admin path = %q, want /admin", admin.Path)
	}
	if admin.Redirect != "/admin/" {
		t.Errorf("admin redirect = %q, want /admin/", admin.Redirect)
	}
	if admin.Host != "127.0.0.1:18099" {
		t.Errorf("admin host = %q, want 127.0.0.1:18099", admin.Host)
	}
}

func TestParseFFUFRefusesGarbage(t *testing.T) {
	if _, err := parseFFUF([]byte("this is not json")); err == nil {
		t.Fatal("parseFFUF accepted non-JSON input")
	}
}

func TestFFUFRowsGroupByStatus(t *testing.T) {
	doc, err := os.ReadFile(ffufFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	discoveries, err := parseFFUF(doc)
	if err != nil {
		t.Fatalf("parseFFUF: %v", err)
	}
	res := FFUFResult{Outcome: OutcomeCompleted, Discoveries: discoveries}
	rows := res.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (both discoveries are 301)", len(rows))
	}
	row := rows[0]
	if row.Occurrences != 2 || len(row.Evidence) != 2 {
		t.Errorf("occurrences = %d, evidence = %d, want 2 and 2", row.Occurrences, len(row.Evidence))
	}
	if row.Severity != "Informational" {
		t.Errorf("severity = %q; content discovery is an observation, not a vulnerability", row.Severity)
	}
	if !strings.Contains(row.Name, "301") {
		t.Errorf("row name %q does not name the status it groups", row.Name)
	}
	if row.AdvisoryNote == "" {
		t.Error("row carries no advisory note; a deliberate catalogue absence must be stated")
	}
	// A run that could not look renders no rows at all — never an empty clean report.
	notRun := FFUFResult{Outcome: OutcomeUnavailable, Discoveries: discoveries}
	if got := notRun.Rows(); got != nil {
		t.Errorf("an unavailable run produced %d rows", len(got))
	}
}

func TestParseNucleiReadsRealJSONL(t *testing.T) {
	doc, err := os.ReadFile(nucleiFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	hits, truncated, err := parseNuclei(doc)
	if err != nil {
		t.Fatalf("parseNuclei: %v", err)
	}
	if truncated {
		t.Error("the fixture is complete but parsed as truncated")
	}
	if len(hits) != 12 {
		t.Fatalf("parsed %d hits, want 12", len(hits))
	}
	seen := map[string]bool{}
	for _, h := range hits {
		seen[h.TemplateID] = true
		if h.MatchedAt == "" {
			t.Errorf("hit %q has no matched-at location", h.TemplateID)
		}
		if h.Severity == "" {
			t.Errorf("hit %q has no severity", h.TemplateID)
		}
	}
	for _, want := range []string{"tech-detect", "http-missing-security-headers"} {
		if !seen[want] {
			t.Errorf("template %q missing from the parse; got %v", want, seen)
		}
	}
}

// Log noise in the stream must not fail a scan, but a genuinely broken record
// in the middle of it must not be silently dropped either.
func TestParseNucleiSkipsNonJSONAndRefusesABrokenRecord(t *testing.T) {
	doc, err := os.ReadFile(nucleiFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	withNoise := append([]byte("[INF] Templates loaded for current scan: 894\n\n"), doc...)
	hits, _, err := parseNuclei(withNoise)
	if err != nil {
		t.Fatalf("parseNuclei rejected a stream containing a log line: %v", err)
	}
	if len(hits) != 12 {
		t.Errorf("parsed %d hits alongside log noise, want 12", len(hits))
	}

	broken := append([]byte("{\"template-id\": \"broken\", \n"), doc...)
	if _, _, err := parseNuclei(broken); err == nil {
		t.Error("a malformed record in the middle of the stream was accepted")
	}
}

// A capped capture cuts the last record in half. That is a completed-but-partial
// run, not a failed one, and the flag is how a caller can say so.
func TestParseNucleiReportsATruncatedFinalRecord(t *testing.T) {
	doc, err := os.ReadFile(nucleiFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cut := doc[:len(doc)-200]
	hits, truncated, err := parseNuclei(cut)
	if err != nil {
		t.Fatalf("parseNuclei: %v", err)
	}
	if !truncated {
		t.Error("a half-written final record did not report as truncated")
	}
	if len(hits) != 11 {
		t.Errorf("parsed %d hits from a truncated stream, want the 11 complete ones", len(hits))
	}
}

func TestNucleiRowsGroupByTemplateAndMapSeverity(t *testing.T) {
	doc, err := os.ReadFile(nucleiFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	hits, _, err := parseNuclei(doc)
	if err != nil {
		t.Fatalf("parseNuclei: %v", err)
	}
	res := NucleiResult{Outcome: OutcomeCompleted, Hits: hits}
	rows := res.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (one per template)", len(rows))
	}
	total := 0
	for _, r := range rows {
		total += r.Occurrences
		if r.Severity != "Informational" {
			t.Errorf("row %q severity = %q; both fixture templates are nuclei-severity info, "+
				"which maps to burpsy's Informational", r.Name, r.Severity)
		}
		if len(r.Evidence) != r.Occurrences {
			t.Errorf("row %q has %d evidence entries for %d occurrences", r.Name, len(r.Evidence), r.Occurrences)
		}
		if r.AdvisoryNote == "" || !strings.Contains(r.AdvisoryNote, "nuclei") {
			t.Errorf("row %q does not attribute itself to nuclei", r.Name)
		}
		if r.Remediation == "" {
			t.Errorf("row %q has no remediation text at all", r.Name)
		}
	}
	if total != 12 {
		t.Errorf("rows account for %d hits, want all 12", total)
	}
}

// Severity ordering is what makes a merged report readable, so it is pinned
// rather than left to whatever order the stream arrived in.
func TestNucleiRowsSortWorstFirst(t *testing.T) {
	res := NucleiResult{Outcome: OutcomeCompleted, Hits: []TemplateHit{
		{TemplateID: "b-info", Name: "an info thing", Severity: "info", Path: "/"},
		{TemplateID: "a-crit", Name: "a critical thing", Severity: "critical", Path: "/"},
		{TemplateID: "c-med", Name: "a medium thing", Severity: "medium", Path: "/"},
	}}
	rows := res.Rows()
	got := []string{rows[0].Severity, rows[1].Severity, rows[2].Severity}
	want := []string{"Critical", "Medium", "Informational"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row order = %v, want %v", got, want)
		}
	}
}
