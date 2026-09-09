package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The report honours a filter (burpsy-react-ui-8r6): severity as a comma list, host as a
// substring, false positives excluded on request — the axes the Issues page already filters
// by, so "the High and Critical findings on this host" is the query string rather than a
// manual pass over the whole-store export.

// seedReportFindings loads three findings covering every axis: a High on shop.test, a Low on
// shop.test marked false-positive, and a Medium on other.test.
func seedReportFindings(t *testing.T, s *Server) {
	t.Helper()
	put := func(name, host, severity string, fp bool) {
		// An occurrence backed by a real exchange: findingHosts resolves hosts from the
		// occurrence's exchange, so the host axis has something to match against.
		reqID, err := s.store.Put([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		ex := &core.Exchange{Host: host, Port: 443, TLS: true, Method: "GET", Path: "/", Request: reqID}
		s.store.AddExchange(ex)
		id := s.findings.Add(core.NewFinding{
			Name:       name,
			Severity:   severityFor(severity),
			Confidence: core.ConfidenceFirm,
			Occurrences: []core.Occurrence{{
				ExchangeID: ex.ID,
				Request:    reqID,
			}},
			Target: core.FindingTarget{Host: host, Port: 443, TLS: true},
		})
		if fp {
			s.findings.Triage(id, func(f *core.Finding) { f.FalsePositive = true })
		}
	}
	put("SQL injection", "shop.test", "high", false)
	put("Cookie without flag", "shop.test", "low", true)
	put("Frameable response", "other.test", "medium", false)
}

func severityFor(name string) core.Severity {
	switch name {
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	default:
		return core.SeverityLow
	}
}

func reportNames(t *testing.T, s *Server, query string) []string {
	t.Helper()
	rec := get(t, s, "/api/report/json"+query)
	if rec.Code != http.StatusOK {
		t.Fatalf("report answered %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Rows []struct {
			Name string `json:"name"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	names := make([]string, 0, len(body.Rows))
	for _, r := range body.Rows {
		names = append(names, r.Name)
	}
	return names
}

func reportContains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// No filter: the whole store, exactly what the unparameterised URL always meant.
func TestTheUnfilteredReportCarriesEverything(t *testing.T) {
	s := newTestServer()
	seedReportFindings(t, s)
	names := reportNames(t, s, "")
	if !reportContains(names, "SQL injection") || !reportContains(names, "Cookie without flag") || !reportContains(names, "Frameable response") {
		t.Fatalf("unfiltered report = %v, want all three", names)
	}
}

// Severity as a comma list keeps the named severities and drops the rest.
func TestTheReportFiltersBySeverity(t *testing.T) {
	s := newTestServer()
	seedReportFindings(t, s)
	names := reportNames(t, s, "?severity=high,medium")
	if reportContains(names, "Cookie without flag") {
		t.Errorf("a Low finding survived severity=high,medium: %v", names)
	}
	if !reportContains(names, "SQL injection") || !reportContains(names, "Frameable response") {
		t.Errorf("the named severities were dropped: %v", names)
	}
}

// Host as a substring over the finding's hosts.
func TestTheReportFiltersByHostSubstring(t *testing.T) {
	s := newTestServer()
	seedReportFindings(t, s)
	names := reportNames(t, s, "?host=shop.test")
	if reportContains(names, "Frameable response") {
		t.Errorf("other.test survived host=shop.test: %v", names)
	}
	if !reportContains(names, "SQL injection") {
		t.Errorf("the shop.test finding was dropped: %v", names)
	}
}

// False positives excluded on request — the operator's triage decision respected in the export.
func TestTheReportCanExcludeFalsePositives(t *testing.T) {
	s := newTestServer()
	seedReportFindings(t, s)
	with := reportNames(t, s, "")
	if !reportContains(with, "Cookie without flag") {
		t.Fatalf("setup: the false positive should be present unfiltered: %v", with)
	}
	names := reportNames(t, s, "?exclude_false_positives=true")
	if reportContains(names, "Cookie without flag") {
		t.Errorf("a false positive survived exclude_false_positives=true: %v", names)
	}
	if !reportContains(names, "SQL injection") {
		t.Errorf("the real finding was dropped by the false-positive filter: %v", names)
	}
}

// The axes compose: severity AND host AND false-positive exclusion in one query.
func TestTheReportFiltersCompose(t *testing.T) {
	s := newTestServer()
	seedReportFindings(t, s)
	names := reportNames(t, s, "?severity=low,high&host=shop&exclude_false_positives=true")
	if len(names) != 1 || !reportContains(names, "SQL injection") {
		t.Fatalf("composed filter = %v, want exactly the one High on shop.test that is not a false positive", names)
	}
}

// An unknown severity value is refused rather than ignored — a filter parameter that silently
// does not filter would produce a report claiming to be the filtered set while carrying
// everything.
func TestTheReportRefusesAnUnknownSeverity(t *testing.T) {
	s := newTestServer()
	seedReportFindings(t, s)
	rec := get(t, s, "/api/report/json?severity=high,higy")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("severity=higy answered %d, want 400 — a typo must not silently become informational", rec.Code)
	}
}
