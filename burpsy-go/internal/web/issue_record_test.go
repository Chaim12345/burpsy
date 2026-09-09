package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Record an issue (burpsy-react-ui-4qqz): the operator's hand-recorded finding, attached to one
// exchange — Burp's "Record an issue" context-menu action. The recorded issue is a first-class
// finding: it rides the same store, the same triage endpoints and the same persistence as a
// scanner-produced one.

// putExchange stores one exchange so a record target exists.
func putExchangeForRecord(t *testing.T, s *Server) uint64 {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET /login HTTP/1.1\r\nHost: shop.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{
		Host:    "shop.test",
		Port:    443,
		TLS:     true,
		Method:  "GET",
		Path:    "/login",
		Request: reqID,
	}
	s.store.AddExchange(ex)
	return uint64(ex.ID)
}

func recordIssue(t *testing.T, s *Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	rec := postJSON(t, s, "/api/issues/record", body)
	var out map[string]any
	if rec.Code >= 200 && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

// The core loop: record against an exchange, and the finding exists with the operator's name,
// the exchange as its occurrence, Certain confidence and a jumpable exchange id. Exchange 0 is
// a real id — the stores are dense counters from zero — so the test pins the first exchange
// explicitly: a field-absence check must not reject it.
func TestAnIssueCanBeRecordedByHandAgainstAnExchange(t *testing.T) {
	s := newTestServer()
	exchangeID := putExchangeForRecord(t, s)

	code, out := recordIssue(t, s, map[string]any{
		"name":        "Login accepts weak passwords",
		"description": "Tried password '123456' and it was accepted.",
		"severity":    "high",
		"exchange_id": exchangeID,
	})
	if code != http.StatusCreated {
		t.Fatalf("record answered %d (%s), want 201", code, out)
	}
	id := uint64(out["id"].(float64))

	finding, err := s.findings.Get(id)
	if err != nil {
		t.Fatalf("recorded finding %d not found: %v", id, err)
	}
	if finding.Name != "Login accepts weak passwords" {
		t.Errorf("name = %q", finding.Name)
	}
	if finding.EffectiveSeverity() != core.SeverityHigh {
		t.Errorf("severity = %v, want High", finding.EffectiveSeverity())
	}
	// Certain is the operator's own certainty — stronger evidence than any scanner produces,
	// so a hand record does not inherit the scanner default of Tentative.
	if finding.EffectiveConfidence() != core.ConfidenceCertain {
		t.Errorf("confidence = %v, want Certain", finding.EffectiveConfidence())
	}
	if len(finding.Occurrences) != 1 || finding.Occurrences[0].ExchangeID != core.ExchangeID(exchangeID) {
		t.Fatalf("occurrences = %+v, want exactly the recorded exchange", finding.Occurrences)
	}
	if finding.Target.Host != "shop.test" || finding.Target.Port != 443 || !finding.Target.TLS {
		t.Errorf("target = %+v, want shop.test:443 tls", finding.Target)
	}
}

// Defaults: an ungraded record is Low/Certain, not Critical/Tentative — a hand-recorded issue
// the operator forgot to grade must not inflate a High count.
func TestARecordedIssueDefaultsToLowSeverityAndCertainConfidence(t *testing.T) {
	s := newTestServer()
	exchangeID := putExchangeForRecord(t, s)

	code, out := recordIssue(t, s, map[string]any{"name": "Suspicious redirect", "exchange_id": exchangeID})
	if code != http.StatusCreated {
		t.Fatalf("record answered %d", code)
	}
	finding, _ := s.findings.Get(uint64(out["id"].(float64)))
	if finding.EffectiveSeverity() != core.SeverityLow {
		t.Errorf("default severity = %v, want Low", finding.EffectiveSeverity())
	}
	if finding.EffectiveConfidence() != core.ConfidenceCertain {
		t.Errorf("default confidence = %v, want Certain", finding.EffectiveConfidence())
	}
}

// The description is supplied, not invented — but when the operator leaves it blank the record
// still says where it came from rather than presenting an empty report row.
func TestARecordedIssueWithoutADescriptionNamesItsExchange(t *testing.T) {
	s := newTestServer()
	exchangeID := putExchangeForRecord(t, s)

	code, out := recordIssue(t, s, map[string]any{"name": "Odd header", "exchange_id": exchangeID})
	if code != http.StatusCreated {
		t.Fatalf("record answered %d", code)
	}
	finding, _ := s.findings.Get(uint64(out["id"].(float64)))
	if finding.Description == "" {
		t.Error("an empty description would render as an empty report row; it must name the exchange it was recorded from")
	}
}

// The comment is operator state: it lands on the finding and survives, but the description is
// untouched by it.
func TestARecordedIssueCarriesTheOperatorsComment(t *testing.T) {
	s := newTestServer()
	exchangeID := putExchangeForRecord(t, s)

	code, out := recordIssue(t, s, map[string]any{
		"name":        "Debug endpoint live",
		"exchange_id": exchangeID,
		"description": "/debug/console answers without authentication.",
		"comment":     "found while mapping; re-check after the next deploy",
	})
	if code != http.StatusCreated {
		t.Fatalf("record answered %d", code)
	}
	finding, _ := s.findings.Get(uint64(out["id"].(float64)))
	if finding.Comment != "found while mapping; re-check after the next deploy" {
		t.Errorf("comment = %q", finding.Comment)
	}
	if finding.Description != "/debug/console answers without authentication." {
		t.Errorf("description = %q; the comment must not be folded into it", finding.Description)
	}
}

// An issue must point at a real exchange: 404 for one that does not exist, 400 for a request
// that names none — an issue pointing at nothing cannot be jumped to or verified later.
func TestRecordingAgainstAMissingExchangeIsRefused(t *testing.T) {
	s := newTestServer()
	putExchangeForRecord(t, s)

	code, _ := recordIssue(t, s, map[string]any{"name": "Ghost", "exchange_id": 9999})
	if code != http.StatusNotFound {
		t.Errorf("record against exchange 9999 answered %d, want 404", code)
	}
	code, _ = recordIssue(t, s, map[string]any{"name": "No target"})
	if code != http.StatusBadRequest {
		t.Errorf("record without exchange answered %d, want 400", code)
	}
	code, _ = recordIssue(t, s, map[string]any{"exchange_id": 1})
	if code != http.StatusBadRequest {
		t.Errorf("record without name answered %d, want 400", code)
	}
}

// Burp's other mode for this action — "adds to a previously created issue" — is the ordinary
// dedup path: a second record with the same name on the same host merges into the first finding
// as a second occurrence, not a duplicate row.
func TestASecondRecordWithTheSameNameMergesIntoTheFirst(t *testing.T) {
	s := newTestServer()
	first := putExchangeForRecord(t, s)

	// Second exchange on the same host.
	reqID, _ := s.store.Put([]byte("GET /admin HTTP/1.1\r\nHost: shop.test\r\n\r\n"), core.DirectionRequest)
	ex2 := &core.Exchange{Host: "shop.test", Port: 443, TLS: true, Method: "GET", Path: "/admin", Request: reqID}
	s.store.AddExchange(ex2)

	code1, out1 := recordIssue(t, s, map[string]any{"name": "TLS not enforced", "exchange_id": first})
	code2, out2 := recordIssue(t, s, map[string]any{"name": "TLS not enforced", "exchange_id": uint64(ex2.ID)})
	if code1 != http.StatusCreated || code2 != http.StatusCreated {
		t.Fatalf("records answered %d and %d", code1, code2)
	}
	id1, id2 := uint64(out1["id"].(float64)), uint64(out2["id"].(float64))
	if id1 != id2 {
		t.Fatalf("same-name records produced findings %d and %d; they must merge (Burp's add-to-issue)", id1, id2)
	}
	finding, _ := s.findings.Get(id1)
	if len(finding.Occurrences) != 2 {
		t.Fatalf("merged finding has %d occurrences, want 2", len(finding.Occurrences))
	}
}

var _ = fmt.Sprintf // keep fmt if helpers change
