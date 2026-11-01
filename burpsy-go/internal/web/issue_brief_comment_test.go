package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The Issues tree edits a finding's comment from its summary row: the row initialises the
// editor, so a summary row without the comment saves "" over it. The brief row must therefore
// carry the comment — while still omitting the prose (detail, remediation, evidence) that made
// the document grow with the issue count.
func TestIssueSummaryRowCarriesCommentButNotProse(t *testing.T) {
	s := newTestServer()
	exchangeID := putExchangeForRecord(t, s)
	code, out := recordIssue(t, s, map[string]any{
		"name":        "Weak password policy",
		"description": "prose that must stay off the summary row",
		"severity":    "high",
		"exchange_id": exchangeID,
	})
	if code != http.StatusCreated {
		t.Fatalf("record = %d", code)
	}
	id := uint64(out["id"].(float64))
	rec := putJSON(t, s, "/api/issues/"+itoa(id), map[string]any{"comment": "keep-me-note"})
	if rec.Code != http.StatusOK {
		t.Fatalf("comment PUT = %d: %s", rec.Code, rec.Body.String())
	}

	rec = getJSON(t, s, "/api/issues?summary=1")
	var list struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(list.Findings))
	}
	row := list.Findings[0]
	if row["comment"] != "keep-me-note" {
		t.Errorf("summary row comment = %v, want the saved comment (an editor opened from this row would overwrite it)", row["comment"])
	}
	if row["detail"] != nil {
		t.Errorf("summary row carries detail prose: %v", row["detail"])
	}
	if row["remediation"] != nil {
		t.Errorf("summary row carries remediation prose: %v", row["remediation"])
	}

	// The dock badge (count=1) stays minimal: counts only, no rows, so no comment or prose
	// travels on a request the shell mounts on every page.
	rec = getJSON(t, s, "/api/issues?count=1")
	var badge struct {
		Counted  int              `json:"counted"`
		Counts   map[string]int   `json:"counts"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &badge); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if badge.Counted != 1 || badge.Counts["high"] != 1 {
		t.Errorf("badge counted=%d counts=%v, want 1 high finding", badge.Counted, badge.Counts)
	}
	if len(badge.Findings) != 0 {
		t.Errorf("badge carried %d rows; the count path must not serve rows", len(badge.Findings))
	}
}

// The badge's skip of the exchange snapshot must not change what it counts: findings raised only
// on isolated-scan traffic stay excluded by default and are counted with include_isolated=1.
func TestIssueCountStillExcludesIsolatedFindings(t *testing.T) {
	s := newTestServer()
	normalEx := putExchangeForRecord(t, s)
	if code, _ := recordIssue(t, s, map[string]any{"name": "normal", "severity": "low", "exchange_id": normalEx}); code != http.StatusCreated {
		t.Fatalf("record normal = %d", code)
	}
	// A finding whose only occurrence sits on an isolated scan's exchange.
	reqID, err := s.store.Put([]byte("GET /iso HTTP/1.1\r\nHost: shop.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Host: "shop.test", Port: 443, TLS: true, Method: "GET", Path: "/iso",
		Request: core.MsgPtr(reqID), Source: core.SourceIsolatedScan}
	s.store.AddExchange(ex)
	if code, _ := recordIssue(t, s, map[string]any{"name": "isolated", "severity": "low", "exchange_id": uint64(ex.ID)}); code != http.StatusCreated {
		t.Fatalf("record isolated = %d", code)
	}

	count := func(url string) int {
		rec := getJSON(t, s, url)
		var badge struct {
			Counted int `json:"counted"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &badge); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return badge.Counted
	}
	if n := count("/api/issues?count=1"); n != 1 {
		t.Errorf("badge counted %d findings, want 1 (isolated finding must stay excluded)", n)
	}
	if n := count("/api/issues?count=1&include_isolated=1"); n != 2 {
		t.Errorf("badge with include_isolated counted %d findings, want 2", n)
	}
}
