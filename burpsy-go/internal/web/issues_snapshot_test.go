package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// M3 (Entire trail 4): the issues list/summary path took a full-history ExchangeBriefs snapshot
// even with zero findings, and sized the snapshot by captured traffic rather than by what the
// findings reference. These tests pin both halves of the fix: no findings means no snapshot, and
// a snapshot copies only the referenced briefs while attribution still resolves.

func seedExchanges(t *testing.T, s *Server, n int) []core.MsgId {
	t.Helper()
	reqIDs := make([]core.MsgId, 0, n)
	for i := 0; i < n; i++ {
		reqID, err := s.store.Put([]byte("GET /p HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put request: %v", err)
		}
		rspID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nx"), core.DirectionResponse)
		if err != nil {
			t.Fatalf("put response: %v", err)
		}
		s.store.AddExchange(&core.Exchange{Host: "h.test", Port: 80, Method: "GET", Path: "/p", Request: core.MsgPtr(reqID), Response: &rspID})
		reqIDs = append(reqIDs, reqID)
	}
	return reqIDs
}

func TestIssuesZeroFindingsSkipsSnapshot(t *testing.T) {
	s := newTestServer()
	seedExchanges(t, s, 30)
	for _, path := range []string{"/api/issues", "/api/issues?summary=true"} {
		if rec := get(t, s, path); rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	_ = s.renderUI2Issues()
	if got := s.exchangeSnapshots.Load(); got != 0 {
		t.Fatalf("zero-findings issues views built %d full-history snapshots; want 0", got)
	}
}

func TestIssuesSnapshotCoversOnlyReferencedExchanges(t *testing.T) {
	s := newTestServer()
	reqIDs := seedExchanges(t, s, 30)
	s.findings.Add(core.NewFinding{
		Name:       "Reflected XSS",
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceFirm,
		Target:     core.FindingTarget{Host: "h.test", Port: 80, Path: "/p"},
		Occurrences: []core.Occurrence{{
			ExchangeID: 3,
			Request:    core.MsgPtr(reqIDs[3]),
		}},
	})
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues = %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.exchangeSnapshots.Load(); got != 1 {
		t.Fatalf("one finding with references built %d snapshots; want 1", got)
	}
	if got := s.exchangeSnapshotBriefs.Load(); got > 2 {
		t.Fatalf("snapshot copied %d briefs for a finding referencing 1 of 30 exchanges; want <= 2", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, "h.test") {
		t.Fatalf("attribution lost with the targeted snapshot; body: %s", body)
	}
}

// Multi-occurrence, mixed-key and edge-case coverage for the targeted snapshot: every key shape
// resolveOccurrence and isolatedAgainst can use must resolve from the collected superset, and
// deleted/empty references must behave exactly as in the full snapshot.
func TestIssuesSnapshotResolvesEveryReferenceShape(t *testing.T) {
	s := newTestServer()
	mk := func(host string, src core.Source) (core.ExchangeID, core.MsgId) {
		reqID, err := s.store.Put([]byte("GET /p HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		ex := &core.Exchange{Host: host, Port: 80, Method: "GET", Path: "/p", Request: core.MsgPtr(reqID), Source: src}
		s.store.AddExchange(ex)
		return ex.ID, reqID
	}
	idA, reqA := mk("a.test", core.SourceCrawl) // referenced by id+request
	idB, _ := mk("b.test", core.SourceCrawl)    // referenced by id only
	_, reqC := mk("c.test", core.SourceCrawl)   // referenced by request only
	idIso, _ := mk("iso.test", core.SourceIsolatedScan)
	idGone, _ := mk("gone.test", core.SourceCrawl)
	s.store.DeleteExchanges([]core.ExchangeID{idGone})

	s.findings.Add(core.NewFinding{
		Name: "Multi", Severity: core.SeverityHigh, Confidence: core.ConfidenceFirm,
		Target: core.FindingTarget{Host: "a.test", Port: 80, Path: "/p"},
		Occurrences: []core.Occurrence{
			{ExchangeID: idA, Request: core.MsgPtr(reqA)},
			{ExchangeID: idB},
			{ExchangeID: 999, Request: core.MsgPtr(reqC)}, // request resolves even with a bogus id
			{ExchangeID: idGone},                          // deleted: dropped, not fatal
		},
	})
	s.findings.Add(core.NewFinding{
		Name: "NoOccs", Severity: core.SeverityLow, Confidence: core.ConfidenceTentative,
		Target: core.FindingTarget{Host: "none.test", Port: 80, Path: "/"},
	})
	s.findings.Add(core.NewFinding{
		Name: "Iso", Severity: core.SeverityMedium, Confidence: core.ConfidenceFirm,
		Target:      core.FindingTarget{Host: "iso.test", Port: 80, Path: "/p"},
		Occurrences: []core.Occurrence{{ExchangeID: idIso}},
	})

	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// Occurrence payloads carry exchange_id + path (host lives at finding level), so resolved
	// attribution means: id-referenced, id+request, and request-only shapes all carry "/p".
	for _, want := range []string{
		`{"exchange_id":0,"response":0,"path":"/p"}`, // idA by id+request
		`{"exchange_id":1,"response":0,"path":"/p"}`, // idB by id only
		`{"exchange_id":2,"response":0,"path":"/p"}`, // reqC by request only, bogus id corrected
		`{"exchange_id":4,"response":0,"path":""}`,   // deleted exchange: listed, unresolved
	} {
		if !strings.Contains(body, want) {
			t.Errorf("occurrence shape %s not resolved as the full snapshot resolves it; body: %s", want, body)
		}
	}
	if strings.Contains(body, "iso.test") {
		t.Errorf("isolated finding leaked into the default issues view")
	}
	if got := s.exchangeSnapshotBriefs.Load(); got > 6 {
		t.Errorf("snapshot copied %d briefs for 4 referenced exchanges; want <= 6", got)
	}
	rec2 := get(t, s, "/api/issues?include_isolated=true")
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "iso.test") {
		t.Errorf("include_isolated view lost the isolated finding: %d %s", rec2.Code, rec2.Body.String())
	}
}
