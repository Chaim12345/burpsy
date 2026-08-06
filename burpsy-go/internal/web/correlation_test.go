package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Everything is tied to what produced it (G4, G5, G6) ---------------------------------------
//
// Source said which *kind* of surface produced an exchange; nothing said which *run*, so "show me
// the traffic this attack produced" had no answer. Nothing recorded lineage either, so a Repeater
// resend could not be traced back to the capture it was built from. These pin both, and the rule
// that keeps a link trustworthy: an id that does not resolve is dropped, never stored.

// The shared capture path stamps the run onto both the exchange it indexes and the findings that
// come out of scanning it, so the two agree without either producer restating it.
func TestCaptureStampsItsRunOnBothTheExchangeAndItsFindings(t *testing.T) {
	store := core.NewTrafficStore()
	findings := core.NewFindingStore()
	const runID = 7

	cap := scanner.Capture{
		Store:    store,
		Findings: findings,
		Logger:   zap.NewNop(),
		Source:   core.SourceCrawl,
		TaskID:   runID,
	}
	ex, err := cap.Record(scanner.CapturedExchange{
		Host: "shop.test", Port: 80, Method: "GET", Path: "/",
		Request:  []byte("GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"),
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if ex.TaskID != runID {
		t.Errorf("exchange TaskID = %d, want %d", ex.TaskID, runID)
	}
	if ex.Source != core.SourceCrawl {
		t.Errorf("exchange Source = %q, want crawl — TaskID must not displace Source", ex.Source)
	}
	for _, f := range findings.All() {
		if f.TaskID != runID {
			t.Errorf("finding %q TaskID = %d, want %d", f.Name, f.TaskID, runID)
		}
	}
}

// A per-exchange task id overrides the handle's default, and an unset one falls back to it — the
// same precedence Source already follows, so one surface can record an exchange as another's.
func TestPerExchangeRunOverridesTheHandleDefault(t *testing.T) {
	store := core.NewTrafficStore()
	cap := scanner.Capture{Store: store, Logger: zap.NewNop(), TaskID: 3}

	fallback, err := cap.Record(scanner.CapturedExchange{
		Host: "shop.test", Port: 80, Method: "GET", Path: "/a",
		Request:  []byte("GET /a HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if fallback.TaskID != 3 {
		t.Errorf("unset per-exchange id: TaskID = %d, want the handle's 3", fallback.TaskID)
	}

	override, err := cap.Record(scanner.CapturedExchange{
		Host: "shop.test", Port: 80, Method: "GET", Path: "/b", TaskID: 9,
		Request:  []byte("GET /b HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if override.TaskID != 9 {
		t.Errorf("per-exchange id: TaskID = %d, want 9", override.TaskID)
	}
}

// Traffic no task owns reports no task, rather than being adopted by whichever run happened to be
// open. Zero is the sentinel only because registry ids start at 1.
func TestUntrackedTrafficReportsNoRun(t *testing.T) {
	store := core.NewTrafficStore()
	cap := scanner.Capture{Store: store, Logger: zap.NewNop(), Source: core.SourceProxy}
	ex, err := cap.Record(scanner.CapturedExchange{
		Host: "shop.test", Port: 80, Method: "GET", Path: "/",
		Request:  []byte("GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if ex.TaskID != 0 {
		t.Errorf("TaskID = %d, want 0 for traffic no task owns", ex.TaskID)
	}
}

// A parent id the caller supplies is only stored when it resolves. A dangling link is worse than no
// link: the store grows, and an id that pointed at nothing yesterday points at an unrelated exchange
// tomorrow.
func TestAnUnresolvableParentIsDroppedRatherThanStored(t *testing.T) {
	s := newTestServer()
	real := addTraffic(t, s.store, "shop.test", "GET", "/one")

	if got := s.validParent(&real.ID); got == nil || *got != real.ID {
		t.Errorf("a resolvable parent must be kept, got %v", got)
	}
	missing := core.ExchangeID(9999)
	if got := s.validParent(&missing); got != nil {
		t.Errorf("parent %d does not exist and must be dropped, got %v", missing, *got)
	}
	if got := s.validParent(nil); got != nil {
		t.Errorf("no parent named must stay nil, got %v", *got)
	}
	// Exchange 0 is a real exchange and the one most often sent to Repeater first. A zero-sentinel
	// design would have discarded exactly this link.
	zero := core.ExchangeID(0)
	if got := s.validParent(&zero); got == nil || *got != 0 {
		t.Errorf("exchange 0 is a valid parent and must survive, got %v", got)
	}
}

// Lineage and run both reach the wire, and both are omitted rather than sent as zero when absent —
// so a reader can tell "no parent" from "parent is exchange 0".
func TestTheHistoryViewCarriesRunAndLineage(t *testing.T) {
	s := newTestServer()
	parent := addTraffic(t, s.store, "shop.test", "GET", "/one")

	child := addTraffic(t, s.store, "shop.test", "GET", "/two")
	child.TaskID = 4
	child.ParentID = &parent.ID

	rec := get(t, s, "/api/history?limit=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/history: %d", rec.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var sawChild, sawParent bool
	for _, r := range rows {
		switch r["path"] {
		case "/two":
			sawChild = true
			if r["task_id"] != float64(4) {
				t.Errorf("child task_id = %v, want 4", r["task_id"])
			}
			if r["parent_id"] != float64(parent.ID) {
				t.Errorf("child parent_id = %v, want %d", r["parent_id"], parent.ID)
			}
		case "/one":
			sawParent = true
			if _, ok := r["task_id"]; ok {
				t.Errorf("an untracked exchange must omit task_id, got %v", r["task_id"])
			}
			if _, ok := r["parent_id"]; ok {
				t.Errorf("an exchange with no antecedent must omit parent_id, got %v", r["parent_id"])
			}
		}
	}
	if !sawChild || !sawParent {
		t.Fatalf("history did not return both exchanges (child=%v parent=%v)", sawChild, sawParent)
	}
}

// A Repeater resend records the path the server saw, not the absolute URI the proxy request line
// carried.
//
// Send-to-Repeater hands back the stored request verbatim, and a captured proxy request is in
// absolute form (RFC 7230 §5.3) — so the resend's request line is
// `POST http://127.0.0.1:9091/login HTTP/1.1`. Taking that target verbatim made the whole URI the
// exchange's path, and the site map split it on its own slashes into a phantom branch:
// `http:` → “ → `127.0.0.1:9091` → `login`, listing one resource twice.
func TestARepeaterResendRecordsAnOriginFormPath(t *testing.T) {
	cases := []struct{ line, want string }{
		{"POST http://127.0.0.1:9091/login HTTP/1.1", "/login"},
		{"GET https://shop.test/search?q=hello HTTP/1.1", "/search?q=hello"},
		{"GET /already/origin/form HTTP/1.1", "/already/origin/form"},
		{"GET /search?q=a://b HTTP/1.1", "/search?q=a://b"},
		// Not paths, and must not be rewritten into one.
		{"OPTIONS * HTTP/1.1", "*"},
		{"CONNECT shop.test:443 HTTP/1.1", "shop.test:443"},
	}
	for _, c := range cases {
		if got := firstLinePath(c.line + "\r\nHost: x\r\n\r\n"); got != c.want {
			t.Errorf("firstLinePath(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

// Exchange 0 is a real exchange, and the organizer must accept it.
//
// The guard was `req.Exchange <= 0` with the message "A positive exchange id is required" — which
// asserted something untrue about the id space. Ids are a dense counter from zero, so exchange 0 is
// the first request captured in a session and the one an operator reaches for first. The same
// off-by-one sat in four frontend validators. Invariant 3 in docs/DATA-MODEL.md, as a 400.
func TestTheOrganizerAcceptsExchangeZeroAndRejectsOneThatDoesNotExist(t *testing.T) {
	s := newTestServer()
	first := addTraffic(t, s.store, "shop.test", "GET", "/")
	if first.ID != 0 {
		t.Fatalf("precondition: first exchange id = %d, want 0", first.ID)
	}

	if rec := postJSON(t, s, "/api/tools/organizer", map[string]any{"exchange": 0}); rec.Code != http.StatusOK {
		t.Errorf("saving exchange 0: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// An id no exchange has is refused rather than stored as an entry that opens onto nothing.
	if rec := postJSON(t, s, "/api/tools/organizer", map[string]any{"exchange": 4242}); rec.Code != http.StatusNotFound {
		t.Errorf("saving a nonexistent exchange: status = %d, want 404", rec.Code)
	}
	if rec := postJSON(t, s, "/api/tools/organizer", map[string]any{"exchange": -1}); rec.Code != http.StatusBadRequest {
		t.Errorf("saving a negative id: status = %d, want 400", rec.Code)
	}
}
