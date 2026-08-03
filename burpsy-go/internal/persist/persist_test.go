package persist

import (
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// newTestStore opens a fresh database in a temp dir.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	p, err := Open(filepath.Join(t.TempDir(), "test.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestRestore_RoundTripsMessagesAndExchanges(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)

	reqID, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("Put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("Put response: %v", err)
	}
	status := uint16(200)
	store.AddExchange(&core.Exchange{
		Request: reqID, Response: &respID, Host: "a", Port: 80, TLS: false,
		Method: "GET", Path: "/", Status: &status, ResponseLen: 20,
	})

	// A fresh store restored from the same DB must see both messages and the exchange.
	restored := core.NewTrafficStore()
	if err := p.Restore(restored, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	msgs, exs := restored.Count()
	if msgs != 2 || exs != 1 {
		t.Fatalf("counts = %d/%d, want 2/1", msgs, exs)
	}
	ex, err := restored.GetExchange(0)
	if err != nil {
		t.Fatalf("GetExchange(0): %v", err)
	}
	if ex.Host != "a" || ex.Method != "GET" || ex.Path != "/" || ex.Status == nil || *ex.Status != 200 {
		t.Fatalf("exchange = %+v", ex)
	}
	// The raw request must still be retrievable by its original id.
	msg, err := restored.Get(reqID)
	if err != nil {
		t.Fatalf("Get(reqID): %v", err)
	}
	if string(msg.Raw()) != "GET / HTTP/1.1\r\nHost: a\r\n\r\n" {
		t.Fatalf("raw = %q", msg.Raw())
	}
	// Append after restore: ids continue from the restored count.
	next, err := restored.Put([]byte("POST /x HTTP/1.1\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("Put after restore: %v", err)
	}
	if uint64(next) != 2 {
		t.Fatalf("next id = %d, want 2", next)
	}
}

func TestRestore_RoundTripsFindingsAndOrganizer(t *testing.T) {
	p := newTestStore(t)
	findings := core.NewFindingStore()
	findings.SetPersistenceSink(p.SaveFinding)
	findings.Add(core.NewFinding{
		Name: "SQL injection", Severity: core.SeverityHigh, Confidence: core.ConfidenceFirm,
		Description: "Payload matched.", Remediation: "Parameterise.",
	})

	org := organizer.New()
	it := org.Add(42)
	org.Update(it.ID, "Title", "Note", "yellow")
	p.SaveOrganizer(org.List())

	restoredF := core.NewFindingStore()
	restoredOrg := organizer.New()
	if err := p.Restore(nil, restoredF, nil, nil, nil, restoredOrg, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restoredF.Count() != 1 {
		t.Fatalf("findings = %d, want 1", restoredF.Count())
	}
	f := restoredF.All()[0]
	if f.Name != "SQL injection" || f.Severity != core.SeverityHigh || f.Description != "Payload matched." {
		t.Fatalf("finding = %+v", f)
	}
	items := restoredOrg.List()
	if len(items) != 1 || items[0].Exchange != 42 || items[0].Title != "Title" || items[0].Highlight != "yellow" {
		t.Fatalf("organizer = %+v", items)
	}
}

func TestRestore_RoundTripsScopeMatchreplaceSessionToolLog(t *testing.T) {
	p := newTestStore(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	mr := matchreplace.NewRuleSet()
	rule, err := matchreplace.NewRule(matchreplace.TargetResponseBody, matchreplace.CategoryRegex, `X-(\d+)`, "Y", "comment")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	mr.SetRules([]*matchreplace.Rule{rule})
	mr.SetUpdateContentLength(true)
	p.SaveMatchRules(mr.Rules(), mr.UpdateContentLength())

	sess := session.NewCoordinator(zap.NewNop())
	sess.AddRule(session.NewSessionRule("login", []string{"127.0.0.1"}, []session.MacroStep{{Method: "GET", URL: "http://127.0.0.1/login"}}))
	p.SaveSessionRules(sess.AllRules())

	tl := toollog.New()
	tl.SetPersistenceSink(p.SaveToolLog)
	tl.Record(toollog.ToolRepeater, "h", 80, false, "GET", "/", 200, 5, "")

	restoredScope := core.NewScope()
	restoredMR := matchreplace.NewRuleSet()
	restoredSess := session.NewCoordinator(zap.NewNop())
	restoredTL := toollog.New()
	if err := p.Restore(nil, nil, restoredScope, restoredMR, restoredSess, nil, restoredTL); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if !restoredScope.Contains("127.0.0.1", 80, "/", false) {
		t.Fatalf("scope rule did not survive restore")
	}
	if !restoredMR.UpdateContentLength() {
		t.Fatalf("content-length flag did not survive restore")
	}
	mrRules := restoredMR.Rules()
	if len(mrRules) != 1 || mrRules[0].StringMatch != `X-(\d+)` {
		t.Fatalf("matchreplace rules = %+v", mrRules)
	}
	// The regex must be recompiled, not just copied. UpdateContentLength(true)
	// was restored too, so the content-length header is rewritten for the new
	// body length (1 byte).
	if out := restoredMR.Apply(matchreplace.DirResponse, []byte("HTTP/1.1 200 OK\r\n\r\nX-7")); string(out) != "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nY" {
		t.Fatalf("regex apply after restore = %q", out)
	}
	rs := restoredSess.AllRules()
	if len(rs) != 1 || rs[0].Name != "login" {
		t.Fatalf("session rules = %+v", rs)
	}
	if restoredTL.Count() != 1 || restoredTL.All()[0].Tool != toollog.ToolRepeater {
		t.Fatalf("tool log = %+v", restoredTL.All())
	}
}

func TestOpen_FailsOnBogusPath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "no", "such", "dir", "x.db"), zap.NewNop()); err == nil {
		t.Fatalf("Open in missing directory succeeded, want error")
	}
}
