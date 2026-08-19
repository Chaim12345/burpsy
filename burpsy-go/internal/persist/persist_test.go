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
	// The param column round-trips like any other: an insertion-point finding must come back
	// naming the parameter it was observed at, and a resource finding must come back with none —
	// the distinction is the whole point of the column.
	findings.Add(core.NewFinding{
		Name: "Reflected input", Severity: core.SeverityMedium, Confidence: core.ConfidenceCertain,
		Description: "Value echoed.", Remediation: "Encode output.", Param: "q",
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
	if restoredF.Count() != 2 {
		t.Fatalf("findings = %d, want 2", restoredF.Count())
	}
	all := restoredF.All()
	if all[0].Name != "SQL injection" || all[0].Severity != core.SeverityHigh || all[0].Description != "Payload matched." {
		t.Fatalf("finding = %+v", all[0])
	}
	if all[0].Param != "" {
		t.Fatalf("resource finding param = %q, want empty", all[0].Param)
	}
	if all[1].Name != "Reflected input" || all[1].Param != "q" {
		t.Fatalf("finding = %+v, want param %q", all[1], "q")
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
	sessRule := session.NewSessionRule("login", []string{"127.0.0.1"}, []session.MacroStep{
		{Method: "GET", URL: "http://127.0.0.1/form"},
		{Method: "POST", URL: "http://127.0.0.1/login?csrf={{csrf}}"},
	})
	// An extraction bound to the *second* step and reading a named header: both are fields the load
	// path used to drop, because it rebuilt each extraction from the four arguments it happened to
	// name rather than recompiling the one it unmarshalled.
	csrf, err := session.NewExtraction("csrf", "header", `(.+)`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	csrf.Header = "X-CSRF"
	csrf.Step = 0
	sessRule.Extractions = []*session.Extraction{csrf}
	if _, err := sess.AddRule(sessRule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	p.SaveSessionRules(sess.AllRules())

	tl := toollog.New()
	tl.SetPersistenceSink(p.SaveToolLog)
	tl.Record(toollog.ToolRepeater, "h", 80, false, "GET", "/", 200, toollog.Bytes(64), 5, "")

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
	if len(rs[0].Extractions) != 1 {
		t.Fatalf("session rule extractions = %+v, want one", rs[0].Extractions)
	}
	ex := rs[0].Extractions[0]
	if ex.Header != "X-CSRF" || ex.Step != 0 {
		t.Fatalf("restored extraction = %+v, want its header name and owning step intact", ex)
	}
	// Recompiled, not merely copied: an extraction whose regexp was not rebuilt runs and silently
	// returns nothing, which is a rule that looks restored and cannot log in.
	if got := ex.Run(map[string]string{"X-CSRF": "tok-9f3a"}, nil); got != "tok-9f3a" {
		t.Fatalf("restored extraction ran to %q, want the header value", got)
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

// A merged finding must survive a restart as one finding with its whole occurrence and parameter
// set, and it must still be able to attract new occurrences afterwards. The first half tests that
// SaveFinding's INSERT OR REPLACE really does rewrite the row a merge changed rather than leaving a
// stale copy; the second tests that Restore rebuilds the dedup index from the persisted target.
func TestRestore_RoundTripsMergedFinding(t *testing.T) {
	p := newTestStore(t)
	findings := core.NewFindingStore()
	findings.SetPersistenceSink(p.SaveFinding)

	target := core.FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/search"}
	var id uint64
	for i, param := range []string{"q", "sort", "page"} {
		id = findings.Add(core.NewFinding{
			Name: "Cross-site scripting (reflected)", Severity: core.SeverityHigh,
			Confidence: core.ConfidenceFirm, Param: param, Target: target,
			Occurrences: []core.Occurrence{{ExchangeID: core.ExchangeID(i), Request: core.MsgId(i * 2)}},
		})
	}

	restored := core.NewFindingStore()
	if err := p.Restore(nil, restored, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restored.Count() != 1 {
		t.Fatalf("findings = %d, want 1 merged row — the sink must rewrite, not insert", restored.Count())
	}
	f := restored.All()[0]
	if f.ID != id {
		t.Errorf("id = %d, want %d", f.ID, id)
	}
	if len(f.Occurrences) != 3 {
		t.Errorf("occurrences = %d, want 3", len(f.Occurrences))
	}
	if len(f.Params) != 3 || f.Params[0] != "q" || f.Params[2] != "page" {
		t.Errorf("params = %v, want [q sort page]", f.Params)
	}
	if f.Target != target {
		t.Errorf("target = %+v, want %+v", f.Target, target)
	}

	// The restored store still knows this finding's key, so a fourth observation joins it.
	got := restored.Add(core.NewFinding{
		Name: "Cross-site scripting (reflected)", Severity: core.SeverityHigh,
		Confidence: core.ConfidenceFirm, Param: "lang", Target: target,
		Occurrences: []core.Occurrence{{ExchangeID: 9, Request: 18}},
	})
	if got != id {
		t.Fatalf("Add after restore returned %d, want the restored finding %d", got, id)
	}
	if restored.Count() != 1 {
		t.Errorf("findings = %d after a post-restore observation, want 1", restored.Count())
	}
}

// TaskID is the link between a coverage summary and the findings that produced it: the dashboard
// can say an audit swept 200 exchanges and that 12 findings exist, and TaskID is the only thing
// relating the two. It was carried in memory and dropped on the way to disk, so that link survived
// exactly until the first restart, silently — every restored finding read back as "nothing tracked
// it", which is also what a genuinely untracked finding reads as.
func TestRestore_RoundTripsFindingTaskID(t *testing.T) {
	p := newTestStore(t)
	findings := core.NewFindingStore()
	findings.SetPersistenceSink(p.SaveFinding)

	tracked := findings.Add(core.NewFinding{
		Name: "SQL injection", Severity: core.SeverityHigh, Confidence: core.ConfidenceFirm,
		TaskID: 4242,
		Target: core.FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/items"},
	})
	// A finding nobody tracked keeps TaskID 0, and must stay distinguishable from a tracked one.
	untracked := findings.Add(core.NewFinding{
		Name: "Cleartext submission of password", Severity: core.SeverityMedium,
		Confidence: core.ConfidenceCertain,
		Target:     core.FindingTarget{Host: "app.test", Port: 80, Path: "/login"},
	})

	restored := core.NewFindingStore()
	if err := p.Restore(nil, restored, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	byID := map[uint64]*core.Finding{}
	for _, f := range restored.All() {
		byID[f.ID] = f
	}
	if got := byID[tracked]; got == nil {
		t.Fatalf("tracked finding %d did not survive the restore", tracked)
	} else if got.TaskID != 4242 {
		t.Errorf("TaskID = %d after restore, want 4242 — the finding/coverage link was dropped", got.TaskID)
	}
	if got := byID[untracked]; got == nil {
		t.Fatalf("untracked finding %d did not survive the restore", untracked)
	} else if got.TaskID != 0 {
		t.Errorf("TaskID = %d, want 0 for a finding no task produced", got.TaskID)
	}
}
