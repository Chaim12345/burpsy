package persist

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// capturedLogs collects what the store reported, so a test can assert that a silent failure is not
// silent. Guarded because zap may write from any goroutine.
type capturedLogs struct {
	mu sync.Mutex
	in []string
}

func (c *capturedLogs) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.in))
	copy(out, c.in)
	return out
}

// recordingLogger returns a logger whose entries land in the returned buffer, message and fields
// flattened into one line per entry.
func recordingLogger() (*capturedLogs, *zap.Logger) {
	logs := &capturedLogs{}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&logWriter{logs: logs}),
		zapcore.DebugLevel,
	)
	return logs, zap.New(core)
}

type logWriter struct{ logs *capturedLogs }

func (w *logWriter) Write(p []byte) (int, error) {
	w.logs.mu.Lock()
	w.logs.in = append(w.logs.in, string(p))
	w.logs.mu.Unlock()
	return len(p), nil
}

// openTestStoreWith is newTestStore with a caller-supplied logger.
func openTestStoreWith(t *testing.T, logger *zap.Logger) *Store {
	t.Helper()
	p, err := Open(filepath.Join(t.TempDir(), "test.db"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// A scope rule restricted to one port comes back restricted to that port.
//
// The bug: LoadScope selected the port column, scanned it into a variable and built the rule from the
// pattern alone. So `include app.test:8443` came back as `include app.test` — every port on that host
// authorised, by a restart, with nothing reporting it. For an include rule that widens what the sender,
// the crawler and the scanner are allowed to touch; for an exclude rule it silently takes a host the
// operator had allowed out of scope entirely.
func TestRestoreKeepsAScopeRulesPort(t *testing.T) {
	p := newTestStore(t)
	p.SaveScope([]*core.ScopeRule{
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 8443),
	})

	loaded, err := p.LoadScope()
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(loaded))
	}
	r := loaded[0]
	if r.Port == nil {
		t.Fatal("the restored rule has no port, so it now authorises every port on that host")
	}
	if *r.Port != 8443 {
		t.Fatalf("port = %d, want 8443", *r.Port)
	}
	if r.Matches("app.test", 80) {
		t.Error("the restored rule matches port 80, which the operator did not authorise")
	}
	if !r.Matches("app.test", 8443) {
		t.Error("the restored rule no longer matches the port it was saved with")
	}
}

// A path-limited rule keeps its path prefix. The old table had no column for one at all, so an include
// rule limited to /api came back covering the whole host.
func TestRestoreKeepsAScopeRulesPathPrefix(t *testing.T) {
	p := newTestStore(t)
	p.SaveScope([]*core.ScopeRule{
		core.NewScopeRuleWithPath(core.ScopeInclude, "app.test", "/api"),
	})

	loaded, err := p.LoadScope()
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(loaded))
	}
	r := loaded[0]
	if r.PathPrefix == nil || *r.PathPrefix != "/api" {
		t.Fatalf("path prefix = %v, want /api: an authorisation boundary was widened by a restart", r.PathPrefix)
	}
	if r.MatchesRequest("app.test", 80, "/admin") {
		t.Error("the restored rule matches /admin, which is outside the prefix it was saved with")
	}
	if !r.MatchesRequest("app.test", 80, "/api/users") {
		t.Error("the restored rule no longer matches its own prefix")
	}
}

// Two rules that differ only by port both survive.
//
// The old table keyed on (kind, pattern), so this pair collided and the second row replaced the
// first — an operator who authorised both ports of a host got one of them back.
func TestRestoreKeepsTwoScopeRulesThatDifferOnlyByPort(t *testing.T) {
	p := newTestStore(t)
	p.SaveScope([]*core.ScopeRule{
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 80),
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 443),
	})

	loaded, err := p.LoadScope()
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d rules, want both: two rules differing only by port must not collide", len(loaded))
	}
	// Order is preserved too, so a scope that reads top-to-bottom in the UI reads the same after a restart.
	if loaded[0].Port == nil || *loaded[0].Port != 80 || loaded[1].Port == nil || *loaded[1].Port != 443 {
		t.Fatalf("restored ports are %v and %v, want 80 then 443", loaded[0].Port, loaded[1].Port)
	}
}

// A database written before scope_rules_v2 existed still loads, from the legacy table, with the port it
// did manage to store.
//
// The case is specifically **v2 present and empty**, not v2 missing: migrate creates the table on open,
// so every old database reaches the loader with an empty v2 beside a populated legacy one. A loader that
// short-circuited on "v2 is the current table" would hand core.Scope zero rules — and an empty
// core.Scope is default-allow, so it would fail *open*, recreating the widening this whole change exists
// to stop. That is why the emptiness of v2 is asserted first: this test must not be able to pass because
// v2 was absent.
func TestLoadScopeFallsBackToAnEmptyV2AndAPopulatedLegacyTable(t *testing.T) {
	p := newTestStore(t)
	// Exactly what an older build left behind: rows in scope_rules and nothing in v2.
	if _, err := p.db.Exec(
		`INSERT INTO scope_rules (kind, pattern, port) VALUES ('exclude', 'admin.test', 9000)`); err != nil {
		t.Fatalf("insert legacy scope row: %v", err)
	}
	var v2Rows int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM scope_rules_v2`).Scan(&v2Rows); err != nil {
		t.Fatalf("scope_rules_v2 must exist for this test to mean anything: %v", err)
	}
	if v2Rows != 0 {
		t.Fatalf("scope_rules_v2 holds %d rows; this test is about an *empty* v2, not a missing one", v2Rows)
	}

	loaded, err := p.LoadScope()
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("an empty v2 beside a populated legacy table loaded zero rules; core.Scope reads that as " +
			"allow-everything, so the engagement would come back with no scope at all")
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d rules from the legacy table, want 1", len(loaded))
	}
	if loaded[0].Kind != core.ScopeExclude {
		t.Error("the legacy row's kind was lost")
	}
	if loaded[0].Port == nil || *loaded[0].Port != 9000 {
		t.Fatalf("port = %v, want 9000: the legacy table does carry a port, so it must be read", loaded[0].Port)
	}
}

// Port, path prefix and order survive a *double* round trip: save → load → save → load.
//
// One round trip is not the interesting case. A running server re-saves whatever the live scope holds on
// the next edit, so the rules it writes the second time are rules that came *out* of this loader — and
// that is the shape in which the session-rule bug lived, where the second pass through the same code
// changed the data. If anything is lost or reordered on re-save, the scope decays a little on every
// restart-and-edit cycle rather than failing once and visibly.
func TestScopeSurvivesADoubleRoundTrip(t *testing.T) {
	p := newTestStore(t)
	original := []*core.ScopeRule{
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 8443),
		core.NewScopeRuleWithPath(core.ScopeExclude, "app.test", "/admin"),
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 80),
		core.NewScopeRule(core.ScopeInclude, "*.other.test"),
	}

	p.SaveScope(original)
	first, err := p.LoadScope()
	if err != nil {
		t.Fatalf("first LoadScope: %v", err)
	}
	// Re-save exactly what came back, as a live server does when the operator next edits the scope.
	p.SaveScope(first)
	second, err := p.LoadScope()
	if err != nil {
		t.Fatalf("second LoadScope: %v", err)
	}

	describe := func(rules []*core.ScopeRule) []string {
		out := make([]string, 0, len(rules))
		for _, r := range rules {
			port := "any"
			if r.Port != nil {
				port = fmt.Sprint(*r.Port)
			}
			path := "any"
			if r.PathPrefix != nil {
				path = *r.PathPrefix
			}
			out = append(out, fmt.Sprintf("%s %s port=%s path=%s", scopeKindName(r.Kind), r.Pattern, port, path))
		}
		return out
	}
	want := describe(original)
	if got := describe(first); !reflect.DeepEqual(got, want) {
		t.Fatalf("after one round trip:\n got %v\nwant %v", got, want)
	}
	if got := describe(second); !reflect.DeepEqual(got, want) {
		t.Fatalf("after a second round trip:\n got %v\nwant %v\n(the scope decays on every save-load cycle)", got, want)
	}
	// The rebuilt matcher has to work on the twice-restored rule too, or the rule is present and inert.
	twicePortRestricted := second[0]
	if !twicePortRestricted.Matches("app.test", 8443) || twicePortRestricted.Matches("app.test", 80) {
		t.Error("the twice-restored port rule does not match its own port, or matches another")
	}
	if !second[1].MatchesRequest("app.test", 80, "/admin/x") || second[1].MatchesRequest("app.test", 80, "/public") {
		t.Error("the twice-restored path rule no longer bounds its own prefix")
	}
}

// A legacy scope row this build did not write is reported, because it means an older build edited the
// scope afterwards and the restored scope is the *older* set.
//
// This is the one silent path the two tables still leave, and the warning is what makes it not silent.
// The signal is sound rather than a guess: SaveScope mirrors every rule's (kind, pattern, port) into the
// legacy table, and the legacy key can only drop rows, never invent them — so a legacy triple absent from
// v2 can only have come from something else.
func TestLoadScopeReportsALegacyRowThisBuildDidNotWrite(t *testing.T) {
	logs, logger := recordingLogger()
	p := openTestStoreWith(t, logger)

	p.SaveScope([]*core.ScopeRule{
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 8443),
	})
	// An older build's edit: it can only write the legacy table, and its rule is one v2 never saw.
	if _, err := p.db.Exec(
		`INSERT OR REPLACE INTO scope_rules (kind, pattern, port) VALUES ('include', 'staging.test', 443)`); err != nil {
		t.Fatalf("simulate an older build's scope edit: %v", err)
	}

	loaded, err := p.LoadScope()
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	// v2 stays authoritative: preferring the legacy rows would discard path prefixes, and merging the two
	// sets would widen every include — failing open, which this path must never do.
	if len(loaded) != 1 || loaded[0].Pattern != "app.test" {
		t.Fatalf("loaded %d rules (%v); v2 must stay authoritative", len(loaded), loaded)
	}
	found := ""
	for _, line := range logs.lines() {
		if strings.Contains(line, "scope tables diverge") {
			found = line
		}
	}
	if found == "" {
		t.Fatalf("nothing was reported; the operator's older-build edit is not in effect and they would "+
			"never know. logged: %v", logs.lines())
	}
	if !strings.Contains(found, "staging.test") {
		t.Errorf("the warning does not name the rule that is not in effect: %s", found)
	}
}

// And it stays quiet in normal operation, including the case where the legacy key legitimately dropped a
// row: two rules differing only by port collapse to one legacy row, which is a *subset* of v2 and must
// not be reported as a divergence. A warning that cries wolf on every ordinary save is worse than none.
func TestLoadScopeDoesNotReportTheLegacyTablesOwnCollisions(t *testing.T) {
	logs, logger := recordingLogger()
	p := openTestStoreWith(t, logger)

	p.SaveScope([]*core.ScopeRule{
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 80),
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 443),
		core.NewScopeRuleWithPath(core.ScopeExclude, "app.test", "/admin"),
	})
	if _, err := p.LoadScope(); err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	for _, line := range logs.lines() {
		if strings.Contains(line, "scope tables diverge") {
			t.Fatalf("an ordinary save was reported as a divergence: %s", line)
		}
	}
}

// The legacy table keeps being written, so a build that only knows it does not come up with an empty
// scope — which core.Scope reads as allow-everything.
func TestSaveScopeStillMirrorsToTheLegacyTable(t *testing.T) {
	p := newTestStore(t)
	p.SaveScope([]*core.ScopeRule{
		core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 8443),
	})
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM scope_rules`).Scan(&n); err != nil {
		t.Fatalf("count legacy rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("the legacy table holds %d rows, want 1: an older build reading it would see no scope at "+
			"all, which it treats as allow-everything", n)
	}
}
