package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// savedRule is a valid rule already carrying the id it was persisted with.
func savedRule(id session.RuleID, name, url string) *session.SessionRule {
	r := session.NewSessionRule(name, nil, []session.MacroStep{{Method: "POST", URL: url}})
	r.ID = id
	return r
}

// A rule saved at a non-trivial id comes back at that same id.
//
// The bug: Restore installed saved rules with Coordinator.AddRule, which mints a fresh id. A rule
// saved as 42 came back as 1, so anything holding the old id — an operator's note, a log line, a
// `POST /api/session/rules/42/run` — silently addressed a different rule's login macro.
func TestRestoreKeepsSessionRuleIDs(t *testing.T) {
	p := newTestStore(t)
	p.SaveSessionRules([]*session.SessionRule{
		savedRule(42, "prod login", "https://app.test/login"),
	})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	all := sess.AllRules()
	if len(all) != 1 {
		t.Fatalf("restored %d rules, want 1", len(all))
	}
	if all[0].ID != 42 {
		t.Fatalf("the rule came back as id %d, want 42: a recorded RuleID now names a different rule", all[0].ID)
	}
	if sess.Rule(42) == nil {
		t.Fatal("Rule(42) is nil after a restore of a rule saved at 42")
	}
}

// The evaluation order survives the round trip even when it is not id order.
//
// LoadSessionRules had no ORDER BY at all, so the restored order was whatever the query returned.
// Coordinator.MatchingRule returns the *first* rule covering a host, so the order decides which login
// macro runs: ordering by id here would silently promote the wrong rule to first.
func TestRestoreKeepsSessionRuleOrder(t *testing.T) {
	p := newTestStore(t)
	// Saved in an order that ascending-id would reverse. This is the shape a coordinator can hold after
	// rules have been removed and re-added, and the shape that makes the assertion mean something.
	p.SaveSessionRules([]*session.SessionRule{
		savedRule(9, "checked first", "https://app.test/a"),
		savedRule(4, "checked second", "https://app.test/b"),
	})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	all := sess.AllRules()
	if len(all) != 2 {
		t.Fatalf("restored %d rules, want 2", len(all))
	}
	if all[0].ID != 9 || all[1].ID != 4 {
		t.Fatalf("restored order is %d,%d; want the saved order 9,4 (ordering by id would give 4,9)",
			all[0].ID, all[1].ID)
	}
	if got := sess.MatchingRule("app.test"); got == nil || got.Name != "checked first" {
		t.Fatalf("MatchingRule picked %v; the first rule in the saved order must still win after a restart", got)
	}
}

// Duplicate ids have two lines of defence, and this pins both.
//
// The table's own INTEGER PRIMARY KEY refuses a second row at the same id, so a database *this* store
// wrote cannot carry duplicates. The second line is the coordinator's, and it is reachable: restoring
// twice into one coordinator — two owners each restoring what they hold, a repeated load — offers every
// id a second time. Each is refused with ErrDuplicateRuleID and counted apart from a rule that no longer
// validates, and the rules already installed are left exactly as they were.
func TestRestoreRefusesDuplicateSessionRuleIDs(t *testing.T) {
	p := newTestStore(t)
	p.SaveSessionRules([]*session.SessionRule{
		savedRule(5, "the real login", "https://app.test/login"),
	})

	// Defence one: the schema.
	_, err := p.db.Exec(
		`INSERT INTO session_rules (id, name, enabled, scope_hosts, macro, validity, max_attempts, extractions, ord)
		 VALUES (?, ?, 1, '[]', ?, NULL, 3, NULL, ?)`,
		5, "the impostor", `[{"method":"POST","url":"https://app.test/other","headers":{},"body":""}]`, 1,
	)
	if err == nil {
		t.Fatal("a second session_rules row at id 5 was accepted; the table's primary key is the first thing " +
			"stopping two rules from sharing an id")
	}

	// Defence two: the coordinator, on a restore that offers an id it already holds.
	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("first Restore: %v", err)
	}
	first := sess.Rule(5)
	if first == nil {
		t.Fatal("the rule was not installed by the first restore")
	}
	// A second restore must not double-install, must not renumber, and must not replace the live rule
	// object — anything holding a pointer to it (an in-flight login) keeps working.
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("second Restore: %v", err)
	}
	if n := len(sess.AllRules()); n != 1 {
		t.Fatalf("the coordinator holds %d rules after restoring the same database twice, want 1", n)
	}
	if sess.Rule(5) != first {
		t.Fatal("id 5 holds a different rule object after the second restore: the duplicate was installed anyway")
	}
}

// One unrestorable rule does not take the rest of the set down with it, and the good rules keep their
// ids: a refusal is counted and logged, not turned into an aborted restore.
func TestRestoreKeepsGoingPastAnUnrestorableRule(t *testing.T) {
	p := newTestStore(t)
	broken := savedRule(2, "no steps", "https://app.test/login")
	broken.Steps = nil // valid when saved by some earlier build, refused by validation now
	p.SaveSessionRules([]*session.SessionRule{
		broken,
		savedRule(8, "still good", "https://app.test/ok"),
	})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	all := sess.AllRules()
	if len(all) != 1 {
		t.Fatalf("restored %d rules, want only the one that still validates", len(all))
	}
	if all[0].ID != 8 {
		t.Fatalf("the surviving rule has id %d, want 8: a refusal must not shift the ids of its neighbours", all[0].ID)
	}
}

// A rule with a json-path extraction survives the round trip with its path, and comes back runnable —
// the same property the regex arm needs Recompile for.
func TestRestoreRoundTripsAJSONPathExtraction(t *testing.T) {
	p := newTestStore(t)
	rule := savedRule(11, "token login", "https://app.test/token")
	ex, err := session.NewJSONPathExtraction("token", "body", "data.token")
	if err != nil {
		t.Fatalf("NewJSONPathExtraction: %v", err)
	}
	rule.Extractions = []*session.Extraction{ex}
	p.SaveSessionRules([]*session.SessionRule{rule})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restored := sess.Rule(11)
	if restored == nil {
		t.Fatal("the rule was not restored")
	}
	if len(restored.Extractions) != 1 {
		t.Fatalf("restored %d extractions, want 1", len(restored.Extractions))
	}
	got := restored.Extractions[0]
	if got.JSONPath != "data.token" {
		t.Fatalf("restored json path %q, want data.token", got.JSONPath)
	}
	// Restored *and* usable: an extraction whose path was never parsed runs and lifts nothing, which is
	// how a rule comes back looking restored and unable to log in.
	res := got.RunResult(nil, []byte(`{"data":{"token":"abc123"}}`))
	if !res.Outcome.Resolved() || res.Value != "abc123" {
		t.Fatalf("the restored extraction produced %+v; want the token, so the path was re-parsed on load", res)
	}
}

// The URL scope (7nh2) survives the round trip: the mode radio and the custom scope's path prefix,
// port and protocol.
//
// The bug this pins is 6db6: 7nh2 landed those four fields in the model, the matcher, the validator
// and the wire, but not in this table, so SaveSessionRules wrote none of them and LoadSessionRules
// read none back. A rule saved as "Use custom scope, path prefix /api" matched every path and every
// port after a restart — the operator's stated exclusion silently gone, and in the dangerous
// direction: a rule they confined to /api would replay a login macro at /logout.
//
// Each arm is asserted against a request it must now refuse, not just for equality of the field: a
// column that round-trips a value the matcher ignores would pass a field-by-field test and still be
// the same defect.
func TestRestoreKeepsAURLScopedRuleAndLeavesLegacyRulesUnscoped(t *testing.T) {
	p := newTestStore(t)
	scoped := savedRule(21, "api refresh", "https://app.test/api/refresh")
	scoped.ScopeMode = "custom"
	scoped.ScopePathPrefix = "/api"
	port := uint16(8443)
	scoped.ScopePort = &port
	scoped.ScopeProtocol = "https"
	suite := savedRule(22, "suite login", "https://app.test/login")
	suite.ScopeMode = "suite"
	p.SaveSessionRules([]*session.SessionRule{savedRule(23, "plain login", "https://app.test/plain"), scoped, suite})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	byID := map[session.RuleID]*session.SessionRule{}
	for _, r := range sess.AllRules() {
		byID[r.ID] = r
	}
	got := byID[21]
	if got == nil {
		t.Fatal("the URL-scoped rule did not come back")
	}
	if got.ScopeMode != "custom" || got.ScopePathPrefix != "/api" || got.ScopePort == nil || *got.ScopePort != 8443 || got.ScopeProtocol != "https" {
		t.Fatalf("restored URL scope = mode %q path %q port %v protocol %q; want custom /api 8443 https",
			got.ScopeMode, got.ScopePathPrefix, got.ScopePort, got.ScopeProtocol)
	}
	// The arms must be *load-bearing* after the restore, not merely present. A rule whose stated
	// scope came back but is no longer consulted matches the path it excluded, which is the whole
	// defect this test exists for.
	inScope := session.RequestIdentity{Host: "app.test", Path: "/api/refresh", Port: 8443, TLS: true}
	if !got.MatchCustomArms(inScope) {
		t.Error("the restored rule no longer matches a request inside its own stated scope")
	}
	outOfScope := session.RequestIdentity{Host: "app.test", Path: "/logout", Port: 8443, TLS: true}
	if got.MatchCustomArms(outOfScope) {
		t.Error("the restored rule matched /logout; the path prefix did not survive the restart, so a rule " +
			"confined to /api would replay a login macro at /logout")
	}
	wrongPort := session.RequestIdentity{Host: "app.test", Path: "/api/refresh", Port: 443, TLS: true}
	if got.MatchCustomArms(wrongPort) {
		t.Error("the restored rule matched a port it excludes; the port arm did not survive the restart")
	}
	plainHTTP := session.RequestIdentity{Host: "app.test", Path: "/api/refresh", Port: 8443, TLS: false}
	if got.MatchCustomArms(plainHTTP) {
		t.Error("the restored rule matched http; the protocol arm did not survive the restart")
	}

	if byID[22] == nil || byID[22].ScopeMode != "suite" {
		t.Fatalf("the suite-mode rule came back with ScopeMode=%q; want suite, or it silently widens to every URL",
			byID[22].ScopeMode)
	}

	// The dangerous direction for a legacy row: absent arms must read as *unrestricted*, never as
	// restricted to the empty path or to port 0, which would silently stop every pre-existing rule
	// from matching after the upgrade.
	legacy := byID[23]
	if legacy == nil {
		t.Fatal("the legacy rule did not come back")
	}
	if legacy.ScopeMode != "" || legacy.StatesURLArms() {
		t.Fatalf("a legacy rule came back stating a URL scope (mode %q, arms %v); a row written before these "+
			"columns existed states none", legacy.ScopeMode, legacy.StatesURLArms())
	}
	if !legacy.MatchCustomArms(session.RequestIdentity{Host: "app.test", Path: "/anything", Port: 443, TLS: true}) {
		t.Error("the legacy rule no longer matches a request; the empty default must read as unrestricted")
	}
}

// The parameter scope (burpsy-react-ui-9hip) survives the round trip. The dangerous direction
// is the legacy read: a rule written before the column existed must come back UNRESTRICTED —
// reading a legacy rule as parameter-restricted would silently stop every existing login
// macro from matching after the upgrade.
func TestRestoreKeepsAParameterScopedRuleAndLeavesLegacyRulesUnrestricted(t *testing.T) {
	p := newTestStore(t)
	scoped := savedRule(7, "csrf refresh", "https://app.test/refresh")
	scoped.ScopeParams = []string{"csrf_token", "session_id"}
	p.SaveSessionRules([]*session.SessionRule{savedRule(8, "plain login", "https://app.test/login"), scoped})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	byID := map[session.RuleID]*session.SessionRule{}
	for _, r := range sess.AllRules() {
		byID[r.ID] = r
	}
	got := byID[7]
	if got == nil {
		t.Fatal("the scoped rule did not come back")
	}
	if len(got.ScopeParams) != 2 || got.ScopeParams[0] != "csrf_token" || got.ScopeParams[1] != "session_id" {
		t.Fatalf("restored ScopeParams = %v, want [csrf_token session_id]", got.ScopeParams)
	}
	if !got.MatchParams([]string{"csrf_token", "session_id"}) {
		t.Error("the restored scope does not match a request carrying both parameters")
	}
	if got.MatchParams([]string{"csrf_token"}) {
		t.Error("the restored scope matched a request missing session_id; the list must survive as a conjunction")
	}

	legacy := byID[8]
	if legacy == nil {
		t.Fatal("the legacy rule did not come back")
	}
	if len(legacy.ScopeParams) != 0 {
		t.Fatalf("a legacy rule came back with ScopeParams=%v; a rule written before the column existed is unrestricted", legacy.ScopeParams)
	}
	if !legacy.MatchParams(nil) {
		t.Error("the legacy rule no longer matches a parameter-less request; the empty default must read as unrestricted")
	}
}
