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
