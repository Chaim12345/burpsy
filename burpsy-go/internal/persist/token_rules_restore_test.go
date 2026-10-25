package persist

// Round trip of the project-level token rules (xe82): save whole-list, restore with persisted
// IDs and insertion order, extraction recompiled enough to capture on the other side.

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

func savedTokenRule(t *testing.T, id, name, header string) *session.TokenRule {
	t.Helper()
	ex, err := session.NewExtraction("csrf", "body", `name="csrf" value="([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("build extraction: %v", err)
	}
	return &session.TokenRule{
		ID: id, Name: name, Enabled: true, ScopeHosts: []string{"*"}, ScopeTools: []string{"repeater"},
		Extract: *ex, InjectHeader: header, InjectValue: "Bearer {{csrf}}",
	}
}

func TestRestoreKeepsTokenRuleIDsAndOrder(t *testing.T) {
	p := newTestStore(t)
	p.SaveTokenRules([]*session.TokenRule{
		savedTokenRule(t, "token-7", "second added", "X-Second"),
		savedTokenRule(t, "token-3", "first added", "X-First"),
	})

	sess := session.NewCoordinator(zap.NewNop())
	if err := p.Restore(nil, nil, nil, nil, sess, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	all := sess.TokenRules()
	if len(all) != 2 {
		t.Fatalf("restored %d token rules, want 2", len(all))
	}
	if all[0].ID != "token-7" || all[1].ID != "token-3" {
		t.Fatalf("the persisted insertion order did not survive: %q, %q", all[0].ID, all[1].ID)
	}
	if all[1].Name != "first added" || !all[1].Enabled || all[1].InjectValue != "Bearer {{csrf}}" {
		t.Errorf("the rule's fields did not round-trip: %+v", all[1])
	}
	if len(all[1].ScopeTools) != 1 || all[1].ScopeTools[0] != "repeater" {
		t.Errorf("the tools scope did not round-trip: %v", all[1].ScopeTools)
	}

	// The restored extraction's matcher was recompiled: it captures from an observed response.
	sess.ObserveTokenResponse(session.RequestIdentity{Host: "app.test", Tool: "repeater"},
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-restored"></form>`))
	if got, ok := sess.TokenValue(all[1].ID); !ok || got != "tok-restored" {
		t.Errorf("a restored rule could not capture: %q, %v", got, ok)
	}
}

func TestRestoreTokenRuleRefusesADuplicateID(t *testing.T) {
	sess := session.NewCoordinator(zap.NewNop())
	if err := sess.RestoreTokenRule(savedTokenRule(t, "token-1", "one", "X-One")); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	if err := sess.RestoreTokenRule(savedTokenRule(t, "token-1", "dup", "X-Dup")); err != session.ErrDuplicateTokenRuleID {
		t.Fatalf("a duplicate persisted ID must be refused, got %v", err)
	}
	if got := sess.TokenRules()[0].Name; got != "one" {
		t.Errorf("the refused duplicate replaced the rule: %q", got)
	}
}
