package core

import (
	"strings"
	"sync"
	"testing"
)

// ---- Scope-rule content digest and digest-checked whole-list operations -------------------------
//
// The scope-library review binds content, not a name: these tests pin what the digest counts as
// content (every field a scope decision reads, plus order) and that the checked operations refuse
// — and change nothing, and notify nobody — when the content moved since the review.

func TestScopeRulesDigestCoversEveryLoadBearingField(t *testing.T) {
	base := []*ScopeRule{
		{Kind: ScopeInclude, Pattern: "app.test", Enabled: true},
		{Kind: ScopeExclude, Pattern: "admin.test", Port: digestPort(), Enabled: false},
	}
	baseDigest := ScopeRulesDigest(base)
	if baseDigest == "" || len(baseDigest) != 64 {
		t.Fatalf("digest = %q, want a sha256 hex", baseDigest)
	}
	// Identical content, rebuilt: the digest is content, not identity.
	again := []*ScopeRule{
		{Kind: ScopeInclude, Pattern: "app.test", Enabled: true},
		{Kind: ScopeExclude, Pattern: "admin.test", Port: digestPort(), Enabled: false},
	}
	if ScopeRulesDigest(again) != baseDigest {
		t.Errorf("identical content hashed differently")
	}
	variants := map[string][]*ScopeRule{
		"order swapped": {base[1], base[0]},
		"enabled flipped": {
			{Kind: ScopeInclude, Pattern: "app.test", Enabled: true},
			{Kind: ScopeExclude, Pattern: "admin.test", Port: digestPort(), Enabled: true},
		},
		"kind changed": {
			{Kind: ScopeExclude, Pattern: "app.test", Enabled: true},
			base[1],
		},
		"pattern changed": {
			{Kind: ScopeInclude, Pattern: "app2.test", Enabled: true},
			base[1],
		},
		"port added": {
			{Kind: ScopeInclude, Pattern: "app.test", Enabled: true, Port: digestPort()},
			base[1],
		},
		"path added": {
			{Kind: ScopeInclude, Pattern: "app.test", Enabled: true, PathPrefix: digestStr("/v1")},
			base[1],
		},
		"protocol added": {
			{Kind: ScopeInclude, Pattern: "app.test", Enabled: true, Protocol: digestStr("https")},
			base[1],
		},
		"rule removed": {base[0]},
	}
	for name, v := range variants {
		if ScopeRulesDigest(v) == baseDigest {
			t.Errorf("%s: digest unchanged — the review would bind content it does not show", name)
		}
	}
	// Empty has one digest whether the list is nil or empty: "no rules" is one state.
	if ScopeRulesDigest(nil) != ScopeRulesDigest([]*ScopeRule{}) {
		t.Errorf("nil and empty lists hash differently; the empty-scope state must have one digest")
	}
}

func digestPort() *uint16        { v := uint16(8443); return &v }
func digestStr(s string) *string { return &s }

func TestReplaceRulesIfUnchangedSwapsOnlyTheReviewedContent(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRule(ScopeInclude, "one.test"))
	reviewed := ScopeRulesDigest(s.Rules())

	var mu sync.Mutex
	var events []ScopeChange
	s.OnChange(func(c ScopeChange) {
		mu.Lock()
		events = append(events, c)
		mu.Unlock()
	})

	// A stale digest refuses: no swap, no event.
	incoming := []*ScopeRule{NewScopeRule(ScopeExclude, "other.test")}
	if s.ReplaceRulesIfUnchanged("0000000000000000000000000000000000000000000000000000000000000000", incoming) {
		t.Fatal("a stale digest swapped the rules")
	}
	if got := s.Rules(); len(got) != 1 || got[0].Pattern != "one.test" {
		t.Fatalf("a refused replace changed the rules: %+v", got)
	}
	mu.Lock()
	if len(events) != 0 {
		t.Fatalf("a refused replace notified %d watchers; a refusal must be silent", len(events))
	}
	mu.Unlock()

	// The reviewed digest swaps, exactly once, with one event after the fact.
	if !s.ReplaceRulesIfUnchanged(reviewed, incoming) {
		t.Fatal("the reviewed digest was refused")
	}
	got := s.Rules()
	if len(got) != 1 || got[0].Kind != ScopeExclude || got[0].Pattern != "other.test" {
		t.Fatalf("rules after replace = %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("replace fired %d events, want exactly one (a swap of equal-count lists still changes meaning)", len(events))
	}
	if events[0].Operation != "replace" || events[0].Before != 1 || events[0].After != 1 {
		t.Errorf("event = %+v, want one replace 1->1", events[0])
	}
	// And the swap made the OLD digest stale: a replay of the same reviewed call refuses.
	if s.ReplaceRulesIfUnchanged(reviewed, []*ScopeRule{}) {
		t.Errorf("replaying the pre-swap digest swapped again; the token's content moved and must refuse")
	}
}

func TestSnapshotIfUnchangedCopiesTheReviewedMoment(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRule(ScopeInclude, "one.test"))
	reviewed := ScopeRulesDigest(s.Rules())

	if _, ok := s.SnapshotIfUnchanged("bad-digest"); ok {
		t.Fatal("a stale digest handed out a snapshot")
	}
	snap, ok := s.SnapshotIfUnchanged(reviewed)
	if !ok || len(snap) != 1 {
		t.Fatalf("snapshot = (%v, %v), want one rule", snap, ok)
	}
	// The snapshot is a value copy: flipping the live rule after the review must not rewrite
	// what the review bound.
	s.SetRuleEnabled(ScopeInclude, "one.test", nil, nil, nil, false)
	if !snap[0].Enabled {
		t.Errorf("a toggle after the snapshot rewrote the reviewed document")
	}
}

func TestScopeRulesDigestIsByteStableForPersistParity(t *testing.T) {
	// The digest is defined over a fixed canonical form: field order, omitempty arms, enabled
	// always written. Pin the exact bytes so a silent struct-tag drift is a test failure, not a
	// review that binds nothing.
	rules := []*ScopeRule{{Kind: ScopeInclude, Pattern: "app.test", Enabled: true}}
	want := `[{"kind":"include","pattern":"app.test","enabled":true}]`
	if got := string(ScopeRulesCanonical(rules)); got != want {
		t.Fatalf("canonical form = %s, want %s", got, want)
	}
	full := []*ScopeRule{{Kind: ScopeExclude, Pattern: "a.test", Port: digestPort(), PathPrefix: digestStr("/v1"), Protocol: digestStr("https"), Enabled: false}}
	want = `[{"kind":"exclude","pattern":"a.test","port":8443,"path_prefix":"/v1","protocol":"https","enabled":false}]`
	if got := string(ScopeRulesCanonical(full)); got != want {
		t.Fatalf("canonical form with all arms = %s, want %s", got, want)
	}
	if !strings.HasPrefix(ScopeRulesDigest(rules), "") || ScopeRulesDigest(rules) == ScopeRulesDigest(full) {
		t.Fatalf("digests of different content collided")
	}
}
