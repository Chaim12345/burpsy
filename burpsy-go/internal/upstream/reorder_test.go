package upstream

// Tests for rule reordering (burpsy-react-ui-ldtj).
//
// The capability is only real if ORDER CHANGES RESOLUTION. `For` is first-match over the slice, so a
// Move that permutes the list without changing which proxy a host resolves to would satisfy every
// structural assertion and be worth nothing. So the load-bearing tests here assert on `For` before and
// after, not on the slice contents — and the last one is the mutation that catches a Move implemented
// as a swap rather than a reorder.

import "testing"

// orderedPolicy builds a policy whose rules OVERLAP, so their order decides the answer.
//
// Overlapping patterns are the whole point: `*` matches everything, so with `*.internal.example` also
// present, whichever is earlier wins for an internal host. A disjoint fixture would let a Move that did
// nothing still pass every resolution assertion.
//
// Note that matching is GLOB and not "most specific wins": `*.internal.example` also matches
// api.internal.example, so it takes that host whenever it is earlier in the list. That is not a quirk of
// this fixture — it is `For`'s documented first-match rule, and it is precisely why reordering is a
// capability rather than a cosmetic one: only the operator can say which of two matching rules should
// win, and the only way to say it is their order.
func orderedPolicy(t *testing.T) *Policy {
	t.Helper()
	p := &Policy{}
	for _, r := range []struct{ pattern, proxy string }{
		{"*", "http://catchall.test:8080"},
		{"*.internal.example", "http://internal.test:8080"},
		{"api.internal.example", "http://api.test:8080"},
	} {
		if _, err := p.Set(r.pattern, r.proxy); err != nil {
			t.Fatalf("set %s: %v", r.pattern, err)
		}
	}
	return p
}

// A move changes which proxy a host resolves to. That is the acceptance criterion stated as behaviour
// rather than as a slice comparison.
func TestMovingARuleChangesWhichProxyAHostResolvesTo(t *testing.T) {
	p := orderedPolicy(t)

	// As built, `*` is first, so everything resolves to the catchall — including the host a specific
	// rule exists for. That is the operator's problem in one sentence: their specific rule never fires.
	if got := p.For("api.internal.example").URL(); got == nil || got.Host != "catchall.test:8080" {
		t.Fatalf("fixture assumption broken: api.internal.example resolved to %v, want the catchall "+
			"because `*` is first", got)
	}

	// Move `*` to the end. The specific rules now get a chance.
	if _, moved := p.Move("*", 2); !moved {
		t.Fatal("Move reported no movement for a rule that had two rules after it")
	}

	// `*.internal.example` is now ahead of `api.internal.example`, so it wins the overlapping host —
	// first-match, not specificity. The point of the assertion is that the answer CHANGED.
	if got := p.For("api.internal.example").URL(); got == nil || got.Host != "internal.test:8080" {
		t.Errorf("after moving `*` last, api.internal.example resolved to %v, want internal.test:8080 — "+
			"reordering that does not change resolution is not the capability", got)
	}
	if got := p.For("db.internal.example").URL(); got == nil || got.Host != "internal.test:8080" {
		t.Errorf("after moving `*` last, db.internal.example resolved to %v, want internal.test:8080", got)
	}
	// And a host no specific rule covers still falls through to the default, not to the moved rule.
	if got := p.For("unrelated.example").URL(); got == nil || got.Host != "catchall.test:8080" {
		t.Errorf("an unrelated host resolved to %v, want the catchall (the moved `*` still covers it)", got)
	}
}

// Moving up and down are the two actions a UI offers, and they are the same operation with a sign.
func TestAMoveUpAndADownAreOneOperationWithASign(t *testing.T) {
	p := orderedPolicy(t)
	// Start: [* (0), *.internal.example (1), api.internal.example (2)] — `*` first, so every host
	// resolves to the catchall and the two specific rules never fire. That is the operator's problem:
	// they wrote rules that are unreachable.

	// DOWN one place: `*` goes behind *.internal.example, which now wins the overlapping host.
	if idx, moved := p.Move("*", 1); !moved || idx != 1 {
		t.Fatalf("Move(*, +1) = (%d, %v), want (1, true)", idx, moved)
	}
	if got := p.For("db.internal.example").URL(); got == nil || got.Host != "internal.test:8080" {
		t.Errorf("db.internal.example resolved to %v, want internal.test:8080 — the rule ahead of `*` "+
			"should now win the overlapping host", got)
	}

	// UP one place puts `*` back in front and the answer goes back with it.
	if idx, moved := p.Move("*", -1); !moved || idx != 0 {
		t.Fatalf("Move(*, -1) = (%d, %v), want (0, true)", idx, moved)
	}
	if got := p.For("db.internal.example").URL(); got == nil || got.Host != "catchall.test:8080" {
		t.Errorf("db.internal.example resolved to %v, want the catchall — `*` is first again", got)
	}

	// DOWN twice puts `*` last: [*.internal.example, api.internal.example, *]. db.internal.example is
	// covered by the wildcard rule and now resolves through it.
	if _, moved := p.Move("*", 2); !moved {
		t.Fatal("moving `*` to the end reported no movement")
	}
	if got := p.For("db.internal.example").URL(); got == nil || got.Host != "internal.test:8080" {
		t.Errorf("with `*` last, db.internal.example resolved to %v, want internal.test:8080", got)
	}
	// api.internal.example matches BOTH specific rules and is still won by *.internal.example, which is
	// now first. That is the documented first-match rule and NOT a specificity bug — worth stating in
	// the test, because "the more specific pattern should win" is the assumption this whole feature
	// exists to let an operator OVERRIDE.
	if got := p.For("api.internal.example").URL(); got == nil || got.Host != "internal.test:8080" {
		t.Errorf("api.internal.example resolved to %v, want internal.test:8080 — first-match, not "+
			"most-specific; an operator who wants api.test first moves that rule UP", got)
	}
	// And moving api.internal.example up does exactly that, which is the capability in one assertion.
	if _, moved := p.Move("api.internal.example", -1); !moved {
		t.Fatal("moving api.internal.example up reported no movement")
	}
	if got := p.For("api.internal.example").URL(); got == nil || got.Host != "api.test:8080" {
		t.Errorf("after moving api.internal.example up, it resolved to %v, want api.test:8080 — this is "+
			"the capability: an operator deciding which of two matching rules wins", got)
	}
}

// A move closes the gap it leaves. This is the mutation the reorder must not become: a SWAP exchanges
// two rules, so a three-rule list loses the one between them.
func TestAMoveClosesTheGapRatherThanSwappingTwoRules(t *testing.T) {
	p := orderedPolicy(t)
	before := p.Rules()
	if len(before) != 3 {
		t.Fatalf("fixture has %d rules, want 3", len(before))
	}

	// Move the first rule to the end.
	if _, moved := p.Move("*", 2); !moved {
		t.Fatal("Move reported no movement")
	}

	after := p.Rules()
	if len(after) != 3 {
		t.Fatalf("after the move the policy has %d rules, want 3 — a move must not drop one", len(after))
	}
	// Every rule survives, exactly once.
	seen := map[string]int{}
	for _, r := range after {
		seen[r.Pattern]++
	}
	for _, r := range before {
		if seen[r.Pattern] != 1 {
			t.Errorf("pattern %q appears %d times after the move, want exactly 1 — a swap would have "+
				"duplicated one and lost another", r.Pattern, seen[r.Pattern])
		}
	}
	// And the order is the ROTATION a move makes, not a transposition.
	//
	// This is the assertion that distinguishes a splice from a swap, and it needs a move where the two
	// differ — which is any move that is NOT to an adjacent position. Moving index 0 to index 2 in a
	// three-rule list: a splice gives [1,2,0]; a swap gives [2,1,0]. The first version of this test
	// asserted only that every pattern survived, and a swap mutation passed it, because a swap of
	// adjacent positions does preserve every pattern. It took a THREE-rule move with a gap to tell them
	// apart.
	want := []string{"*.internal.example", "api.internal.example", "*"}
	for i, pattern := range want {
		if after[i].Pattern != pattern {
			t.Errorf("rule %d is %q, want %q; moving the first rule to the end is a rotation "+
				"[1,2,0], and a swap would have produced [2,1,0] — which preserves every pattern while "+
				"silently reordering the middle one", i, after[i].Pattern, pattern)
		}
	}
}

// The adjacent case, where a swap and a splice agree on the SET but not on the order — the case that
// made the rotation assertion necessary rather than merely thorough.
func TestAnAdjacentMoveReordersWithoutLosingAnything(t *testing.T) {
	p := orderedPolicy(t)

	// Move the middle rule to the end: [*, api.internal, *.internal] under a splice.
	if _, moved := p.Move("*.internal.example", 1); !moved {
		t.Fatal("Move reported no movement")
	}
	want := []string{"*", "api.internal.example", "*.internal.example"}
	for i, pattern := range want {
		if got := p.Rules()[i].Pattern; got != pattern {
			t.Errorf("rule %d is %q, want %q", i, got, pattern)
		}
	}
	// And the resolution follows the new order: db.internal.example is now matched by `*` again,
	// because the wildcard moved back in front of the rule that covers it.
	if got := p.For("db.internal.example").URL(); got == nil || got.Host != "catchall.test:8080" {
		t.Errorf("db.internal.example resolved to %v, want the catchall", got)
	}
}

// Moving past either end clamps and says so, rather than erroring or silently claiming success.
func TestAMoveBeyondTheEndClampsAndReportsWhetherItMoved(t *testing.T) {
	p := orderedPolicy(t)

	// `*` is at index 0. Moving it up by 3 clamps to 0 and reports NO movement — the operator pressed
	// up on the top row, which is already true, and an error there would make a double-click look like
	// a failure.
	idx, moved := p.Move("*", -3)
	if idx != 0 {
		t.Errorf("clamped index = %d, want 0", idx)
	}
	if moved {
		t.Error("a clamp that changed nothing reported movement; a caller would render a move that did not happen")
	}

	// The last rule moved down by 5 likewise.
	last := p.Rules()[2].Pattern
	idx, moved = p.Move(last, 5)
	if idx != 2 || moved {
		t.Errorf("Move(last, +5) = (%d, %v), want (2, false)", idx, moved)
	}
}

// A pattern that is not there moves nothing, and reports the index the caller turns into a 404 —
// the same convention Remove already uses for a double-clicked delete.
func TestMovingARuleThatIsNotThereReportsNoIndex(t *testing.T) {
	p := orderedPolicy(t)
	idx, moved := p.Move("nope.example", 1)
	if idx != -1 {
		t.Errorf("index = %d, want -1 for a pattern that is not in the policy", idx)
	}
	if moved {
		t.Error("moving an absent pattern reported movement")
	}
	if len(p.Rules()) != 3 {
		t.Errorf("the policy now has %d rules, want 3", len(p.Rules()))
	}
}

// Reordering must survive a Save/Restore round trip, or the ordering is a session-only illusion — and
// the ordering is the part an operator set deliberately.
func TestTheOrderSurvivesASnapshotAndRestore(t *testing.T) {
	p := orderedPolicy(t)
	if _, moved := p.Move("*", 2); !moved {
		t.Fatal("Move reported no movement")
	}
	before := p.Rules()

	restored := &Policy{}
	if err := restored.Restore(p.Snapshot()); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	after := restored.Rules()
	if len(after) != len(before) {
		t.Fatalf("restored %d rules, want %d", len(after), len(before))
	}
	for i := range before {
		if after[i].Pattern != before[i].Pattern {
			t.Errorf("rule %d is %q after restore, want %q — an ordering an operator set must survive "+
				"a restart, or first-match precedence is a session-only illusion", i, after[i].Pattern, before[i].Pattern)
		}
	}
	// And the resolution follows, which is the part that actually matters.
	if got := restored.For("api.internal.example").URL(); got == nil || got.Host != "internal.test:8080" {
		t.Errorf("after restore, api.internal.example resolved to %v, want internal.test:8080", got)
	}
}

// A nil Policy answers like every other method on it, rather than panicking: the whole type guards
// nil, and one method that did not would be a crash an operator finds by clicking a button.
func TestMoveOnANilPolicyIsRefusedNotPanicked(t *testing.T) {
	var p *Policy
	if idx, moved := p.Move("anything", 1); idx != -1 || moved {
		t.Errorf("Move on nil = (%d, %v), want (-1, false)", idx, moved)
	}
}

// The concurrent case: Move takes the write lock, so a resolution running while an operator drags a
// rule cannot observe a half-permuted slice. This is the property that a lock-free version would lose.
func TestResolutionDuringAMoveNeverSeesAHalfReorderedList(t *testing.T) {
	p := orderedPolicy(t)
	done := make(chan struct{})
	// A reader racing the writer. Any iteration over p.rules that saw a torn slice would panic or
	// return a rule that is not in the policy; For holds the read lock, so it cannot.
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			p.For("api.internal.example")
		}
	}()
	for i := 0; i < 200; i++ {
		p.Move("*", i%3-1)
	}
	<-done
	// Whatever the interleaving, the policy is still coherent.
	if len(p.Rules()) != 3 {
		t.Errorf("after concurrent moves the policy has %d rules, want 3", len(p.Rules()))
	}
	for _, r := range p.Rules() {
		if r.Proxy.URL() == nil {
			t.Errorf("rule %q lost its proxy during a concurrent move", r.Pattern)
		}
	}
}
