package intruder

import "testing"

// Burp's Copy other payload exists for one case, and it gives it explicitly: two parameters that must
// always match, with the Cluster bomb attack type used to manipulate the other parameters
// (tools/intruder/configure-attack/payload-types.html:709-722). That is a password and its
// confirmation, varied against everything else.
//
// burpsy refused the combination as copy_other outside pitchfork, and the reason it recorded was
// exact: cluster bomb's mixed-radix Fill advances each position's set at a rate that depends on that
// position's place in the radix system, so a copy stepped by its own ordinal coincided with its
// source on some requests and diverged on the rest. Right most of the time, which is the worst
// possible disguise for a correctness bug (burpsy-react-ui-kwe0).
//
// The plan now decodes the SOURCE's digit for the copied position, which is exact by construction.
// These tests assert the property the payload type exists to guarantee, on every request, rather
// than on a sample that could have been lucky.

// A cluster bomb where the second position copies the first: the two must carry the SAME payload on
// every request, while the other positions vary independently. Set lengths are deliberately
// different, so a copy stepped by its own ordinal would drift immediately rather than coincidentally.
func TestACopiedPositionMatchesItsSourceOnEveryClusterBombRequest(t *testing.T) {
	// Three positions: 0 and 1 copy each other, 2 varies on its own.
	plan := NewAttackPlan(AttackKindClusterBomb, 3, []int{3, 3, 2}, 10_000).
		WithCopies(map[int]int{1: 0})

	setA := []string{"a1", "a2", "a3"}
	setB := []string{"a1", "a2", "a3"} // the copy's own set: never read, and deliberately identical
	setC := []string{"c1", "c2"}
	sets := [][]string{setA, setB, setC}

	var asg Assignment
	for i := 0; i < plan.Len(); i++ {
		if !plan.Fill(i, &asg) {
			t.Fatalf("Fill(%d) reported the end of the plan at Len()=%d", i, plan.Len())
		}
		if len(asg.Slots) != 3 {
			t.Fatalf("request %d produced %d slots, want 3", i, len(asg.Slots))
		}
		got0 := payloadAt(t, sets, asg.Slots[0])
		got1 := payloadAt(t, sets, asg.Slots[1])
		got2 := payloadAt(t, sets, asg.Slots[2])
		if got0 != got1 {
			t.Fatalf("request %d: position 0 carries %q and the position copying it carries %q; "+
				"Copy other exists so the two ALWAYS match, and a mismatch here is the exact bug the "+
				"refusal used to be preventing (burpsy-react-ui-kwe0)", i, got0, got1)
		}
		// And the varied position really does vary, or the copy assertion above would pass on a plan
		// that froze every position identically.
		//
		// The independent position is the SLOWEST digit here (sets 3, 3, 2 → its weight is 9), so it
		// legitimately repeats across nine requests. The first place it must differ is exactly there,
		// and asserting that is what stops this test from passing on a frozen plan.
		if i == 0 {
			if later := payloadAt(t, sets, slotAt(t, plan, len(setA)*len(setB), 2)); later == got2 {
				t.Fatalf("the independent position is %q at request 0 and %q at request %d; a plan that "+
					"varied nothing would satisfy the copy assertion above for the wrong reason",
					got2, later, len(setA)*len(setB))
			}
		}
	}
}

// The same property under an UNEVEN radix, which is where a copy stepped by its own ordinal drifts
// fastest. Set lengths 5, 5, 3 with the copy second: the digits for position 0 advance on a
// different schedule than position 1's would, so any own-ordinal copy diverges within a few requests.
func TestACopyIsExactUnderAnUnevenRadix(t *testing.T) {
	plan := NewAttackPlan(AttackKindClusterBomb, 3, []int{5, 5, 3}, 10_000).
		WithCopies(map[int]int{1: 0})

	setA := []string{"a1", "a2", "a3", "a4", "a5"}
	setB := []string{"a1", "a2", "a3", "a4", "a5"}
	setC := []string{"c1", "c2", "c3"}
	sets := [][]string{setA, setB, setC}

	var asg Assignment
	mismatches := 0
	for i := 0; i < plan.Len(); i++ {
		plan.Fill(i, &asg)
		if payloadAt(t, sets, asg.Slots[0]) != payloadAt(t, sets, asg.Slots[1]) {
			mismatches++
		}
	}
	if mismatches != 0 {
		t.Errorf("%d of %d requests carried different payloads in the pair; Copy other guarantees they "+
			"match on every request", mismatches, plan.Len())
	}
}

// Pitchfork keeps working, and takes the same path. Every position advances at one index there, so a
// copy is exact for a different reason — which is why this asserts the property rather than the
// mechanism.
func TestACopyIsStillExactInPitchfork(t *testing.T) {
	plan := NewAttackPlan(AttackKindPitchfork, 2, []int{3, 3}, 100).WithCopies(map[int]int{1: 0})
	setA := []string{"a1", "a2", "a3"}
	setB := []string{"a1", "a2", "a3"}
	sets := [][]string{setA, setB}

	var asg Assignment
	for i := 0; i < plan.Len(); i++ {
		plan.Fill(i, &asg)
		if payloadAt(t, sets, asg.Slots[0]) != payloadAt(t, sets, asg.Slots[1]) {
			t.Fatalf("request %d: pitchfork's copy drifted", i)
		}
	}
}

// A copy whose source is out of range, forward, or itself is REFUSED rather than clamped. A copy that
// silently resolved to the wrong position would produce requests whose two "identical" fields differ,
// which is the failure this payload type exists to prevent, and it would look like an application bug
// rather than a misconfiguration.
func TestACopyThatCannotBeResolvedIsRefusedRatherThanGuessed(t *testing.T) {
	plan := NewAttackPlan(AttackKindClusterBomb, 3, []int{2, 2, 2}, 100)

	// Forward: position 1 naming position 2.
	plan.WithCopies(map[int]int{1: 2})
	// Self.
	plan.WithCopies(map[int]int{1: 1})
	// Out of range.
	plan.WithCopies(map[int]int{1: 9})

	var asg Assignment
	plan.Fill(0, &asg)
	for _, slot := range asg.Slots {
		if slot.Set != slot.Point {
			t.Fatalf("slot for point %d resolved to set %d; a refused copy must leave the position using "+
				"its OWN set rather than a guess", slot.Point, slot.Set)
		}
	}

	// And a valid copy still takes, so the refusals are not "every copy is ignored".
	plan.WithCopies(map[int]int{2: 0})
	plan.Fill(0, &asg)
	if asg.Slots[2].Set != 0 {
		t.Errorf("a valid backward copy was refused: point 2 resolved to set %d, want the source's 0", asg.Slots[2].Set)
	}
}

// A plan with no copies behaves exactly as it did before the mapping existed: every position uses its
// own set. A copyFrom that defaulted to something would quietly change every attack shape in the tool.
func TestAPlanWithNoCopiesIsUnchanged(t *testing.T) {
	plan := NewAttackPlan(AttackKindClusterBomb, 3, []int{2, 3, 4}, 100)
	var asg Assignment
	plan.Fill(0, &asg)
	for _, slot := range asg.Slots {
		if slot.Set != slot.Point {
			t.Errorf("point %d resolved to set %d with no copies declared; the mapping must default to "+
				"each position using its own set", slot.Point, slot.Set)
		}
	}
}

// payloadAt reads the payload a slot would put on the wire, from the caller's sets. It mirrors what
// the engine does at engine.go's splice, so a test failure means the WIRING is wrong rather than the
// plan producing a shape the engine cannot read.
func payloadAt(t *testing.T, sets [][]string, slot Slot) string {
	t.Helper()
	if slot.Set < 0 || slot.Set >= len(sets) {
		t.Fatalf("slot names set %d, which does not exist", slot.Set)
	}
	if slot.Payload < 0 || slot.Payload >= len(sets[slot.Set]) {
		t.Fatalf("slot names payload %d of a %d-entry set", slot.Payload, len(sets[slot.Set]))
	}
	return sets[slot.Set][slot.Payload]
}

// slotAt fills the plan at ordinal i and returns one position's slot. A function because Assignment
// is reused across Fill calls, so a caller must not be left holding another request's slots.
func slotAt(t *testing.T, plan *AttackPlan, i, point int) Slot {
	t.Helper()
	var asg Assignment
	if !plan.Fill(i, &asg) {
		t.Fatalf("Fill(%d) reported the end of the plan at Len()=%d", i, plan.Len())
	}
	if point >= len(asg.Slots) {
		t.Fatalf("Fill(%d) produced %d slots, want one for point %d", i, len(asg.Slots), point)
	}
	return asg.Slots[point]
}
