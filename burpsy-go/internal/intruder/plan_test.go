package intruder

import (
	"math"
	"reflect"
	"sort"
	"testing"
)

// Ports burpsy-intruder::plan's test suite (plan.rs:301-430).

// combos materialises a plan as (point, payload) pairs, like the Rust helper.
func combos(t *testing.T, p *AttackPlan) [][]struct{ point, payload int } {
	t.Helper()
	var out [][]struct{ point, payload int }
	var asg Assignment
	for i := 0; i < p.Len(); i++ {
		if !p.Fill(i, &asg) {
			t.Fatalf("fill(%d) returned false inside the plan's length", i)
		}
		var row []struct{ point, payload int }
		for _, s := range asg.Slots {
			row = append(row, struct{ point, payload int }{s.Point, s.Payload})
		}
		out = append(out, row)
	}
	return out
}

func TestSniperWalksOnePositionAtATime(t *testing.T) {
	p := NewAttackPlan(AttackKindSniper, 3, []int{2}, math.MaxInt)
	if p.Len() != 6 {
		t.Fatalf("len = %d, want 6", p.Len())
	}
	got := combos(t, p)
	want := [][]struct{ point, payload int }{
		{{0, 0}}, {{0, 1}}, {{1, 0}}, {{1, 1}}, {{2, 0}}, {{2, 1}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("combos = %+v, want %+v", got, want)
	}
}

func TestBatteringRamPutsTheSamePayloadInEveryPosition(t *testing.T) {
	p := NewAttackPlan(AttackKindBatteringRam, 3, []int{2}, math.MaxInt)
	if p.Len() != 2 {
		t.Fatalf("len = %d, want one request per payload, not per position", p.Len())
	}
	got := combos(t, p)
	want := [][]struct{ point, payload int }{
		{{0, 0}, {1, 0}, {2, 0}},
		{{0, 1}, {1, 1}, {2, 1}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("combos = %+v, want %+v", got, want)
	}
}

func TestPitchforkAdvancesInLockstepAndStopsAtTheShortestSet(t *testing.T) {
	p := NewAttackPlan(AttackKindPitchfork, 3, []int{5, 2, 4}, math.MaxInt)
	if p.Len() != 2 {
		t.Fatalf("len = %d, want the 2-entry set to end the attack", p.Len())
	}
	got := combos(t, p)
	want := [][]struct{ point, payload int }{
		{{0, 0}, {1, 0}, {2, 0}},
		{{0, 1}, {1, 1}, {2, 1}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("combos = %+v, want %+v", got, want)
	}
}

func TestPitchforkWithOneEmptySetPlansNothing(t *testing.T) {
	p := NewAttackPlan(AttackKindPitchfork, 2, []int{9, 0}, math.MaxInt)
	if p.Len() != 0 {
		t.Fatalf("len = %d, want 0", p.Len())
	}
	if p.Combinations() != 0 {
		t.Fatalf("combinations = %d, want 0", p.Combinations())
	}
	var a Assignment
	if p.Fill(0, &a) {
		t.Fatal("fill(0) must be false on an empty plan")
	}
}

func TestClusterBombIsTheCartesianProductWithTheFirstSetVaryingFastest(t *testing.T) {
	p := NewAttackPlan(AttackKindClusterBomb, 2, []int{3, 2}, math.MaxInt)
	if p.Len() != 6 {
		t.Fatalf("len = %d, want 6", p.Len())
	}
	got := combos(t, p)
	// Sprays: every set-0 payload against set-1 payload 0 before moving to payload 1.
	want := [][]struct{ point, payload int }{
		{{0, 0}, {1, 0}},
		{{0, 1}, {1, 0}},
		{{0, 2}, {1, 0}},
		{{0, 0}, {1, 1}},
		{{0, 1}, {1, 1}},
		{{0, 2}, {1, 1}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("combos = %+v, want %+v", got, want)
	}
}

func TestClusterBombCoversEveryCombinationExactlyOnce(t *testing.T) {
	p := NewAttackPlan(AttackKindClusterBomb, 3, []int{4, 3, 2}, math.MaxInt)
	if p.Len() != 24 {
		t.Fatalf("len = %d, want 24", p.Len())
	}
	var seen [][]int
	var asg Assignment
	for i := 0; i < p.Len(); i++ {
		p.Fill(i, &asg)
		row := make([]int, len(asg.Slots))
		for j, s := range asg.Slots {
			row[j] = s.Payload
		}
		seen = append(seen, row)
	}
	sort.Slice(seen, func(i, j int) bool {
		for k := range seen[i] {
			if seen[i][k] != seen[j][k] {
				return seen[i][k] < seen[j][k]
			}
		}
		return false
	})
	for i := 1; i < len(seen); i++ {
		if reflect.DeepEqual(seen[i-1], seen[i]) {
			t.Fatalf("combination repeated: %v", seen[i])
		}
	}
	if len(seen) != 24 {
		t.Fatalf("only %d distinct combinations", len(seen))
	}
}

// The point of the whole module: a plan that would be terabytes as a Vec is a struct with a
// few small fields, and only the bounded prefix is ever produced.
func TestABillionCombinationClusterBombCostsNothingToDescribe(t *testing.T) {
	p := NewAttackPlan(AttackKindClusterBomb, 3, []int{1_000, 1_000, 1_000}, 5_000)
	if p.Combinations() != 1_000_000_000 {
		t.Fatalf("combinations = %d, want 1e9", p.Combinations())
	}
	if !p.CombinationsExact() {
		t.Fatal("a product within uint64 must be exact")
	}
	if p.Len() != 5_000 {
		t.Fatalf("len = %d, want the bound, not the product", p.Len())
	}
	if !p.Truncated() {
		t.Fatal("the caller must be able to see the attack was cut")
	}
	if got := p.setLens(); !reflect.DeepEqual(got, []int{1_000, 1_000, 1_000}) {
		t.Fatalf("plan holds only the set lengths, got %v", got)
	}

	// The bounded prefix still decodes correctly at its far end.
	var a Assignment
	if !p.Fill(4_999, &a) {
		t.Fatal("fill(4999) must succeed")
	}
	var payloads []int
	for _, s := range a.Slots {
		payloads = append(payloads, s.Payload)
	}
	if !reflect.DeepEqual(payloads, []int{999, 4, 0}) {
		t.Fatalf("fill(4999) = %v, want [999 4 0]", payloads)
	}
	if p.Fill(5_000, &a) {
		t.Fatal("fill(5000) must fail past the bound")
	}
}

func TestAnAbsurdProductSaturatesAndSaysSo(t *testing.T) {
	p := NewAttackPlan(AttackKindClusterBomb, 8, []int{math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt}, 10)
	if p.Combinations() != math.MaxUint64 {
		t.Fatalf("combinations = %d, want the saturated report", p.Combinations())
	}
	if p.CombinationsExact() {
		t.Fatal("a saturated count must not be presented as exact")
	}
	if !p.Truncated() {
		t.Fatal("a saturated product must report truncation")
	}
	if p.Len() != 10 {
		t.Fatalf("len = %d, want 10", p.Len())
	}
}

func TestUntruncatedPlansReportNoBoundApplied(t *testing.T) {
	p := NewAttackPlan(AttackKindSniper, 2, []int{3}, 1_000)
	if p.Len() != 6 {
		t.Fatalf("len = %d, want 6", p.Len())
	}
	if p.Truncated() {
		t.Fatal("6 requests under a 1000 bound is not truncated")
	}
	if p.Combinations() != 6 {
		t.Fatalf("combinations = %d, want 6", p.Combinations())
	}
}

func TestPlanIsIndicesNotRequests(t *testing.T) {
	v := Plan(50, 10_000, AttackKindSniper)
	if len(v) != 500_000 {
		t.Fatalf("len = %d, want 500000", len(v))
	}
	if v[0] != (planPair{0, 0}) {
		t.Fatalf("v[0] = %+v, want (0, 0)", v[0])
	}
	if v[499_999] != (planPair{49, 9_999}) {
		t.Fatalf("v[499999] = %+v, want (49, 9999)", v[499_999])
	}
}
