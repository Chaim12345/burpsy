package tools

import "testing"

// Mirrors comparer.rs's the_default_budget_shrinks_as_the_inputs_grow. Small
// inputs get the ceiling; a pair of 200 KB bodies gets the floor, which is what
// keeps the bail-out cheap instead of burning 10^8 comparisons before giving up.
func TestBudgetForShrinksAsTheInputsGrow(t *testing.T) {
	if got := budgetFor(100); got != 2048 {
		t.Errorf("budgetFor(100) = %d, want the 2048 ceiling", got)
	}
	if got := budgetFor(400_000); got != 64 {
		t.Errorf("budgetFor(400_000) = %d, want the 64 floor", got)
	}
}
