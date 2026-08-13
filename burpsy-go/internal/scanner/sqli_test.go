package scanner

// The four tests that used to live here exercised analyzeSQLiEvidence, sqlInjectionProbes and the
// SQLiEvidence bitmask. All three went with ActiveScanner.checkSQLi — see sqli.go's header for why —
// and a test is not a reason to keep unreachable production code alive. The row they nominally
// covered is now demonstrated end-to-end against a live vulnerable target by
// runtime_coverage_test.go, which is strictly better evidence than a decision table exercised in
// isolation from anything that sends a request.
//
// responsesDiffer is what remains, and it has four live callers, so it is tested here directly.

import "testing"

func TestResponsesDifferIgnoresSurroundingWhitespaceOnly(t *testing.T) {
	// Identical bytes: not a difference.
	if responsesDiffer("rows=1", "rows=1") {
		t.Error("identical bodies reported as differing")
	}
	// Differing only by surrounding whitespace: transport formatting noise, not behaviour. Four
	// checks key on this helper, and treating a trailing newline as a behavioural change would make
	// every one of them fire on any server that is inconsistent about it.
	if responsesDiffer("rows=1", "  rows=1\n") {
		t.Error("bodies differing only by surrounding whitespace reported as differing")
	}
	// A real substitution: the case boolean injection produces.
	if !responsesDiffer("rows=1", "rows=0") {
		t.Error("a genuine body substitution was not reported as differing")
	}
	// Interior whitespace is content, not framing: trimming is deliberately only at the ends.
	if !responsesDiffer("rows=1", "rows= 1") {
		t.Error("an interior change was missed; trimming must apply to the ends only")
	}
	// One side empty is a difference.
	if !responsesDiffer("", "rows=1") {
		t.Error("an empty body against a populated one was not reported as differing")
	}
	// Both effectively empty is not.
	if responsesDiffer("", "   \n\t") {
		t.Error("two effectively empty bodies reported as differing")
	}
}
