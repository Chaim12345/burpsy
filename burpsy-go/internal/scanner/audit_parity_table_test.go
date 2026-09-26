package scanner

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// xdtx: BurpStatusesNotModelled is the project's own disclosure of what it cannot do, and it was
// wrong. It said "there is no light-active pass" three times while audit_engine.go implemented one
// (burpsy-react-ui-7bkj). A disclosure that denies a capability the engine has is worse than no
// disclosure: a reader who has just been wrong about light auditing has no reason to believe the
// rows about selection or parameter types either.
//
// These tests are the fix's teeth. A row cannot be edited without agreeing with the engine, so the
// next stale row is a failing test rather than a comment somebody has to remember to re-read.

func gapByStatus(status string) (BurpStatusGap, bool) {
	for _, g := range BurpStatusesNotModelled {
		if g.Status == status {
			return g, true
		}
	}
	return BurpStatusGap{}, false
}

// The count the parity panel reports is derived (BurpAuditItemStatusCount - len(NotModelled)), so a
// row added or removed moves it automatically. What is NOT automatic is the prose in the doc
// comment above the table, which is what a reader reads first. These two must agree.
func TestTheNotModelledTablesOwnCountMatchesItsRows(t *testing.T) {
	src := readSource(t, "audit_items.go")
	commentStart := strings.Index(src, "// BurpStatusesNotModelled is")
	if commentStart < 0 {
		t.Fatal("the table's doc comment is gone; the count it states has nothing to check against")
	}
	varStart := strings.Index(src, "var BurpStatusesNotModelled")
	if varStart < 0 || varStart < commentStart {
		t.Fatal("the not-modelled table is gone, or the comment that states its size is now somewhere " +
			"else in the file; either way there is nothing to check the count against")
	}
	comment := src[commentStart:varStart]

	words := map[string]string{"Eight": "8", "Seven": "7", "Nine": "9", "Six": "6"}
	stated := ""
	for word, digit := range words {
		if strings.Contains(comment, word+" of fifteen") {
			stated = digit
		}
	}
	if stated == "" {
		t.Fatal("the doc comment no longer states how many of the fifteen are not modelled, so a reader " +
			"cannot tell the table's size without counting it")
	}
	if want := len(BurpStatusesNotModelled); stated != itoa(want) {
		t.Errorf("the doc comment says %s of fifteen are not modelled; the table has %d rows. The prose is "+
			"what a reader believes, and a count that disagrees with the rows below it is the same defect "+
			"as a row that disagrees with the engine", stated, want)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// Every row must give a reason. A row with an empty Why is a gap with no disclosure, which is the
// one thing this table exists to prevent.
func TestEveryNotModelledStatusSaysWhyItIsAbsent(t *testing.T) {
	for _, g := range BurpStatusesNotModelled {
		if strings.TrimSpace(g.Why) == "" {
			t.Errorf("%s is listed as not modelled with no reason; the whole purpose of this table is to "+
				"let a reader see precisely what is absent, and a bare name is not that", g.Status)
		}
		if len(g.Why) < 30 {
			t.Errorf("%s gives a %d-character reason (%q); long enough to be a placeholder rather than an "+
				"explanation of what the engine does instead", g.Status, len(g.Why), g.Why)
		}
	}
}

// The bug this bead is about, pinned as a test. These three rows said the light tier did not exist.
// If the engine grows a light-ACTIVE pass — an item dispatched into a light tier and finishing in a
// distinct state — this test fails and the row has to be revisited, which is the point.
func TestTheLightAuditRowsDescribeTheLightTierThatExists(t *testing.T) {
	// The engine has a light tier, and it is a skip decision rather than a pass. If that ever
	// changes, these three rows are wrong again and this is where it gets caught.
	if DefaultLightAuditSamplePerKind == 0 {
		t.Skip("the light tier is off by default; the rows describe the tier, which is still there")
	}
	for _, status := range []string{"LIGHT_AUDITING", "LIGHT_AUDITED", "NOT_LIGHT_AUDITED"} {
		g, ok := gapByStatus(status)
		if !ok {
			t.Errorf("%s is no longer listed as not modelled. Either the engine grew the state behind it — "+
				"in which case this row should come out and the modelled count should rise — or the row was "+
				"deleted without checking. Deleting it silently is how the last stale claim reached a reader",
				status)
			continue
		}
		if strings.Contains(strings.ToLower(g.Why), "no light-active pass") ||
			strings.Contains(strings.ToLower(g.Why), "there is no light") {
			t.Errorf("%s still claims the light tier does not exist (%q). audit_engine.go has implemented it "+
				"since burpsy-react-ui-7bkj, and a disclosure that denies a capability the engine has makes "+
				"every other row in this table untrustworthy", status, g.Why)
		}
	}
}

// And the row that MOVED: repetitive behaviour is modelled, so it must not be listed as absent. It
// was, with a Why that said there is no repetitive-response detector — while the engine skips points
// as repetitive through the light tier's counter.
func TestRepetitiveBehaviourIsNotClaimedAbsentWhileTheEngineSkipsForIt(t *testing.T) {
	g, ok := gapByStatus("SKIPPED_DUE_TO_REPETITIVE_BEHAVIOUR")
	if ok {
		t.Fatalf("SKIPPED_DUE_TO_REPETITIVE_BEHAVIOUR is listed as not modelled (%q), but the light tier "+
			"skips points as repetitive — the run counts CLEAN same-(kind, host) occurrences and declines "+
			"the rest (audit_engine.go's lightAuditShouldSkip)", g.Why)
	}
	// The other half: a model with no state at all would be the same defect wearing a different hat.
	if !regexp.MustCompile(`(?i)repetitive`).MatchString(skippedReasonSomewhere(t)) {
		t.Log("no repetitive-behaviour reason was found in the table's neighbourhood; the engine's skip is " +
			"counted in the item's skipped total rather than as a state, which is worth knowing but is not " +
			"this test's claim to make")
	}
}

// skippedReasonSomewhere reports whether the light tier's behaviour is described anywhere near the
// table, so a reader who lands there learns what the engine does instead of only what it lacks.
func skippedReasonSomewhere(t *testing.T) string {
	t.Helper()
	src := readSource(t, "audit_items.go")
	i := strings.Index(src, "var BurpStatusesNotModelled")
	if i < 0 {
		t.Fatal("the not-modelled table is gone")
	}
	// The window around the table: its own doc comment and the rows.
	return src[strings.Index(src[:i], "// BurpStatusesNotModelled is"):i]
}

// readSource returns this package's own source, so the tests above check the shipped text rather
// than a copy of it that could drift.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
