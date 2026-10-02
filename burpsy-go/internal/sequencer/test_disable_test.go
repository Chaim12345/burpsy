package sequencer

// Tests for the per-test disable switch (burpsy-react-ui-3iao).
//
// # The property under test, and why it is not obvious
//
// The bead's own suggestion is the test to write: "disabling the compression test removes it from
// advanced.tests while Grade and Fips stay byte-identical." The second half is the load-bearing one.
//
// These extended tests were added explicitly NOT to touch the grade (advanced.go:11-16 — the grade and
// verdict sentence are byte-for-byte the Rust reference's, and the port is measured against it). A
// change that filters the battery can very easily perturb something else on the way through, and a
// test that only checks the disabled test disappeared would pass on an implementation that had
// quietly changed the grade. So every test here compares Grade, Verdict and the FIPS report against
// the same run with nothing disabled.

import (
	"bytes"
	"encoding/json"
	"testing"
)

// batteryFixture is a sample with enough structure for the extended tests to RUN rather than refuse.
//
// Every one of the four records why it could not run when the sample will not support it, and a
// fixture on which they all decline would let a broken filter pass: the disabled list would be
// indistinguishable from a battery that never ran.
func batteryFixture() []string {
	tokens := make([]string, 0, 4096)
	for i := 0; i < 4096; i++ {
		// A deliberately non-uniform alphabet, so the transition table has structure to test.
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
		var b [8]byte
		for j := range b {
			b[j] = alphabet[(i*7+j*13)%len(alphabet)]
		}
		tokens = append(tokens, string(b[:]))
	}
	return tokens
}

// jsonOf marshals a value for a byte-identical comparison.
func jsonOf(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling for comparison: %v", err)
	}
	return b
}

// The bead's named test: disabling one test removes it, and nothing else moves.
func TestDisablingOneTestRemovesItWhileTheGradeAndFipsStayIdentical(t *testing.T) {
	tokens := batteryFixture()

	full := AnalyseWith(tokens, nil, 1)
	withoutCompression := AnalyseWith(tokens, nil, 1)
	withoutCompression.Advanced = advancedFor(tokens, Encoding(0), nil, []string{"compression"})

	// The compression test is MARKED, not gone. This originally asserted the row left the list;
	// burpsy-react-ui-nm81 supersedes it, because a row that vanishes is indistinguishable from a
	// build that never had the test and the operator cannot tell what they switched off.
	for _, test := range withoutCompression.Advanced.Tests {
		if test.ID != "compression" {
			continue
		}
		if !test.Disabled {
			t.Errorf("the compression row is present but not marked disabled: %+v", test)
		}
		if test.DisableReason == "" {
			t.Error("the compression row is marked disabled without saying why")
		}
	}
	if len(withoutCompression.Advanced.Tests) != len(full.Advanced.Tests) {
		t.Errorf("advanced.tests has %d entries with compression off and %d with it on, want the same: a "+
			"switch changes whether a test RAN, not whether the battery HAS it",
			len(withoutCompression.Advanced.Tests), len(full.Advanced.Tests))
	}

	// And no test was introduced or lost by the switch.
	fullIDs := map[string]bool{}
	for _, test := range full.Advanced.Tests {
		fullIDs[test.ID] = true
	}
	for _, test := range withoutCompression.Advanced.Tests {
		if !fullIDs[test.ID] {
			t.Errorf("switching off compression introduced the test %q", test.ID)
		}
	}

	// The grade, the verdict and the FIPS report must be untouched. These are the fields the Rust
	// reference fixes and the port is measured against, so a change here is a parity break whatever
	// the extended battery does.
	if !bytes.Equal(jsonOf(t, full.Grade), jsonOf(t, withoutCompression.Grade)) {
		t.Errorf("the grade changed when an extended test was switched off: %+v vs %+v",
			full.Grade, withoutCompression.Grade)
	}
	if full.Verdict != withoutCompression.Verdict {
		t.Errorf("the verdict changed: %q vs %q", full.Verdict, withoutCompression.Verdict)
	}
	if !bytes.Equal(jsonOf(t, full.Fips), jsonOf(t, withoutCompression.Fips)) {
		t.Error("the FIPS report changed when an extended test was switched off; that battery is the " +
			"parity oracle and nothing here may perturb it")
	}
	if full.Advanced.AffectsGrade != withoutCompression.Advanced.AffectsGrade {
		t.Error("affects_grade changed; it is always false and is stated on the wire for exactly " +
			"this reason")
	}
}

// The Options field is what an HTTP caller sets, so the switch has to work end to end through it —
// not only through the internal function the previous test could reach.
func TestOptionsDisabledTestsIsHonouredEndToEnd(t *testing.T) {
	tokens := batteryFixture()

	report := analyseWithOptions(t, tokens, []string{"compression", "spectral"})
	ids := map[string]bool{}
	for _, test := range report.Advanced.Tests {
		ids[test.ID] = true
	}
	// Every row is still present, and the two named are marked. See the note above on why the row
	// is kept rather than dropped.
	if !ids["compression"] || !ids["spectral"] || !ids["transition"] || !ids["correlation"] {
		t.Errorf("advanced.tests is missing a row: %v, want all four present with two marked", ids)
	}
	for _, test := range report.Advanced.Tests {
		want := test.ID == "compression" || test.ID == "spectral"
		if test.Disabled != want {
			t.Errorf("the %s row reports disabled=%v, want %v", test.ID, test.Disabled, want)
		}
	}
}

// A disabled test is a DECISION by the reader and an untestable one is a LIMIT of the sample. Both
// appear in the report and they must not be reported the same way.
func TestADisabledTestIsReportedDifferentlyFromAnUntestableOne(t *testing.T) {
	// A sample too short for the extended battery: every test declines with a reason.
	short := []string{"abcd", "efgh", "ijkl"}

	report := analyseWithOptions(t, short, nil)
	for _, test := range report.Advanced.Tests {
		if test.Disabled {
			t.Errorf("%q is marked disabled with nothing switched off", test.ID)
		}
	}

	// Now disable one on the same short sample. The row is KEPT and marked, while every other row
	// is kept and UNmarked-because-untestable — so the two remain distinguishable by the flag rather
	// than by presence, which is what burpsy-react-ui-nm81's criterion 2 asks for.
	off := analyseWithOptions(t, short, []string{"compression"})
	disabled, untestable := 0, 0
	for _, test := range off.Advanced.Tests {
		if test.ID == "compression" {
			if !test.Disabled {
				t.Errorf("the compression row is present but not marked disabled: %+v", test)
			}
			disabled++
			continue
		}
		if test.Disabled {
			t.Errorf("the %s row is marked disabled though only compression was named", test.ID)
		}
		untestable++
	}
	if disabled != 1 {
		t.Errorf("%d rows are marked disabled, want 1", disabled)
	}
	if untestable == 0 {
		t.Error("no row came back untestable; the short sample should have declined several, which is " +
			"what makes the two states comparable")
	}
	if !bytes.Contains([]byte(off.Advanced.Summary), []byte("Switched off")) {
		t.Errorf("the summary does not name the tests that were switched off: %q", off.Advanced.Summary)
	}
}

// The summary's denominator must stay the FULL battery. "3 of 4 tests ran" reads as a smaller
// battery unless the report says which one is missing.
func TestTheSummaryQuotesTheWholeBatteryNotOnlyTheTestsThatRan(t *testing.T) {
	tokens := batteryFixture()
	report := analyseWithOptions(t, tokens, []string{"compression", "spectral"})

	summary := report.Advanced.Summary

	// The DENOMINATOR is the whole battery, whichever tests ran. This fixture cannot test every test
	// (one is reported untestable), so the count that matters is the "of 4" — a summary quoting "of 2"
	// would describe a smaller battery rather than a narrower run of the same one, and an operator
	// comparing two runs could not tell which it was.
	if !bytes.Contains([]byte(summary), []byte("of 4")) {
		t.Errorf("summary = %q, want the denominator to be the whole battery (\"of 4\"): quoting the "+
			"tests that survived the filter would read as a smaller battery", summary)
	}
	// And the switched-off tests are named, so the gap between the two counts is explained rather
	// than leaving the reader to work out which test is missing.
	for _, id := range []string{"compression", "spectral"} {
		if !bytes.Contains([]byte(summary), []byte(id)) {
			t.Errorf("summary = %q, want it to NAME %q as switched off", summary, id)
		}
	}
}

// With nothing disabled the report must be EXACTLY what it was before this change. Without this, a
// defaulting caller could have gained a "Switched off: none" sentence or a changed denominator and
// every existing snapshot would shift for no reason.
func TestDisablingNothingChangesNothingInTheReport(t *testing.T) {
	tokens := batteryFixture()
	full := AnalyseWith(tokens, nil, 1)
	none := analyseWithOptions(t, tokens, nil)

	if !bytes.Equal(jsonOf(t, full.Advanced), jsonOf(t, none.Advanced)) {
		t.Errorf("the advanced report differs with no tests disabled.\n full: %s\nnone: %s",
			jsonOf(t, full.Advanced), jsonOf(t, none.Advanced))
	}
}

// An id that names no test is ignored rather than refused. This is a filter over a battery a
// different build may have more or fewer of, and a stale id in a saved configuration must not fail
// the analysis.
func TestAnUnknownTestIdIsIgnoredRatherThanFailingTheAnalysis(t *testing.T) {
	tokens := batteryFixture()
	report := analyseWithOptions(t, tokens, []string{"compression", "not-a-real-test", "  ", ""})

	if len(report.Advanced.Tests) != 4 {
		t.Errorf("advanced.tests has %d entries, want 4 — an unknown id must not remove a row",
			len(report.Advanced.Tests))
	}
	marked := 0
	for _, test := range report.Advanced.Tests {
		if test.Disabled {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("%d rows are marked disabled, want 1: the real id must be honoured and the unknown "+
			"ones ignored", marked)
	}
}

// Every test can be switched off at once, and the report must then say so rather than reading as a
// battery that found nothing.
func TestSwitchingEveryTestOffStillReportsWhatWasNotRun(t *testing.T) {
	tokens := batteryFixture()
	report := analyseWithOptions(t, tokens, []string{"transition", "spectral", "correlation", "compression"})

	// Kept and marked, not dropped — the same correction as above.
	if len(report.Advanced.Tests) != 4 {
		t.Errorf("advanced.tests has %d entries with every test off, want 4 marked rows",
			len(report.Advanced.Tests))
	}
	for _, test := range report.Advanced.Tests {
		if !test.Disabled {
			t.Errorf("the %s row is not marked disabled", test.ID)
		}
	}
	if report.Advanced.Summary == "" {
		t.Error("the summary is empty with every test switched off; the reader needs to be told their " +
			"analysis considered nothing")
	}
	for _, id := range []string{"transition", "spectral", "correlation", "compression"} {
		if !bytes.Contains([]byte(report.Advanced.Summary), []byte(id)) {
			t.Errorf("the summary does not name %q as switched off: %q", id, report.Advanced.Summary)
		}
	}
}

// analyseWithOptions runs the analysis through Options, which is the path an HTTP caller takes.
func analyseWithOptions(t *testing.T, tokens, disabled []string) SequencerReport {
	t.Helper()
	report, err := AnalyseOpts(tokens, Options{
		SignificancePercent:   DefaultSignificancePercent,
		SignificanceDefaulted: true,
		DisabledTests:         disabled,
	})
	if err != nil {
		t.Fatalf("AnalyseOpts: %v", err)
	}
	return report
}
