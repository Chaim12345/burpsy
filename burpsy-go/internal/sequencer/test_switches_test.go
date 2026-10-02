package sequencer

import "testing"

// Tests for the per-test switches (burpsy-react-ui-nm81).
//
// # The bead's own named test, and why it is the right one
//
// Criterion 4 asks for a test-pinned assertion that flipping fips_poker off changes which rows the
// report carries WHILE THE GRADE IS UNCHANGED. Both halves are load-bearing and they fail in
// opposite directions:
//
//   - If the report kept the row, the switch does nothing.
//   - If the report dropped the row silently, an operator cannot tell a switched-off test from a
//     build that lacks it, which is the dishonest-reporting shape this repository treats as a defect.
//
// So every test here asserts BOTH: the row is present AND marked, and the grade is untouched.

// fipsFixture is a sample with enough bits for the FIPS battery to answer every test, so a disabled
// row is a decision rather than a battery that declined to run anyway.
func fipsFixture() []string {
	tokens := make([]string, 0, 4096)
	const alphabet = "0123456789abcdef"
	for i := 0; i < 4096; i++ {
		var b [8]byte
		for j := range b {
			b[j] = alphabet[(i*7+j*3)%len(alphabet)]
		}
		tokens = append(tokens, string(b[:]))
	}
	return tokens
}

// rowsFor reports which test ids a report carries.
func rowsFor(f FipsReport) []string {
	out := make([]string, 0, len(f.Tests))
	for _, t := range f.Tests {
		out = append(out, t.ID)
	}
	return out
}

func hasRow(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// THE criterion. FIPS poker off changes the rows the report carries; everything else does not move.
func TestFlippingFipsPokerOffChangesTheRowsAndNotTheGrade(t *testing.T) {
	tokens := fipsFixture()

	full := AnalyseWith(tokens, nil, 1)
	withoutPoker := AnalyseWith(tokens, nil, 1)
	withoutPoker.Fips = AnalyseFipsBits(BitsOf(tokens, DetectEncoding(tokens)), []string{"poker"})

	// The FIPS battery's rows.
	fullRows, offRows := rowsFor(full.Fips), rowsFor(withoutPoker.Fips)
	if !hasRow(offRows, "poker") {
		t.Error("the poker row is ABSENT from the report; a row that vanishes is indistinguishable " +
			"from a build that never had the test, and the operator cannot tell what they switched off")
	}
	// It is present AND marked, and marked as not-passed: a disabled row that still read Passed would
	// be the worst of the three states, because it reports success for a test nobody ran.
	for _, row := range withoutPoker.Fips.Tests {
		if row.ID != "poker" {
			continue
		}
		if !row.Disabled {
			t.Error("the poker row is present but not marked disabled")
		}
		if row.Passed {
			t.Error("the poker row reports Passed for a test that was not run")
		}
		if row.DisableReason == "" {
			t.Error("the poker row is marked disabled without saying why")
		}
	}
	if len(offRows) != len(fullRows) {
		t.Errorf("the battery has %d rows with poker off and %d with it on, want the same count: a "+
			"switch changes whether a test RAN, not whether the battery HAS the test", len(offRows), len(fullRows))
	}
	// The other three are untouched.
	for _, id := range []string{"monobit", "runs", "long_runs"} {
		if !hasRow(offRows, id) {
			t.Errorf("the %s row went missing when poker was switched off", id)
		}
		for _, row := range withoutPoker.Fips.Tests {
			if row.ID == id && row.Disabled {
				t.Errorf("the %s row is marked disabled though only poker was named", id)
			}
		}
	}

	// THE other half: the grade and verdict are the FIPS battery's parity surface and must not move.
	if full.Grade != withoutPoker.Grade {
		t.Errorf("the grade changed when a FIPS test was switched off: %+v vs %+v — the grade is the "+
			"Rust reference's, byte for byte", full.Grade, withoutPoker.Grade)
	}
	if full.Verdict != withoutPoker.Verdict {
		t.Errorf("the verdict changed: %q vs %q", full.Verdict, withoutPoker.Verdict)
	}
}

// The switched-off list is on the report, so a reader learns what it declined without parsing rows.
func TestTheReportNamesWhatItWasToldNotToRun(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	report := AnalyseFipsBits(bits, []string{"monobit", "compression"})
	if len(report.SwitchedOff) != 1 || report.SwitchedOff[0] != "monobit" {
		t.Errorf("SwitchedOff = %v, want [monobit]: the list must name only what this battery declined, "+
			"so a test from the OTHER battery is not reported here as switched off", report.SwitchedOff)
	}
}

// An id from the other battery, or one that names nothing, is ignored rather than honoured.
func TestAnIdFromTheOtherBatteryOrAnUnknownOneIsIgnored(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	// "compression" is a REAL test — of the extended battery. Naming it here must not disable a FIPS
	// row, or the two batteries share a switch and switching one silently switches another.
	report := AnalyseFipsBits(bits, []string{"compression", "not-a-test", "  "})
	if len(report.Tests) != 4 {
		t.Errorf("the FIPS battery has %d rows, want 4: a name from the other battery must not remove one",
			len(report.Tests))
	}
	if len(report.SwitchedOff) != 0 {
		t.Errorf("SwitchedOff = %v, want empty: nothing in this list is a FIPS test", report.SwitchedOff)
	}
	for _, row := range report.Tests {
		if row.Disabled {
			t.Errorf("the %s row was disabled by naming a test from the other battery", row.ID)
		}
	}
}

// Every switchable test resolves to an id, and every id resolves back — the round trip a settings
// surface depends on, since it lists Burp keys and writes ids.
func TestTheTestVocabularyRoundTripsBetweenBurpKeysAndIDs(t *testing.T) {
	for _, test := range AnalysisTests {
		id, ok := AnalysisTestByBurpKey(test.BurpKey)
		if !ok {
			t.Errorf("%q (id %q) has a Burp key that does not resolve back to an id", test.BurpKey, test.ID)
			continue
		}
		if id != test.ID {
			t.Errorf("Burp key %q resolves to id %q, want %q", test.BurpKey, id, test.ID)
		}
		if !KnownAnalysisTest(test.ID) {
			t.Errorf("id %q is not reported as known", test.ID)
		}
		if test.Name == "" {
			t.Errorf("test %q has no name, so a settings surface would render an id", test.ID)
		}
	}
	// The descriptive count is NOT a switchable test — it is Burp's count of positions, and there is
	// nothing to turn off.
	if _, ok := AnalysisTestByBurpKey("count"); ok {
		t.Error("sequencer.token_analysis.count resolves to a switchable test; it is a descriptive " +
			"setting, not a test")
	}
}

// The table is sorted, because a settings surface renders it and an operator hunting for a control
// should not have to re-find it between visits.
func TestTheTestVocabularyIsSortedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i, test := range AnalysisTests {
		if seen[test.ID] {
			t.Errorf("test id %q appears twice", test.ID)
		}
		seen[test.ID] = true
		if i > 0 && AnalysisTests[i-1].ID > test.ID {
			t.Errorf("the table is out of order at %d: %q follows %q", i, test.ID, AnalysisTests[i-1].ID)
		}
	}
	if len(AnalysisTests) != 8 {
		t.Errorf("the table has %d tests, want 8 — four FIPS and four extended, which is what Burp's "+
			"panel switches (Zsiz.java:180-186)", len(AnalysisTests))
	}
}

// With nothing switched off, both batteries are byte-identical to before the feature. Without this a
// defaulting caller could have gained a "switched off: none" sentence and every existing snapshot
// would shift for no reason.
func TestSwitchingNothingChangesNothingInEitherBattery(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	before := AnalyseFipsBits(bits)
	after := AnalyseFipsBits(bits, nil)
	if len(before.Tests) != len(after.Tests) {
		t.Fatalf("row count changed with nothing switched off: %d vs %d", len(before.Tests), len(after.Tests))
	}
	for i := range before.Tests {
		if before.Tests[i].ID != after.Tests[i].ID {
			t.Errorf("row %d is %q with nothing disabled and %q with an empty list", i, before.Tests[i].ID, after.Tests[i].ID)
		}
		if after.Tests[i].Disabled {
			t.Errorf("the %s row is marked disabled with nothing switched off", after.Tests[i].ID)
		}
	}
	if len(after.SwitchedOff) != 0 {
		t.Errorf("SwitchedOff = %v with nothing switched off, want empty", after.SwitchedOff)
	}
}

// The variadic collapses correctly: several lists union rather than the first silently winning.
func TestSeveralDisableListsUnionRatherThanTheFirstWinning(t *testing.T) {
	off := DisabledSet(firstDisableList([][]string{{"monobit"}, {"poker"}}))
	if !off["monobit"] || !off["poker"] {
		t.Errorf("two disable lists produced %v, want both honoured: a variadic that kept only the "+
			"first would lose a setting with no error", off)
	}
	if len(firstDisableList(nil)) != 0 {
		t.Error("no lists produced a non-empty result")
	}
}

// A disabled test costs nothing to REPORT but the battery still answered the others — the switch
// changes what ran, not whether the battery could run.
func TestSwitchingEveryTestOffStillProducesABattery(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	report := AnalyseFipsBits(bits, []string{"monobit", "poker", "runs", "long_runs"})
	if len(report.Tests) != 4 {
		t.Fatalf("the battery has %d rows with everything switched off, want 4", len(report.Tests))
	}
	for _, row := range report.Tests {
		if !row.Disabled {
			t.Errorf("the %s row is not marked disabled", row.ID)
		}
	}
	if len(report.SwitchedOff) != 4 {
		t.Errorf("SwitchedOff has %d entries, want 4", len(report.SwitchedOff))
	}
	// And the block count is still reported, because the sample WAS decoded — the battery was told
	// not to judge it, not that it could not.
	if report.BitsTested == 0 {
		t.Error("bits_tested is 0 with every test switched off; the sample was decoded either way, " +
			"and a report claiming nothing was examined misstates what the run cost")
	}
}

// M2's target: a switch that honours an id this build does not know would let a caller suppress a test
// by naming something that is not one — and, worse, a future test added to the vocabulary would be
// switchable by a name nobody chose deliberately.
func TestAnUnknownIdCannotSuppressAnything(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	// Only UNKNOWN ids here. "transition" is a known id — of the extended battery — so including it
	// would make this test pass or fail on which battery a row belongs to rather than on the guard.
	report := AnalyseFipsBits(bits, []string{"monobit_typo", "POKER", "", "   "})
	if len(report.SwitchedOff) != 0 {
		t.Errorf("SwitchedOff = %v, want empty: only ids in the vocabulary may be honoured, and case "+
			"matters — %q and %q are not ids any test has", report.SwitchedOff, "monobit_typo", "POKER")
	}
	for _, row := range report.Tests {
		if row.Disabled {
			t.Errorf("the %s row was disabled by an id this build does not know", row.ID)
		}
	}
}

// The guard itself, where removing it is visible: DisabledSet drops every id outside the vocabulary.
// A switch that honoured an arbitrary string would let a caller suppress a test by naming something
// that is not one, and would make a test added to the vocabulary later switchable by a name nobody
// chose deliberately.
func TestDisabledSetDropsEveryIdOutsideTheVocabulary(t *testing.T) {
	known := AnalysisTests[0].ID // a real one, whatever it is
	got := DisabledSet([]string{known, "not-a-test", "POKER", "", "  ", "transition"})
	if !got[known] {
		t.Errorf("DisabledSet dropped the real id %q: %v", known, got)
	}
	for id := range got {
		if !KnownAnalysisTest(id) {
			t.Errorf("DisabledSet honoured %q, which is not in the vocabulary", id)
		}
	}
	if len(got) != 2 {
		t.Errorf("DisabledSet(%v) = %v, want exactly the two known ids (the fixture's %q and "+
			"\"transition\"); anything more means the guard is not applied", known, got, known)
	}
}

// Surrounding whitespace is TOLERATED, which is a separate property from the one above and the
// opposite case: a stored configuration with a trailing space must still switch the test the
// operator named, or a cosmetic difference in how the file was written silently does nothing.
func TestSurroundingWhitespaceInAnIdDoesNotDefeatTheSwitch(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	report := AnalyseFipsBits(bits, []string{"  poker  "})
	if len(report.SwitchedOff) != 1 || report.SwitchedOff[0] != "poker" {
		t.Errorf("SwitchedOff = %v, want [poker]: an id with surrounding whitespace is the same test, "+
			"and failing to match it would make a stored configuration depend on invisible characters",
			report.SwitchedOff)
	}
}

// M3's target: a disabled row that keeps Passed=true reports SUCCESS for a test nobody ran, which is
// worse than omitting the row — an omission is a gap, this is a false claim.
func TestADisabledRowDoesNotReportPassingOrAnyMeasuredNumbers(t *testing.T) {
	tokens := fipsFixture()
	bits := BitsOf(tokens, DetectEncoding(tokens))

	// MONOBIT, not poker: monobit PASSES on this fixture, which is what makes the assertion
	// load-bearing. A disabled row on a sample where the test happened to fail anyway would report
	// passed=false with or without the clearing, so removing the clear would go unobserved — which is
	// exactly what happened with poker in the first version of this test.
	on := AnalyseFipsBits(bits)
	off := AnalyseFipsBits(bits, []string{"monobit"})

	var wasOn, nowOff FipsTest
	for _, row := range on.Tests {
		if row.ID == "monobit" {
			wasOn = row
		}
	}
	for _, row := range off.Tests {
		if row.ID == "monobit" {
			nowOff = row
		}
	}
	if nowOff.ID == "" {
		t.Fatal("the monobit row is missing entirely, so there is nothing to check")
	}
	if !wasOn.Passed {
		t.Fatalf("fixture assumption broken: monobit does not pass with nothing switched off, so this "+
			"test cannot observe whether a disabled row's verdict was cleared. Report said passed=%v with "+
			"blocksPassed=%d", wasOn.Passed, wasOn.BlocksPassed)
	}
	if nowOff.Passed {
		t.Error("a row that PASSED with the test enabled reports passed with it disabled: that is " +
			"success for a test nobody ran, which is a false claim rather than a gap")
	}
	if nowOff.BlocksPassed != 0 || nowOff.BlocksFailed != 0 {
		t.Errorf("a disabled row carries block counts (%d passed, %d failed) from a run it was told "+
			"not to judge; the row it replaced measured %d", nowOff.BlocksPassed, nowOff.BlocksFailed,
			wasOn.BlocksPassed)
	}
	if nowOff.Observed != "" {
		t.Errorf("a disabled row still carries an observation: %q", nowOff.Observed)
	}
}
