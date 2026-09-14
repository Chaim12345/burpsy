package sequencer

import (
	"encoding/json"
	"math"
	"math/bits"
	"strings"
	"testing"
)

// The fixture the whole file is anchored to, chosen so every number below is
// arrived at with a pen rather than read off this implementation.
//
// Ten hex tokens of two characters each. Hex decodes four bits per character,
// most-significant first, so each token is eight bit positions: 0..3 from the
// first character, 4..7 from the second.
//
//	first character  '0' in all ten tokens -> bits 0000
//	                 => positions 0,1,2,3 carry a 1 in 0 of 10 tokens
//	second character 'f' in five, '0' in five -> 1111 / 0000
//	                 => positions 4,5,6,7 carry a 1 in exactly 5 of 10 tokens
//
// The two-sided exact binomial p-values follow directly:
//
//	k=0, n=10: 2 x P(X=0) = 2 x 2^-10 = 2^-9 = 0.001953125  (the constant nibble)
//	k=5, n=10: 2 x P(X<=5) = 2 x 638/1024 = 1.24..., clamped to 1  (the even split)
//	           where 638 = 1+10+45+120+210+252
//
// So at any level strictly above 0.1953125% the four constant positions are
// rejected and the four even ones are not: four bits of effective entropy out of
// eight. At or below that level nothing can be rejected at all, which is the
// insufficiency the curve is required to report rather than paper over.
func constantNibbleFixture() []string {
	return []string{"0f", "00", "0f", "00", "0f", "00", "0f", "00", "0f", "00"}
}

const fixtureConstantP = 0.001953125 // 2^-9, exactly

func pointAtLevel(t *testing.T, report EffectiveEntropyReport, percent float64) EffectiveEntropyPoint {
	t.Helper()
	for _, point := range report.Curve {
		if sameLevel(point.SignificancePercent, percent) {
			return point
		}
	}
	t.Fatalf("the curve has no point at %g%%, so this sample's behaviour at that level cannot be checked at all; levels present: %v",
		percent, curveLevels(report))
	return EffectiveEntropyPoint{}
}

func curveLevels(report EffectiveEntropyReport) []float64 {
	out := make([]float64, 0, len(report.Curve))
	for _, point := range report.Curve {
		out = append(out, point.SignificancePercent)
	}
	return out
}

// The exact two-sided binomial tail is the one number every bit count rests on,
// so it is pinned against values computed by hand from the binomial
// coefficients rather than against anything this package produced.
func TestTheTwoSidedBinomialPValueMatchesTheHandComputedTail(t *testing.T) {
	cases := []struct {
		n, k int
		want float64
		how  string
	}{
		{10, 0, 0.001953125, "2 x C(10,0)/2^10 = 2/1024"},
		{10, 10, 0.001953125, "the same by symmetry: every token carrying a 1"},
		{10, 1, 0.021484375, "2 x (C(10,0)+C(10,1))/2^10 = 2 x 11/1024"},
		{10, 5, 1, "2 x 638/1024 exceeds 1 and is clamped: an even split is the least surprising result there is"},
		{4, 0, 0.125, "2 x 1/16"},
		{1, 0, 1, "one token can never be surprising: 2 x 1/2"},
		{2, 0, 0.5, "2 x 1/4"},
		{20, 3, 0.002576828, "2 x (1+20+190+1140)/2^20 = 2 x 1351/1048576"},
	}
	for _, c := range cases {
		got := binomialTwoSidedP(c.n, c.k)
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("binomialTwoSidedP(%d, %d) = %.12g, want %.12g (%s). A wrong tail here moves every bit count on the curve, in the direction of either inventing or hiding a rejected position.",
				c.n, c.k, got, c.want, c.how)
		}
	}
}

// The number that decides whether a curve point exists at all has to be exact:
// a rounding error in it turns "this sample cannot answer here" into a confident
// count of surviving bits.
func TestTheSmallestReachablePValueIsExactlyTwoToTheOneMinusN(t *testing.T) {
	for n := 2; n <= 60; n++ {
		want := math.Ldexp(1, 1-n)
		if got := minAttainableP(n); got != want {
			t.Fatalf("minAttainableP(%d) = %.20g, want exactly %.20g. This value is compared against the significance level to decide whether the sample has any power at all, so it must not be approximate.",
				n, got, want)
		}
	}
	if got := minAttainableP(1); got != 1 {
		t.Fatalf("minAttainableP(1) = %v, want 1: a single token can produce no evidence against any hypothesis, so no level can have power over it.", got)
	}
	if got := minAttainableP(0); got != 1 {
		t.Fatalf("minAttainableP(0) = %v, want 1: an empty sample cannot reject anything.", got)
	}
}

// The headline claim of the fixture, stated as bits at a level.
func TestFourOfEightBitPositionsSurviveTheFixtureAtTwoTenthsOfAPercent(t *testing.T) {
	report := AnalyseWith(constantNibbleFixture(), nil, 0.2).EffectiveEntropy
	if report.BitPositionsExamined != 8 {
		t.Fatalf("bit_positions_examined = %d, want 8: two hex characters decode to eight bit positions, and examining a different number means the decode, not the statistics, is wrong.",
			report.BitPositionsExamined)
	}
	if report.TokensUsed != 10 {
		t.Fatalf("tokens_used = %d, want 10: every p-value is computed against this n, so it must be the sample size.", report.TokensUsed)
	}
	point := pointAtLevel(t, report, 0.2)
	if !point.Computed {
		t.Fatalf("the 0.2%% point is not computed (%s), but 2^-9 = %.9f is below 0.002, so this sample does have power at that level.",
			point.Reason, fixtureConstantP)
	}
	if *point.Bits != 4 {
		t.Fatalf("bits at 0.2%% = %d, want 4. The four positions from the constant '0' nibble score p = %.9f and are rejected; the four from the 'f'/'0' split score p = 1 and are not. A different count means positions are being rejected on the wrong evidence.",
			*point.Bits, fixtureConstantP)
	}
	if *point.BitsRejected != 4 {
		t.Fatalf("bits_rejected at 0.2%% = %d, want 4: bits and bits_rejected must sum to the eight positions examined, or the report is double-counting.", *point.BitsRejected)
	}
	if want := 0.002 * 8; math.Abs(*point.ExpectedChanceRejections-want) > 1e-12 {
		t.Fatalf("expected_chance_rejections at 0.2%% = %v, want %v. This is the number an operator compares the loss against; without it a loss of 4 of 8 cannot be told from the level's own false-positive rate.",
			*point.ExpectedChanceRejections, want)
	}
	if report.Chosen.SignificancePercent != 0.2 || !report.Chosen.Chosen {
		t.Fatalf("chosen = %+v, want the 0.2%% point flagged as chosen: the operator's level is the one number the report leads with.", report.Chosen)
	}
}

// The refusal the sample size forces, and the rule that it is never rendered as
// a zero or as a pass.
func TestTheFixtureRefusesToAnswerBelowItsSmallestReachablePValue(t *testing.T) {
	report := AnalyseWith(constantNibbleFixture(), nil, 0.1).EffectiveEntropy
	point := pointAtLevel(t, report, 0.1)
	if point.Computed {
		t.Fatalf("the 0.1%% point reports %d bit(s), but 0.1%% is 0.001 and no bit position in a ten-token sample can score below 2^-9 = %.9f. A count here would be an artefact of the sample size presented as a measurement.",
			*point.Bits, fixtureConstantP)
	}
	if point.Bits != nil || point.BitsRejected != nil || point.ExpectedChanceRejections != nil {
		t.Fatalf("an uncomputed point carries numbers (%+v): they must be absent, because a zero in `bits` reads as 'no bit survived', the exact opposite of 'this sample cannot say'.", point)
	}
	if point.Reason == "" {
		t.Fatalf("an uncomputed point carries no reason. 'Absent' without a reason is indistinguishable from a bug in the caller's chart.")
	}
	// Every ladder point at or below 0.1% is in the same position, and every one
	// above 0.1953125% is answerable.
	for _, p := range report.Curve {
		wantComputed := fixtureConstantP < p.Significance
		if p.Computed != wantComputed {
			t.Fatalf("the %g%% point has computed = %v, want %v: the sample has power at a level exactly when its smallest reachable p-value (%.9f) is below that level as a fraction (%.9f).",
				p.SignificancePercent, p.Computed, wantComputed, fixtureConstantP, p.Significance)
		}
	}
	if !warningsContain(AnalyseWith(constantNibbleFixture(), nil, 0.1).Warnings, "effective-entropy figure at the 0.1% significance level") {
		t.Fatalf("no warning names the missing figure at the chosen level. An operator who reads only the headline must still be told there is no headline number.")
	}
}

// Burp's chart exists to answer one question at a glance: does the verdict move
// with the level? The report answers it for the sample in front of it rather
// than asserting Burp's "in most cases it does not".
func TestTheCurveSaysWhetherTheVerdictSurvivesTheChoiceOfLevel(t *testing.T) {
	report := AnalyseWith(constantNibbleFixture(), nil, 1).EffectiveEntropy
	if !report.Robust {
		t.Fatalf("robust = false for a sample where every answerable level gives 4 bits (%s). A verdict that does not move must not be reported as one that does.", report.RobustnessNote)
	}
	for _, p := range report.Curve {
		if p.Computed && *p.Bits != 4 {
			t.Fatalf("the %g%% point gives %d bit(s), want 4 at every answerable level for this fixture: the four constant positions score %.9f, which is below every level from 0.2%% up.",
				p.SignificancePercent, *p.Bits, fixtureConstantP)
		}
	}
	// A sample where the level does matter. Ten single-hex-character tokens, one
	// '8' (1000) and nine '0' (0000): bit position 0 carries a 1 in exactly 1 of
	// 10 tokens, p = 2 x (C(10,0)+C(10,1))/2^10 = 22/1024 = 0.021484375, which is
	// below 5% and above 2%. Positions 1..3 are constant and score 2^-9, so they
	// are rejected from 0.2% up. The count therefore falls from 1 bit to 0 between
	// those two levels, which is exactly the movement Burp's chart exists to show.
	biased := []string{"8", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	moving := AnalyseWith(biased, nil, 5).EffectiveEntropy
	at5 := pointAtLevel(t, moving, 5)
	at2 := pointAtLevel(t, moving, 2)
	if !at5.Computed || !at2.Computed {
		t.Fatalf("both 2%% and 5%% should be answerable for ten tokens; got computed=%v/%v", at2.Computed, at5.Computed)
	}
	if *at2.Bits != 1 || *at5.Bits != 0 {
		t.Fatalf("bits at 2%% = %d and at 5%% = %d, want 1 and 0. The one-in-ten position scores p = 0.021484375: above 0.02 and below 0.05, so it survives the stricter level and not the looser one. Getting the same count at both means the comparison is not using the level it was given.",
			*at2.Bits, *at5.Bits)
	}
	if moving.Robust {
		t.Fatalf("robust = true for a sample whose bit count changes across the curve (%s): an operator would read that as licence to quote the number without the level.", moving.RobustnessNote)
	}
}

// Positions the shortest token does not have are excluded rather than tested
// against the wrong sample size.
func TestPositionsAbsentFromTheShortestTokenAreExcludedAndCounted(t *testing.T) {
	report := AnalyseWith([]string{"0f", "0f0", "00", "000"}, nil, 1).EffectiveEntropy
	if report.BitPositionsExamined != 8 {
		t.Fatalf("bit_positions_examined = %d, want 8: the shortest token is two hex characters, and a ninth position present in only half the sample has a different n from its neighbours — testing it against n=4 would manufacture a rejection.",
			report.BitPositionsExamined)
	}
	if report.BitPositionsSkippedVariableLength != 4 {
		t.Fatalf("bit_positions_skipped_variable_length = %d, want 4: the longest token carries three hex characters, four bits more than the shortest, and dropping those positions silently would leave the bit count unexplained.",
			report.BitPositionsSkippedVariableLength)
	}
}

// An empty sample reaches no level, and says so at each one.
func TestAnEmptySampleAnswersAtNoSignificanceLevelAtAll(t *testing.T) {
	report := AnalyseWith(nil, nil, 1).EffectiveEntropy
	if len(report.Curve) == 0 {
		t.Fatalf("the curve is empty. The levels still exist for an empty sample; what is missing is an answer at each of them, and that is a different statement.")
	}
	for _, p := range report.Curve {
		if p.Computed {
			t.Fatalf("the %g%% point reports %d bit(s) from no tokens at all.", p.SignificancePercent, *p.Bits)
		}
	}
	if report.Robust {
		t.Fatalf("robust = true with nothing computed: 'the level does not matter' would be read as a verdict, and there is none.")
	}
}

// The FIPS verdict is a fixed battery of constants from the standard. It must be
// the same report at every significance level a caller can pass, or the report
// is quietly inventing a FIPS variant nobody specified.
func TestTheFipsVerdictIsIdenticalAtEverySignificanceLevel(t *testing.T) {
	tokens := hexTokens(1, 1250, 4) // 40,000 bits: two whole FIPS blocks.
	base := AnalyseAs(tokens, nil)
	if base.Fips.Tests == nil {
		t.Fatalf("the fixture no longer fills a FIPS block, so this test cannot check what it claims to check.")
	}
	for _, percent := range []float64{0.001, 0.03, 1, 5, 10} {
		got := AnalyseWith(tokens, nil, percent)
		if got.Grade != base.Grade {
			t.Fatalf("grade at %g%% = %q, want %q: the significance level reaches the effective-entropy curve and nothing else.", percent, got.Grade, base.Grade)
		}
		if got.Verdict != base.Verdict {
			t.Fatalf("the verdict sentence changed at %g%%. It is the Rust reference's, byte for byte, and a level-dependent wording would break that parity in a way no Rust test can see.", percent)
		}
		wantFips, _ := json.Marshal(base.Fips)
		gotFips, _ := json.Marshal(got.Fips)
		if string(wantFips) != string(gotFips) {
			t.Fatalf("the FIPS report changed at %g%%:\n got %s\nwant %s\nEvery FIPS 140-2 threshold is a constant of the standard, not a function of a chosen confidence.", percent, gotFips, wantFips)
		}
		if got.EffectiveEntropy.AffectsGrade {
			t.Fatalf("effective_entropy.affects_grade = true. The grade is the FIPS battery's; saying otherwise on the wire invites a caller to fold this curve into it.")
		}
	}
	if !AnalyseAs(tokens, nil).EffectiveEntropy.SignificanceDefaulted {
		t.Fatalf("AnalyseAs does not mark its level as defaulted, so the UI cannot tell an operator's 1%% from the one nobody chose.")
	}
}

// A report carrying both a FIPS grade and this curve has to reconcile them in
// its own words, because they can disagree without either being wrong.
func TestTheReportReconcilesTheCurveWithTheFipsGradeInWords(t *testing.T) {
	// FIPS cannot run here (80 bits, far below one 20,000-bit block) while the
	// curve can: the two have different sample requirements, which is the
	// commonest way the pair looks contradictory.
	short := AnalyseWith(constantNibbleFixture(), nil, 1)
	if short.Fips.Tests != nil {
		t.Fatalf("the fixture unexpectedly filled a FIPS block; this test checks the case where it does not.")
	}
	note := short.EffectiveEntropy.FipsAgreement
	for _, want := range []string{"20,000-bit block", "different sample requirements"} {
		if !strings.Contains(note, want) {
			t.Fatalf("fips_agreement does not mention %q:\n%s\nA report showing 'FIPS: not tested' beside a computed curve must say why one answered and the other did not.", want, note)
		}
	}
	// And the healthy large sample: FIPS passes, and whatever the curve does the
	// note has to name the chance-rejection expectation rather than leave a loss
	// looking like a defect.
	healthy := AnalyseWith(hexTokens(1, 1250, 4), nil, 5)
	if healthy.Fips.Passed() == nil || !*healthy.Fips.Passed() {
		t.Fatalf("the healthy fixture no longer passes FIPS, so this half of the test checks nothing.")
	}
	hnote := healthy.EffectiveEntropy.FipsAgreement
	if !strings.Contains(hnote, "FIPS passed") {
		t.Fatalf("fips_agreement does not say FIPS passed when it did:\n%s", hnote)
	}
	if healthy.EffectiveEntropy.Chosen.Computed && *healthy.EffectiveEntropy.Chosen.Bits < healthy.EffectiveEntropy.BitPositionsExamined &&
		!strings.Contains(hnote, "expected to lose to chance") {
		t.Fatalf("FIPS passed and the curve lost bit positions, but the note does not point at the chance-rejection expectation:\n%s\nWithout it a loss at the level's own false-positive rate reads as a finding.", hnote)
	}
}

// The wire shape, asserted against the marshalled JSON rather than the struct:
// a Go nil slice and an empty one are indistinguishable in Go and are `null` and
// `[]` in the browser, and the UI reads `.length` on these.
func TestTheMarshalledCurveNeverSendsNullArraysOrAZeroForAnAbsentAnswer(t *testing.T) {
	raw, err := json.Marshal(AnalyseWith(constantNibbleFixture(), nil, 0.1))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire struct {
		EffectiveEntropy struct {
			Curve []struct {
				SignificancePercent float64  `json:"significance_percent"`
				Computed            bool     `json:"computed"`
				Bits                *int     `json:"bits"`
				BitsRejected        *int     `json:"bits_rejected"`
				Expected            *float64 `json:"expected_chance_rejections"`
				Reason              string   `json:"reason"`
			} `json:"curve"`
			Tests        []string `json:"tests"`
			Definition   string   `json:"definition"`
			AffectsGrade bool     `json:"affects_grade"`
		} `json:"effective_entropy"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ee := wire.EffectiveEntropy
	if ee.Curve == nil {
		t.Fatalf("effective_entropy.curve marshalled to null. The UI maps over it; null takes the page down through the error boundary rather than showing an empty chart.")
	}
	if ee.Tests == nil || len(ee.Tests) == 0 {
		t.Fatalf("effective_entropy.tests is null or empty. 'The number of bits that pass the randomness tests' is meaningless without naming them, and the UI renders this list.")
	}
	if ee.Definition == "" {
		t.Fatalf("effective_entropy.definition is empty. An exported report has to carry what its headline number means, or it will be quoted as something else.")
	}
	if ee.AffectsGrade {
		t.Fatalf("effective_entropy.affects_grade is true on the wire.")
	}
	sawAbsent, sawComputed := false, false
	for _, p := range ee.Curve {
		if p.Computed {
			sawComputed = true
			if p.Bits == nil || p.BitsRejected == nil || p.Expected == nil {
				t.Fatalf("the %g%% point is computed but sends a null count: the chart would draw a gap where there is an answer.", p.SignificancePercent)
			}
			continue
		}
		sawAbsent = true
		if p.Bits != nil {
			t.Fatalf("the %g%% point is not computed but sends bits = %d. Zero or any other number here is plotted as a data point; the value must be JSON null.", p.SignificancePercent, *p.Bits)
		}
		if p.Reason == "" {
			t.Fatalf("the %g%% point sends no reason with its null.", p.SignificancePercent)
		}
	}
	if !sawAbsent || !sawComputed {
		t.Fatalf("the fixture no longer produces both an absent and a computed point (absent=%v computed=%v), so this test is not checking the shape it claims to.", sawAbsent, sawComputed)
	}
}

// The range is Burp's, and a level outside it is a caller error rather than
// something to clamp.
func TestOnlyBurpsStatedRangeOfSignificanceLevelsIsAccepted(t *testing.T) {
	for _, ok := range []float64{0.001, 0.002, 0.03, 1, 5, 10} {
		if !ValidSignificancePercent(ok) {
			t.Fatalf("%g%% is refused, but Burp's stated range is 0.001%% to 10%% and its two named bands (FIPS 0.002–0.03%%, scientific 1–5%%) sit inside it.", ok)
		}
	}
	for _, bad := range []float64{0, -1, 10.0001, 50, 100, math.NaN()} {
		if ValidSignificancePercent(bad) {
			t.Fatalf("%v%% is accepted. A level above 10%% is not a stricter or looser reading of the same question — it is a misunderstanding of the parameter, and clamping it would answer a question nobody asked.", bad)
		}
	}
}

// A handful of very long tokens is the case where FIPS answers and this curve
// cannot: FIPS counts BITS and has plenty, while the per-position test counts
// TOKENS and has two. The reconciliation sentence must say that, and must not
// describe the curve as surviving or losing anything.
func TestAVerdictFromFipsBesideAnUnanswerableCurveIsReconciledWithoutInventingACurveResult(t *testing.T) {
	tokens := hexTokens(1, 2, 5000) // 2 tokens x 40,000 bits: four whole FIPS blocks.
	report := AnalyseWith(tokens, nil, 1)
	if report.Fips.Tests == nil {
		t.Fatalf("the fixture no longer fills a FIPS block, so this test cannot check the pairing it exists for.")
	}
	if report.EffectiveEntropy.Chosen.Computed {
		t.Fatalf("the curve answered at 1%% from 2 token(s); minAttainableP(2) = 0.5, so it cannot reject anything at any level in the range and must report no answer.")
	}
	note := report.EffectiveEntropy.FipsAgreement
	for _, forbidden := range []string{"survives", "loses"} {
		if strings.Contains(note, forbidden) {
			t.Fatalf("fips_agreement says %q about a curve that produced no answer at all:\n%s\nA reconciliation that describes bits as surviving or lost when none were tested is exactly the confidently-wrong sentence a report showing both surfaces has to avoid.", forbidden, note)
		}
	}
	if !strings.Contains(note, "no answer at") {
		t.Fatalf("fips_agreement does not say the curve has no answer:\n%s", note)
	}
	if !warningsContain(report.Warnings, "no effective-entropy figure at the 1% significance level") {
		t.Fatalf("warnings = %q, want one naming the missing figure at the chosen level.", report.Warnings)
	}
	// And the grade is still FIPS's own, unmoved.
	if report.Grade != AnalyseAs(tokens, nil).Grade {
		t.Fatalf("the grade differs from the default-level analysis of the same sample.")
	}
}

// The hand-computed cases above pin the formula at the points a person can reach
// with a pen; this one checks it everywhere, against an oracle that shares no
// code with it. Enumerating all 2^n outcomes and summing the exact probability of
// every outcome no more likely than the observed one is the definition of the
// two-sided exact test, so a defect in the log-space tail — an off-by-one in the
// recurrence, a missing symmetry, a lost term in the extreme branch — cannot
// agree with it and still be wrong.
func TestTheTwoSidedTailMatchesBruteForceEnumeration(t *testing.T) {
	for n := 1; n <= 12; n++ {
		total := float64(uint64(1) << n)
		count := make([]float64, n+1)
		for mask := 0; mask < 1<<n; mask++ {
			count[bits.OnesCount(uint(mask))] += 1
		}
		for k := 0; k <= n; k++ {
			pObs := count[k] / total
			sum := 0.0
			for j := 0; j <= n; j++ {
				if count[j]/total <= pObs+1e-15 {
					sum += count[j] / total
				}
			}
			if sum > 1 {
				sum = 1
			}
			if got := binomialTwoSidedP(n, k); math.Abs(got-sum) > 1e-9 {
				t.Errorf("n=%d k=%d: binomialTwoSidedP = %.12g, brute-force two-sided tail = %.12g. Every bit count on the curve is this number compared against a level, so a disagreement here is a rejected position invented or hidden.",
					n, k, got, sum)
			}
		}
	}
}
