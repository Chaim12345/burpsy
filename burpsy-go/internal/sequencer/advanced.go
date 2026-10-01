package sequencer

// The extended randomness battery: the four tests Burp's Sequencer runs beside
// the FIPS four that internal/sequencer/fips.go ports — character transition
// analysis, the spectral test, the correlation test and the compression test
// (burpsy-react-ui-d2g).
//
// They live in their own file, and are additive to the report, for three
// reasons worth stating rather than discovering:
//
//  1. They do not touch the grade, and cannot: the grade and the verdict
//     sentence are byte-for-byte the Rust reference's, and the parity oracle is
//     what the port is measured against. A failing compression test therefore
//     shows up in this battery and nowhere else. `AdvancedReport.AffectsGrade`
//     carries that fact on the wire so no reader has to infer it from a doc
//     comment.
//
//  2. Every member is a test whose null distribution has to be *stated* rather
//     than assumed, and two of them (the spectral test's tuplet table and the
//     correlation test's pair table) run hundreds of comparisons at once. So
//     every verdict here is held to a Bonferroni-corrected 0.05 and says what
//     the correction was — the alternative, comparing each data point at 0.05,
//     manufactures a significant result on roughly one run in twenty per point
//     and would report an honest generator as broken.
//
//  3. Each one can fail to apply to a given sample, and when it does it reports
//     "not tested" **with the reason the sample could not support it**, exactly
//     as the FIPS battery refuses to print a verdict below one whole 20,000-bit
//     block. A number that is not reported is better than a confident number
//     that means nothing.
//
// The method each test uses is named in its Basis so a reader can check it
// against its source. Burp's documentation describes what each test does and
// does not publish the arithmetic, so where the description leaves a choice
// (overlapping or non-overlapping tuplets, what a compression reduction is
// compared against) the choice is made toward the statistic whose distribution
// is actually known, and the cost of that choice is stated in the test's
// notices rather than left for someone to discover.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"math"
	"math/bits"
	"strings"
)

const (
	// SignificanceLevel is the family-wise false-positive rate the extended
	// battery holds itself to. Each test spans many comparisons and divides
	// this by the number it actually ran (Bonferroni), so the chance of at
	// least one flag on a genuinely uniform sample stays at or below 0.05
	// however many comparisons there were.
	//
	// Bonferroni is deliberately the conservative direction: the comparisons
	// within one test are not independent, so the correction over-corrects and
	// a real bias has to be a little stronger to be flagged. Under-correcting
	// would flag honest generators, which is the failure this package exists
	// to refuse.
	SignificanceLevel = 0.05

	// MinCellExpectation is the smallest expected count a contingency-table
	// cell may carry before the chi-square approximation stops holding
	// (Cochran's condition). Below it the statistic is not distributed as
	// chi-square and its p-value would be fiction.
	MinCellExpectation = 5.0

	// MaxLowExpectationShare is Cochran's companion rule: no more than this
	// share of cells may fall below MinCellExpectation. Applied together with
	// a hard floor of 1.0 on the smallest expected count, which is the other
	// half of the same rule.
	MaxLowExpectationShare = 0.2

	// MaxCorrelationBits caps how many bit positions the correlation test
	// compares. The pair table is quadratic in this, so the cap is what keeps
	// a pathological token from turning one analysis into minutes of work. The
	// truncation is stated in the test's notices — never silent.
	MaxCorrelationBits = 1024

	// MinTokensForCorrelation is the sample floor for the correlation test.
	// The chi-square score statistic used for each pair is asymptotic; thirty
	// samples is the conventional floor below which it is not trustworthy.
	MinTokensForCorrelation = 30

	// MaxCompressionBits caps the compression test's per-position loop, for
	// the same reason as MaxCorrelationBits: work proportional to the token's
	// bit length. Truncation is stated in the notices.
	MaxCompressionBits = 1024

	// MinTokensForCompression is the sample floor for the compression test, and
	// it is deliberately high. DEFLATE carries about eleven bytes of framing
	// (a two-byte header, a four-byte checksum and a block header), so below
	// roughly sixty-four bytes of bit sequence the measurement describes the
	// framing rather than the token. Sixty-four bytes of bits — 512 tokens —
	// is the smallest sample where the reduction is about the data.
	MinTokensForCompression = 512

	// CompressionTolerance is how far above the incompressible control a
	// position's reduction may sit before it counts as structured. It is in
	// units of the reduction ratio, so 0.05 is five percentage points: a
	// position whose bit sequence compresses five points better than a
	// sequence with no structure in it has structure.
	CompressionTolerance = 0.05

	// compressionControls is how many independent incompressible controls are
	// compressed for each sample length. The baseline is the *largest*
	// reduction any of them achieves, which is what keeps a lucky control from
	// making the comparison generous.
	compressionControls = 8
)

// AdvancedTest is one member of the extended battery.
//
// The shape follows FipsTest where it can — a name, the basis it comes from, the
// pass condition, the observed statistic and a verdict — and adds the two
// things these four need and the FIPS four do not: a "not tested" state with a
// reason, because three of them do not apply to every sample, and the counts
// behind the verdict, because a verdict over hundreds of comparisons is
// unreadable without them.
type AdvancedTest struct {
	// ID is "transition" | "spectral" | "correlation" | "compression".
	ID string `json:"id"`
	// Name is the human name of the test, matching Burp's.
	Name string `json:"name"`
	// Basis is what the method is: Burp's description of the test, and the
	// standard statistic used to evaluate it. Where the description left a
	// choice, the choice and its cost are here rather than in a commit message.
	Basis string `json:"basis"`
	// Requirement is the pass condition, spelled out with its constants so a
	// reader can check it against the arithmetic.
	Requirement string `json:"requirement"`
	// Tested is false when the sample could not support the test at all. The
	// verdict fields below are then meaningless and Passed is false.
	Tested bool `json:"tested"`
	// Reason says why the test could not run. Never empty when Tested is false,
	// and always concrete: which condition failed and at what count.
	Reason string `json:"reason,omitempty"`
	// Passed is true only when the test ran and flagged nothing.
	Passed bool `json:"passed"`
	// Observed is the statistic that decided the verdict: the most significant
	// data point the test examined, with the numbers behind it. A flag with no
	// number beside it is not something an operator can check.
	Observed string `json:"observed"`
	// Examined is how many data points the test could evaluate — character
	// positions, tuplet combinations, bit-position pairs, bit positions.
	Examined int `json:"examined"`
	// Flagged is how many of them were significant at Threshold.
	Flagged int `json:"flagged"`
	// Threshold is the per-comparison significance level actually applied,
	// after the Bonferroni correction for this test's own comparison count.
	// Zero for a test whose verdict is a tolerance comparison rather than a
	// significance test — the compression test is the one — and Tolerance is
	// then set instead, so exactly one of the two is ever the rule.
	Threshold float64 `json:"threshold"`
	// Tolerance is the margin this test compares against a control, where it
	// has one. Zero when the test has a distribution instead.
	Tolerance float64 `json:"tolerance,omitempty"`
	// Notices carries the limits that applied to this run: truncations, and the
	// assumptions the statistic rests on. Never a substitute for Reason — a
	// notice is about a test that ran, a reason about one that could not.
	Notices []string `json:"notices,omitempty"`
	// Disabled is true when the operator switched this test off rather than when
	// it could not run (burpsy-react-ui-3iao). Those are different facts and a
	// verdict that leans on neither must still be able to say which happened:
	// "untestable" is a limit of the sample, "disabled" is a decision by the
	// reader, and only the second one is anybody's fault to look into.
	Disabled bool `json:"disabled,omitempty"`
	// DisableReason is set alongside Disabled so the record is self-explaining —
	// a consumer must not have to know this package's policy to render it.
	DisableReason string `json:"disable_reason,omitempty"`
}

// AdvancedReport is the extended battery's outcome.
type AdvancedReport struct {
	Tests []AdvancedTest `json:"tests"`
	// Summary is one sentence over the four, so an operator reading the JSON
	// alone can tell "nothing found" from "nothing ran".
	Summary string `json:"summary"`
	// AffectsGrade is always false, and serialised so it is stated rather than
	// assumed: the grade and verdict sentence in this report are the FIPS
	// battery's, byte-for-byte the Rust reference's, and nothing in this file
	// changes them.
	AffectsGrade bool `json:"affects_grade"`
}

// advancedFor runs the four extended tests over a sample that has already been
// decoded for the bit-level view. It takes the decoded stream rather than
// re-deriving it so the spectral test sees exactly the bits the FIPS battery
// was given — two views of one sample must not disagree about what the sample is.
func advancedFor(tokens []string, enc Encoding, bitStream []byte, disabled map[string]bool) AdvancedReport {
	// Each test is built and then FILTERED, rather than each disabled test being skipped before it
	// runs. The distinction matters: a skipped test costs nothing, while this keeps the report's
	// shape identical whether a test was turned off or found inapplicable, and the record says which
	// — a disabled test and an untestable one are different facts and an operator reading a verdict
	// needs to tell them apart.
	all := []AdvancedTest{
		transitionTest(tokens),
		spectralTest(bitStream),
		correlationTest(tokens, enc),
		compressionTest(tokens, enc),
	}
	tests := make([]AdvancedTest, 0, len(all))
	turnedOff := make([]string, 0, len(disabled))
	for _, test := range all {
		if disabled[test.ID] {
			test.Disabled = true
			test.DisableReason = "switched off by the operator in the analysis settings"
			turnedOff = append(turnedOff, test.ID)
			continue
		}
		tests = append(tests, test)
	}
	// `total` is the FULL battery, not len(tests): the summary quotes "N of M ran", and M has to
	// stay the battery's size or a report from a build with one test switched off reads as though a
	// smaller battery had run. The disabled tests are named at the end so the operator can see which
	// ones their verdict did not consider.
	total := len(all)
	examined, flagged, untested := 0, 0, 0
	for _, test := range tests {
		if test.Tested {
			examined++
		} else {
			untested++
		}
		flagged += test.Flagged
	}
	var summary string
	// Named at the end whenever any are off, because "3 of 4 extended tests ran" is a sentence an
	// operator could read as the battery being smaller rather than as a choice they made.
	offNote := ""
	if len(turnedOff) > 0 {
		offNote = fmt.Sprintf(" Switched off in the analysis settings: %s.", strings.Join(turnedOff, ", "))
	}
	switch {
	case examined == 0:
		summary = fmt.Sprintf(
			"None of the %d extended tests could run on this sample; each names what it needs in its reason. The grade above is the FIPS battery's and is unaffected by them.%s",
			total, offNote,
		)
	case flagged == 0:
		summary = fmt.Sprintf(
			"%d of %d extended tests ran and none flagged a deviation at the 0.05 family-wise level; %d could not be tested on this sample. The grade above is the FIPS battery's and is unaffected.%s",
			examined, total, untested, offNote,
		)
	default:
		summary = fmt.Sprintf(
			"%d of %d extended tests ran and %d data point(s) across them are significant at the 0.05 family-wise level; %d test(s) could not be tested on this sample. The grade above is the FIPS battery's and is unaffected.%s",
			examined, total, flagged, untested, offNote,
		)
	}
	return AdvancedReport{Tests: tests, Summary: summary, AffectsGrade: false}
}

// transitionReject says why one character position could not be tested. Named
// rather than free-text so the aggregate reason is deterministic: map iteration
// order would otherwise decide which of several failures got to describe the
// sample.
type transitionReject int

const (
	transitionOK transitionReject = iota
	transitionNoPairs
	transitionNoVariation
	transitionThinCells
)

// transitionPosition is one position's transition table, evaluated.
type transitionPosition struct {
	position int
	// samples is the transition count: consecutive token pairs that both
	// carried this position.
	samples int
	// cells is rows x columns, the observed alphabet on each side of the
	// transition. Carried even when the position is rejected, because "a table
	// of this shape needs this many transitions" is the actionable half of the
	// reason the test would not run.
	cells int
	chi2  float64
	df    int
	p     float64
}

// transitionTest is Burp's character transition analysis: at each character
// position, is the character in the next token independent of the character in
// this one?
//
// Burp's description of it is the specification — "a character appearing at a
// given position is equally likely to be followed in the next token by any one
// of the characters that is used at that position" — and the standard statistic
// for that claim is Pearson's chi-square test of independence on the table of
// observed transitions. The test is refused, per position, wherever Cochran's
// conditions do not hold: a chi-square p-value from a sparse table is not
// conservative, it is simply wrong, and wrong in the direction of flagging.
func transitionTest(tokens []string) AdvancedTest {
	test := AdvancedTest{
		ID:   "transition",
		Name: "Character transition analysis",
		Basis: "PortSwigger's Sequencer character transition analysis: at each character position, " +
			"the character in the next token is equally likely to be any of the characters used at that " +
			"position. Evaluated as Pearson's chi-square test of independence over the table of observed " +
			"transitions, with the Cochran conditions checked before the statistic is trusted.",
		Requirement: fmt.Sprintf("no character position may show a significant transition dependence at 0.05 / (number of positions tested). A position is only tested when at least two distinct characters appear on each side of the transition, no expected cell count is below 1, and no more than %.0f%% of cells are below %.0f.",
			MaxLowExpectationShare*100, MinCellExpectation),
	}

	positions := 0
	for _, tok := range tokens {
		if len(tok) > positions {
			positions = len(tok)
		}
	}
	if positions > MaxPositionsReported {
		positions = MaxPositionsReported
	}
	if positions == 0 {
		test.Reason = "there is no character position to test: the sample has no tokens, or every token is empty."
		return test
	}

	var (
		evaluated                      []transitionPosition
		noPairs, noVariation, thinCell int
		widest                         transitionPosition
	)
	for pos := 0; pos < positions; pos++ {
		at, why := transitionAt(tokens, pos)
		switch why {
		case transitionNoPairs:
			noPairs++
		case transitionNoVariation:
			noVariation++
		case transitionThinCells:
			thinCell++
			if at.cells > widest.cells {
				widest = at
			}
		case transitionOK:
			evaluated = append(evaluated, at)
		}
	}

	if len(evaluated) == 0 {
		// The count needed is the actionable half of this reason: an operator
		// who is told "too sparse" learns nothing, whereas "a table this wide
		// needs about this many transitions" turns into a capture size.
		needed := widest.cells * int(MinCellExpectation)
		test.Reason = fmt.Sprintf(
			"no character position could be tested. Of %d position(s): %d had no pair of consecutive tokens that both carried the position, %d had fewer than two distinct characters on one side of the transition (nothing to be dependent on), and %d had a transition table too sparse for the chi-square approximation (no expected count may fall below 1, nor more than %.0f%% of cells below %.0f — Cochran's rule). The widest sparse table was %d cell(s), which needs about %d transitions to average %.0f observation(s) a cell; that position supplied %d. More tokens, or tokens over a narrower alphabet, is what makes the table testable.",
			positions, noPairs, noVariation, thinCell, MaxLowExpectationShare*100, MinCellExpectation,
			widest.cells, needed, MinCellExpectation, widest.samples,
		)
		return test
	}

	test.Tested = true
	test.Examined = len(evaluated)
	test.Threshold = SignificanceLevel / float64(len(evaluated))
	worst := evaluated[0]
	for _, at := range evaluated {
		if at.p < test.Threshold {
			test.Flagged++
		}
		if at.p < worst.p {
			worst = at
		}
	}
	test.Passed = test.Flagged == 0
	test.Observed = fmt.Sprintf(
		"position %d: X2 = %.2f on %d degree(s) of freedom over %d transition(s), p = %.3g uncorrected",
		worst.position, worst.chi2, worst.df, worst.samples, worst.p,
	)
	if skipped := noPairs + noVariation + thinCell; skipped > 0 {
		test.Notices = append(test.Notices, fmt.Sprintf(
			"%d of %d position(s) were not tested (%d with no pair of consecutive tokens carrying the position, %d with fewer than two distinct characters on one side, %d with a table too sparse for the chi-square approximation); their transitions are simply not described by this test.",
			skipped, positions, noPairs, noVariation, thinCell,
		))
	}
	test.Notices = append(test.Notices, fmt.Sprintf(
		"each position is tested at %g / %d = %.3g rather than 0.05, so the chance of at least one flag on a uniform sample stays at or below %.2f. The correction is conservative: the positions are not independent of one another.",
		SignificanceLevel, len(evaluated), test.Threshold, SignificanceLevel,
	))
	return test
}

// transitionAt builds position pos's transition table and evaluates it.
//
// Pairs are formed only from consecutive tokens that both carry the position. A
// short token is skipped rather than padded: padding would invent a character
// and pull the table towards it.
func transitionAt(tokens []string, pos int) (transitionPosition, transitionReject) {
	// Counts live in byte-indexed arrays rather than maps so every summation
	// below runs in byte order. A map's iteration order would make the chi-square
	// sum — and therefore the last digits of the statistic and the p-value beside
	// it — differ between two runs over the same sample, and a report two runs
	// disagree about is not one anybody can check.
	var rows, cols [256]int
	pairs := make(map[[2]byte]int)
	samples := 0
	for i := 0; i+1 < len(tokens); i++ {
		a, b := tokens[i], tokens[i+1]
		if pos >= len(a) || pos >= len(b) {
			continue
		}
		rows[a[pos]]++
		cols[b[pos]]++
		pairs[[2]byte{a[pos], b[pos]}]++
		samples++
	}
	if samples == 0 {
		return transitionPosition{position: pos}, transitionNoPairs
	}
	rowKeys := observedBytes(rows[:])
	colKeys := observedBytes(cols[:])
	cells := len(rowKeys) * len(colKeys)
	if len(rowKeys) < 2 || len(colKeys) < 2 {
		return transitionPosition{position: pos, samples: samples, cells: cells}, transitionNoVariation
	}

	low, minExpected := 0, math.Inf(1)
	for _, a := range rowKeys {
		for _, b := range colKeys {
			expected := float64(rows[a]) * float64(cols[b]) / float64(samples)
			if expected < minExpected {
				minExpected = expected
			}
			if expected < MinCellExpectation {
				low++
			}
		}
	}
	if minExpected < 1 || float64(low) > MaxLowExpectationShare*float64(cells) {
		return transitionPosition{position: pos, samples: samples, cells: cells}, transitionThinCells
	}

	chi2 := 0.0
	for _, a := range rowKeys {
		for _, b := range colKeys {
			expected := float64(rows[a]) * float64(cols[b]) / float64(samples)
			delta := float64(pairs[[2]byte{a, b}]) - expected
			chi2 += delta * delta / expected
		}
	}
	df := (len(rowKeys) - 1) * (len(colKeys) - 1)
	return transitionPosition{
		position: pos,
		samples:  samples,
		cells:    cells,
		chi2:     chi2,
		df:       df,
		p:        chiSquareUpperTail(chi2, df),
	}, transitionOK
}

// observedBytes lists the byte values a count array has seen, in byte order.
func observedBytes(counts []int) []byte {
	out := make([]byte, 0, len(counts))
	for value, count := range counts {
		if count > 0 {
			out = append(out, byte(value))
		}
	}
	return out
}

// spectralCombo is one number-size x dimensions combination, evaluated.
type spectralCombo struct {
	numBits int
	dims    int
	groups  int
	cells   int
	chi2    float64
	df      int
	p       float64
}

// spectralTest is Burp's spectral test: consecutive numbers are treated as
// coordinates in a multi-dimensional space, repeated for 1..8 bits per number
// and 2..6 dimensions, and the points are tested for clustering.
//
// The statistic is the classical serial (spectral) test: the stream is cut into
// tuplets of numBits*dims bits, the value of each tuplet is one cell of a
// 2^(numBits*dims)-cell table, and the cell counts are compared against a
// uniform expectation with Pearson's chi-square.
//
// # Why the tuplets do not overlap
//
// The more common formulation slides a window one bit at a time, which uses the
// data far better — it yields (n - w + 1) tuplets instead of n/w, so wider
// tables stay reachable. It is not used here because the resulting cell counts
// are not independent, and Pearson's statistic therefore does not have the
// chi-square null distribution: the threshold the verdict is read against would
// be wrong, and wrong in the direction of failing honest generators. Cutting the
// stream into consecutive, non-overlapping tuplets keeps the count multinomial,
// so the distribution the threshold assumes is the distribution the statistic
// has. The cost is stated in the notices: the widest testable tuplet is bounded
// by the stream length, so structure wider than that is out of reach however it
// is dimensioned.
func spectralTest(bitStream []byte) AdvancedTest {
	test := AdvancedTest{
		ID:   "spectral",
		Name: "Spectral test",
		Basis: "PortSwigger's Sequencer spectral test: each series of consecutive numbers is treated as a coordinate " +
			"in a multi-dimensional space and the points are tested for clustering, repeated for 1..8 bits per number and " +
			"2..6 dimensions. The statistic is the classical serial test — Pearson's chi-square over the table of " +
			"2^(bits x dimensions) tuplet values. Tuplets are cut consecutively without overlap so the cell counts are " +
			"multinomial and the chi-square null distribution is the right one to read the threshold against; overlapping " +
			"windows would reach wider tables but would inflate the statistic.",
		Requirement: fmt.Sprintf("no number-size x dimension combination may show clustering at 0.05 / (number of combinations tested). A combination is only tested when the stream supplies at least two tuplets of its width and at least %.0f expected observation(s) per cell.",
			MinCellExpectation),
	}

	const combos = 8 * 5
	var (
		evaluated                   []spectralCombo
		tooFewGroups, tooFewPerCell int
		widestTestable              int
	)
	for numBits := 1; numBits <= 8; numBits++ {
		for dims := 2; dims <= 6; dims++ {
			tupleBits := numBits * dims
			groups := len(bitStream) / tupleBits
			if groups < 2 {
				tooFewGroups++
				continue
			}
			cellsFloat := math.Ldexp(1, tupleBits)
			if float64(groups)/cellsFloat < MinCellExpectation {
				tooFewPerCell++
				continue
			}
			cells := 1 << tupleBits
			counts := make([]int, cells)
			offset := 0
			for g := 0; g < groups; g++ {
				value := 0
				for k := 0; k < tupleBits; k++ {
					value = value<<1 | int(bitStream[offset])
					offset++
				}
				counts[value]++
			}
			expected := float64(groups) / float64(cells)
			chi2 := 0.0
			for _, observed := range counts {
				delta := float64(observed) - expected
				chi2 += delta * delta / expected
			}
			df := cells - 1
			evaluated = append(evaluated, spectralCombo{
				numBits: numBits, dims: dims, groups: groups, cells: cells,
				chi2: chi2, df: df, p: chiSquareUpperTail(chi2, df),
			})
			if tupleBits > widestTestable {
				widestTestable = tupleBits
			}
		}
	}

	if len(evaluated) == 0 {
		test.Reason = fmt.Sprintf(
			"%d bit(s) were supplied, which cannot fill a testable tuplet table. Of the %d number-size x dimension combinations: %d had fewer than two tuplets of their width, and %d had fewer than %.0f expected observation(s) per cell. A tuplet of w bits needs 2^w cells to be worth %.0f observation(s) each, so this sample cannot reach even the smallest testable table; a longer stream is what widens the reach.",
			len(bitStream), combos, tooFewGroups, tooFewPerCell, MinCellExpectation, MinCellExpectation,
		)
		return test
	}

	test.Tested = true
	test.Examined = len(evaluated)
	test.Threshold = SignificanceLevel / float64(len(evaluated))
	worst := evaluated[0]
	for _, combo := range evaluated {
		if combo.p < test.Threshold {
			test.Flagged++
		}
		if combo.p < worst.p {
			worst = combo
		}
	}
	test.Passed = test.Flagged == 0
	test.Observed = fmt.Sprintf(
		"worst of %d combination(s): %d bit(s) per number x %d dimension(s) = %d-bit tuplets (%d cells, %d tuplets), X2 = %.2f on %d degree(s) of freedom, p = %.3g uncorrected",
		len(evaluated), worst.numBits, worst.dims, worst.numBits*worst.dims, worst.cells, worst.groups, worst.chi2, worst.df, worst.p,
	)
	test.Notices = append(test.Notices, fmt.Sprintf(
		"%d of the %d combinations could not be tested from %d bit(s) (%d had fewer than two tuplets of their width, %d had under %.0f expected observations per cell). The widest testable tuplet here is %d bits: structure in wider tuples is out of this test's reach, which is a limit of the sample size and not a pass.",
		combos-len(evaluated), combos, len(bitStream), tooFewGroups, tooFewPerCell, MinCellExpectation, widestTestable,
	))
	test.Notices = append(test.Notices, "tuplets are cut consecutively without overlap, so each combination discards the trailing bit(s) that do not fill a whole tuplet.")
	test.Notices = append(test.Notices, fmt.Sprintf(
		"each combination is tested at %g / %d = %.3g rather than 0.05, so the chance of at least one flag on a uniform sample stays at or below %.2f.",
		SignificanceLevel, len(evaluated), test.Threshold, SignificanceLevel,
	))
	return test
}

// bitPair is one pair of bit positions, evaluated.
type bitPair struct {
	a, b int
	r    float64
	chi2 float64
	p    float64
}

// correlationTest is Burp's correlation test: is the value at one bit position
// related to the value at another, across the tokens?
//
// This is the one absence with a consequence stated in Burp's own
// documentation, and it is worth repeating: each of the bit-level FIPS tests
// looks at one bit position at a time, so a token whose bit positions are each
// individually evenly split but mutually dependent — position 1 always equal to
// position 2, say — reads as high-entropy everywhere else in the report. This
// test is what sees it.
//
// The statistic for each pair is Pearson's r over the per-token bit values and
// its significance is the chi-square score statistic n*r^2 on one degree of
// freedom, which is the two-by-two contingency test for association. Pairwise
// comparisons are counted and Bonferroni-corrected, so a long token is not more
// likely to be flagged merely for having more pairs.
func correlationTest(tokens []string, enc Encoding) AdvancedTest {
	test := AdvancedTest{
		ID:   "correlation",
		Name: "Correlation test",
		Basis: "PortSwigger's Sequencer correlation test: any statistically significant relationship between the values " +
			"at different bit positions within the tokens, which is what the per-position bit-level tests cannot see. " +
			"Evaluated as Pearson's correlation over the per-token bit values for every pair of positions, with " +
			"significance from the chi-square score statistic n*r^2 (the two-by-two association test).",
		Requirement: fmt.Sprintf("no pair of bit positions may correlate significantly at 0.05 / (number of pairs). A bit position is only eligible when it varies across the sample — correlation with a constant is undefined — and the sample must carry at least %d tokens for the score statistic to be trustworthy.", MinTokensForCorrelation),
	}

	vectors, uniform := perTokenBits(tokens, enc)
	if len(vectors) == 0 {
		test.Reason = "there are no tokens to correlate."
		return test
	}
	if !uniform {
		test.Reason = "the token lengths vary, so a bit position is not a fixed part of the token and \"the value at bit 7\" does not mean one thing across the sample. Group the sample by length, or correlate a fixed-width field."
		return test
	}
	n := len(tokens)
	if n < MinTokensForCorrelation {
		test.Reason = fmt.Sprintf(
			"%d token(s) were supplied and the pair significance is an asymptotic score statistic: below %d samples it is not trustworthy. The character-level analysis above is descriptive and still stands.",
			n, MinTokensForCorrelation,
		)
		return test
	}
	bitLen := len(vectors[0])
	if bitLen < 2 {
		test.Reason = fmt.Sprintf("each token is %d bit(s) wide decoded as %s, and a correlation needs two bit positions to relate.", bitLen, enc)
		return test
	}
	truncated := false
	if bitLen > MaxCorrelationBits {
		bitLen, truncated = MaxCorrelationBits, true
	}

	// One word-packed bit vector per position: word w, bit i holds token i's
	// value at this position, so a pair's joint count is an AND and a popcount
	// rather than a pass over the sample.
	words := (n + 63) / 64
	packed := make([][]uint64, bitLen)
	ones := make([]int, bitLen)
	variable := make([]int, 0, bitLen)
	for position := 0; position < bitLen; position++ {
		word := make([]uint64, words)
		count := 0
		for i := 0; i < n; i++ {
			if vectors[i][position] == 1 {
				word[i>>6] |= 1 << uint(i&63)
				count++
			}
		}
		packed[position] = word
		ones[position] = count
		if count > 0 && count < n {
			variable = append(variable, position)
		}
	}
	constant := bitLen - len(variable)
	if len(variable) < 2 {
		test.Reason = fmt.Sprintf(
			"every one of the %d bit position(s) is fixed at a single value across the sample, so there is no pair whose correlation is defined. That is itself the finding — see Character positions above — but this test has nothing to measure.",
			bitLen,
		)
		return test
	}

	pairs := len(variable) * (len(variable) - 1) / 2
	test.Tested = true
	test.Examined = pairs
	test.Threshold = SignificanceLevel / float64(pairs)

	var worst *bitPair
	for i := 0; i < len(variable); i++ {
		a := variable[i]
		pa := float64(ones[a]) / float64(n)
		for j := i + 1; j < len(variable); j++ {
			b := variable[j]
			joint := 0
			for w := 0; w < words; w++ {
				joint += bits.OnesCount64(packed[a][w] & packed[b][w])
			}
			pb := float64(ones[b]) / float64(n)
			r := (float64(joint)/float64(n) - pa*pb) / math.Sqrt(pa*(1-pa)*pb*(1-pb))
			chi2 := float64(n) * r * r
			p := chiSquareUpperTail(chi2, 1)
			if p < test.Threshold {
				test.Flagged++
			}
			if worst == nil || p < worst.p {
				candidate := bitPair{a: a, b: b, r: r, chi2: chi2, p: p}
				worst = &candidate
			}
		}
	}
	test.Passed = test.Flagged == 0
	test.Observed = fmt.Sprintf(
		"worst of %d pair(s): bit %d <-> bit %d, r = %+.4f, X2 = %.2f, p = %.3g uncorrected (%d flagged)",
		pairs, worst.a, worst.b, worst.r, worst.chi2, worst.p, test.Flagged,
	)
	if constant > 0 {
		test.Notices = append(test.Notices, fmt.Sprintf(
			"%d of %d bit position(s) never vary across the sample and were excluded: correlation with a constant is undefined, and a fixed bit position is the stronger finding anyway — it is visible in Character positions above.",
			constant, bitLen,
		))
	}
	if truncated {
		test.Notices = append(test.Notices, fmt.Sprintf(
			"only the first %d bit position(s) were compared; the token is wider, and a pair beyond that was not examined.",
			MaxCorrelationBits,
		))
	}
	test.Notices = append(test.Notices, fmt.Sprintf(
		"each pair is tested at %g / %d = %.3g rather than 0.05, so the chance of at least one flag on a uniform sample stays at or below %.2f. The correction is conservative: the pairs share bit positions and are not independent of one another.",
		SignificanceLevel, pairs, test.Threshold, SignificanceLevel,
	))
	return test
}

// compressionPosition is one bit position's compression result.
type compressionPosition struct {
	position  int
	reduction float64
}

// compressionTest is Burp's compression test: how much does a general-purpose
// compressor shrink the bit sequence at each position?
//
// Burp's documentation gives the statistic — "the proportional reduction in the
// size of the bit sequence when it is compressed" — and no threshold, which
// leaves the verdict to be defined honestly rather than borrowed. A raw
// reduction cannot be the verdict on its own, because DEFLATE's ~11 bytes of
// framing make even a perfectly random sequence "shrink" by a length-dependent
// amount: at sixty-four bytes of bits the framing alone is 17% of the input. So
// each position's reduction is compared against the reduction the same
// compressor achieves on bit sequences of the same length that have no
// structure in them, and the baseline is the *largest* reduction of those
// controls, which is the direction that avoids flagging.
//
// The controls are SHA-256 in counter mode over a fixed seed. They are not
// claimed to be random; they are claimed to be incompressible, which is the
// property the comparison needs and the only one it uses.
func compressionTest(tokens []string, enc Encoding) AdvancedTest {
	test := AdvancedTest{
		ID:   "compression",
		Name: "Compression test",
		Basis: "PortSwigger's Sequencer compression test: the bit sequence at each position is compressed with standard " +
			"ZLIB, and the proportional reduction in size is the statistic. Because DEFLATE's framing alone shrinks a short " +
			"incompressible sequence, the reduction is compared against the largest reduction achieved on same-length " +
			"control sequences that carry no structure (SHA-256 in counter mode over a fixed seed), not against zero.",
		Requirement: fmt.Sprintf("no bit position's sequence may compress more than %.0f percentage point(s) better than the incompressible control of the same length. The sample must carry at least %d tokens: below that, DEFLATE's framing dominates the measurement and the reduction describes the framing rather than the token.",
			CompressionTolerance*100, MinTokensForCompression),
		Tolerance: CompressionTolerance,
	}

	vectors, uniform := perTokenBits(tokens, enc)
	if len(vectors) == 0 {
		test.Reason = "there are no tokens to compress."
		return test
	}
	if !uniform {
		test.Reason = "the token lengths vary, so \"the bit sequence at position 7\" is not one sequence across the sample. Group the sample by length, or compress a fixed-width field."
		return test
	}
	n := len(tokens)
	if n < MinTokensForCompression {
		test.Reason = fmt.Sprintf(
			"%d token(s) were supplied and this test needs at least %d: the bit sequence at each position is %d byte(s) long, and DEFLATE carries about eleven bytes of framing, so at this length the reduction measures the framing rather than the token. The FIPS battery has the same kind of floor in its whole %d-bit block.",
			n, MinTokensForCompression, (n+7)/8, BlockBits,
		)
		return test
	}
	bitLen := len(vectors[0])
	if bitLen < 1 {
		test.Reason = "each token is zero bits wide decoded as " + enc.String() + "."
		return test
	}
	truncated := false
	if bitLen > MaxCompressionBits {
		bitLen, truncated = MaxCompressionBits, true
	}

	rawBytes := (n + 7) / 8
	baseline := incompressibleReduction(n)
	sequence := make([]byte, rawBytes)
	var worst *compressionPosition
	for position := 0; position < bitLen; position++ {
		for i := range sequence {
			sequence[i] = 0
		}
		for i := 0; i < n; i++ {
			if vectors[i][position] == 1 {
				sequence[i>>3] |= 1 << uint(7-(i&7))
			}
		}
		reduction := (float64(rawBytes) - float64(deflateSize(sequence))) / float64(rawBytes)
		if reduction > baseline+CompressionTolerance {
			test.Flagged++
		}
		if worst == nil || reduction > worst.reduction {
			candidate := compressionPosition{position: position, reduction: reduction}
			worst = &candidate
		}
	}

	test.Tested = true
	test.Examined = bitLen
	test.Passed = test.Flagged == 0
	test.Observed = fmt.Sprintf(
		"worst of %d position(s): position %d, %.1f%% reduction against the %.1f%% incompressible control (the largest of %d), tolerance %.0f percentage point(s) (%d flagged)",
		bitLen, worst.position, worst.reduction*100, baseline*100, compressionControls, CompressionTolerance*100, test.Flagged,
	)
	if truncated {
		test.Notices = append(test.Notices, fmt.Sprintf(
			"only the first %d bit position(s) were compressed; the token is wider and the rest were not examined.",
			MaxCompressionBits,
		))
	}
	test.Notices = append(test.Notices, fmt.Sprintf(
		"DEFLATE compresses in windows and carries framing, so at %d byte(s) of bits per position this test only sees structure a general-purpose compressor finds in a sequence that short. A weak bias passes it — the character-level and FIPS results above are what describe a weak bias.",
		rawBytes,
	))
	return test
}

// perTokenBits returns each token's own bit vector under the chosen encoding.
// BitsOf concatenates the whole sample; the two tests that need per-position
// sequences need the same decoding applied one token at a time. The second
// return is false when any token decoded to a different width than the first —
// characters outside the alphabet are skipped by BitsOf, so equal-length
// character strings can still decode to different bit lengths.
func perTokenBits(tokens []string, enc Encoding) ([][]byte, bool) {
	vectors := make([][]byte, 0, len(tokens))
	width, uniform := -1, true
	for _, token := range tokens {
		vector := BitsOf([]string{token}, enc)
		if width < 0 {
			width = len(vector)
		} else if len(vector) != width {
			uniform = false
		}
		vectors = append(vectors, vector)
	}
	return vectors, uniform
}

// deflateSize is the length of the zlib stream for data. The writer's errors are
// discarded because a bytes.Buffer cannot fail to write or close; there is no
// partial-compression outcome to report.
func deflateSize(data []byte) int {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return buf.Len()
}

// incompressibleReduction is the largest reduction any of compressionControls
// control sequences achieves at this sample length. The largest, not the mean:
// a position has to beat the best-behaved control, so one lucky control cannot
// make the comparison generous.
func incompressibleReduction(bits int) float64 {
	rawBytes := (bits + 7) / 8
	// Seeded below any achievable reduction, not at zero: DEFLATE's framing
	// makes a short incompressible sequence *grow*, so an incompressible
	// control's reduction is negative. Starting at zero would report that as
	// 0% and quietly hand every position a free five percentage points.
	worst := math.Inf(-1)
	for seed := 0; seed < compressionControls; seed++ {
		reduction := (float64(rawBytes) - float64(deflateSize(controlBitSequence(bits, seed)))) / float64(rawBytes)
		if reduction > worst {
			worst = reduction
		}
	}
	return worst
}

// controlBitSequence returns bits pseudo-random bits from SHA-256 in counter
// mode over a fixed seed. Deterministic by construction so any report can be
// reproduced by hand from its own description.
func controlBitSequence(bits int, seed int) []byte {
	size := (bits + 7) / 8
	out := make([]byte, 0, size+sha256.Size)
	for counter := 0; len(out) < size; counter++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("burpsy-sequencer-compression-control-%d-%d", seed, counter)))
		out = append(out, sum[:]...)
	}
	return out[:size]
}
