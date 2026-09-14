package sequencer

// Effective entropy against a chosen significance level — Burp's Sequencer
// headline output, which burpsy reported as one scalar and a grade until this
// file (burpsy-react-ui-boq).
//
// Burp's own documentation states the contract twice. On the operator's input:
//
//	"Compares the probability to a range of significance levels. You can reject
//	the hypothesis that the sample is randomly generated if the probability
//	falls below the significance level you choose for your analysis. […]
//	Scientific experiments often use levels between 1% and 5%. FIPS tests often
//	use levels between 0.002% and 0.03%. A lower significance level means that
//	stronger evidence is required to reject the hypothesis…"
//
// and on the output:
//
//	"The Effective entropy chart shows the number of bits that pass the
//	randomness tests at various significance levels, ranging from > 0.001% to
//	10%. In most cases, the Effective entropy chart shows that the choice of
//	significance level is not important."
//
// # What the number in this file is, exactly
//
// EffectiveEntropyPoint.Bits at significance level a is:
//
//	the count of bit positions of the token, among those this sample can
//	examine, whose observed distribution of ones across the tokens was NOT
//	rejected at level a by the tests named in EffectiveEntropyReport.Tests.
//
// That is the honest definition and it is deliberately not any of the following
// tempting readings:
//
//   - It is NOT a probability that the tokens are random. No test in this or any
//     other battery produces one; a p-value is P(a sample this extreme | the
//     source is fair), which is a different conditional and cannot be inverted
//     without a prior nobody has.
//   - It is NOT a measurement of entropy. A position that survives is counted as
//     one whole bit, and the tests cannot show a position carries a whole bit —
//     only fail to show that it does not. A position split 60/40 sails through a
//     sample of 50 tokens and is counted as a full bit here while carrying
//     0.97 of one. So this is an UPPER bound the tests could not knock down.
//   - It is NOT the character-level `characters.total_entropy_bits`, which is a
//     Shannon sum over character positions under a stated independence
//     assumption. The two answer different questions and will not agree.
//
// # The one test, and what it is blind to
//
// The test set is exactly {frequency}: per bit position, the two-sided exact
// binomial test of the observed count of ones against Binomial(n, 1/2), where n
// is the token count. Exact rather than a normal approximation because the whole
// point of the low end of Burp's range is levels around 1e-5, where the
// approximation's tail is wrong by orders of magnitude — and because an exact
// binomial tail is a number a reader can recompute by hand.
//
// The curve is therefore blind to sequential structure: a generator emitting
// 0101…0101 at some position has a perfect 50/50 split there and loses no bits
// here while being completely predictable. That blindness is not papered over —
// it is what the FIPS runs and poker tests (fips.go) and the extended battery's
// transition, spectral, correlation and compression tests (advanced.go) are for,
// and they are reported beside this curve rather than folded into it. Folding a
// second per-position test in here would also duplicate advanced.go's transition
// test under a different correction rule.
//
// # No multiple-comparison correction, and why
//
// advanced.go Bonferroni-corrects every verdict over its own comparison count.
// This curve deliberately does not, and must not: correcting would flatten the
// slope that is the entire point of Burp's chart. At level a, a sample from a
// perfect generator is EXPECTED to lose about a x (bit positions) positions to
// chance, so every point carries `expected_chance_rejections` — the count an
// operator compares the loss against before calling it a defect. "Lost 12 of 128
// bits at 10%" against an expectation of 12.8 is not a finding; the same loss at
// 0.01% against an expectation of 0.013 is.
//
// # Where the curve refuses to answer
//
// The two-sided exact binomial test on n tokens cannot produce a p-value below
// 2^(1-n), which is what the most extreme possible outcome — every token
// carrying the same bit at that position — scores. If 2^(1-n) is not below the
// significance level, then no bit position could be rejected at that level
// whatever the data says, and reporting "all N bits survived" would be an
// artefact of the sample size rather than a result. Those points are reported as
// not computed, with the reason and the count of tokens that would be needed.
// They are never plotted as zero and never counted as a pass.

import (
	"fmt"
	"math"
	"sort"
)

// MaxBitPositionsExamined bounds the curve's width for the same reason
// MaxPositionsReported bounds the character table: one pathological multi-megabyte
// "token" must not turn a report into a memory problem. Truncation is stated in
// the report (`positions_truncated`) and, because the curve's unit is a count of
// bits, it changes the number — so it is never silent.
const MaxBitPositionsExamined = 2048

// DefaultSignificancePercent is the level used when the caller names none. 1% is
// the low end of the range Burp calls the usual choice for scientific work, and
// picking the strictest-of-the-lenient band means a default report rejects a
// position only on evidence that would satisfy that convention.
const DefaultSignificancePercent = 1.0

// MinSignificancePercent and MaxSignificancePercent are the ends of Burp's range
// ("> 0.001% to 10%"). Levels outside it are refused at the HTTP boundary rather
// than clamped: an operator who typed 50% has misunderstood the parameter, and a
// silently-clamped 10% would answer a question they did not ask.
const MinSignificancePercent = 0.001
const MaxSignificancePercent = 10.0

// significanceLadder is the x-axis of the chart: Burp's stated range, with enough
// points inside each band it names to show the shape there. 0.002, 0.01 and 0.03
// bracket the FIPS band Burp quotes (0.002%–0.03%); 1, 2 and 5 bracket the
// scientific band (1%–5%). Percent, not fraction — the conversion happens once,
// in pointAt.
var significanceLadder = []float64{
	0.001, 0.002, 0.005, 0.01, 0.02, 0.03, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10,
}

// EffectiveEntropyPoint is the curve at one significance level.
//
// Two states, like every other refusal in this package: `computed`, carrying a
// bit count, or not computed, carrying the reason the sample cannot support an
// answer at this level. `bits` is a pointer so the not-computed state marshals to
// JSON null — a zero there would render as "no bits survived", which is the exact
// opposite of what it means.
type EffectiveEntropyPoint struct {
	// SignificancePercent is the level as the operator states it: 0.03 means
	// 0.03%, not 3%.
	SignificancePercent float64 `json:"significance_percent"`
	// Significance is the same level as a fraction, the form p-values are
	// compared against. Carried so no reader has to guess which unit a field is
	// in.
	Significance float64 `json:"significance"`
	// Computed is false when this sample cannot support an answer at this level.
	Computed bool `json:"computed"`
	// Bits is the effective entropy: bit positions not rejected at this level.
	// Null exactly when Computed is false.
	Bits *int `json:"bits"`
	// BitsExamined is the number of bit positions the sample could test at all,
	// the ceiling Bits is counted against.
	BitsExamined int `json:"bits_examined"`
	// BitsRejected is BitsExamined - Bits. Null exactly when Computed is false.
	BitsRejected *int `json:"bits_rejected"`
	// ExpectedChanceRejections is significance x bits_examined: how many
	// positions a perfect generator would be expected to lose at this level. The
	// number a loss is read against, since this curve applies no
	// multiple-comparison correction. Null exactly when Computed is false.
	ExpectedChanceRejections *float64 `json:"expected_chance_rejections"`
	// Reason is why no answer was reached. Present exactly when Computed is
	// false.
	Reason string `json:"reason,omitempty"`
	// Chosen marks the point at the level the operator asked for, which is
	// inserted into the ladder when it is not already one of its points.
	Chosen bool `json:"chosen"`
}

// EffectiveEntropyReport is the whole significance-level surface: the operator's
// chosen level, the curve over Burp's range, and the sentences that keep the
// number from being read as something it is not.
type EffectiveEntropyReport struct {
	// SignificancePercent is the level the operator chose (or the default).
	SignificancePercent float64 `json:"significance_percent"`
	// SignificanceDefaulted is true when no level was supplied and
	// DefaultSignificancePercent was used, so the UI can say "default" rather
	// than implying a choice was made.
	SignificanceDefaulted bool `json:"significance_defaulted"`
	// Chosen is the curve point at SignificancePercent. Also present in Curve,
	// flagged; repeated here so a caller reading one number does not have to
	// search the array for it.
	Chosen EffectiveEntropyPoint `json:"chosen"`
	// Curve is the whole ladder, ascending. Never null.
	Curve []EffectiveEntropyPoint `json:"curve"`
	// Tests names the test set the bit counts come from, because "passes the
	// randomness tests" is meaningless without it. Never null.
	Tests []string `json:"tests"`
	// Definition is this file's definition of the number, on the wire, so an
	// exported report carries it and nobody has to read the Go source to know
	// what they are quoting.
	Definition string `json:"definition"`
	// TokensUsed is n: the sample size every p-value was computed against.
	TokensUsed int `json:"tokens_used"`
	// BitPositionsExamined is how many bit positions of the token were tested.
	BitPositionsExamined int `json:"bit_positions_examined"`
	// BitPositionsSkippedVariableLength is how many positions the longest token
	// has that the shortest does not. Those positions have a smaller sample than
	// the rest, so they are excluded rather than tested against the wrong n.
	BitPositionsSkippedVariableLength int `json:"bit_positions_skipped_variable_length"`
	// PositionsTruncated is true when the token is wider than
	// MaxBitPositionsExamined and later positions were not examined. It changes
	// the bit count, so it is stated.
	PositionsTruncated bool `json:"positions_truncated"`
	// Robust is true when every computed point on the curve carries the same bit
	// count — Burp's "in most cases the choice of significance level is not
	// important". False means the verdict moves with the level and the operator
	// must say which one they used.
	Robust bool `json:"robust"`
	// RobustnessNote says the above in a sentence, with the numbers in it.
	RobustnessNote string `json:"robustness_note"`
	// FipsAgreement reconciles this curve with the FIPS grade above it in its own
	// words. The two tests answer different questions over different units and
	// can disagree without either being wrong; a report carrying both must say
	// how, rather than leaving a reader to decide which one is lying.
	FipsAgreement string `json:"fips_agreement"`
	// AffectsGrade is always false, and on the wire for the same reason
	// AdvancedReport.AffectsGrade is: `grade` and `verdict` are the FIPS
	// battery's, byte-for-byte the Rust reference's, and this curve does not move
	// them.
	AffectsGrade bool `json:"affects_grade"`
}

// effectiveEntropyTests is the test set, named on the wire.
var effectiveEntropyTests = []string{
	"frequency (two-sided exact binomial on the count of ones at each bit position, against Binomial(n, 1/2))",
}

// effectiveEntropyDefinition is the definition of the reported number, carried on
// the wire so an exported report cannot be quoted without it.
const effectiveEntropyDefinition = "Bits at a significance level is the number of bit positions of the token, among those examined, whose count of ones across the sample was not rejected at that level by the tests named in `tests`. It is an upper bound the tests could not knock down, not a measurement of entropy and not a probability that the tokens are random: a position that survives is counted as one whole bit, and a test that fails to reject has not shown the position carries one."

// ClampSignificancePercent reports whether a level is inside Burp's range. It is
// a predicate rather than a clamp on purpose — see MinSignificancePercent.
func ValidSignificancePercent(percent float64) bool {
	return !math.IsNaN(percent) && percent >= MinSignificancePercent && percent <= MaxSignificancePercent
}

// AnalyseEffectiveEntropy builds the curve for one sample at one chosen level.
//
// fips is read only to write FipsAgreement; no FIPS number feeds any bit count,
// and no bit count feeds the grade.
func AnalyseEffectiveEntropy(tokens []string, enc Encoding, significancePercent float64, defaulted bool, fips *FipsReport) EffectiveEntropyReport {
	ones, examined, skipped, truncated := onesPerBitPosition(tokens, enc)
	n := len(tokens)

	// One p-value per position, computed once and reused at every level: the
	// p-value is a property of the sample, not of the level. Only the comparison
	// moves along the ladder.
	pValues := make([]float64, examined)
	for i := 0; i < examined; i++ {
		pValues[i] = binomialTwoSidedP(n, ones[i])
	}

	levels := make([]float64, 0, len(significanceLadder)+1)
	levels = append(levels, significanceLadder...)
	if !containsLevel(levels, significancePercent) {
		levels = append(levels, significancePercent)
		sort.Float64s(levels)
	}

	curve := make([]EffectiveEntropyPoint, 0, len(levels))
	var chosen EffectiveEntropyPoint
	for _, percent := range levels {
		point := pointAt(percent, pValues, examined, n)
		point.Chosen = sameLevel(percent, significancePercent)
		if point.Chosen {
			chosen = point
		}
		curve = append(curve, point)
	}

	robust, note := robustness(curve)
	return EffectiveEntropyReport{
		SignificancePercent:               significancePercent,
		SignificanceDefaulted:             defaulted,
		Chosen:                            chosen,
		Curve:                             curve,
		Tests:                             effectiveEntropyTests,
		Definition:                        effectiveEntropyDefinition,
		TokensUsed:                        n,
		BitPositionsExamined:              examined,
		BitPositionsSkippedVariableLength: skipped,
		PositionsTruncated:                truncated,
		Robust:                            robust,
		RobustnessNote:                    note,
		FipsAgreement:                     fipsAgreement(fips, chosen, examined, n),
		AffectsGrade:                      false,
	}
}

// pointAt evaluates the curve at one level.
func pointAt(percent float64, pValues []float64, examined, tokens int) EffectiveEntropyPoint {
	alpha := percent / 100
	point := EffectiveEntropyPoint{
		SignificancePercent: percent,
		Significance:        alpha,
		BitsExamined:        examined,
	}
	if examined == 0 {
		point.Reason = fmt.Sprintf(
			"no bit position could be examined: %d token(s) decoded to a shortest length of 0 bits, so there is nothing to test at any significance level",
			tokens,
		)
		return point
	}
	// The power check. `<` and not `<=`: rejection is p < alpha, so an extreme
	// outcome scoring exactly alpha does not reject, and a level where the most
	// extreme possible outcome scores exactly alpha has no power either.
	minP := minAttainableP(tokens)
	if !(minP < alpha) {
		point.Reason = fmt.Sprintf(
			"insufficient sample: with %d token(s) the most extreme result a bit position can produce — every token carrying the same bit there — scores p = %s, which is not below this %g%% level, so no position could be rejected here whatever the data says. About %d token(s) would be needed to reach it.",
			tokens, formatP(minP), percent, tokensForLevel(alpha),
		)
		return point
	}
	rejected := 0
	for _, p := range pValues {
		if p < alpha {
			rejected++
		}
	}
	bits := examined - rejected
	expected := alpha * float64(examined)
	point.Computed = true
	point.Bits = &bits
	point.BitsRejected = &rejected
	point.ExpectedChanceRejections = &expected
	return point
}

// onesPerBitPosition counts, for each bit position of the token, how many tokens
// carry a 1 there.
//
// Only the positions EVERY token has are examined. Tokens vary in length more
// often than they should, and a position present in 40 of 100 tokens has a
// different n from its neighbours — testing it against the sample's n would
// compare a count of ones to the wrong distribution and manufacture a rejection.
// The excluded positions are counted and reported rather than dropped quietly.
//
// Each token is decoded on its own (BitsOf over a one-element slice) rather than
// the concatenated stream being cut into equal pieces, because BitsOf skips
// characters outside the chosen alphabet: one stray character in one token would
// otherwise shift every later token's bits by four and turn the whole curve into
// an artefact of that one character.
func onesPerBitPosition(tokens []string, enc Encoding) (ones []int, examined, skippedVariable int, truncated bool) {
	if len(tokens) == 0 {
		return []int{}, 0, 0, false
	}
	minBits, maxBits := -1, 0
	ones = []int{}
	for _, token := range tokens {
		bits := BitsOf([]string{token}, enc)
		if len(bits) > maxBits {
			maxBits = len(bits)
		}
		if minBits < 0 || len(bits) < minBits {
			minBits = len(bits)
		}
		limit := len(bits)
		if limit > MaxBitPositionsExamined {
			limit = MaxBitPositionsExamined
		}
		for len(ones) < limit {
			ones = append(ones, 0)
		}
		for i := 0; i < limit; i++ {
			if bits[i] == 1 {
				ones[i]++
			}
		}
	}
	if minBits < 0 {
		minBits = 0
	}
	examined = minBits
	if examined > MaxBitPositionsExamined {
		examined = MaxBitPositionsExamined
		truncated = true
	}
	return ones[:examined], examined, maxBits - minBits, truncated
}

// minAttainableP is the smallest p-value the frequency test can produce on n
// tokens: the score of "every token carries the same bit at this position",
// 2 x 2^-n. Computed with Ldexp rather than through the general path so it is
// exact — this number decides whether a curve point exists at all, and a rounding
// error in it would silently turn an insufficient sample into a confident one.
func minAttainableP(n int) float64 {
	if n <= 1 {
		return 1
	}
	p := math.Ldexp(1, 1-n)
	if p > 1 {
		return 1
	}
	return p
}

// tokensForLevel is the smallest n whose minAttainableP falls below alpha: the
// answer to "how many more tokens would make this level answerable". Solving
// 2^(1-n) < alpha gives n > 1 - log2(alpha).
func tokensForLevel(alpha float64) int {
	if alpha <= 0 {
		return 0
	}
	n := int(math.Floor(2 - math.Log2(alpha)))
	if n < 2 {
		n = 2
	}
	// Guard the boundary rather than trust the float: step up until the
	// predicate this function exists to satisfy actually holds.
	for !(minAttainableP(n) < alpha) {
		n++
	}
	return n
}

// binomialTwoSidedP is P(|X - n/2| >= |k - n/2|) for X ~ Binomial(n, 1/2): the
// exact two-sided p-value for observing k ones in n tokens at one bit position.
//
// Exact, not a normal approximation. The low end of Burp's range is 1e-5, where
// the normal tail is wrong by orders of magnitude, and this package's rule is
// that a number it prints has to be defensible at the level it is quoted at.
//
// By the symmetry of p = 1/2 the two tails are equal, so the whole thing is
// 2 x P(X <= min(k, n-k)), clamped at 1 for the even-split case where the two
// tails overlap on the centre.
func binomialTwoSidedP(n, k int) float64 {
	if n <= 0 {
		return 1
	}
	if k < 0 || k > n {
		return math.NaN()
	}
	if k == 0 || k == n {
		// The exact path, for the same reason minAttainableP has one.
		return minAttainableP(n)
	}
	m := k
	if n-k < m {
		m = n - k
	}
	p := 2 * binomialLowerTailHalf(n, m)
	if p > 1 {
		return 1
	}
	return p
}

// binomialLowerTailHalf is P(X <= m) for X ~ Binomial(n, 1/2), summed in log
// space. The terms are C(n, i) / 2^n; at n in the thousands C(n, i) overflows
// float64 long before the quotient does, so the log-gamma form is not an
// optimisation but the only form that computes.
func binomialLowerTailHalf(n, m int) float64 {
	if m < 0 {
		return 0
	}
	if m >= n {
		return 1
	}
	lnN1, _ := math.Lgamma(float64(n) + 1)
	logHalfN := -float64(n) * math.Ln2
	sum := 0.0
	for i := 0; i <= m; i++ {
		lnI1, _ := math.Lgamma(float64(i) + 1)
		lnNI1, _ := math.Lgamma(float64(n-i) + 1)
		sum += math.Exp(lnN1 - lnI1 - lnNI1 + logHalfN)
	}
	return sum
}

// formatP renders a p-value for a sentence an operator reads: as a percentage
// where that is legible, and in exponent form where it is not.
func formatP(p float64) float64Text {
	return float64Text(p)
}

// float64Text formats a probability without the %g surprises — small tails keep
// their exponent, ordinary ones read as decimals.
type float64Text float64

func (p float64Text) String() string {
	v := float64(p)
	switch {
	case v >= 0.001:
		return fmt.Sprintf("%.6g (%.4g%%)", v, v*100)
	default:
		return fmt.Sprintf("%.3e (%.5f%%)", v, v*100)
	}
}

// robustness answers Burp's "in most cases the choice of significance level is
// not important" for this sample specifically, rather than asserting it.
func robustness(curve []EffectiveEntropyPoint) (bool, string) {
	var lo, hi *int
	computed, uncomputed := 0, 0
	var loLevel, hiLevel float64
	for _, point := range curve {
		if !point.Computed {
			uncomputed++
			continue
		}
		computed++
		if lo == nil || *point.Bits < *lo {
			lo = point.Bits
			loLevel = point.SignificancePercent
		}
		if hi == nil || *point.Bits > *hi {
			hi = point.Bits
			hiLevel = point.SignificancePercent
		}
	}
	switch {
	case computed == 0:
		return false, fmt.Sprintf(
			"No point on the curve could be computed: this sample supports no answer at any level between %g%% and %g%%. The curve is absent, not flat at zero.",
			MinSignificancePercent, MaxSignificancePercent)
	case *lo == *hi:
		note := fmt.Sprintf(
			"The choice of significance level does not change this verdict: %d bit(s) survive at every level the sample can answer, from %g%% to %g%%.",
			*lo, curve[0].SignificancePercent, curve[len(curve)-1].SignificancePercent)
		if uncomputed > 0 {
			note = fmt.Sprintf(
				"The choice of significance level does not change this verdict across the %d level(s) this sample can answer: %d bit(s) survive at every one of them. %d level(s) are below what %s can support and are reported as insufficient rather than as a pass.",
				computed, *lo, uncomputed, "this sample size")
		}
		return true, note
	default:
		return false, fmt.Sprintf(
			"The verdict moves with the significance level: %d bit(s) survive at %g%% and %d at %g%%. Any finding quoted from this curve has to name the level it was read at.",
			*hi, hiLevel, *lo, loLevel)
	}
}

// fipsAgreement writes the reconciliation between this curve and the FIPS grade
// beside it. Three cases, because all three happen in ordinary use and each needs
// a different sentence — a report that shows "FIPS: pass" over a curve losing
// bits, and says nothing about the pair, has invited its reader to conclude one
// of them is broken.
func fipsAgreement(fips *FipsReport, chosen EffectiveEntropyPoint, examined, tokens int) string {
	const shared = "The two measure different things over different units: the FIPS battery pools every token into one stream and tests whole 20,000-bit blocks of it, while this curve tests each bit position of the token across the sample. Neither contains the other — pooling hides a single stuck position among thousands of healthy bits, and a per-position frequency test is blind to the sequential structure poker and runs are built to catch."
	if fips == nil {
		return shared
	}
	passed := fips.Passed()
	switch {
	// The FIPS-ran-but-the-curve-cannot case has to come first, and needs its own
	// sentence. A handful of very long tokens fills several 20,000-bit blocks —
	// so FIPS reaches a verdict — while the per-position test still has n = the
	// token COUNT, which at two or three tokens has no power at any level in the
	// range. Falling through to the pass/fail branches below would print "every
	// examined bit position survives" or "this curve also loses bit positions"
	// about a curve that said nothing at all.
	case passed != nil && !chosen.Computed:
		verdict := "passed"
		if !*passed {
			verdict = "failed"
		}
		return fmt.Sprintf(
			"FIPS %s over %d whole %d-bit block(s) while this curve has no answer at %g%% at all. Nothing here contradicts anything: the two count different samples. FIPS needs BITS, and %d token(s) of this length supply plenty; this curve needs TOKENS, and %d of them cannot reject a bit position at any level in its range. %s",
			verdict, fips.BlocksTested, BlockBits, chosen.SignificancePercent, tokens, tokens, shared)
	case passed == nil && chosen.Computed:
		return fmt.Sprintf(
			"FIPS reached no verdict here (%d bit(s) supplied, below one whole %d-bit block) while this curve did, and that is expected rather than a contradiction: the two have different sample requirements. FIPS needs %d bits in one stream; this curve needs enough TOKENS for a per-position test to have power at the chosen level, which %d token(s) provide. %s",
			fips.BitsSupplied, BlockBits, BlockBits, chosen.BitsExamined, shared)
	case passed == nil:
		return fmt.Sprintf(
			"Neither surface reached a verdict: FIPS had %d of the %d bits one block needs, and this curve has no computable point at the chosen level. Nothing here is a pass. %s",
			fips.BitsSupplied, BlockBits, shared)
	case *passed && chosen.Computed && chosen.Bits != nil && *chosen.Bits < examined:
		return fmt.Sprintf(
			"FIPS passed and this curve still loses %d of %d bit position(s) at %g%%. That is not a contradiction. %s Read the loss against the %.2f position(s) a perfect generator would be expected to lose to chance at this level: a loss near that number is the level's own false-positive rate, and a loss well above it is a finding FIPS could not see.",
			examined-*chosen.Bits, examined, chosen.SignificancePercent, shared, chosen.expectedChance())
	case *passed:
		return fmt.Sprintf(
			"FIPS passed and every examined bit position survives at %g%%. The two surfaces agree, which is the most a battery of tests can say: neither is proof of unpredictability. %s",
			chosen.SignificancePercent, shared)
	case chosen.Computed && chosen.Bits != nil && *chosen.Bits == examined:
		return fmt.Sprintf(
			"FIPS failed while every examined bit position survives this curve at %g%%. That is not a contradiction. %s A stream that fails poker, runs or long-runs while every position's ones/zeros split is unremarkable is exactly the shape this curve cannot see; the FIPS failure stands.",
			chosen.SignificancePercent, shared)
	default:
		return fmt.Sprintf("FIPS failed and this curve also loses bit positions at %g%%. The two agree. %s",
			chosen.SignificancePercent, shared)
	}
}

func (p EffectiveEntropyPoint) expectedChance() float64 {
	if p.ExpectedChanceRejections == nil {
		return 0
	}
	return *p.ExpectedChanceRejections
}

// sameLevel compares two significance levels for identity as the operator typed
// them. A relative epsilon rather than == because the chosen level arrives
// through JSON and 0.03 is not exactly representable; the ladder's points are
// three orders of magnitude apart at the closest, so nothing can collide here.
func sameLevel(a, b float64) bool {
	return math.Abs(a-b) <= 1e-12*math.Max(1, math.Abs(a))
}

func containsLevel(levels []float64, want float64) bool {
	for _, level := range levels {
		if sameLevel(level, want) {
			return true
		}
	}
	return false
}
