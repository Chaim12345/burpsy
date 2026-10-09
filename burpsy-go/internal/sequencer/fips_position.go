package sequencer

// The FIPS 140-2 battery run at each bit position across tokens (burpsy-react-ui-c0k3): the
// deferred half of 3f3, and what Burp's Sequencer means by "bit-level analysis".
//
// fips.go runs the four tests over the flattened stream in 20,000-bit blocks, where the FIPS
// intervals apply as written. Burp runs them a second way as well: for bit position i of the token,
// the sample is bit i of every captured token, in capture order, so N is the number of tokens. That
// view answers "which bits of the token are weak", the question the stream view cannot answer. A
// fixed prefix or a counter field fails here at exactly the positions it occupies.
//
// # The statistical method, and where it comes from
//
// FIPS 140-2 defines its intervals at N = 20,000 only. Burp 2026.7.1 handles other N like this
// (decompiled burp/Zpu3, burp/Zc6a and burp/Zpix):
//
//   - At N == 20,000, a position passes when its statistic lies inside the FIPS interval. This is
//     the same set of intervals as fips.go.
//   - At any other N, a position passes when its significance (the probability of a statistic at
//     least this extreme from a fair, independent source) exceeds a fixed per-test threshold:
//     1e-4 for monobit and poker, 1.8e-5 for runs, 2.98e-4 for the long run. A longest run under 12
//     always passes.
//   - Significance is floored at 1e-6, and Burp charts it as 6 + log10(p). Its "FIPS pass level"
//     line is 6 + log10(threshold).
//
// Those pass rules and thresholds are copied exactly. Burp reads significance from precomputed tables
// (Zw_0, Zcmb's five run tables, Zphy) at 28 sample sizes from 100 to 20,000 and interpolates
// between them. This file computes the same quantities exactly at the actual N instead:
//
//   - Monobit is the exact two-sided binomial tail for the count of ones. Burp's Zw_0 rows are this
//     value to eight digits. They are off by one key above the centre, an artefact of how the tables
//     were generated that is not reproduced here.
//   - Poker groups 4 consecutive tokens into a nibble and computes X = (16/k)·Σf² − k over the
//     k = ⌊N/4⌋ nibbles. Its significance is the two-sided chi-square tail with 15 degrees of
//     freedom, which is Burp's Zp2s.ZK exactly.
//   - Runs counts runs of ones and of zeros separately, in lengths 1-5 and 6 or more, as FIPS
//     specifies. Each count is scored against its exact distribution, computed below by dynamic
//     programming. Burp's run tables match that distribution for each length (checked against
//     Zxh7 and Zi0_ at N=100). Burp's counter does not: it pools both symbols in one histogram,
//     restarts the length at 0 rather than 1 on a change, and never counts the final run. It also
//     scores the "6 or more" bucket with its exactly-5 table (Zcmb maps both to Zi0_). Neither the
//     counter nor that table choice is ported. A position's runs significance is the least likely of its twelve
//     cells, and it passes only when every cell does.
//   - Long run is the longest run of either symbol, scored by its exact upper tail P(L ≥ l). The
//     long-run test can only fail on a run that is too long. Burp's Zphy table does not match
//     the exact distribution; it sits roughly one sample-size row off. That divergence is
//     recorded in gaps.md.
//
// Like Advanced and EffectiveEntropy, this is additive. Grade, Verdict and the stream-level Fips
// report do not read it, and AffectsGrade says so on the wire.

import (
	"fmt"
	"math"
)

// MinFipsPositionTokens is the smallest sample Burp's per-position tables cover (Zsge's first sample
// size). Below it the result is "not computed", not a verdict extrapolated past Burp's own range.
const MinFipsPositionTokens = 100

// MaxFipsPositionTokens is the largest sample Burp's tables cover, which is also the sample size the
// FIPS intervals are defined on. Tokens beyond it are not analysed, and the report counts them.
const MaxFipsPositionTokens = BlockBits

// significanceFloor is where Burp's tables end and where its chart's axis bottoms out: 6 + log10(1e-6)
// = 0.
const significanceFloor = 1e-6

// positionThresholds are Burp's per-test significance pass levels for N != 20,000 (Zpu3.Zc).
var positionThresholds = map[string]float64{
	"monobit":   1e-4,
	"poker":     1e-4,
	"runs":      1.8e-5,
	"long_runs": 2.98e-4,
}

// autoPassLongestRun is Zpu3's rule that a longest run under 12 passes at any N. Burp needs it because
// its long-run table is two-sided, so an implausibly short longest run scores as significant. Here the
// significance is the one-sided upper tail, and P(L >= 11) is at least 0.045 at every N >= 100, so the
// rule never changes a verdict. It is kept so that the rule set stays literally Zpu3's.
const autoPassLongestRun = 12

// FipsPositionTest is one test's result at every examined bit position. The per-position values are
// parallel arrays indexed by position, rather than one object per position, because a 2,048-position
// token would otherwise put 8,192 objects on the wire.
type FipsPositionTest struct {
	// ID is the same as the stream-level test's: "monobit" | "poker" | "runs" | "long_runs". A test the
	// operator switches off is switched off in both views.
	ID            string `json:"id"`
	Name          string `json:"name"`
	Disabled      bool   `json:"disabled,omitempty"`
	DisableReason string `json:"disable_reason,omitempty"`
	// Requirement is the pass condition actually applied at this N, with its constants.
	Requirement string `json:"requirement"`
	// Threshold is the significance a position must exceed when N != 20,000.
	Threshold float64 `json:"threshold"`
	// PassLevel is 6 + log10(Threshold), the y-value of Burp's "FIPS pass level" line on a chart
	// whose y is 6 + log10(Significance).
	PassLevel float64 `json:"pass_level"`
	// StatisticLabel names what Statistic holds, because it differs per test.
	StatisticLabel string `json:"statistic_label"`
	// Statistic is per position: the count of ones, poker's X, the count in the least likely run
	// cell, or the longest run.
	Statistic []float64 `json:"statistic"`
	// Significance is per position, floored at 1e-6.
	Significance []float64 `json:"significance"`
	Passed       []bool    `json:"passed"`
	// FailingPositions lists the positions that failed, so a reader need not scan Passed.
	FailingPositions []int `json:"failing_positions"`
	PositionsPassed  int   `json:"positions_passed"`
	PositionsFailed  int   `json:"positions_failed"`
}

// FipsPositionReport is the battery at each bit position.
type FipsPositionReport struct {
	// Computed is false when the sample cannot support the analysis, and Reason says why.
	Computed bool   `json:"computed"`
	Reason   string `json:"reason,omitempty"`
	// Tokens is the number of tokens analysed: N, the sample size at every position.
	Tokens int `json:"tokens"`
	// TokensNotAnalysed counts tokens past MaxFipsPositionTokens.
	TokensNotAnalysed int `json:"tokens_not_analysed"`
	// PositionsExamined is the shortest token's bit width, capped at MaxBitPositionsExamined.
	PositionsExamined        int  `json:"positions_examined"`
	PositionsSkippedVariable int  `json:"positions_skipped_variable"`
	PositionsTruncated       bool `json:"positions_truncated"`
	// ExactIntervals is true when N == 20,000 and the FIPS intervals are applied as written, rather
	// than the significance thresholds.
	ExactIntervals bool   `json:"exact_intervals"`
	Method         string `json:"method"`
	AffectsGrade   bool   `json:"affects_grade"`
	// Tests is always an array: [] when Computed is false.
	Tests []FipsPositionTest `json:"tests"`
}

const fipsPositionMethod = "Each test runs on bit i of every token, in capture order (N = tokens). " +
	"At N = 20,000 the FIPS 140-2 intervals apply as written. At other N a position passes when its " +
	"significance exceeds Burp's per-test threshold (monobit and poker 1e-4, runs 1.8e-5, long run " +
	"2.98e-4; a longest run under 12 always passes). Significance is computed exactly at N rather " +
	"than interpolated from Burp's tables: an exact binomial tail (monobit), a two-sided chi-square " +
	"with 15 df (poker), the exact distribution of each run-length count for each symbol (runs), and " +
	"the exact upper tail of the longest run (long run). Values are floored at 1e-6."

// AnalyseFipsPositions runs the battery at each bit position of tokens under enc.
func AnalyseFipsPositions(tokens []string, enc Encoding, disabled []string) FipsPositionReport {
	report := FipsPositionReport{
		Method: fipsPositionMethod,
		Tests:  []FipsPositionTest{},
	}
	if len(tokens) > MaxFipsPositionTokens {
		report.TokensNotAnalysed = len(tokens) - MaxFipsPositionTokens
		tokens = tokens[:MaxFipsPositionTokens]
	}
	n := len(tokens)
	report.Tokens = n
	if n < MinFipsPositionTokens {
		report.Reason = fmt.Sprintf(
			"needs at least %d tokens, the smallest sample Burp's per-position significance covers; %d supplied",
			MinFipsPositionTokens, n)
		return report
	}

	vectors, _ := perTokenBits(tokens, enc)
	minBits, maxBits := len(vectors[0]), 0
	for _, v := range vectors {
		minBits = min(minBits, len(v))
		maxBits = max(maxBits, len(v))
	}
	examined := minBits
	if examined > MaxBitPositionsExamined {
		examined = MaxBitPositionsExamined
		report.PositionsTruncated = true
	}
	report.PositionsExamined = examined
	report.PositionsSkippedVariable = maxBits - minBits
	if examined == 0 {
		report.Reason = "no bit position is shared by every token under this encoding"
		return report
	}
	report.Computed = true
	report.ExactIntervals = n == BlockBits

	dists := newPositionDistributions(n)
	tests := []FipsPositionTest{
		newPositionTest("monobit", "Monobit Test", "count of ones", examined),
		newPositionTest("poker", "Poker Test", "X", examined),
		newPositionTest("runs", "Runs Test", "count in the least likely run cell", examined),
		newPositionTest("long_runs", "Long Runs Test", "longest run", examined),
	}
	if report.ExactIntervals {
		tests[0].Requirement = "9725 < ones < 10275 (FIPS 140-2 §4.9.1, N = 20000)"
		tests[1].Requirement = "2.16 < X < 46.17 over 5000 nibbles (FIPS 140-2 §4.9.1, N = 20000)"
		tests[2].Requirement = "runs of length 1..6 within 2315-2685, 1114-1386, 527-723, 240-384, 103-209, 103-209 for both zeros and ones (FIPS 140-2 §4.9.1, N = 20000)"
		tests[3].Requirement = "no run of length 26 or more (FIPS 140-2 §4.9.1, N = 20000)"
	} else {
		for i := range tests {
			tests[i].Requirement = fmt.Sprintf("significance > %g at N = %d", tests[i].Threshold, n)
		}
		tests[3].Requirement = fmt.Sprintf("longest run < %d, or significance > %g at N = %d",
			autoPassLongestRun, tests[3].Threshold, n)
	}

	column := make([]byte, n)
	for pos := 0; pos < examined; pos++ {
		for t, v := range vectors {
			column[t] = v[pos]
		}
		r := dists.positionResult(column)
		tests[0].record(pos, float64(r.ones), r.monobitP, r.monobitOK)
		tests[1].record(pos, r.pokerX, r.pokerP, r.pokerOK)
		tests[2].record(pos, float64(r.runsWorstCount), r.runsP, r.runsOK)
		tests[3].record(pos, float64(r.longest), r.longRunP, r.longRunOK)
	}

	off := DisabledSet(disabled)
	for i := range tests {
		if off[tests[i].ID] {
			// Marked and kept, never dropped (nm81). The numbers are cleared too, because a switched-off
			// test that still reports positions failed is a measurement of nothing.
			tests[i] = FipsPositionTest{
				ID:               tests[i].ID,
				Name:             tests[i].Name,
				Disabled:         true,
				DisableReason:    "switched off in the analysis settings",
				Requirement:      tests[i].Requirement,
				Threshold:        tests[i].Threshold,
				PassLevel:        tests[i].PassLevel,
				StatisticLabel:   tests[i].StatisticLabel,
				Statistic:        []float64{},
				Significance:     []float64{},
				Passed:           []bool{},
				FailingPositions: []int{},
			}
		}
	}
	report.Tests = tests
	return report
}

func newPositionTest(id, name, label string, positions int) FipsPositionTest {
	threshold := positionThresholds[id]
	return FipsPositionTest{
		ID:               id,
		Name:             name,
		Threshold:        threshold,
		PassLevel:        6 + math.Log10(threshold),
		StatisticLabel:   label,
		Statistic:        make([]float64, positions),
		Significance:     make([]float64, positions),
		Passed:           make([]bool, positions),
		FailingPositions: []int{},
	}
}

func (t *FipsPositionTest) record(pos int, statistic, significance float64, passed bool) {
	t.Statistic[pos] = statistic
	t.Significance[pos] = significance
	t.Passed[pos] = passed
	if passed {
		t.PositionsPassed++
	} else {
		t.PositionsFailed++
		t.FailingPositions = append(t.FailingPositions, pos)
	}
}

// positionResult is one position's four statistics, their significances and their verdicts.
type positionResult struct {
	ones           int
	monobitP       float64
	monobitOK      bool
	pokerX         float64
	pokerP         float64
	pokerOK        bool
	runsWorstCount int
	runsP          float64
	runsOK         bool
	longest        int
	longRunP       float64
	longRunOK      bool
}

// positionDistributions holds the null distributions for one N. Every position shares them, so they
// are computed once per analysis rather than once per position.
type positionDistributions struct {
	n int
	// binomCDF[k] = P(X <= k) for X ~ Binomial(n, 1/2).
	binomCDF []float64
	// runs[b] is the distribution of the count of one-runs in length bucket b (0..4 = exactly 1..5,
	// 5 = 6 or more). Zero-runs have the same distribution by symmetry.
	runs [6]discreteDist
	// longTail caches P(longest run >= l).
	longTail map[int]float64
}

func newPositionDistributions(n int) *positionDistributions {
	d := &positionDistributions{n: n, longTail: map[int]float64{}}
	d.binomCDF = binomialHalfCDF(n)
	for b := 0; b < 6; b++ {
		d.runs[b] = runCountDistribution(n, b+1, b == 5)
	}
	return d
}

func (d *positionDistributions) positionResult(column []byte) positionResult {
	n := d.n
	exact := n == BlockBits
	var r positionResult

	r.ones = monobit(column)
	m := min(r.ones, n-r.ones)
	r.monobitP = floorSignificance(2 * d.binomCDF[m])
	if exact {
		r.monobitOK = r.ones > monobitLow && r.ones < monobitHigh
	} else {
		r.monobitOK = r.monobitP > positionThresholds["monobit"]
	}

	r.pokerX = pokerOver(column)
	q := chiSquareUpperTail(r.pokerX, 15)
	if q > 0.5 {
		r.pokerP = floorSignificance(2 * (1 - q))
	} else {
		r.pokerP = floorSignificance(2 * q)
	}
	if exact {
		r.pokerOK = r.pokerX > pokerLow && r.pokerX < pokerHigh
	} else {
		r.pokerOK = r.pokerP > positionThresholds["poker"]
	}

	zeros, ones, longest := runHistogram(column)
	r.runsP = 1
	r.runsOK = true
	r.runsWorstCount = ones[0]
	for b := 0; b < 6; b++ {
		for _, count := range []int{zeros[b], ones[b]} {
			p := floorSignificance(d.runs[b].twoSided(count))
			if p < r.runsP {
				r.runsP = p
				r.runsWorstCount = count
			}
			if exact {
				if count < runIntervals[b][0] || count > runIntervals[b][1] {
					r.runsOK = false
				}
			} else if !(p > positionThresholds["runs"]) {
				r.runsOK = false
			}
		}
	}

	r.longest = longest
	r.longRunP = floorSignificance(d.longestRunUpperTail(longest))
	switch {
	case longest < autoPassLongestRun:
		r.longRunOK = true
	case exact:
		r.longRunOK = longest < longRunBits
	default:
		r.longRunOK = r.longRunP > positionThresholds["long_runs"]
	}
	return r
}

func floorSignificance(p float64) float64 {
	if math.IsNaN(p) || p < significanceFloor {
		return significanceFloor
	}
	if p > 1 {
		return 1
	}
	return p
}

// pokerOver is FIPS poker generalised to any length: ⌊len/4⌋ nibbles of four consecutive bits,
// X = (16/k)·Σf² − k. At len = 20,000 it equals poker(). Fewer than one nibble gives 0.
func pokerOver(bits []byte) float64 {
	k := len(bits) / 4
	if k == 0 {
		return 0
	}
	var f [16]int
	for i := 0; i+3 < 4*k; i += 4 {
		v := int(bits[i])<<3 | int(bits[i+1])<<2 | int(bits[i+2])<<1 | int(bits[i+3])
		f[v]++
	}
	sumSquares := 0
	for _, c := range f {
		sumSquares += c * c
	}
	return (16.0/float64(k))*float64(sumSquares) - float64(k)
}

// binomialHalfCDF is P(X <= k) for X ~ Binomial(n, 1/2), k = 0..n, built from log-space terms for the
// same reason binomialLowerTailHalf is: C(n, k) overflows float64 long before the quotient does.
func binomialHalfCDF(n int) []float64 {
	cdf := make([]float64, n+1)
	lnN1, _ := math.Lgamma(float64(n) + 1)
	logHalfN := -float64(n) * math.Ln2
	sum := 0.0
	for k := 0; k <= n; k++ {
		lnK1, _ := math.Lgamma(float64(k) + 1)
		lnNK1, _ := math.Lgamma(float64(n-k) + 1)
		sum += math.Exp(lnN1 - lnK1 - lnNK1 + logHalfN)
		cdf[k] = sum
	}
	return cdf
}

// discreteDist is a probability mass function over the integers lo..lo+len(pmf)-1, with zero mass
// elsewhere. lower[i] = P(X <= lo+i) and upper[i] = P(X >= lo+i) are kept separately rather than
// derived as 1 - the other, because a tail of 1e-9 cannot be recovered from 1 - 0.999999999.
type discreteDist struct {
	lo    int
	lower []float64
	upper []float64
}

func newDiscreteDist(lo int, pmf []float64) discreteDist {
	d := discreteDist{lo: lo, lower: make([]float64, len(pmf)), upper: make([]float64, len(pmf))}
	sum := 0.0
	for i, p := range pmf {
		sum += p
		d.lower[i] = sum
	}
	sum = 0
	for i := len(pmf) - 1; i >= 0; i-- {
		sum += pmf[i]
		d.upper[i] = sum
	}
	return d
}

// twoSided is min(1, 2·min(P(X <= c), P(X >= c))). A count outside the support has probability 0
// (a count past the pruned tail is below 1e-40), and the floor applies.
func (d discreteDist) twoSided(c int) float64 {
	i := c - d.lo
	if i < 0 || i >= len(d.lower) {
		return 0
	}
	return min(1, 2*min(d.lower[i], d.upper[i]))
}

// runPruneMass is the probability below which a count at the edge of the window is dropped. It is far
// below the 1e-6 floor, so pruning cannot move a reported significance.
const runPruneMass = 1e-40

// runCountDistribution is the exact distribution of the number of runs of ones of length exactly k
// (or k or more, when atLeast) in n fair, independent bits, a run being a maximal block of ones.
//
// The dynamic programme walks the bits with state (length of the trailing run of ones, capped,
// count so far). A 0 closes the run, counting it if its length qualifies, and a 1 extends it. The
// final run is closed after the last bit. The count window is pruned at both edges, so the work is
// proportional to n × the count's spread rather than n².
func runCountDistribution(n, k int, atLeast bool) discreteDist {
	// States 0..cap. cap = k+1 stands for "longer than k" in the exact case, while in the at-least
	// case cap = k already means "k or more".
	capState := k + 1
	if atLeast {
		capState = k
	}
	states := capState + 1
	width := n + 2
	cur := make([][]float64, states)
	next := make([][]float64, states)
	for s := range cur {
		cur[s] = make([]float64, width)
		next[s] = make([]float64, width)
	}
	cur[0][0] = 1
	lo, hi := 0, 1 // live window of counts [lo, hi)
	for bit := 0; bit < n; bit++ {
		for s := range next {
			clear(next[s][lo : hi+1])
		}
		for s := 0; s < states; s++ {
			row := cur[s]
			closes := s == k
			grow := min(s+1, capState)
			for c := lo; c < hi; c++ {
				p := row[c]
				if p == 0 {
					continue
				}
				p *= 0.5
				if closes {
					next[0][c+1] += p
				} else {
					next[0][c] += p
				}
				next[grow][c] += p
			}
		}
		hi++
		cur, next = next, cur
		for lo < hi-1 && columnMass(cur, lo) < runPruneMass {
			lo++
		}
		for hi-1 > lo && columnMass(cur, hi-1) < runPruneMass {
			hi--
		}
	}
	pmf := make([]float64, hi-lo+1)
	for s := 0; s < states; s++ {
		for c := lo; c < hi; c++ {
			if s == k {
				pmf[c+1-lo] += cur[s][c]
			} else {
				pmf[c-lo] += cur[s][c]
			}
		}
	}
	return newDiscreteDist(lo, pmf)
}

func columnMass(rows [][]float64, c int) float64 {
	sum := 0.0
	for _, row := range rows {
		sum += row[c]
	}
	return sum
}

// longestRunUpperTail is P(L >= l), where L is the longest run of either symbol in n fair bits.
func (d *positionDistributions) longestRunUpperTail(l int) float64 {
	if p, ok := d.longTail[l]; ok {
		return p
	}
	var p float64
	switch {
	case l <= 1:
		p = 1
	case float64(d.n)*math.Ldexp(1, 1-l) < 1e-9:
		// Union bound: a run of l or more starts at one of n places, each with probability 2^(1-l).
		// Below 1e-9 the floor applies whatever the exact value, so there is no point paying O(n·l) for
		// it, which matters for a stuck bit where l = n.
		p = 0
	default:
		p = 1 - longestRunAtMost(d.n, l-1)
	}
	d.longTail[l] = p
	return p
}

// longestRunAtMost is P(L <= m), where L is the longest run of either symbol in n fair bits. The state
// is the length of the current run. Each new bit continues it with probability 1/2 and starts a new
// run of length 1 with probability 1/2, and any path that would exceed m is dropped.
func longestRunAtMost(n, m int) float64 {
	if n == 0 || m >= n {
		return 1
	}
	if m < 1 {
		return 0
	}
	cur := make([]float64, m+1)
	next := make([]float64, m+1)
	cur[1] = 1
	for i := 1; i < n; i++ {
		total := 0.0
		for r := 1; r <= m; r++ {
			total += cur[r]
		}
		clear(next)
		next[1] = total * 0.5
		for r := 1; r < m; r++ {
			next[r+1] = cur[r] * 0.5
		}
		cur, next = next, cur
	}
	sum := 0.0
	for r := 1; r <= m; r++ {
		sum += cur[r]
	}
	return sum
}
