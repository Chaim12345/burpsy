package sequencer

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// The per-position FIPS battery (burpsy-react-ui-c0k3). The distributions are checked against brute
// enumeration and against the cells of Burp's own tables where the two agree. The pass rules are
// checked at their edges, and the wire shape is checked as marshalled.

func near(a, b, rel float64) bool {
	return math.Abs(a-b) <= rel*math.Max(math.Abs(a), math.Abs(b))
}

// Every distribution the DP produces matches brute enumeration of all 2^n sequences.
func Test_run_count_and_longest_run_distributions_match_enumeration(t *testing.T) {
	const n = 13
	for _, atLeast := range []bool{false, true} {
		for k := 1; k <= 6; k++ {
			counts := map[int]float64{}
			for seq := 0; seq < 1<<n; seq++ {
				c, run := 0, 0
				for i := 0; i <= n; i++ {
					if i < n && seq>>i&1 == 1 {
						run++
						continue
					}
					if run == k || (atLeast && run >= k) {
						c++
					}
					run = 0
				}
				counts[c] += 1.0 / (1 << n)
			}
			d := runCountDistribution(n, k, atLeast)
			for c := 0; c <= n; c++ {
				i := c - d.lo
				got := 0.0
				if i >= 0 && i < len(d.lower) {
					got = d.lower[i]
					if i > 0 {
						got -= d.lower[i-1]
					}
				}
				if math.Abs(got-counts[c]) > 1e-12 {
					t.Errorf("k=%d atLeast=%v: P(count=%d) = %g, enumeration %g", k, atLeast, c, got, counts[c])
				}
			}
		}
	}
	for m := 0; m <= n; m++ {
		want := 0
		for seq := 0; seq < 1<<n; seq++ {
			longest, run := 0, 0
			for i := 0; i < n; i++ {
				if i > 0 && seq>>i&1 == seq>>(i-1)&1 {
					run++
				} else {
					run = 1
				}
				longest = max(longest, run)
			}
			if longest <= m {
				want++
			}
		}
		if got := longestRunAtMost(n, m); math.Abs(got-float64(want)/(1<<n)) > 1e-12 {
			t.Errorf("P(longest <= %d) = %g, enumeration %g", m, got, float64(want)/(1<<n))
		}
	}
}

// Cells where Burp 2026.7.1's tables and the exact computation agree (lower-tail cells, below the
// key where Burp's tables shift by one). Values are copied from the decompiled classes.
func Test_significance_matches_burps_table_cells(t *testing.T) {
	cdf := binomialHalfCDF(100)
	for _, c := range []struct {
		ones int
		want float64 // burp/Zw_0, row N=100
	}{{26, 1.6673627e-6}, {40, 0.056887932}, {49, 0.92041075}} {
		if got := 2 * cdf[c.ones]; !near(got, c.want, 1e-6) {
			t.Errorf("monobit N=100 ones=%d: %g, Burp %g", c.ones, got, c.want)
		}
	}
	if got := runCountDistribution(100, 4, false).twoSided(0); !near(got, 0.38880473, 1e-6) {
		t.Errorf("runs of 4, N=100, count 0: %g, Burp Zxh7 0.38880473", got)
	}
	if got := runCountDistribution(100, 5, false).twoSided(0); !near(got, 0.9044905, 1e-6) {
		t.Errorf("runs of 5, N=100, count 0: %g, Burp Zi0_ 0.9044905", got)
	}
	// Poker is Burp's Zp2s.ZK, the two-sided chi-square tail with 15 df. X = 46.17, FIPS's upper bound,
	// lands at Burp's 1e-4 threshold once doubled.
	q := chiSquareUpperTail(46.17, 15)
	if !(q > 3e-5 && q < 1e-4) {
		t.Errorf("chi2(15) tail at 46.17 = %g, want ≈5e-5 — the FIPS bound sits at Burp's 1e-4 two-sided threshold", q)
	}
}

func columnWithOnes(n, ones int) []byte {
	col := make([]byte, n)
	// Spread the ones so runs and nibbles stay unremarkable; only the count matters to monobit.
	for i := 0; i < ones; i++ {
		col[i*n/ones] = 1
	}
	return col
}

// At N=20,000 the FIPS intervals apply as written: 9725 and 10275 fail, one inside each passes.
func Test_monobit_uses_the_fips_interval_at_20000(t *testing.T) {
	d := &positionDistributions{n: BlockBits, binomCDF: binomialHalfCDF(BlockBits), longTail: map[int]float64{}}
	for i := range d.runs {
		d.runs[i] = newDiscreteDist(0, []float64{1})
	}
	for _, c := range []struct {
		ones int
		ok   bool
	}{{9725, false}, {9726, true}, {10274, true}, {10275, false}} {
		if got := d.positionResult(columnWithOnes(BlockBits, c.ones)).monobitOK; got != c.ok {
			t.Errorf("N=20000 ones=%d: pass=%v, want %v", c.ones, got, c.ok)
		}
	}
	// Long run: 25 passes, 26 fails, whatever the significance says.
	for _, c := range []struct {
		run int
		ok  bool
	}{{25, true}, {26, false}} {
		col := make([]byte, BlockBits)
		for i := range col {
			col[i] = byte(i % 2)
		}
		// Exactly c.run ones, fenced by zeros so the alternating neighbours cannot extend it.
		col[1000] = 0
		for i := 0; i < c.run; i++ {
			col[1001+i] = 1
		}
		col[1001+c.run] = 0
		if got := d.positionResult(col); got.longest != c.run || got.longRunOK != c.ok {
			t.Errorf("N=20000 longest run %d: got longest %d pass=%v, want pass=%v", c.run, got.longest, got.longRunOK, c.ok)
		}
	}
}

// Away from 20,000 the verdict is the significance against Burp's threshold. The edge sits where
// 2·P(X <= k) crosses 1e-4, and the verdicts flip exactly there.
func Test_monobit_uses_the_significance_threshold_away_from_20000(t *testing.T) {
	const n = 100
	d := newPositionDistributions(n)
	edge := -1
	for k := 0; k < n/2; k++ {
		if 2*d.binomCDF[k] > 1e-4 {
			edge = k
			break
		}
	}
	if edge < 0 {
		t.Fatal("no threshold crossing found")
	}
	if got := d.positionResult(columnWithOnes(n, edge-1)); got.monobitOK || !(got.monobitP <= 1e-4) {
		t.Errorf("ones=%d (p=%g): passed, want fail", edge-1, got.monobitP)
	}
	if got := d.positionResult(columnWithOnes(n, edge)); !got.monobitOK || !(got.monobitP > 1e-4) {
		t.Errorf("ones=%d (p=%g): failed, want pass", edge, got.monobitP)
	}
	// Symmetric: too many ones fails as too few does.
	if got := d.positionResult(columnWithOnes(n, n-edge+1)); got.monobitOK {
		t.Errorf("ones=%d: passed, want fail", n-edge+1)
	}
}

// The long-run test only fails on a run that is too long. An alternating column, whose longest
// run is 1, passes long run and fails runs.
func Test_a_short_longest_run_passes_and_alternation_fails_runs(t *testing.T) {
	const n = 1000
	d := newPositionDistributions(n)
	col := make([]byte, n)
	for i := range col {
		col[i] = byte(i % 2)
	}
	r := d.positionResult(col)
	if !r.longRunOK || r.longest != 1 || r.longRunP != 1 {
		t.Errorf("alternating column: longest %d p=%g pass=%v, want 1, 1, true", r.longest, r.longRunP, r.longRunOK)
	}
	if r.runsOK || r.runsP != significanceFloor {
		t.Errorf("alternating column: runs pass=%v p=%g, want a floored failure", r.runsOK, r.runsP)
	}
	if !r.monobitOK {
		t.Errorf("alternating column has exactly n/2 ones and must pass monobit (p=%g)", r.monobitP)
	}
}

func randomHexTokens(seed int64, count, chars int) []string {
	rng := rand.New(rand.NewSource(seed))
	tokens := make([]string, count)
	const hexDigits = "0123456789abcdef"
	for i := range tokens {
		var b strings.Builder
		for j := 0; j < chars; j++ {
			b.WriteByte(hexDigits[rng.Intn(16)])
		}
		tokens[i] = b.String()
	}
	return tokens
}

// A stuck bit fails at its position and nowhere else. The first hex digit is pinned to '0', so bits 0-3
// are constant and every other bit is random.
func Test_a_stuck_field_fails_at_exactly_its_positions(t *testing.T) {
	tokens := randomHexTokens(7, 500, 16)
	for i := range tokens {
		tokens[i] = "0" + tokens[i][1:]
	}
	r := AnalyseFipsPositions(tokens, EncodingHex, nil)
	if !r.Computed || r.PositionsExamined != 64 || r.ExactIntervals {
		t.Fatalf("computed=%v positions=%d exact=%v (reason %q)", r.Computed, r.PositionsExamined, r.ExactIntervals, r.Reason)
	}
	byID := map[string]FipsPositionTest{}
	for _, test := range r.Tests {
		byID[test.ID] = test
	}
	for _, id := range []string{"monobit", "long_runs"} {
		if got := fmt.Sprint(byID[id].FailingPositions); got != "[0 1 2 3]" {
			t.Errorf("%s failing positions = %s, want [0 1 2 3]", id, got)
		}
	}
	mono := byID["monobit"]
	if mono.Significance[0] != significanceFloor || mono.Statistic[0] != 0 {
		t.Errorf("stuck bit 0: significance %g ones %g, want the floor and 0", mono.Significance[0], mono.Statistic[0])
	}
	if mono.PositionsPassed != 60 || mono.PositionsFailed != 4 {
		t.Errorf("monobit passed/failed = %d/%d, want 60/4", mono.PositionsPassed, mono.PositionsFailed)
	}
	if !near(mono.PassLevel, 2, 1e-12) || !near(byID["runs"].PassLevel, 6+math.Log10(1.8e-5), 1e-12) {
		t.Errorf("pass levels %g / %g, want 6+log10(threshold)", mono.PassLevel, byID["runs"].PassLevel)
	}
}

func Test_fips_positions_marshal_as_arrays_never_null(t *testing.T) {
	short := AnalyseFipsPositions(randomHexTokens(1, 99, 8), EncodingHex, nil)
	raw, _ := json.Marshal(short)
	if short.Computed || !strings.Contains(string(raw), `"tests":[]`) || !strings.Contains(short.Reason, "at least 100") {
		t.Errorf("99 tokens: %s", raw)
	}
	off := AnalyseFipsPositions(randomHexTokens(1, 200, 8), EncodingHex, []string{"poker"})
	raw, _ = json.Marshal(off)
	var got struct {
		Tests []map[string]json.RawMessage `json:"tests"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tests) != 4 {
		t.Fatalf("a switched-off test was dropped: %d tests", len(got.Tests))
	}
	for _, test := range got.Tests {
		if string(test["id"]) != `"poker"` {
			continue
		}
		if string(test["disabled"]) != "true" {
			t.Errorf("poker not marked disabled: %s", test["disabled"])
		}
		for _, field := range []string{"statistic", "significance", "passed", "failing_positions"} {
			if string(test[field]) != "[]" {
				t.Errorf("disabled poker %s = %s, want []", field, test[field])
			}
		}
	}
}

// Tokens past 20,000 are not analysed, and the report counts them.
func Test_fips_positions_cap_the_sample_at_20000(t *testing.T) {
	tokens := randomHexTokens(3, BlockBits+5, 1)
	r := AnalyseFipsPositions(tokens, EncodingHex, nil)
	if r.Tokens != BlockBits || r.TokensNotAnalysed != 5 || !r.ExactIntervals {
		t.Errorf("tokens %d not-analysed %d exact %v", r.Tokens, r.TokensNotAnalysed, r.ExactIntervals)
	}
	for _, test := range r.Tests {
		if test.PositionsFailed != 0 {
			t.Errorf("%s failed at %v on a random sample of 20000", test.ID, test.FailingPositions)
		}
	}
}

// FIPS's sixth run bucket is "6 or more", not "exactly 6". Burp scores it with its length-5 table,
// which the comment in fips_position.go records. The two distributions differ by about 2x in mean
// (≈n/128 against ≈n/256), so a mis-wired bucket moves every position's runs verdict.
func Test_the_sixth_run_bucket_is_six_or_more(t *testing.T) {
	const n = 1000
	d := newPositionDistributions(n)
	atLeast, exactly := runCountDistribution(n, 6, true), runCountDistribution(n, 6, false)
	for _, c := range []int{0, 4, 8, 16} {
		if got, want := d.runs[5].twoSided(c), atLeast.twoSided(c); got != want {
			t.Errorf("bucket 6+ at count %d: %g, want the at-least distribution's %g", c, got, want)
		}
	}
	if atLeast.twoSided(16) == exactly.twoSided(16) {
		t.Fatal("the two distributions coincide at 16, so this test cannot tell them apart")
	}
}
