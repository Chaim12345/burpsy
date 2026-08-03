package sequencer

// The four FIPS 140-2 statistical RNG tests, ported to the letter of
// crates/sequencer/src/fips.rs (which itself follows FIPS PUB 140-2 §4.9.1,
// "Power-Up Tests", subsection *Statistical random number generator tests*).
//
// Every test is specified on a single 20,000-bit sample. The pass intervals below
// are the 140-2 numbers (not the looser 140-1 set, which would be the classic way
// to get this wrong):
//
//	Monobit    9_725 < ones < 10_275
//	Poker      2.16 < X < 46.17
//	Long runs  no run of length >= 26
//
// Because every interval is a function of the 20,000-bit sample size, the stream is
// cut into whole 20,000-bit blocks, each is tested exactly as specified, and the
// leftover bits are reported as untested rather than folded in. Fewer than one whole
// block yields no verdict at all (Tests is nil): a pass is not a proof of randomness,
// and a failure is strong evidence of the absence of it, but a verdict printed from
// thresholds that do not apply would be a confidently-wrong number.
//
// Stated honestly: FIPS 140-2 Change Notice 2 struck the statistical tests from the
// mandatory power-up self-test list in 2002. What they remain is the standard, cheap,
// widely-understood battery for "is this token generator obviously broken", which is
// the use Burp's Sequencer puts them to.

import (
	"encoding/json"
	"fmt"
	"math"
)

// BlockBits is the sample size every FIPS 140-2 statistical test is defined on.
// Not a tunable.
const BlockBits = 20000

// Monobit: 9_725 < ones < 10_275 (FIPS 140-2 §4.9.1).
const monobitLow = 9725
const monobitHigh = 10275

// Poker: 2.16 < X < 46.17 (FIPS 140-2 §4.9.1).
const pokerLow = 2.16
const pokerHigh = 46.17

// Poker's 4-bit segments: 20,000 / 4.
const pokerSegments = BlockBits / 4

// Long runs: a run of 26 or more bits of the same value fails (FIPS 140-2 §4.9.1).
const longRunBits = 26

// Runs test intervals for run lengths 1..=6, where 6 means "6 or more". All twelve
// counts — six lengths for zeros and six for ones — must fall inside their interval.
var runIntervals = [6][2]int{
	{2315, 2685},
	{1114, 1386},
	{527, 723},
	{240, 384},
	{103, 209},
	{103, 209},
}

// Encoding is how a bit stream was derived from the captured token bytes.
//
// This matters more than it looks. A 32-character hex session id carries at most 128
// bits, but its *ASCII* form is 256 bits in which bit 7 of every byte is always 0 and
// bit 6 is fixed across the digit range — so running FIPS over the characters
// guarantees a spectacular failure that says nothing whatever about the generator,
// only about hex. Reporting that as a randomness verdict would be precisely the kind
// of confidently-wrong number this project refuses to print, so the encoding is
// detected, decoded, and named in the report.
type Encoding int

const (
	// EncodingRaw is the token bytes as they stand, 8 bits per byte. Right for a
	// genuinely binary token.
	EncodingRaw Encoding = iota
	// EncodingHex is hex digits, 4 bits per character. Case-insensitive.
	EncodingHex
	// EncodingBase64 is base64 (standard or URL alphabet), 6 bits per character.
	// `=` padding is dropped.
	EncodingBase64
)

func (e Encoding) String() string {
	switch e {
	case EncodingHex:
		return "hex"
	case EncodingBase64:
		return "base64"
	default:
		return "raw"
	}
}

func (e Encoding) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

// DetectEncoding picks the narrowest encoding every token fits, so the bit stream
// carries signal rather than the alphabet's padding. Falls back to EncodingRaw,
// which always applies. An empty token set cannot know an encoding, so it too
// reports raw.
func DetectEncoding(tokens []string) Encoding {
	if len(tokens) == 0 {
		return EncodingRaw
	}
	allHex, allB64 := true, true
	for _, t := range tokens {
		if t == "" {
			// An empty token fits no alphabet; raw is the only honest answer.
			allHex, allB64 = false, false
			break
		}
		for i := 0; i < len(t); i++ {
			b := t[i]
			if !isHexDigit(b) {
				allHex = false
			}
			if !isBase64Byte(b) {
				allB64 = false
			}
			if !allHex && !allB64 {
				break
			}
		}
		if !allHex && !allB64 {
			break
		}
	}
	if allHex {
		return EncodingHex
	}
	if allB64 {
		return EncodingBase64
	}
	return EncodingRaw
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isBase64Byte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		b == '+' || b == '/' || b == '-' || b == '_' || b == '='
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func base64Value(b byte) (byte, bool) {
	switch {
	case b >= 'A' && b <= 'Z':
		return b - 'A', true
	case b >= 'a' && b <= 'z':
		return b - 'a' + 26, true
	case b >= '0' && b <= '9':
		return b - '0' + 52, true
	case b == '+' || b == '-':
		return 62, true
	case b == '/' || b == '_':
		return 63, true
	}
	return 0, false
}

// BitsOf concatenates every token into one bit stream under encoding.
//
// Bit order for EncodingRaw is most-significant-first within each byte, which is the
// conventional textbook and network order and is stated here so the numbers in a
// report can be reproduced by hand. Characters that do not belong to the chosen
// alphabet are skipped rather than mapped to zero: inventing bits would move the
// statistic.
func BitsOf(tokens []string, encoding Encoding) []byte {
	per := 8
	switch encoding {
	case EncodingHex:
		per = 4
	case EncodingBase64:
		per = 6
	}
	total := 0
	for _, t := range tokens {
		total += len(t)
	}
	out := make([]byte, 0, total*per)
	for _, t := range tokens {
		for i := 0; i < len(t); i++ {
			var value byte
			var width byte
			switch encoding {
			case EncodingRaw:
				value, width = t[i], 8
			case EncodingHex:
				v, ok := hexValue(t[i])
				if !ok {
					continue
				}
				value, width = v, 4
			case EncodingBase64:
				v, ok := base64Value(t[i])
				if !ok {
					continue
				}
				value, width = v, 6
			}
			for shift := width; shift > 0; shift-- {
				out = append(out, (value>>(shift-1))&1)
			}
		}
	}
	return out
}

// BitStats is statistics over the whole supplied stream, whatever its length.
//
// Reported unconditionally and deliberately kept apart from FipsReport: these are
// descriptive and always meaningful, whereas a FIPS *verdict* is only meaningful on
// a whole 20,000-bit block. Mixing the two would let a 300-bit sample look like it
// had been tested.
type BitStats struct {
	Bits       int     `json:"bits"`
	Ones       int     `json:"ones"`
	Zeros      int     `json:"zeros"`
	BitEntropy float64 `json:"bit_entropy"`
	LongestRun int     `json:"longest_run"`
	RunsZeros  [6]int  `json:"runs_zeros"`
	RunsOnes   [6]int  `json:"runs_ones"`
}

// BitStatsOf computes descriptive statistics over a bit stream.
func BitStatsOf(bits []byte) BitStats {
	ones := 0
	for _, b := range bits {
		if b == 1 {
			ones++
		}
	}
	runsZeros, runsOnes, longest := runHistogram(bits)
	return BitStats{
		Bits:       len(bits),
		Ones:       ones,
		Zeros:      len(bits) - ones,
		BitEntropy: binaryEntropy(ones, len(bits)),
		LongestRun: longest,
		RunsZeros:  runsZeros,
		RunsOnes:   runsOnes,
	}
}

func binaryEntropy(ones, total int) float64 {
	if total == 0 || ones == 0 || ones == total {
		return 0
	}
	p := float64(ones) / float64(total)
	q := 1 - p
	return -(p*math.Log2(p) + q*math.Log2(q))
}

// runHistogram counts runs of each length for zeros and ones, plus the longest run
// seen. A run is a maximal sequence of equal bits. Lengths above 6 are counted in the
// length-6 bucket, as the spec directs — the *longest* run is returned separately
// because the long-runs test needs the true length, and clamping it into the bucket
// would lose exactly the information that test asks for.
func runHistogram(bits []byte) (zeros, ones [6]int, longest int) {
	i := 0
	for i < len(bits) {
		value := bits[i]
		start := i
		for i < len(bits) && bits[i] == value {
			i++
		}
		length := i - start
		if length > longest {
			longest = length
		}
		bucket := length - 1
		if bucket > 5 {
			bucket = 5
		}
		if value == 1 {
			ones[bucket]++
		} else {
			zeros[bucket]++
		}
	}
	return zeros, ones, longest
}

// FipsTest is one of the four tests, aggregated over every block that was run.
type FipsTest struct {
	// ID is "monobit" | "poker" | "runs" | "long_runs".
	ID string `json:"id"`
	// Name is the human name of the test.
	Name string `json:"name"`
	// Spec is the spec section this comes from, so a reader can check the
	// constants against the source.
	Spec string `json:"spec"`
	// Requirement is the pass condition, spelled out with its constants.
	Requirement string `json:"requirement"`
	// Passed is true only when every block passed. A suite that passed 9 blocks
	// and failed 1 has not passed.
	Passed       bool `json:"passed"`
	BlocksPassed int  `json:"blocks_passed"`
	BlocksFailed int  `json:"blocks_failed"`
	// Observed is what was actually measured: the first failing block's statistic,
	// or the first block's when none failed. A bare pass/fail with no number is
	// not something an operator can check.
	Observed string `json:"observed"`
}

// FipsReport is the suite's outcome over the supplied stream.
type FipsReport struct {
	BitsSupplied int `json:"bits_supplied"`
	// BitsTested is blocks_tested * 20,000.
	BitsTested int `json:"bits_tested"`
	// BitsUntested is the tail that did not fill a block. Reported, never folded
	// into a block.
	BitsUntested int `json:"bits_untested"`
	BlocksTested int `json:"blocks_tested"`
	// BlockBits is the block size the tests are defined on, echoed so the report
	// is self-describing.
	BlockBits int `json:"block_bits"`
	// Tests is nil when not one whole block was supplied — the honest answer in
	// that case is "not tested", not a verdict computed from thresholds that do
	// not apply. Marshals to JSON null, matching the UI's `tests: FipsTest[] | null`.
	Tests []FipsTest `json:"tests"`
}

// Passed is true when every test in an applicable suite passed. Nil when the suite
// did not run.
func (r FipsReport) Passed() *bool {
	if r.Tests == nil {
		return nil
	}
	passed := true
	for _, t := range r.Tests {
		if !t.Passed {
			passed = false
			break
		}
	}
	return &passed
}

// Failures returns the human names of the tests that failed. Empty when the suite
// passed or did not run.
func (r FipsReport) Failures() []string {
	if r.Tests == nil {
		return nil
	}
	var out []string
	for _, t := range r.Tests {
		if !t.Passed {
			out = append(out, t.Name)
		}
	}
	return out
}

// blockResult is one block's four results, as raw numbers.
type blockResult struct {
	monobitOnes int
	pokerX      float64
	runsZeros   [6]int
	runsOnes    [6]int
	longestRun  int
}

func (b blockResult) monobitOK() bool {
	return b.monobitOnes > monobitLow && b.monobitOnes < monobitHigh
}

func (b blockResult) pokerOK() bool {
	return b.pokerX > pokerLow && b.pokerX < pokerHigh
}

func (b blockResult) runsOK() bool {
	return b.failingRun() == nil
}

func (b blockResult) longRunsOK() bool {
	return b.longestRun < longRunBits
}

// runFailure names the first run bucket outside its interval.
type runFailure struct {
	value  byte
	length int
	count  int
	lo     int
	hi     int
}

func (b blockResult) failingRun() *runFailure {
	for i, interval := range runIntervals {
		for _, vc := range []struct {
			value  byte
			counts *[6]int
		}{{0, &b.runsZeros}, {1, &b.runsOnes}} {
			count := vc.counts[i]
			if count < interval[0] || count > interval[1] {
				return &runFailure{value: vc.value, length: i + 1, count: count, lo: interval[0], hi: interval[1]}
			}
		}
	}
	return nil
}

// monobit test (FIPS 140-2 §4.9.1): count the ones in the 20,000-bit block.
func monobit(block []byte) int {
	ones := 0
	for _, b := range block {
		if b == 1 {
			ones++
		}
	}
	return ones
}

// poker test (FIPS 140-2 §4.9.1).
//
// Divide the 20,000 bits into 5,000 contiguous 4-bit segments, count the occurrences
// f(i) of each of the 16 possible values, and evaluate
//
//	X = (16 / 5000) * Σ f(i)² - 5000
//
// The interval is two-sided: a stream whose sixteen nibble values are *too* evenly
// spread fails the lower bound, because a real random source does not distribute that
// neatly.
func poker(block []byte) float64 {
	var f [16]int
	for i := 0; i+3 < len(block); i += 4 {
		v := int(block[i])<<3 | int(block[i+1])<<2 | int(block[i+2])<<1 | int(block[i+3])
		f[v]++
	}
	sumSquares := 0
	for _, c := range f {
		sumSquares += c * c
	}
	return (16.0/float64(pokerSegments))*float64(sumSquares) - float64(pokerSegments)
}

func testBlock(block []byte) blockResult {
	runsZeros, runsOnes, longest := runHistogram(block)
	return blockResult{
		monobitOnes: monobit(block),
		pokerX:      poker(block),
		runsZeros:   runsZeros,
		runsOnes:    runsOnes,
		longestRun:  longest,
	}
}

// AnalyseFipsBits runs the suite over bits, in whole 20,000-bit blocks.
func AnalyseFipsBits(bits []byte) FipsReport {
	blockCount := len(bits) / BlockBits
	blocks := make([]blockResult, 0, blockCount)
	for i := 0; i < blockCount; i++ {
		blocks = append(blocks, testBlock(bits[i*BlockBits:(i+1)*BlockBits]))
	}
	report := FipsReport{
		BitsSupplied: len(bits),
		BitsTested:   blockCount * BlockBits,
		BitsUntested: len(bits) - blockCount*BlockBits,
		BlocksTested: blockCount,
		BlockBits:    BlockBits,
		Tests:        nil,
	}
	if len(blocks) == 0 {
		return report
	}

	monobitTest := aggregate(
		"monobit",
		"Monobit Test",
		"FIPS 140-2 \u00a74.9.1",
		"9725 < ones < 10275 per 20000-bit block",
		blocks,
		blockResult.monobitOK,
		func(b blockResult) string { return fmt.Sprintf("%d ones in 20000 bits", b.monobitOnes) },
	)
	pokerTest := aggregate(
		"poker",
		"Poker Test",
		"FIPS 140-2 \u00a74.9.1",
		"2.16 < X < 46.17, X = (16/5000)\u00b7\u03a3f(i)\u00b2 - 5000",
		blocks,
		blockResult.pokerOK,
		func(b blockResult) string { return fmt.Sprintf("X = %.4f", b.pokerX) },
	)
	runsTest := aggregate(
		"runs",
		"Runs Test",
		"FIPS 140-2 \u00a74.9.1",
		"runs of length 1..6 within 2315-2685, 1114-1386, 527-723, 240-384, 103-209, 103-209 for both zeros and ones",
		blocks,
		blockResult.runsOK,
		func(b blockResult) string {
			if f := b.failingRun(); f != nil {
				value := "zero"
				if f.value == 1 {
					value = "one"
				}
				return fmt.Sprintf("%d runs of %d %s(s) \u2014 outside %d-%d", f.count, f.length, value, f.lo, f.hi)
			}
			return fmt.Sprintf("zeros %v, ones %v for lengths 1..6", b.runsZeros, b.runsOnes)
		},
	)
	longRunsTest := aggregate(
		"long_runs",
		"Long Runs Test",
		"FIPS 140-2 \u00a74.9.1",
		"no run of length 26 or more",
		blocks,
		blockResult.longRunsOK,
		func(b blockResult) string { return fmt.Sprintf("longest run %d bits", b.longestRun) },
	)

	report.Tests = []FipsTest{monobitTest, pokerTest, runsTest, longRunsTest}
	return report
}

// AnalyseFips is AnalyseFipsBits for a token list: the encoding is detected first, so
// hex session ids are decoded to 4 bits a character rather than libelled as ASCII.
func AnalyseFips(tokens []string) FipsReport {
	return AnalyseFipsBits(BitsOf(tokens, DetectEncoding(tokens)))
}

// aggregate collapses one test across blocks. It reports the first *failing* block's
// numbers where there is one, because "which block broke and by how much" is the only
// useful thing to show next to a failure.
func aggregate(
	id, name, spec, requirement string,
	blocks []blockResult,
	ok func(blockResult) bool,
	describe func(blockResult) string,
) FipsTest {
	blocksPassed := 0
	var failing *blockResult
	for i := range blocks {
		if ok(blocks[i]) {
			blocksPassed++
		} else if failing == nil {
			failing = &blocks[i]
		}
	}
	blocksFailed := len(blocks) - blocksPassed
	shown := blocks[0]
	if failing != nil {
		shown = *failing
	}
	return FipsTest{
		ID:           id,
		Name:         name,
		Spec:         spec,
		Requirement:  requirement,
		Passed:       blocksFailed == 0,
		BlocksPassed: blocksPassed,
		BlocksFailed: blocksFailed,
		Observed:     describe(shown),
	}
}
