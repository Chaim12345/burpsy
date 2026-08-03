package sequencer

// FIPS 140-2 suite tests, mirroring crates/sequencer/src/fips.rs.
//
// Every reference figure here was computed independently (in Python, per the Rust
// crate's own documentation) from the same xorshift64* definition below before the
// Rust implementation existed. Agreement here is therefore evidence that the Go port
// matches the Rust behaviour, not that the Go port is self-consistent.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
)

// xorshift64* — the same generator the Rust known-answer tests use, reimplemented
// so the reference values can be recomputed from scratch in any language.
// Big-endian bytes of each 64-bit output.
func xorshift64star(seed uint64, nbytes int) []byte {
	x := seed
	out := make([]byte, 0, nbytes+8)
	for len(out) < nbytes {
		x ^= x >> 12
		x ^= x << 25
		x ^= x >> 27
		val := x * 0x2545F4914F6CDD1D
		out = append(out,
			byte(val>>56), byte(val>>48), byte(val>>40), byte(val>>32),
			byte(val>>24), byte(val>>16), byte(val>>8), byte(val),
		)
	}
	return out[:nbytes]
}

func alternatingBits() []byte {
	bits := make([]byte, BlockBits)
	for i := range bits {
		bits[i] = byte(i % 2)
	}
	return bits
}

// 5,000 nibbles cycling 0,1,…,15. Every 4-bit value appears 312 or 313 times — a
// *perfectly* even spread, which is why it fails the poker test's lower bound.
func uniformNibbles() []byte {
	bits := make([]byte, 0, BlockBits)
	for k := 0; k < BlockBits/4; k++ {
		v := byte(k % 16)
		bits = append(bits, (v>>3)&1, (v>>2)&1, (v>>1)&1, v&1)
	}
	return bits
}

// blockWithOnes is a 20,000-bit block with the first n bits set to one and the rest
// zero — a construction for pinning the exact monobit thresholds.
func blockWithOnes(ones int) []byte {
	bits := make([]byte, BlockBits)
	for i := 0; i < ones; i++ {
		bits[i] = 1
	}
	return bits
}

func allZero(bits []byte) bool {
	for _, b := range bits {
		if b != 0 {
			return false
		}
	}
	return true
}

func allOne(bits []byte) bool {
	for _, b := range bits {
		if b != 1 {
			return false
		}
	}
	return true
}

// ---- the known-answer test ----------------------------------------------------------------

// Reference for xorshift64* seed 1, 2,500 bytes = 20,000 bits:
//
//	first bytes 71,228,206,75,137,108,221,29 · ones 9,956 · Σf(i)² = 1,566,958 → X = 14.2656
//	run lengths 1..6, zeros [2491,1281,598,297,166,167] ones [2517,1282,587,302,151,161]
//	longest run 18 · 10,000 runs in total
func TestReferenceStreamMatchesIndependentlyComputedValues(t *testing.T) {
	stream := xorshift64star(1, 2500)
	if !bytes.Equal(stream[:8], []byte{71, 228, 206, 75, 137, 108, 221, 29}) {
		t.Fatalf("the PRNG itself drifted, so nothing below would mean anything: %v", stream[:8])
	}
	bits := BitsOf([]string{string(stream)}, EncodingRaw)
	if len(bits) != BlockBits {
		t.Fatalf("bits = %d, want %d", len(bits), BlockBits)
	}

	stats := BitStatsOf(bits)
	if stats.Ones != 9956 {
		t.Errorf("monobit count must match the reference: got %d", stats.Ones)
	}
	if stats.RunsZeros != [6]int{2491, 1281, 598, 297, 166, 167} {
		t.Errorf("runs zeros = %v, want [2491 1281 598 297 166 167]", stats.RunsZeros)
	}
	if stats.RunsOnes != [6]int{2517, 1282, 587, 302, 151, 161} {
		t.Errorf("runs ones = %v, want [2517 1282 587 302 151 161]", stats.RunsOnes)
	}
	if stats.LongestRun != 18 {
		t.Errorf("longest run = %d, want 18", stats.LongestRun)
	}
	sum := 0
	for i := 0; i < 6; i++ {
		sum += stats.RunsZeros[i] + stats.RunsOnes[i]
	}
	if sum != 10000 {
		t.Errorf("every run must be counted exactly once: total %d, want 10000", sum)
	}

	report := AnalyseFipsBits(bits)
	if report.BlocksTested != 1 {
		t.Errorf("blocks = %d, want 1", report.BlocksTested)
	}
	if report.BitsUntested != 0 {
		t.Errorf("untested = %d, want 0", report.BitsUntested)
	}
	if got := report.Tests[1].Observed; got != "X = 14.2656" {
		t.Errorf("poker X = %q, want %q", got, "X = 14.2656")
	}
	if p := report.Passed(); p == nil || !*p {
		t.Errorf("a decent PRNG must pass all four: %v", report.Failures())
	}
}

// ---- independence of the four tests --------------------------------------------------------

// An alternating stream has a *perfect* ones count and is as far from random as a stream
// can be. This is the pair of vectors that prove the tests are independent rather than
// four names for one check.
func TestAlternatingStreamPassesMonobitAndFailsTheRest(t *testing.T) {
	bits := alternatingBits()
	stats := BitStatsOf(bits)
	if stats.Ones != 10000 {
		t.Errorf("ones = %d, want exactly 10000", stats.Ones)
	}
	if stats.RunsZeros != [6]int{10000, 0, 0, 0, 0, 0} {
		t.Errorf("runs zeros = %v", stats.RunsZeros)
	}
	if stats.RunsOnes != [6]int{10000, 0, 0, 0, 0, 0} {
		t.Errorf("runs ones = %v", stats.RunsOnes)
	}
	if stats.LongestRun != 1 {
		t.Errorf("longest run = %d, want 1", stats.LongestRun)
	}

	report := AnalyseFipsBits(bits)
	if !report.Tests[0].Passed {
		t.Errorf("10000 ones is dead centre and must pass monobit")
	}
	if report.Tests[1].Passed {
		t.Errorf("alternating must fail poker")
	}
	if got := report.Tests[1].Observed; got != "X = 75000.0000" {
		t.Errorf("poker X = %q, want %q", got, "X = 75000.0000")
	}
	if report.Tests[2].Passed {
		t.Errorf("alternating must fail runs")
	}
	if got := report.Tests[2].Observed; got != "10000 runs of 1 zero(s) \u2014 outside 2315-2685" {
		t.Errorf("runs observed = %q", got)
	}
	if !report.Tests[3].Passed {
		t.Errorf("no run reaches 26, so long-runs genuinely passes here")
	}
	if got := report.Tests[3].Observed; got != "longest run 1 bits" {
		t.Errorf("long-runs observed = %q", got)
	}
	if p := report.Passed(); p == nil || *p {
		t.Errorf("the suite must fail")
	}
	if got := report.Failures(); len(got) != 2 || got[0] != "Poker Test" || got[1] != "Runs Test" {
		t.Errorf("failures = %v, want [Poker Test Runs Test]", got)
	}
}

// ---- poker: the two-sided interval ----------------------------------------------------------

func TestPokerIntervalIsTwoSided(t *testing.T) {
	cases := []struct {
		name         string
		bits         func() []byte
		wantObserved string
		wantPassed   bool
	}{
		{
			name:         "uniform nibbles fail the lower bound",
			bits:         uniformNibbles,
			wantObserved: "X = 0.0128",
			wantPassed:   false,
		},
		{
			name:         "alternating fails the upper bound",
			bits:         alternatingBits,
			wantObserved: "X = 75000.0000",
			wantPassed:   false,
		},
		{
			name: "reference stream passes",
			bits: func() []byte {
				return BitsOf([]string{string(xorshift64star(1, 2500))}, EncodingRaw)
			},
			wantObserved: "X = 14.2656",
			wantPassed:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := AnalyseFipsBits(tc.bits())
			poker := report.Tests[1]
			if poker.Observed != tc.wantObserved {
				t.Errorf("observed = %q, want %q", poker.Observed, tc.wantObserved)
			}
			if poker.Passed != tc.wantPassed {
				t.Errorf("passed = %v, want %v", poker.Passed, tc.wantPassed)
			}
		})
	}
}

// The poker vector whose sixteen nibble counts are 313×8 and 312×8 gives
// X = (16·1,562,504 − 25,000,000)/5,000 = 64/5,000 = 0.0128 — exact rational
// arithmetic, so this is a true known answer rather than a tolerance check.
func TestTooEvenNibbleSpreadStillPassesMonobit(t *testing.T) {
	stats := BitStatsOf(uniformNibbles())
	if stats.Ones != 9996 {
		t.Errorf("popcount 0..15 is 32 per cycle, so this passes monobit: got %d, want 9996", stats.Ones)
	}
	report := AnalyseFipsBits(uniformNibbles())
	if !report.Tests[0].Passed {
		t.Errorf("9996 ones must pass monobit")
	}
	if report.Tests[1].Passed {
		t.Errorf("0.0128 is below the 2.16 floor: too uniform to be random")
	}
}

// ---- pass/fail boundaries -------------------------------------------------------------------

// Monobit is `9725 < ones < 10275`, strict on both sides: 9725 fails, 9726 passes,
// 10274 passes, 10275 fails. An off-by-one here would be invisible on real data and
// wrong on the one case these tests exist for.
func TestMonobitBoundary(t *testing.T) {
	cases := []struct {
		name string
		ones int
		want bool
	}{
		{"9725 is not above the strict floor", 9725, false},
		{"9726 is inside", 9726, true},
		{"10000 is dead centre", 10000, true},
		{"10274 is inside", 10274, true},
		{"10275 is not below the strict ceiling", 10275, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := AnalyseFipsBits(blockWithOnes(tc.ones))
			if got := report.Tests[0].Passed; got != tc.want {
				t.Errorf("monobit passed = %v, want %v", got, tc.want)
			}
		})
	}
}

// Long runs fails at 26, not 25.
func TestLongRunBoundaryIsTwentySixNotTwentyFive(t *testing.T) {
	cases := []struct {
		name   string
		length int
		want   bool
	}{
		{"25 is not yet a long run", 25, true},
		{"26 is the failure threshold", 26, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bits := make([]byte, 0, BlockBits)
			for i := 0; i < tc.length; i++ {
				bits = append(bits, 1)
			}
			// Fill the rest with an alternating tail so nothing else produces a long run.
			for len(bits) < BlockBits {
				bits = append(bits, 0)
				if len(bits) < BlockBits {
					bits = append(bits, 1)
				}
			}
			report := AnalyseFipsBits(bits)
			if got := report.Tests[3].Passed; got != tc.want {
				t.Errorf("long-runs passed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConstantStreamFailsEveryTestIncludingLongRuns(t *testing.T) {
	bits := make([]byte, BlockBits)
	stats := BitStatsOf(bits)
	if stats.Ones != 0 {
		t.Errorf("ones = %d, want 0", stats.Ones)
	}
	if stats.LongestRun != BlockBits {
		t.Errorf("longest run = %d, want %d", stats.LongestRun, BlockBits)
	}
	report := AnalyseFipsBits(bits)
	if report.Tests[3].Passed {
		t.Errorf("a 20000-bit run must fail long-runs")
	}
	if got := len(report.Failures()); got != 4 {
		t.Errorf("all four must bite: %v", report.Failures())
	}
}

// ---- block accounting, honestly --------------------------------------------------------------

func TestSampleShorterThanOneBlockIsReportedUntestedRatherThanJudged(t *testing.T) {
	bits := make([]byte, BlockBits-1)
	for i := range bits {
		bits[i] = 1
	}
	report := AnalyseFipsBits(bits)
	if report.Tests != nil {
		t.Fatalf("19999 bits must not be judged against 20000-bit thresholds")
	}
	if p := report.Passed(); p != nil {
		t.Fatalf("passed() must be nil when no block ran, got %v", *p)
	}
	if report.BlocksTested != 0 {
		t.Errorf("blocks = %d, want 0", report.BlocksTested)
	}
	if report.BitsUntested != BlockBits-1 {
		t.Errorf("untested = %d, want %d", report.BitsUntested, BlockBits-1)
	}
	if got := report.Failures(); len(got) != 0 {
		t.Errorf("failures must be empty when nothing ran: %v", got)
	}
}

func TestLeftoverBitsBeyondTheLastWholeBlockAreReportedNotAbsorbed(t *testing.T) {
	stream := xorshift64star(7, 2500+13)
	bits := BitsOf([]string{string(stream)}, EncodingRaw)
	report := AnalyseFipsBits(bits)
	if report.BlocksTested != 1 {
		t.Errorf("blocks = %d, want 1", report.BlocksTested)
	}
	if report.BitsTested != BlockBits {
		t.Errorf("tested = %d, want %d", report.BitsTested, BlockBits)
	}
	if report.BitsUntested != 13*8 {
		t.Errorf("untested = %d, want %d", report.BitsUntested, 13*8)
	}
	if report.BitsSupplied != BlockBits+13*8 {
		t.Errorf("supplied = %d, want %d", report.BitsSupplied, BlockBits+13*8)
	}
}

func TestOneBadBlockAmongGoodOnesFailsTheSuiteAndNamesTheCount(t *testing.T) {
	bits := BitsOf([]string{string(xorshift64star(1, 2500))}, EncodingRaw)
	bits = append(bits, make([]byte, BlockBits)...)
	report := AnalyseFipsBits(bits)
	if report.BlocksTested != 2 {
		t.Errorf("blocks = %d, want 2", report.BlocksTested)
	}
	if p := report.Passed(); p == nil || *p {
		t.Errorf("one bad block must fail the suite")
	}
	mono := report.Tests[0]
	if mono.BlocksPassed != 1 || mono.BlocksFailed != 1 {
		t.Errorf("blocks passed/failed = %d/%d, want 1/1", mono.BlocksPassed, mono.BlocksFailed)
	}
	if !strings.Contains(mono.Observed, "0 ones") {
		t.Errorf("the failing block's numbers are what should be shown: %s", mono.Observed)
	}
}

// ---- encodings -------------------------------------------------------------------------------

func TestHexTokensAreDecodedToFourBitsACharacterRatherThanEight(t *testing.T) {
	tokens := []string{"00ff", "a5A5"}
	if DetectEncoding(tokens) != EncodingHex {
		t.Fatalf("detect = %v, want hex", DetectEncoding(tokens))
	}
	bits := BitsOf(tokens, EncodingHex)
	if len(bits) != 2*4*4 {
		t.Fatalf("two 4-character tokens at 4 bits per hex digit, not 8: got %d", len(bits))
	}
	if !allZero(bits[:8]) {
		t.Errorf(`"00" must be eight zero bits`)
	}
	if !allOne(bits[8:16]) {
		t.Errorf(`"ff" must be eight one bits`)
	}
	// 0xa5A5 -> 1010 0101 1010 0101, and the case of the digits must not matter.
	want := []byte{1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1}
	if !bytes.Equal(bits[16:], want) {
		t.Errorf("a5A5 = %v, want %v", bits[16:], want)
	}
}

// The reason the encoding step exists at all: the *same* tokens, read as hex, are the
// reference stream and pass all four tests; read as ASCII they fail monobit by more
// than a thousand — an artefact of hex, not of the generator.
func TestSameTokensPassDecodedAndFailAsAsciiWhichIsWhyEncodingIsDetected(t *testing.T) {
	stream := xorshift64star(1, 2500)
	tokens := make([]string, 250)
	var sb strings.Builder
	for i := 0; i < 250; i++ {
		sb.Reset()
		for j := 0; j < 10; j++ {
			fmt.Fprintf(&sb, "%02x", stream[i*10+j])
		}
		tokens[i] = sb.String()
	}
	if len(tokens) != 250 || len(tokens[0]) != 20 {
		t.Fatalf("expected 250 tokens of 20 characters")
	}
	if DetectEncoding(tokens) != EncodingHex {
		t.Fatalf("detect = %v, want hex", DetectEncoding(tokens))
	}

	hexBits := BitsOf(tokens, EncodingHex)
	if len(hexBits) != BlockBits {
		t.Fatalf("hex view must be exactly one block: %d", len(hexBits))
	}
	rawBits := BitsOf([]string{string(stream)}, EncodingRaw)
	if !bytes.Equal(hexBits, rawBits) {
		t.Errorf("hex-encoding bytes and decoding them again must be the identity on the bit stream")
	}
	if p := AnalyseFipsBits(hexBits).Passed(); p == nil || !*p {
		t.Errorf("decoded, this is the reference stream and must pass: %v", AnalyseFipsBits(hexBits).Failures())
	}

	asciiBits := BitsOf(tokens, EncodingRaw)
	if len(asciiBits) != BlockBits*2 {
		t.Fatalf("ASCII view is 40,000 bits, got %d", len(asciiBits))
	}
	for k := 0; k < len(asciiBits); k += 8 {
		if asciiBits[k] != 0 {
			t.Fatalf("the top bit of every ASCII byte is structurally zero — that is the whole problem")
		}
	}
	asAscii := AnalyseFipsBits(asciiBits)
	if asAscii.BlocksTested != 2 {
		t.Errorf("blocks = %d, want 2", asAscii.BlocksTested)
	}
	mono := asAscii.Tests[0]
	if mono.Passed {
		t.Errorf("both ASCII blocks must fail monobit")
	}
	if mono.BlocksFailed != 2 {
		t.Errorf("both ASCII blocks must fail, and for a reason about hex rather than randomness: got %d", mono.BlocksFailed)
	}
	if !strings.Contains(mono.Observed, "8698") {
		t.Errorf("the first failing block's real count belongs in the report: %s", mono.Observed)
	}
}

func TestBase64IsDetectedAndDecodedAtSixBitsACharacter(t *testing.T) {
	tokens := []string{"AAAA", "////", "a-_z"}
	if DetectEncoding(tokens) != EncodingBase64 {
		t.Fatalf("detect = %v, want base64", DetectEncoding(tokens))
	}
	zeros := BitsOf([]string{"AAAA"}, EncodingBase64)
	if len(zeros) != 24 {
		t.Errorf("len = %d, want 24", len(zeros))
	}
	if !allZero(zeros) {
		t.Errorf("'A' is value 0")
	}
	ones := BitsOf([]string{"////"}, EncodingBase64)
	if !allOne(ones) {
		t.Errorf("'/' is value 63")
	}
}

func TestNonAlphabetTokenFallsBackToRawBytes(t *testing.T) {
	tokens := []string{"tok=en!"}
	if DetectEncoding(tokens) != EncodingRaw {
		t.Fatalf("detect = %v, want raw", DetectEncoding(tokens))
	}
	if got := len(BitsOf(tokens, EncodingRaw)); got != 7*8 {
		t.Errorf("len = %d, want 56", got)
	}
}

func TestDetectionPrefersHexOverBase64WhenBothWouldFit(t *testing.T) {
	if DetectEncoding([]string{"deadbeef"}) != EncodingHex {
		t.Errorf("hex digits are also base64 characters, so the narrowest alphabet wins")
	}
}

func TestEmptyTokenSetDoesNotClaimAnEncodingItCannotKnow(t *testing.T) {
	if DetectEncoding(nil) != EncodingRaw {
		t.Errorf("empty set must not claim an encoding")
	}
	if got := len(BitsOf(nil, EncodingRaw)); got != 0 {
		t.Errorf("bits = %d, want 0", got)
	}
	report := AnalyseFipsBits(nil)
	if report.BlocksTested != 0 || report.Tests != nil {
		t.Errorf("empty bit stream must not be judged")
	}
}

// ---- token-list entry point ------------------------------------------------------------------

func TestAnalyseFipsOperatesOnATokenListDetectingTheEncoding(t *testing.T) {
	stream := xorshift64star(1, 2500)
	tokens := make([]string, 250)
	var sb strings.Builder
	for i := 0; i < 250; i++ {
		sb.Reset()
		for j := 0; j < 10; j++ {
			fmt.Fprintf(&sb, "%02x", stream[i*10+j])
		}
		tokens[i] = sb.String()
	}
	report := AnalyseFips(tokens)
	if report.BlocksTested != 1 {
		t.Errorf("blocks = %d, want 1", report.BlocksTested)
	}
	if p := report.Passed(); p == nil || !*p {
		t.Errorf("decoded hex tokens must pass: %v", report.Failures())
	}
}

// The UI declares the FipsTest/FipsReport wire shapes at
// internal/web/ui/src/sequencer.ts:55,66. This test pins the marshalled field names to
// exactly those shapes, so "the backend can satisfy the UI contract" is checkable
// rather than asserted in prose.
func TestFipsReportMarshalsToTheUIContract(t *testing.T) {
	report := AnalyseFipsBits(BitsOf([]string{string(xorshift64star(1, 2500))}, EncodingRaw))
	if report.Tests == nil {
		t.Fatalf("reference stream must produce a full suite")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := map[string]bool{
		"bits_supplied": true, "bits_tested": true, "bits_untested": true,
		"blocks_tested": true, "block_bits": true, "tests": true,
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(m) != len(want) {
		t.Errorf("report keys = %v, want exactly %v", sortedKeys(m), sortedKeysMap(want))
	}
	for k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("missing report key %q", k)
		}
	}

	var tests []map[string]json.RawMessage
	if err := json.Unmarshal(m["tests"], &tests); err != nil {
		t.Fatalf("unmarshal tests: %v", err)
	}
	if len(tests) != 4 {
		t.Fatalf("tests = %d, want 4", len(tests))
	}
	wantTest := map[string]bool{
		"id": true, "name": true, "spec": true, "requirement": true,
		"passed": true, "blocks_passed": true, "blocks_failed": true, "observed": true,
	}
	testRow := tests[0]
	if len(testRow) != len(wantTest) {
		t.Errorf("test keys = %v, want exactly %v", sortedKeys(testRow), sortedKeysMap(wantTest))
	}
	for k := range wantTest {
		if _, ok := testRow[k]; !ok {
			t.Errorf("missing test key %q", k)
		}
	}

	// An insufficient sample marshals tests as JSON null, not [].
	insufficient := AnalyseFipsBits(make([]byte, BlockBits-1))
	rawInsufficient, err := json.Marshal(insufficient)
	if err != nil {
		t.Fatalf("marshal insufficient: %v", err)
	}
	if !strings.Contains(string(rawInsufficient), `"tests":null`) {
		t.Errorf("insufficient report must marshal tests as null: %s", rawInsufficient)
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysMap(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- BitStats --------------------------------------------------------------------------------

func TestBitStatsDescribeAStreamOfAnyLengthWithoutPretendingItWasTested(t *testing.T) {
	cases := []struct {
		name          string
		bits          []byte
		wantBits      int
		wantOnes      int
		wantZeros     int
		wantLongest   int
		wantEntropy   float64
		wantRunsZeros [6]int
		wantRunsOnes  [6]int
	}{
		{
			name:          "one run of each length",
			bits:          []byte{1, 1, 1, 0, 0, 1},
			wantBits:      6,
			wantOnes:      4,
			wantZeros:     2,
			wantLongest:   3,
			wantEntropy:   0.9182958, // H(4/6)
			wantRunsZeros: [6]int{0, 1, 0, 0, 0, 0},
			wantRunsOnes:  [6]int{1, 0, 1, 0, 0, 0},
		},
		{
			name:         "a single constant run sits in its length bucket",
			bits:         []byte{1, 1, 1, 1},
			wantBits:     4,
			wantOnes:     4,
			wantZeros:    0,
			wantLongest:  4,
			wantEntropy:  0,
			wantRunsOnes: [6]int{0, 0, 0, 1, 0, 0},
		},
		{
			name:        "an empty stream is described as empty",
			bits:        nil,
			wantBits:    0,
			wantOnes:    0,
			wantZeros:   0,
			wantLongest: 0,
			wantEntropy: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stats := BitStatsOf(tc.bits)
			if stats.Bits != tc.wantBits || stats.Ones != tc.wantOnes || stats.Zeros != tc.wantZeros {
				t.Errorf("bits/ones/zeros = %d/%d/%d, want %d/%d/%d",
					stats.Bits, stats.Ones, stats.Zeros, tc.wantBits, tc.wantOnes, tc.wantZeros)
			}
			if stats.LongestRun != tc.wantLongest {
				t.Errorf("longest = %d, want %d", stats.LongestRun, tc.wantLongest)
			}
			if math.Abs(stats.BitEntropy-tc.wantEntropy) > 1e-6 {
				t.Errorf("bit entropy = %f, want %f", stats.BitEntropy, tc.wantEntropy)
			}
			if stats.RunsZeros != tc.wantRunsZeros {
				t.Errorf("runs zeros = %v, want %v", stats.RunsZeros, tc.wantRunsZeros)
			}
			if stats.RunsOnes != tc.wantRunsOnes {
				t.Errorf("runs ones = %v, want %v", stats.RunsOnes, tc.wantRunsOnes)
			}
		})
	}
}
