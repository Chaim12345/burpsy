package sequencer

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// hexTokens reproduces the helper in crates/sequencer/src/lib.rs: the same
// xorshift64* (same multiplier, top byte per step) written as lowercase hex,
// so a known-good 20,000-bit stream can be built in any test.
func hexTokens(seed uint64, count, bytesEach int) []string {
	x := seed
	out := make([]string, 0, count)
	for c := 0; c < count; c++ {
		var b strings.Builder
		for k := 0; k < bytesEach; k++ {
			x ^= x >> 12
			x ^= x << 25
			x ^= x >> 27
			byte := byte((x * 0x2545F4914F6CDD1D) >> 56)
			fmt.Fprintf(&b, "%02x", byte)
		}
		out = append(out, b.String())
	}
	return out
}

func TestPastedBlockBecomesOneTokenPerLineIgnoringBlanksAndPadding(t *testing.T) {
	got := TokensFromText("  abc123 \n\n\tdef456\r\n\n   \nghi789\n")
	want := []string{"abc123", "def456", "ghi789"}
	if len(got) != len(want) {
		t.Fatalf("tokens = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tokens = %q, want %q", got, want)
		}
	}
}

// An empty paste is answered, not refused: the report says "no tokens were
// supplied", and that is more useful to whoever pasted the wrong buffer than
// an error with no analysis in it.
func TestEmptyPasteYieldsNoTokensAndAReportThatSaysSo(t *testing.T) {
	if got := TokensFromText("   \n\n"); len(got) != 0 {
		t.Fatalf("TokensFromText(blank) = %q, want empty", got)
	}
	report := AnalyseReport(TokensFromText(""))
	if report.Tokens != 0 {
		t.Fatalf("tokens = %d, want 0", report.Tokens)
	}
	if report.Grade != GradeInsufficient {
		t.Fatalf("grade = %q, want insufficient", report.Grade)
	}
	if report.Fips.Tests != nil {
		t.Fatalf("fips.tests = %v, want null for an empty sample", report.Fips.Tests)
	}
	if !warningsContain(report.Warnings, "no tokens") {
		t.Fatalf("warnings = %q, want one mentioning 'no tokens'", report.Warnings)
	}
}

// The end-to-end happy path: enough good tokens to fill a block, and everything
// passes. 1,250 tokens of 8 hex characters is 1,250 x 32 = 40,000 bits, two
// whole 20,000-bit blocks.
func TestHealthySamplePassesAndReportsWhichEncodingItUsed(t *testing.T) {
	tokens := hexTokens(1, 1250, 4)
	report := AnalyseReport(tokens)
	if report.Tokens != 1250 {
		t.Fatalf("tokens = %d, want 1250", report.Tokens)
	}
	if report.Encoding != EncodingHex {
		t.Fatalf("encoding = %s, want hex", report.Encoding)
	}
	if !report.EncodingDetected {
		t.Fatalf("encoding_detected = false, want true")
	}
	if report.Bits.Bits != 40000 {
		t.Fatalf("bits = %d, want 40000", report.Bits.Bits)
	}
	if report.Fips.BlocksTested != 2 {
		t.Fatalf("blocks_tested = %d, want 2", report.Fips.BlocksTested)
	}
	if report.Fips.BitsUntested != 0 {
		t.Fatalf("bits_untested = %d, want 0", report.Fips.BitsUntested)
	}
	if report.Grade != GradePass {
		t.Fatalf("grade = %q, verdict = %q, failures = %v", report.Grade, report.Verdict, report.Fips.Failures())
	}
	if !strings.Contains(report.Verdict, "All four FIPS 140-2 tests passed") {
		t.Fatalf("verdict = %q, want the pass sentence", report.Verdict)
	}
	if report.Characters.AlphabetSize != 16 {
		t.Fatalf("alphabet_size = %d, want 16", report.Characters.AlphabetSize)
	}
	if report.Characters.MinLen != 8 || report.Characters.MaxLen != 8 {
		t.Fatalf("len = %d..%d, want 8..8", report.Characters.MinLen, report.Characters.MaxLen)
	}
	if report.Characters.TotalEntropyBits <= 31.0 {
		t.Fatalf("total_entropy_bits = %f, want > 31", report.Characters.TotalEntropyBits)
	}
	if math.Abs(report.Characters.MaxPossibleBits-32.0) > 1e-9 {
		t.Fatalf("max_possible_bits = %f, want 32", report.Characters.MaxPossibleBits)
	}
}

// The failure this tool is for: a token with a fixed prefix and a counter in
// the tail. It looks like a 16-character hex id and carries almost nothing.
func TestCounterDressedUpAsASessionIDIsCaughtAtBothLevels(t *testing.T) {
	tokens := make([]string, 0, 2000)
	for i := uint32(0); i < 2000; i++ {
		tokens = append(tokens, fmt.Sprintf("deadbeef%08x", i))
	}
	report := AnalyseReport(tokens)
	if report.Encoding != EncodingHex {
		t.Fatalf("encoding = %s, want hex", report.Encoding)
	}
	if report.Grade != GradeFail {
		t.Fatalf("grade = %q, want fail", report.Grade)
	}
	if len(report.Fips.Failures()) == 0 {
		t.Fatalf("a counter must not pass the bit-level suite")
	}
	for _, p := range report.Characters.Positions[:8] {
		if p.EntropyBits != 0.0 {
			t.Fatalf("position %d entropy = %f, want 0 for the fixed prefix", p.Index, p.EntropyBits)
		}
	}
	if report.Characters.TotalEntropyBits >= 20.0 {
		t.Fatalf("total_entropy_bits = %f, want < 20 (16 hex chars could carry 64)", report.Characters.TotalEntropyBits)
	}
}

// A short sample is graded insufficient, not fail. This is the distinction the
// Grade type exists for, and getting it wrong would mean reporting untested
// tokens as bad ones.
func TestShortSampleIsInsufficientRatherThanFailedAndSaysHowShort(t *testing.T) {
	tokens := hexTokens(9, 20, 8)
	report := AnalyseReport(tokens)
	if report.Bits.Bits != 20*64 {
		t.Fatalf("bits = %d, want %d", report.Bits.Bits, 20*64)
	}
	if report.Grade != GradeInsufficient {
		t.Fatalf("grade = %q, want insufficient", report.Grade)
	}
	if report.Fips.Tests != nil {
		t.Fatalf("fips.tests = %v, want null", report.Fips.Tests)
	}
	if report.Fips.BlocksTested != 0 {
		t.Fatalf("blocks_tested = %d, want 0", report.Fips.BlocksTested)
	}
	if report.Fips.BitsUntested != 20*64 {
		t.Fatalf("bits_untested = %d, want %d", report.Fips.BitsUntested, 20*64)
	}
	if !strings.Contains(report.Verdict, "No bit-level verdict") {
		t.Fatalf("verdict = %q, want the insufficient sentence", report.Verdict)
	}
	if !strings.Contains(report.Verdict, "313 token(s)") {
		t.Fatalf("verdict = %q, want it to say how many more tokens are needed", report.Verdict)
	}
	if !warningsContain(report.Warnings, "only 20 token(s)") {
		t.Fatalf("warnings = %q, want the small-sample warning", report.Warnings)
	}
	if report.Characters.AlphabetSize != 16 {
		t.Fatalf("alphabet_size = %d, want 16 (the character half still reports)", report.Characters.AlphabetSize)
	}
}

func TestVaryingTokenLengthsAreReportedAsACaveatRatherThanNormalisedAway(t *testing.T) {
	tokens := hexTokens(3, 200, 4)
	tokens = append(tokens, "abcdef")
	report := AnalyseReport(tokens)
	if report.Characters.MinLen != 6 || report.Characters.MaxLen != 8 {
		t.Fatalf("len = %d..%d, want 6..8", report.Characters.MinLen, report.Characters.MaxLen)
	}
	if !warningsContain(report.Warnings, "token lengths vary") {
		t.Fatalf("warnings = %q, want the variable-length caveat", report.Warnings)
	}
}

func TestEncodingCanBeForcedAndTheReportStopsClaimingItWasDetected(t *testing.T) {
	tokens := hexTokens(5, 400, 4)
	detected := AnalyseReport(tokens)
	forced := AnalyseAs(tokens, encodingPtr(EncodingRaw))
	if detected.Encoding != EncodingHex {
		t.Fatalf("detected encoding = %s, want hex", detected.Encoding)
	}
	if !detected.EncodingDetected {
		t.Fatalf("detected encoding_detected = false, want true")
	}
	if forced.Encoding != EncodingRaw {
		t.Fatalf("forced encoding = %s, want raw", forced.Encoding)
	}
	if forced.EncodingDetected {
		t.Fatalf("forced encoding_detected = true, want false")
	}
	if forced.Bits.Bits != detected.Bits.Bits*2 {
		t.Fatalf("raw view = %d bits, want twice the %d of the hex view", forced.Bits.Bits, detected.Bits.Bits)
	}
	if forced.Characters.TotalEntropyBits != detected.Characters.TotalEntropyBits {
		t.Fatalf("character analysis depends on the bit view: %f != %f",
			forced.Characters.TotalEntropyBits, detected.Characters.TotalEntropyBits)
	}
}

func encodingPtr(e Encoding) *Encoding { return &e }

func warningsContain(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
