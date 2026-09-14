package sequencer

// The whole analysis of one token sample, ported to the letter of
// crates/sequencer/src/lib.rs and crates/sequencer/src/chars.rs: a character-
// level view (what alphabet, how much each position varies) and a bit-level
// view (the FIPS 140-2 battery) assembled into one report.
//
// Three shaping decisions here, and each of them is a refusal:
//
//  1. A verdict is only printed where the test it comes from applies. Every
//     FIPS 140-2 threshold is a function of a 20,000-bit sample. Running those
//     constants against 4,000 bits produces a confident answer to a question
//     nobody asked, so the stream is cut into whole blocks, each is tested, and
//     the remainder is reported as untested. A sample too short for one block
//     gets no verdict at all — tests null, grade "insufficient" — rather than a
//     scaled guess.
//
//  2. The bit stream is decoded before it is tested. A 32-character hex session
//     id read as ASCII is 256 bits in which bit 7 of every byte is structurally
//     zero, and it fails every test spectacularly for reasons that have nothing
//     to do with the generator. The token encoding is detected and decoded
//     first, and named in the report; forcing it is the operator's escape hatch
//     for the case detection cannot see, and the report stops claiming it was
//     detected when it was supplied.
//
//  3. The character-level sum is an upper estimate, not a measurement. Shannon
//     entropy summed per position assumes the positions are independent: a token
//     that is "abc" or "xyz" and nothing else carries 1 bit, but the sum reports
//     3 x 1 = 3. The assumption is named in the report
//     (`assumes_positional_independence`) so a reader is not invited to treat
//     it as a measurement, and the sample ceiling (`entropy_ceiling_bits`) is
//     reported next to it so a small sample cannot be mistaken for a weak
//     generator.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Grade is how much of an answer the sample supports. Three states rather than a
// bare boolean because "we did not have enough data" is a different thing from
// "it failed", and collapsing them is exactly how a tool ends up reporting a
// weak generator that was never tested. Serialised snake_case, matching the
// UI's `grade: "insufficient" | "pass" | "fail"`.
type Grade string

const (
	// GradeInsufficient is not one whole FIPS block; no bit-level verdict was
	// reached.
	GradeInsufficient Grade = "insufficient"
	// GradePass is every applicable test passed.
	GradePass Grade = "pass"
	// GradeFail is at least one applicable test failed.
	GradeFail Grade = "fail"
)

// MinTokensForConfidence is the token count below which no part of the analysis
// is worth acting on. The character-level tests are still computed and reported
// — they are descriptive and a small sample is still a fact about the tokens —
// but the report carries a warning, because with fewer samples than the alphabet
// is wide every position is capped at log2(tokens) bits however good the
// generator is. 100 is the conventional floor and matches the default capture
// size.
const MinTokensForConfidence = 100

// MaxPositionsReported is the number of character positions individually
// reported. Positions past this are counted but not reported, so one
// pathological 10 MB "token" cannot turn a report into a memory problem; the
// truncation is stated in the report.
const MaxPositionsReported = 256

// CharCount is one observed character at one position.
type CharCount struct {
	// Label is the printable form for display: the character itself, or \xNN
	// when it is not printable ASCII.
	Label string `json:"label"`
	Byte  byte   `json:"byte"`
	Count int    `json:"count"`
	// Fraction is the share of the samples at this position, 0.0..=1.0.
	// Precomputed because the bar display needs it and the divisor is not
	// otherwise on the row.
	Fraction float64 `json:"fraction"`
}

// PositionStats is one character position across every token long enough to
// have it.
type PositionStats struct {
	Index int `json:"index"`
	// Samples is the tokens that actually had a character here. Shorter tokens
	// are excluded rather than padded — padding would invent a character and
	// shift the distribution towards it.
	Samples  int `json:"samples"`
	Distinct int `json:"distinct"`
	// EntropyBits is the Shannon entropy of this position's distribution.
	EntropyBits float64 `json:"entropy_bits"`
	// Counts is every observed character, most frequent first, ties broken by
	// byte value so the order is stable across runs.
	Counts []CharCount `json:"counts"`
}

// CharacterAnalysis is the character-level view of a token sample.
type CharacterAnalysis struct {
	Tokens int `json:"tokens"`
	MinLen int `json:"min_len"`
	MaxLen int `json:"max_len"`
	// AlphabetSize is the distinct byte values over every character of every
	// token.
	AlphabetSize int `json:"alphabet_size"`
	// Alphabet is the alphabet itself, in byte order, rendered for display.
	Alphabet []string `json:"alphabet"`
	// Positions is one entry per position, up to MaxPositionsReported.
	Positions []PositionStats `json:"positions"`
	// PositionsTruncated is true when MaxLen exceeded MaxPositionsReported and
	// later positions are absent.
	PositionsTruncated bool `json:"positions_truncated"`
	// EntropyBitsPerChar is the Shannon entropy over every character of every
	// token pooled together, bits per character.
	EntropyBitsPerChar float64 `json:"entropy_bits_per_char"`
	// TotalEntropyBits is the sum of the reported positions' entropies. An
	// upper estimate — see the package header.
	TotalEntropyBits float64 `json:"total_entropy_bits"`
	// AssumesPositionalIndependence is always true, and serialised so the number
	// above is never read without its caveat.
	AssumesPositionalIndependence bool `json:"assumes_positional_independence"`
	// EntropyCeilingBits is log2(tokens): the most any single position can show
	// from this many samples, regardless of the generator. A total near
	// positions x this means the sample ran out before the generator did.
	EntropyCeilingBits float64 `json:"entropy_ceiling_bits"`
	// MaxPossibleBits is positions x log2(alphabet_size): the most this alphabet
	// and length could ever carry.
	MaxPossibleBits float64 `json:"max_possible_bits"`
}

// SequencerReport is the whole analysis of one token sample. The wire contract
// is pinned by internal/web/ui/src/sequencer.ts.
type SequencerReport struct {
	Tokens int `json:"tokens"`
	// Encoding is which bit view the FIPS tests were run over, and why the
	// numbers are what they are.
	Encoding Encoding `json:"encoding"`
	// EncodingDetected is true when the encoding was chosen by DetectEncoding
	// rather than supplied.
	EncodingDetected bool              `json:"encoding_detected"`
	Characters       CharacterAnalysis `json:"characters"`
	// ExtraStats carries the character-uniformity and duplicate-detection
	// statistics the CLI has always reported from the same package but the web
	// report never reached (burpsy-react-ui-3sq). They ride a sub-object rather
	// than flattening into the report so an operator reading the JSON sees the
	// two surfaces named as one group, and each field is labelled for what it
	// measures — chi-square is "larger = less uniform", not a p-value.
	ExtraStats ExtraAnalysis `json:"extra_stats"`
	Bits       BitStats      `json:"bits"`
	Fips       FipsReport    `json:"fips"`
	// Advanced is the extended battery of advanced.go: Burp's four further
	// randomness tests, each of which either reports a statistic or says why
	// the sample could not support it. It is additive and does not feed `Grade`
	// — the grade and verdict below are the FIPS battery's, byte-for-byte the
	// Rust reference's, and `Advanced.AffectsGrade` says so on the wire rather
	// than leaving it to be inferred.
	Advanced AdvancedReport `json:"advanced"`
	// EffectiveEntropy is Burp's headline Sequencer output: the number of bit
	// positions that survive the frequency test at each of a range of
	// significance levels, so an operator can see whether a verdict is robust to
	// the level they picked (burpsy-react-ui-boq). Like Advanced it is additive —
	// `effective_entropy.affects_grade` is false and `Grade` below is still the
	// FIPS battery's, byte-for-byte the Rust reference's. effective.go states in
	// full what the number is and, at more length, what it is not.
	EffectiveEntropy EffectiveEntropyReport `json:"effective_entropy"`
	Grade            Grade                  `json:"grade"`
	// Verdict is one sentence an operator can act on, with the numbers in it.
	Verdict string `json:"verdict"`
	// Warnings is everything that limits how far the verdict can be trusted.
	// Never empty when it should not be.
	Warnings []string `json:"warnings"`
}

// ExtraAnalysis is the uniformity and duplicate group of the report: the
// statistics the CLI has always computed over the same sample (Analysis in
// sequencer.go) that the web report never carried (burpsy-react-ui-3sq).
//
// # What each number is, and what it is not
//
// ChiSquare is the raw chi-square statistic for character uniformity pooled
// across every character of every token: larger means the alphabet is used
// less uniformly. It is NOT a p-value and carries no degrees-of-freedom
// verdict — reading it as one would be inventing a test this package does
// not run.
//
// SerialCorrelation correlates successive character codes within the
// flattened stream, -1..1, random data near 0. It is NOT Burp's
// correlation test, which looks for relationships between values at
// different bit positions across tokens; the label says so, because the
// two must not be conflated (the issue records the caveat explicitly).
//
// RepeatedTokens is the count of distinct tokens that appear more than
// once, and RepeatedList names them: an exact duplicate in a session-token
// sample is a finding on its own, and this is the number that says so.
type ExtraAnalysis struct {
	ChiSquare float64 `json:"chi_square"`
	// SerialCorrelationLabel exists so the JSON can never be read as Burp's
	// bit-position correlation test without the caveat travelling with it.
	SerialCorrelation      float64  `json:"serial_correlation"`
	SerialCorrelationLabel string   `json:"serial_correlation_label"`
	MonteCarloPi           float64  `json:"monte_carlo_pi"`
	MonteCarloDeviation    float64  `json:"monte_carlo_deviation"`
	RepeatedTokens         int      `json:"repeated_tokens"`
	RepeatedList           []string `json:"repeated_list,omitempty"`
}

// extraFor computes the group from the raw tokens, sharing the engine's own
// functions so the two front-ends cannot disagree about what the numbers are.
func extraFor(tokens []string) ExtraAnalysis {
	cs := AnalyseCharacters(tokens)
	var codes []int
	for _, tok := range tokens {
		for _, c := range tok {
			codes = append(codes, int(c))
		}
	}
	var piValues []float64
	for _, c := range codes {
		piValues = append(piValues, float64(c)/256.0)
	}
	pi, dev := MonteCarloPi(piValues)
	pats := DetectPatterns(tokens)
	return ExtraAnalysis{
		ChiSquare:              ChiSquare(cs),
		SerialCorrelation:      SerialCorrelation(codes),
		SerialCorrelationLabel: "serial correlation of successive character codes within the stream — not Burp's bit-position correlation test",
		MonteCarloPi:           pi,
		MonteCarloDeviation:    dev,
		RepeatedTokens:         pats.Repeated,
		RepeatedList:           pats.RepeatedList,
	}
}

// AnalyseReport analyses a token sample, detecting the encoding.
func AnalyseReport(tokens []string) SequencerReport {
	return AnalyseAs(tokens, nil)
}

// AnalyseAs analyses a token sample, optionally forcing the bit-level encoding,
// at the default significance level.
// Forcing the encoding is the operator's escape hatch for the case detection
// cannot see: tokens that happen to be all hex characters but are really opaque
// bytes carried in hex, or the reverse. Detection is a heuristic over the
// alphabet and says so in the report.
func AnalyseAs(tokens []string, encoding *Encoding) SequencerReport {
	return analyse(tokens, encoding, DefaultSignificancePercent, true)
}

// AnalyseWith is AnalyseAs plus the operator's significance level, the input
// Burp's Sequencer takes for the whole analysis (burpsy-react-ui-boq).
//
// The level reaches exactly one part of the report — EffectiveEntropy — and
// nothing else. `Fips`, `Grade` and `Verdict` are identical for every level a
// caller can pass, because every FIPS 140-2 threshold is a fixed constant of the
// standard and not a function of a chosen confidence; pretending otherwise would
// be inventing a FIPS variant nobody specified. effective_test.go pins that
// orthogonality rather than leaving it to be assumed.
//
// An out-of-range level is a caller error and is refused at the HTTP boundary
// (ValidSignificancePercent); this function does not clamp, because a silently
// clamped level answers a question the operator did not ask.
func AnalyseWith(tokens []string, encoding *Encoding, significancePercent float64) SequencerReport {
	return analyse(tokens, encoding, significancePercent, false)
}

func analyse(tokens []string, encoding *Encoding, significancePercent float64, significanceDefaulted bool) SequencerReport {
	detected := encoding == nil
	enc := EncodingRaw
	if detected {
		enc = DetectEncoding(tokens)
	} else {
		enc = *encoding
	}
	characters := AnalyseChars(tokens)
	bitStream := BitsOf(tokens, enc)
	bits := BitStatsOf(bitStream)
	fips := AnalyseFipsBits(bitStream)

	warnings := make([]string, 0, 6)
	if len(tokens) == 0 {
		warnings = append(warnings, "no tokens were supplied, so there is nothing to analyse")
	} else if len(tokens) < MinTokensForConfidence {
		warnings = append(warnings, fmt.Sprintf(
			"only %d token(s): fewer than %d caps every character position at log2(%d) = %.1f bits however good the generator is, so a low per-position entropy here is a fact about the sample and not about the application",
			len(tokens), MinTokensForConfidence, len(tokens), characters.EntropyCeilingBits,
		))
	}
	if characters.MinLen != characters.MaxLen {
		warnings = append(warnings, fmt.Sprintf(
			"token lengths vary (%d to %d): positions past %d have fewer samples than the rest, and a variable-length token is itself worth explaining",
			characters.MinLen, characters.MaxLen, characters.MinLen,
		))
	}
	if characters.PositionsTruncated {
		warnings = append(warnings, fmt.Sprintf(
			"only the first %d character positions are reported, of %d",
			len(characters.Positions), characters.MaxLen,
		))
	}
	if fips.BitsUntested > 0 && fips.BlocksTested > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d bit(s) past the last whole %d-bit block were not tested",
			fips.BitsUntested, BlockBits,
		))
	}
	if detected && enc == EncodingRaw && characters.AlphabetSize <= 64 {
		warnings = append(warnings, fmt.Sprintf(
			"the tokens use %d distinct byte values but did not fit the hex or base64 alphabets, so the bit view is the raw characters — if these are text-encoded bytes in some other alphabet, the bit-level results describe the encoding as much as the generator",
			characters.AlphabetSize,
		))
	}

	grade, verdict := verdictFor(len(tokens), &characters, &fips)
	effective := AnalyseEffectiveEntropy(tokens, enc, significancePercent, significanceDefaulted, &fips)
	// The sample cannot answer at the level the operator chose. That is a limit
	// on the verdict they are about to quote, so it belongs beside the other
	// caveats and not only inside the curve — an operator who reads the headline
	// number and nothing else must still be told there is no headline number.
	if !effective.Chosen.Computed {
		warnings = append(warnings, fmt.Sprintf(
			"no effective-entropy figure at the %g%% significance level you chose: %s",
			effective.SignificancePercent, effective.Chosen.Reason,
		))
	}
	return SequencerReport{
		Tokens:           len(tokens),
		Encoding:         enc,
		EncodingDetected: detected,
		Characters:       characters,
		ExtraStats:       extraFor(tokens),
		Bits:             bits,
		Fips:             fips,
		Advanced:         advancedFor(tokens, enc, bitStream),
		EffectiveEntropy: effective,
		Grade:            grade,
		Verdict:          verdict,
		Warnings:         warnings,
	}
}

// verdictFor maps a sample and its statistics to a grade and the sentence an
// operator can act on. The three sentences are byte-for-byte the Rust ones in
// crates/sequencer/src/lib.rs so a report written by either engine reads the
// same.
func verdictFor(tokens int, characters *CharacterAnalysis, fips *FipsReport) (Grade, string) {
	switch passed := fips.Passed(); {
	case passed == nil:
		return GradeInsufficient, fmt.Sprintf(
			"No bit-level verdict: %d bit(s) supplied and the FIPS 140-2 suite is defined on a %d-bit sample, so not one whole block could be tested. %d token(s) at this length would need about %s in total. The character-level analysis below stands on its own — it measures %.1f bit(s) of entropy across %d position(s).",
			fips.BitsSupplied, BlockBits, tokens, tokensNeeded(tokens, fips.BitsSupplied),
			characters.TotalEntropyBits, len(characters.Positions),
		)
	case *passed:
		return GradePass, fmt.Sprintf(
			"All four FIPS 140-2 tests passed over %d whole %d-bit block(s) from %d token(s). Character-level entropy is %.1f bit(s) per token across %d position(s), against a %.1f-bit ceiling for this alphabet and length. A pass is evidence against an obviously broken generator, not proof of unpredictability.",
			fips.BlocksTested, BlockBits, tokens,
			characters.TotalEntropyBits, len(characters.Positions), characters.MaxPossibleBits,
		)
	default:
		failed := fips.Failures()
		return GradeFail, fmt.Sprintf(
			"%d of 4 FIPS 140-2 tests failed over %d whole %d-bit block(s) from %d token(s): %s. Character-level entropy is %.1f bit(s) per token across %d position(s), against a %.1f-bit ceiling. Check the per-position distribution for a fixed or slow-moving position before concluding the source is weak.",
			len(failed), fips.BlocksTested, BlockBits, tokens, strings.Join(failed, ", "),
			characters.TotalEntropyBits, len(characters.Positions), characters.MaxPossibleBits,
		)
	}
}

// tokensNeeded is a rough answer to "how many more tokens would fill a block".
// Deliberately approximate and phrased that way in the verdict: it is there so
// an operator knows whether they are short by a hundred tokens or by a hundred
// thousand.
func tokensNeeded(tokens, bitsSupplied int) string {
	if tokens == 0 || bitsSupplied == 0 {
		return fmt.Sprintf("%d bits' worth", BlockBits)
	}
	perToken := float64(bitsSupplied) / float64(tokens)
	needed := int(math.Ceil(float64(BlockBits) / perToken))
	return fmt.Sprintf("%d token(s)", needed)
}

// TokensFromText splits a pasted block of text into one token per line. The
// manual path, and the reason it is a function rather than an inline Split at
// the HTTP boundary: an operator pastes from a spreadsheet or a log, so blank
// lines and trailing whitespace are the normal case rather than an error.
// Interior whitespace is left alone — a token containing a space is unusual but
// it is not this function's place to decide it is a mistake.
func TokensFromText(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// AnalyseChars computes the character-level structure of a token sample. This
// is a byte-level analysis, not a rune-level one: a token generator's positions
// are byte positions, and padding shorter tokens to a common length would invent
// a character and pull that position's entropy towards it.
func AnalyseChars(tokens []string) CharacterAnalysis {
	maxLen, minLen := 0, 0
	if len(tokens) > 0 {
		minLen = len(tokens[0])
	}
	for _, t := range tokens {
		if len(t) > maxLen {
			maxLen = len(t)
		}
		if len(t) < minLen {
			minLen = len(t)
		}
	}

	// One pass over every character fills both the pooled histogram and the
	// per-position ones.
	var pooled [256]int
	reported := maxLen
	if reported > MaxPositionsReported {
		reported = MaxPositionsReported
	}
	perPosition := make([][256]int, reported)
	for _, t := range tokens {
		for i := 0; i < len(t); i++ {
			b := t[i]
			pooled[b]++
			if i < reported {
				perPosition[i][b]++
			}
		}
	}

	alphabet := make([]string, 0, 256)
	for b := 0; b < 256; b++ {
		if pooled[b] > 0 {
			alphabet = append(alphabet, label(byte(b)))
		}
	}
	alphabetSize := len(alphabet)

	positions := make([]PositionStats, 0, reported)
	for index := 0; index < reported; index++ {
		hist := perPosition[index]
		samples := 0
		for _, c := range hist {
			samples += c
		}
		counts := make([]CharCount, 0, 256)
		for b := 0; b < 256; b++ {
			if hist[b] > 0 {
				fraction := 0.0
				if samples > 0 {
					fraction = float64(hist[b]) / float64(samples)
				}
				counts = append(counts, CharCount{
					Label: label(byte(b)), Byte: byte(b), Count: hist[b], Fraction: fraction,
				})
			}
		}
		// Most frequent first; byte order breaks ties so two runs over the same
		// data agree.
		sort.Slice(counts, func(i, j int) bool {
			if counts[i].Count != counts[j].Count {
				return counts[i].Count > counts[j].Count
			}
			return counts[i].Byte < counts[j].Byte
		})
		positions = append(positions, PositionStats{
			Index:       index,
			Samples:     samples,
			Distinct:    len(counts),
			EntropyBits: entropyBits(hist[:]),
			Counts:      counts,
		})
	}

	totalEntropyBits := 0.0
	for _, p := range positions {
		totalEntropyBits += p.EntropyBits
	}
	entropyCeiling := 0.0
	if len(tokens) > 0 {
		entropyCeiling = math.Log2(float64(len(tokens)))
	}
	maxPossible := 0.0
	if alphabetSize > 0 {
		maxPossible = float64(reported) * math.Log2(float64(alphabetSize))
	}
	return CharacterAnalysis{
		Tokens:                        len(tokens),
		MinLen:                        minLen,
		MaxLen:                        maxLen,
		AlphabetSize:                  alphabetSize,
		Alphabet:                      alphabet,
		PositionsTruncated:            maxLen > reported,
		Positions:                     positions,
		EntropyBitsPerChar:            entropyBits(pooled[:]),
		TotalEntropyBits:              totalEntropyBits,
		AssumesPositionalIndependence: true,
		EntropyCeilingBits:            entropyCeiling,
		MaxPossibleBits:               maxPossible,
	}
}

// entropyBits is the Shannon entropy of a count distribution, in bits:
// H = -sum p_i log2(p_i). A single observed value gives 0.0 rather than a NaN,
// which is the mathematically right answer (p = 1, log2 1 = 0) and also the one
// a caller can display.
func entropyBits(counts []int) float64 {
	total := 0
	for _, c := range counts {
		if c > 0 {
			total += c
		}
	}
	if total == 0 {
		return 0
	}
	t := float64(total)
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / t
			h -= p * math.Log2(p)
		}
	}
	return h
}

// label renders a byte for a human: itself when printable ASCII, \xNN otherwise.
func label(b byte) string {
	switch {
	case b >= ' ' && b <= '~':
		return string(b)
	case b == '\n':
		return `\n`
	case b == '\r':
		return `\r`
	case b == '\t':
		return `\t`
	default:
		return fmt.Sprintf(`\x%02x`, b)
	}
}
