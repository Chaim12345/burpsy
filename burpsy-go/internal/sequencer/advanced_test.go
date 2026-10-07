package sequencer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The extended battery's tests are written against deterministic samples built
// from SHA-256 in counter mode rather than crypto/rand, so every assertion here
// is reproducible from the test's own seed. A statistical test whose fixture
// changes run to run would make a failure unreproducible, which is the one
// thing worse than a failure.

// streamBytes returns n deterministic bytes derived from one seed.
func streamBytes(n int, seed string) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for counter := 0; len(out) < n; counter++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", seed, counter)))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// hexAlphabet is a real 16-symbol alphabet. The distinction matters more than
// it looks: a sample drawn from 'a'..'p' is sixteen symbols but *not* hex (g
// through p are not hex digits), so DetectEncoding reads it as base64 and the
// bit view becomes six bits a character with only sixteen of the sixty-four
// values reachable — which is a genuinely non-uniform stream, correctly flagged
// by every test in the battery.
const hexAlphabet = "0123456789abcdef"

// alphabetTokens builds count tokens of width characters drawn from alphabet.
func alphabetTokens(count, width int, alphabet string, seed string) []string {
	raw := streamBytes(count*width, seed)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		token := make([]byte, width)
		for j := 0; j < width; j++ {
			token[j] = alphabet[int(raw[i*width+j])%len(alphabet)]
		}
		out = append(out, string(token))
	}
	return out
}

// findByID returns the named member of the battery.
func findByID(t *testing.T, report SequencerReport, id string) AdvancedTest {
	t.Helper()
	for _, test := range report.Advanced.Tests {
		if test.ID == id {
			return test
		}
	}
	t.Fatalf("the report carries no %q test; ids present: %v", id, advancedIDs(report))
	return AdvancedTest{}
}

func advancedIDs(report SequencerReport) []string {
	ids := make([]string, 0, len(report.Advanced.Tests))
	for _, test := range report.Advanced.Tests {
		ids = append(ids, test.ID)
	}
	return ids
}

// ---------------------------------------------------------------------------
// The shape of the battery itself
// ---------------------------------------------------------------------------

// Every member is one of exactly two things: a test that ran and reported its
// statistic, or a test that refused and named what it needed. There is no third
// state, and in particular "did not run" is never dressed up as "passed".
func TestEveryExtendedTestEitherReportsAStatisticOrRefusesWithAReason(t *testing.T) {
	samples := map[string][]string{
		"nothing":          nil,
		"one empty token":  {""},
		"two short tokens": {"ab", "cd"},
		"a hundred hex":    alphabetTokens(100, 32, hexAlphabet, "hex-100"),
		"two thousand hex": alphabetTokens(2000, 32, hexAlphabet, "hex-2000"),
		"narrow alphabet":  alphabetTokens(400, 4, "abcd", "narrow-400"),
		"varying lengths":  {"abc", "de", "fghij", "kl", "mnopq", "rst"},
	}
	for name, tokens := range samples {
		report := AnalyseReport(tokens)
		if len(report.Advanced.Tests) != 4 {
			t.Fatalf("%s: the battery has %d test(s): %v", name, len(report.Advanced.Tests), advancedIDs(report))
		}
		if report.Advanced.AffectsGrade {
			t.Fatalf("%s: affects_grade must be false — the grade is the FIPS battery's", name)
		}
		for _, test := range report.Advanced.Tests {
			switch {
			case test.Tested:
				if test.Observed == "" {
					t.Errorf("%s/%s: ran but reported no statistic; a pass with no number beside it cannot be checked", name, test.ID)
				}
				if test.Reason != "" {
					t.Errorf("%s/%s: ran, so it must not also carry a refusal reason (%q)", name, test.ID, test.Reason)
				}
				// A test reads its verdict off a significance level or off a
				// tolerance against a control, and it must say which: a row with
				// neither is a verdict with no rule behind it.
				significance := test.Threshold > 0 && test.Threshold <= SignificanceLevel
				if !significance && test.Tolerance <= 0 {
					t.Errorf("%s/%s: ran with neither a corrected threshold in (0, %g] (got %g) nor a stated tolerance (got %g)",
						name, test.ID, SignificanceLevel, test.Threshold, test.Tolerance)
				}
			default:
				if test.Reason == "" {
					t.Errorf("%s/%s: did not run but gave no reason; \"not tested\" with no reason is an unanswerable question",
						name, test.ID)
				}
				if test.Observed != "" {
					t.Errorf("%s/%s: did not run but reported a statistic (%q)", name, test.ID, test.Observed)
				}
				if test.Passed {
					t.Errorf("%s/%s: did not run and must not read as passed", name, test.ID)
				}
				if test.Flagged != 0 || test.Examined != 0 {
					t.Errorf("%s/%s: did not run but examined %d and flagged %d", name, test.ID, test.Examined, test.Flagged)
				}
			}
		}
	}
}

// The report is a document somebody checks. Two runs over the same sample must
// produce the same battery — including the floating-point sums behind each
// statistic, which map iteration order would otherwise shuffle.
func TestTheExtendedBatteryIsByteIdenticalAcrossRuns(t *testing.T) {
	tokens := alphabetTokens(600, 8, hexAlphabet, "repeatable")
	first := AnalyseReport(tokens).Advanced
	second := AnalyseReport(tokens).Advanced
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("two analyses of the same sample disagree:\n first: %+v\nsecond: %+v", first, second)
	}
}

// ---------------------------------------------------------------------------
// Character transition analysis
// ---------------------------------------------------------------------------

// A uniform sample over a narrow alphabet has a wide enough table to be tested,
// and it must not be flagged.
func TestTransitionPassesOnIndependentCharacters(t *testing.T) {
	report := AnalyseReport(alphabetTokens(400, 4, "abcd", "independent"))
	test := findByID(t, report, "transition")
	if !test.Tested {
		t.Fatalf("transition did not run on 400 tokens over four symbols, where every table is 4x4 with 399 transitions: %s", test.Reason)
	}
	if test.Flagged != 0 || !test.Passed {
		t.Fatalf("independent characters were flagged: %d of %d position(s), observed %s", test.Flagged, test.Examined, test.Observed)
	}
	if test.Threshold != SignificanceLevel/float64(test.Examined) {
		t.Fatalf("threshold = %g, want the Bonferroni-corrected 0.05/%d = %g",
			test.Threshold, test.Examined, SignificanceLevel/float64(test.Examined))
	}
}

// The claim the test exists to make: a character at a position that depends on
// the previous token's character at the same position is flagged.
func TestTransitionFlagsADependentPosition(t *testing.T) {
	// Every position advances by one symbol from the token before it: the table
	// still uses all four symbols on both sides, but the next character is fully
	// determined by the current one, which is exactly the dependence the test
	// claims to see. (Repeating whole tokens would not do: that makes every
	// position constant, which is the character-count analysis's finding, not a
	// transition one.)
	base := alphabetTokens(400, 4, "abcd", "dependent")
	tokens := make([]string, 0, len(base))
	token := []byte(base[0])
	for range base {
		tokens = append(tokens, string(token))
		for j := range token {
			token[j] = 'a' + (token[j]-'a'+1)%4
		}
	}
	report := AnalyseReport(tokens)
	test := findByID(t, report, "transition")
	if !test.Tested {
		t.Fatalf("transition did not run on a perfectly dependent sample: %s", test.Reason)
	}
	if test.Flagged == 0 || test.Passed {
		t.Fatalf("a fully deterministic position was not flagged: flagged=%d observed=%s", test.Flagged, test.Observed)
	}
	if !strings.Contains(test.Observed, "position") {
		t.Fatalf("the observed statistic does not name the position it describes: %q", test.Observed)
	}
}

// A 16-symbol alphabet at a hundred tokens cannot fill a 256-cell table, and the
// refusal has to say how much more would be needed rather than only that the
// sample was too small.
func TestTransitionRefusesASparseTableAndNamesTheSampleItNeeds(t *testing.T) {
	report := AnalyseReport(alphabetTokens(100, 32, hexAlphabet, "sparse"))
	test := findByID(t, report, "transition")
	if test.Tested {
		t.Fatalf("transition ran on a table it cannot support: observed %s", test.Observed)
	}
	for _, want := range []string{"too sparse", "needs about", "supplied"} {
		if !strings.Contains(test.Reason, want) {
			t.Errorf("the refusal %q does not contain %q; an operator cannot turn it into a capture size without the count", test.Reason, want)
		}
	}
}

// Cochran's two halves are separate refusals and both have to be live. This one
// is a table where no cell's expectation has collapsed to nothing — every
// symbol appears often enough — but where more than a fifth of the cells are
// under five observations, which is the condition that says the chi-square
// approximation has stopped holding even though the table looks populated.
func TestTransitionRefusesATableWhereMostCellsAreThinButNoneAreEmpty(t *testing.T) {
	// Eight symbols over three hundred tokens: every position sees all eight
	// characters, but a 64-cell table with three hundred transitions expects
	// under five observations a cell.
	report := AnalyseReport(alphabetTokens(300, 4, "abcdefgh", "thin-cells"))
	test := findByID(t, report, "transition")
	if test.Tested {
		t.Fatalf("transition trusted a table where most cells are under %.0f observations: observed %s",
			MinCellExpectation, test.Observed)
	}
	if !strings.Contains(test.Reason, "Cochran") {
		t.Fatalf("the refusal %q does not name the rule it applied", test.Reason)
	}
}

// The other half of Cochran's rule: a table can be populated everywhere except
// one corner, and a single cell whose expectation has collapsed below one
// observation is enough to invalidate the statistic. The fixture is built so
// the 20% rule would *not* reject it — fifteen symbols at 150 occurrences each
// and one at exactly one, on a 256-cell table — which isolates the floor.
func TestTransitionRefusesATableWithOneEmptyCorner(t *testing.T) {
	const (
		runs   = 150
		normal = "0123456789abcde"
	)
	tokens := make([]string, 0, runs*len(normal)+1)
	for i := 0; i < runs; i++ {
		for j := 0; j < len(normal); j++ {
			tokens = append(tokens, string(normal[j]))
		}
	}
	// The rare symbol sits in the middle so it appears once on each side of the
	// transition table: its row and its column both expect well under one
	// observation, while every other cell expects about ten.
	middle := len(tokens) / 2
	tokens = append(tokens[:middle], append([]string{"f"}, tokens[middle:]...)...)

	test := transitionTest(tokens)
	if test.Tested {
		t.Fatalf("transition trusted a table with a cell expected well under one observation: observed %s", test.Observed)
	}
	if !strings.Contains(test.Reason, "fall below 1") {
		t.Fatalf("the refusal %q does not name the floor it applied", test.Reason)
	}
}

// ---------------------------------------------------------------------------
// Spectral test
// ---------------------------------------------------------------------------

// Independent bits produce no clusterable tuplet, and every combination that
// could be tested must say so.
func TestSpectralPassesOnRandomBits(t *testing.T) {
	tokens := alphabetTokens(1250, 32, hexAlphabet, "spectral-random")
	test := findByID(t, AnalyseReport(tokens), "spectral")
	if !test.Tested {
		t.Fatalf("spectral did not run on a 20,000-bit stream: %s", test.Reason)
	}
	if test.Flagged != 0 || !test.Passed {
		t.Fatalf("random bits were flagged: %d of %d combination(s), observed %s", test.Flagged, test.Examined, test.Observed)
	}
	if len(test.Notices) == 0 {
		t.Fatalf("spectral ran without stating its limits; the unreachable tuplet widths and the non-overlap choice must travel with the verdict")
	}
}

// A stream of one repeated byte has everything to cluster and nothing to
// distribute: every tuplet has the same value, so every testable combination
// flags.
func TestSpectralFlagsAConstantStream(t *testing.T) {
	bits := make([]byte, 20000) // all zeros, a legal bit stream
	test := spectralTest(bits)
	if !test.Tested {
		t.Fatalf("spectral did not run on 20,000 bits: %s", test.Reason)
	}
	if test.Flagged != test.Examined || test.Passed {
		t.Fatalf("a constant stream flagged %d of %d combination(s): the test is not seeing the structure it exists to find",
			test.Flagged, test.Examined)
	}
}

// Too short a stream cannot fill even the smallest table, and the refusal names
// the arithmetic rather than saying "too short".
func TestSpectralRefusesAStreamTooShortForAnyTupletTable(t *testing.T) {
	test := spectralTest(make([]byte, 16))
	if test.Tested {
		t.Fatalf("spectral ran on 16 bits: %s", test.Observed)
	}
	for _, want := range []string{"expected observation", "longer stream"} {
		if !strings.Contains(test.Reason, want) {
			t.Errorf("the refusal %q does not contain %q", test.Reason, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Correlation test
// ---------------------------------------------------------------------------

// Random bits have no relationship between positions, and the pair table is
// large enough that the correction has to be doing real work: 8128 pairs at
// 0.05 would flag roughly four hundred of them by chance alone.
func TestCorrelationPassesOnRandomBits(t *testing.T) {
	test := findByID(t, AnalyseReport(alphabetTokens(200, 32, hexAlphabet, "corr-random")), "correlation")
	if !test.Tested {
		t.Fatalf("correlation did not run on 200 hex tokens of 128 bits: %s", test.Reason)
	}
	if test.Flagged != 0 || !test.Passed {
		t.Fatalf("independent bit positions were flagged: %d of %d pair(s), observed %s", test.Flagged, test.Examined, test.Observed)
	}
	if test.Examined != 128*127/2 {
		t.Fatalf("examined %d pair(s), want 128 bits to contribute 128*127/2 = %d", test.Examined, 128*127/2)
	}
}

// The finding this test is here for: two bit positions that are individually
// well-distributed but always equal to one another.
func TestCorrelationFlagsTwoPositionsThatAlwaysAgree(t *testing.T) {
	// Four random bits per token, mirrored into bits 4..7, so position p and
	// position p+4 are identical by construction. Both halves are uniform.
	tokens := make([]string, 0, 200)
	raw := streamBytes(200*4, "corr-dependent")
	for i := 0; i < 200; i++ {
		var token [8]byte
		for j := 0; j < 4; j++ {
			bit := raw[i*4+j] & 1
			token[j] = bit
			token[j+4] = bit
		}
		out := make([]byte, 8)
		for j, b := range token {
			out[j] = '0' + b
		}
		tokens = append(tokens, string(out))
	}
	report := AnalyseReport(tokens)
	test := findByID(t, report, "correlation")
	if !test.Tested {
		t.Fatalf("correlation did not run on the mirrored sample: %s", test.Reason)
	}
	if test.Flagged == 0 || test.Passed {
		t.Fatalf("a bit position equal to another in every token was not flagged: flagged=%d observed=%s", test.Flagged, test.Observed)
	}
}

// A position that never varies has no correlation to measure, and the refusal
// says that the fixed position is the stronger finding rather than pretending
// there was nothing to see.
func TestCorrelationRefusesASampleWhereEveryBitPositionIsFixed(t *testing.T) {
	tokens := make([]string, 100)
	for i := range tokens {
		tokens[i] = "abcdefgh"
	}
	test := findByID(t, AnalyseReport(tokens), "correlation")
	if test.Tested {
		t.Fatalf("correlation ran on a sample with no varying bit position: %s", test.Observed)
	}
	if !strings.Contains(test.Reason, "fixed at a single value") {
		t.Errorf("the refusal %q does not name the condition that stopped it", test.Reason)
	}
}

// "The value at bit 7" is not one thing when the tokens are different lengths,
// and inventing an alignment to compare would be exactly the kind of guess this
// package refuses.
func TestCorrelationRefusesVariableLengthTokens(t *testing.T) {
	tokens := []string{"abcd", "ef", "ghij", "kl", "mnop", "qr"}
	for i := 0; i < 40; i++ {
		tokens = append(tokens, fmt.Sprintf("%04x", i*2654435761%65536))
	}
	test := findByID(t, AnalyseReport(tokens), "correlation")
	if test.Tested {
		t.Fatalf("correlation ran on tokens of differing lengths: %s", test.Observed)
	}
	if !strings.Contains(test.Reason, "lengths vary") {
		t.Errorf("the refusal %q does not name the condition that stopped it", test.Reason)
	}
}

// ---------------------------------------------------------------------------
// Compression test
// ---------------------------------------------------------------------------

// rawByteTokens builds count one-byte tokens with the encoding forced to raw,
// so the bit view is eight bits a token whatever the byte values happen to be.
func rawByteTokens(count int, seed string) []string {
	tokens := make([]string, 0, count)
	for _, b := range streamBytes(count, seed) {
		tokens = append(tokens, string([]byte{b & 0x7f}))
	}
	return tokens
}

// 512 tokens of one byte is exactly the floor, and random bytes must not
// compress better than the incompressible control.
func TestCompressionPassesOnRandomBits(t *testing.T) {
	tokens := make([]string, 0, 512)
	for _, b := range streamBytes(512, "compress-random") {
		tokens = append(tokens, string([]byte{b}))
	}
	test := findByID(t, AnalyseReport(tokens), "compression")
	if !test.Tested {
		t.Fatalf("compression did not run at its own 512-token floor: %s", test.Reason)
	}
	if test.Flagged != 0 || !test.Passed {
		t.Fatalf("random bits were flagged: %d of %d position(s), observed %s", test.Flagged, test.Examined, test.Observed)
	}
	if test.Tolerance != CompressionTolerance {
		t.Fatalf("tolerance = %g, want %g — the margin the verdict was read against is not on the row",
			test.Tolerance, CompressionTolerance)
	}
}

// A bit position that never varies compresses to almost nothing, which is the
// structure this test exists to find.
func TestCompressionFlagsABitPositionThatNeverVaries(t *testing.T) {
	tokens := make([]string, 0, 512)
	raw := streamBytes(512, "compress-fixed")
	for _, b := range raw {
		// Bit 7 is always zero; the other seven carry the random byte.
		tokens = append(tokens, string([]byte{b & 0x7f}))
	}
	test := findByID(t, AnalyseReport(tokens), "compression")
	if !test.Tested {
		t.Fatalf("compression did not run: %s", test.Reason)
	}
	if test.Flagged == 0 || test.Passed {
		t.Fatalf("a bit position held at zero for every token was not flagged: flagged=%d observed=%s", test.Flagged, test.Observed)
	}
	if !strings.Contains(test.Observed, "reduction") {
		t.Fatalf("the observed statistic does not carry the reduction it was read from: %q", test.Observed)
	}
}

// The control's reduction is negative at these sample lengths, and the number on
// the row has to be that number. DEFLATE makes a short incompressible sequence
// *grow*, so a baseline of zero would be wrong twice over: it would misreport
// the control, and it would silently hand every position five free percentage
// points of slack it never earned.
func TestTheIncompressibleControlReportsItsOwnNegativeReduction(t *testing.T) {
	const tokens = 512
	small := incompressibleReduction(tokens)
	if small >= 0 {
		t.Fatalf("incompressibleReduction(%d) = %.4f, want a negative reduction: at %d bytes of bits DEFLATE's framing makes an incompressible sequence larger, so a control that reports 0%% is not being measured",
			tokens, small, tokens/8)
	}

	report := AnalyseReport(rawByteTokens(tokens, "baseline-row"))
	test := findByID(t, report, "compression")
	if !test.Tested {
		t.Fatalf("compression did not run: %s", test.Reason)
	}
	want := fmt.Sprintf("%.1f%% incompressible control", small*100)
	if !strings.Contains(test.Observed, want) {
		t.Fatalf("the row reports %q but the control's reduction for this length is %.1f%%; the number read against must be the number measured",
			test.Observed, small*100)
	}
}

// Below the floor the measurement describes DEFLATE's framing, and the refusal
// says so with the byte count rather than only the token count.
func TestCompressionRefusesASampleTooShortToCompress(t *testing.T) {
	test := findByID(t, AnalyseReport(alphabetTokens(100, 32, hexAlphabet, "compress-short")), "compression")
	if test.Tested {
		t.Fatalf("compression ran below its floor: %s", test.Observed)
	}
	for _, want := range []string{"needs at least", "byte(s) long", "framing"} {
		if !strings.Contains(test.Reason, want) {
			t.Errorf("the refusal %q does not contain %q", test.Reason, want)
		}
	}
}

// ---------------------------------------------------------------------------
// The battery does not move the grade
// ---------------------------------------------------------------------------

// The extended battery is additive and the grade stays the FIPS battery's,
// byte-for-byte the Rust reference's. This is the test that would fail if
// somebody later folded a compression flag into the verdict: the sample is
// built so the FIPS suite cannot run at all (4,096 bits, a fifth of one block)
// while the compression test has a real finding.
func TestTheGradeStaysTheFipsVerdictEvenWhenAnExtendedTestFlags(t *testing.T) {
	tokens := make([]string, 0, 512)
	raw := streamBytes(512, "grade-independence")
	for _, b := range raw {
		tokens = append(tokens, string([]byte{b & 0x7f}))
	}
	report := AnalyseReport(tokens)
	if report.Grade != GradeInsufficient {
		t.Fatalf("grade = %q, want %q: 4,096 bits is a fifth of one FIPS block, so the FIPS suite cannot have reached a verdict",
			report.Grade, GradeInsufficient)
	}
	compression := findByID(t, report, "compression")
	if compression.Flagged == 0 {
		t.Fatalf("the fixture no longer produces an extended-battery finding, so it no longer tests anything: %s", compression.Observed)
	}
	if !strings.Contains(report.Verdict, "No bit-level verdict") {
		t.Fatalf("the verdict is not the FIPS one: %q", report.Verdict)
	}
	if !strings.Contains(report.Advanced.Summary, "unaffected") {
		t.Fatalf("the summary does not state that the grade is the FIPS battery's: %q", report.Advanced.Summary)
	}
}

// ---------------------------------------------------------------------------
// The wire shape
// ---------------------------------------------------------------------------

// The UI reads this shape. It is pinned here so a field rename is a test
// failure rather than a blank panel.
func TestExtendedBatterySerialisesWithTheIdsAndTheGradeDisclaimer(t *testing.T) {
	encoded, err := json.Marshal(AnalyseReport(alphabetTokens(400, 4, "abcd", "wire")))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Grade    string `json:"grade"`
		Advanced struct {
			AffectsGrade bool `json:"affects_grade"`
			Summary      string
			Tests        []struct {
				ID          string   `json:"id"`
				Name        string   `json:"name"`
				Basis       string   `json:"basis"`
				Requirement string   `json:"requirement"`
				Tested      bool     `json:"tested"`
				Reason      string   `json:"reason"`
				Observed    string   `json:"observed"`
				Examined    int      `json:"examined"`
				Flagged     int      `json:"flagged"`
				Threshold   float64  `json:"threshold"`
				Notices     []string `json:"notices"`
			} `json:"tests"`
		} `json:"advanced"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Advanced.AffectsGrade {
		t.Fatalf("affects_grade decoded as true")
	}
	if decoded.Advanced.Summary == "" {
		t.Fatalf("the summary is empty on the wire")
	}
	want := []string{"transition", "spectral", "correlation", "compression"}
	if len(decoded.Advanced.Tests) != len(want) {
		t.Fatalf("the wire carries %d test(s), want %d: %v", len(decoded.Advanced.Tests), len(want), decoded.Advanced.Tests)
	}
	for i, id := range want {
		got := decoded.Advanced.Tests[i]
		if got.ID != id {
			t.Errorf("test %d has id %q, want %q", i, got.ID, id)
		}
		if got.Name == "" || got.Basis == "" || got.Requirement == "" {
			t.Errorf("%s: name, basis and requirement must all travel — a verdict without its condition is unreadable", got.ID)
		}
	}
}
