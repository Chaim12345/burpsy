package web

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The significance level and the effective-entropy curve at the wire boundary
// (burpsy-react-ui-boq). These assert the JSON the browser actually receives —
// the shape, not the struct — because a Go nil slice and an empty one are the
// same length in Go and are `null` and `[]` in the browser, and the page maps
// over these arrays.

type effectiveEntropyPointView struct {
	SignificancePercent float64  `json:"significance_percent"`
	Significance        float64  `json:"significance"`
	Computed            bool     `json:"computed"`
	Bits                *int     `json:"bits"`
	BitsExamined        int      `json:"bits_examined"`
	BitsRejected        *int     `json:"bits_rejected"`
	Expected            *float64 `json:"expected_chance_rejections"`
	Reason              string   `json:"reason"`
	Chosen              bool     `json:"chosen"`
}

type effectiveEntropyView struct {
	SignificancePercent   float64                     `json:"significance_percent"`
	SignificanceDefaulted bool                        `json:"significance_defaulted"`
	Chosen                effectiveEntropyPointView   `json:"chosen"`
	Curve                 []effectiveEntropyPointView `json:"curve"`
	Tests                 []string                    `json:"tests"`
	Definition            string                      `json:"definition"`
	TokensUsed            int                         `json:"tokens_used"`
	BitPositionsExamined  int                         `json:"bit_positions_examined"`
	Robust                bool                        `json:"robust"`
	RobustnessNote        string                      `json:"robustness_note"`
	FipsAgreement         string                      `json:"fips_agreement"`
	AffectsGrade          bool                        `json:"affects_grade"`
	Grade                 string                      `json:"-"`
}

func decodeEffectiveEntropy(t *testing.T, body []byte) effectiveEntropyView {
	t.Helper()
	var wrapper struct {
		EffectiveEntropy effectiveEntropyView `json:"effective_entropy"`
		Grade            string               `json:"grade"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("decode effective_entropy from %q: %v", string(body), err)
	}
	wrapper.EffectiveEntropy.Grade = wrapper.Grade
	return wrapper.EffectiveEntropy
}

// The ten-token fixture whose arithmetic is worked out by hand in
// internal/sequencer/effective_test.go: four bit positions constant (p = 2^-9 =
// 0.001953125) and four split exactly 5/5 (p = 1), out of eight positions.
func constantNibbleSample() []string {
	return []string{"0f", "00", "0f", "00", "0f", "00", "0f", "00", "0f", "00"}
}

func TestSequencerAnalyseReportsTheEffectiveEntropyCurveWithoutBeingAsked(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": constantNibbleSample()})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	ee := decodeEffectiveEntropy(t, rec.Body.Bytes())
	if len(ee.Curve) == 0 {
		t.Fatalf("effective_entropy.curve is empty or null. Burp's headline Sequencer output is this curve; a report without it is the gap this bead exists to close.")
	}
	if ee.Tests == nil || len(ee.Tests) == 0 {
		t.Fatalf("effective_entropy.tests is null or empty. 'The number of bits that pass the randomness tests' is not a quotable number until the tests are named.")
	}
	if ee.Definition == "" {
		t.Fatalf("effective_entropy.definition is empty. The exported report has to carry what its headline number is, or it will be read as a probability of randomness.")
	}
	if ee.SignificancePercent != 1 || !ee.SignificanceDefaulted {
		t.Fatalf("significance_percent = %v, defaulted = %v; want 1 and true. An absent level must be answered with the default AND marked as defaulted, or the UI cannot tell it from an operator who typed 1%%.",
			ee.SignificancePercent, ee.SignificanceDefaulted)
	}
	if ee.AffectsGrade {
		t.Fatalf("effective_entropy.affects_grade = true. The grade on this report is the FIPS battery's; a curve that claims to move it would let a caller fold the two together.")
	}
	if ee.FipsAgreement == "" {
		t.Fatalf("effective_entropy.fips_agreement is empty. This report shows a FIPS verdict and a curve side by side; if they can differ it has to say how, in its own words.")
	}
	if ee.Chosen.Bits == nil || *ee.Chosen.Bits != 4 {
		t.Fatalf("chosen.bits = %v, want 4: four of the eight bit positions in this sample are constant across all ten tokens (p = 0.001953125) and are rejected at 1%%; the other four are split exactly 5/5 (p = 1) and survive.", ee.Chosen.Bits)
	}
	if ee.BitPositionsExamined != 8 || ee.TokensUsed != 10 {
		t.Fatalf("bit_positions_examined = %d and tokens_used = %d, want 8 and 10.", ee.BitPositionsExamined, ee.TokensUsed)
	}
}

func TestSequencerAnalyseTakesTheOperatorsSignificanceLevel(t *testing.T) {
	s := newTestServer()
	// 2% and 5% straddle the p-value of a bit position that is 1 in 10 tokens
	// (22/1024 = 0.021484375), so the same sample must give different bit counts
	// at the two levels or the level is not reaching the analysis.
	sample := []string{"8", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	counts := map[float64]int{}
	for _, percent := range []float64{2, 5} {
		rec := postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": sample, "significance_percent": percent})
		if rec.Code != http.StatusOK {
			t.Fatalf("status at %g%% = %d, want 200: %s", percent, rec.Code, rec.Body.String())
		}
		ee := decodeEffectiveEntropy(t, rec.Body.Bytes())
		if ee.SignificancePercent != percent {
			t.Fatalf("significance_percent echoed as %v, want %v: the report has to say which level it was read at.", ee.SignificancePercent, percent)
		}
		if ee.SignificanceDefaulted {
			t.Fatalf("significance_defaulted = true at an explicitly supplied %g%%.", percent)
		}
		if !ee.Chosen.Chosen {
			t.Fatalf("the chosen point at %g%% is not flagged as chosen, so a caller cannot find it on the curve.", percent)
		}
		if ee.Chosen.Bits == nil {
			t.Fatalf("chosen.bits is null at %g%% for a ten-token sample that can answer there.", percent)
		}
		counts[percent] = *ee.Chosen.Bits
	}
	if counts[2] != 1 || counts[5] != 0 {
		t.Fatalf("bits = %d at 2%% and %d at 5%%, want 1 and 0. The one-in-ten bit position scores p = 0.021484375 — above 0.02, below 0.05 — so it survives the stricter level and not the looser one. Equal counts mean the level was accepted and ignored.",
			counts[2], counts[5])
	}
}

func TestSequencerRefusesASignificanceLevelOutsideTheRangeItIsDefinedOver(t *testing.T) {
	s := newTestServer()
	for _, bad := range []float64{0, -1, 50, 100} {
		rec := postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": constantNibbleSample(), "significance_percent": bad})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("significance_percent %g gave status %d, want 400. Clamping an out-of-range level would print an answer to a different question under the operator's number.", bad, rec.Code)
		}
		if body := rec.Body.String(); !containsSub(body, "0.001") || !containsSub(body, "10") {
			t.Fatalf("the refusal for %g does not name the accepted range: %q", bad, body)
		}
	}
}

func TestSequencerReportsAnAbsentEffectiveEntropyRatherThanZeroBitsOnATinySample(t *testing.T) {
	s := newTestServer()
	// 0.1% as a fraction is 0.001, below the 0.001953125 that ten tokens' most
	// extreme possible result scores. Nothing could be rejected there, so there
	// is no answer — and "8 bits survived" would be an artefact of the sample
	// size dressed as a measurement.
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": constantNibbleSample(), "significance_percent": 0.1})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: an unanswerable level is a result, not a request error: %s", rec.Code, rec.Body.String())
	}
	ee := decodeEffectiveEntropy(t, rec.Body.Bytes())
	if ee.Chosen.Computed {
		t.Fatalf("the 0.1%% point is computed with bits = %v for a ten-token sample whose smallest reachable p-value is 0.001953125.", ee.Chosen.Bits)
	}
	if ee.Chosen.Bits != nil {
		t.Fatalf("chosen.bits = %d on an unanswerable level. It must be JSON null: any number there is plotted, and zero reads as 'no bit survived' — the opposite of 'this sample cannot say'.", *ee.Chosen.Bits)
	}
	if ee.Chosen.Reason == "" {
		t.Fatalf("chosen.reason is empty beside a null bit count, leaving the absence indistinguishable from a bug.")
	}
	// The same sample at a level it CAN answer, to show the absence is about the
	// level and not about the endpoint.
	rec = postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": constantNibbleSample(), "significance_percent": 0.2})
	answered := decodeEffectiveEntropy(t, rec.Body.Bytes())
	if !answered.Chosen.Computed || answered.Chosen.Bits == nil || *answered.Chosen.Bits != 4 {
		t.Fatalf("the same sample at 0.2%% gives %+v, want a computed 4 bits: 0.001953125 is below 0.002, so the four constant positions are rejected there.", answered.Chosen)
	}
	var absent, present int
	for _, p := range answered.Curve {
		if p.Computed {
			present++
		} else {
			absent++
			if p.Bits != nil {
				t.Fatalf("the %g%% point sends a bit count beside computed = false.", p.SignificancePercent)
			}
		}
	}
	if absent == 0 || present == 0 {
		t.Fatalf("the curve for this sample has %d absent and %d present point(s); it should have both, since the ladder spans levels this sample can and cannot answer.", absent, present)
	}
}

// The grade is the FIPS battery's, and the significance level must not move it.
func TestSequencerGradeIsUnchangedByTheSignificanceLevel(t *testing.T) {
	s := newTestServer()
	tokens := hexSeqTokens(1, 1250, 4) // 40,000 bits: two whole FIPS blocks.
	var first string
	for _, percent := range []float64{0.001, 1, 10} {
		rec := postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": tokens, "significance_percent": percent})
		if rec.Code != http.StatusOK {
			t.Fatalf("status at %g%% = %d: %s", percent, rec.Code, rec.Body.String())
		}
		rep := decodeSequencerReport(t, rec)
		if rep.Grade != "pass" {
			t.Fatalf("grade at %g%% = %q, want pass: this sample fills two whole FIPS blocks and passes the battery.", percent, rep.Grade)
		}
		if first == "" {
			first = rep.Verdict
		} else if rep.Verdict != first {
			t.Fatalf("the verdict sentence changed with the significance level. Every FIPS 140-2 threshold is a constant of the standard, not a function of a chosen confidence.")
		}
	}
}

func containsSub(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
