package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sequencerReport mirrors the UI's SequencerReport shape (internal/web/ui/src/sequencer.ts)
// so a test can assert the wire contract without importing internals it should not.
type sequencerReport struct {
	Tokens           int              `json:"tokens"`
	Encoding         string           `json:"encoding"`
	EncodingDetected bool             `json:"encoding_detected"`
	Characters       charAnalysisView `json:"characters"`
	Bits             bitStatsView     `json:"bits"`
	Fips             fipsReportView   `json:"fips"`
	Grade            string           `json:"grade"`
	Verdict          string           `json:"verdict"`
	Warnings         []string         `json:"warnings"`
}

type charAnalysisView struct {
	AlphabetSize   int     `json:"alphabet_size"`
	MinLen         int     `json:"min_len"`
	MaxLen         int     `json:"max_len"`
	Positions      []any   `json:"positions"`
	TotalEntropy   float64 `json:"total_entropy_bits"`
	MaxPossible    float64 `json:"max_possible_bits"`
	EntropyCeiling float64 `json:"entropy_ceiling_bits"`
}

type bitStatsView struct {
	Bits int `json:"bits"`
}

type fipsReportView struct {
	BlocksTested int `json:"blocks_tested"`
	BitsUntested int `json:"bits_untested"`
	Tests        any `json:"tests"`
}

func decodeSequencerReport(t *testing.T, rec *httptest.ResponseRecorder) sequencerReport {
	t.Helper()
	var rep sequencerReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode sequencer report %q: %v", rec.Body.String(), err)
	}
	return rep
}

func hexSeqTokens(seed uint64, count, bytesEach int) []string {
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

// The Rust route test this mirrors (crates/web/src/routes/sequencer.rs,
// a_pasted_token_list_is_analysed_in_one_call): 400 tokens of 8 hex characters
// is 12,800 bits — short of one block, so the honest answer is no verdict.
func TestPastedTokenListIsAnalysedInOneCall(t *testing.T) {
	s := newTestServer()
	var lines []string
	for i := uint32(0); i < 400; i++ {
		lines = append(lines, fmt.Sprintf("%08x", i*2654435761))
	}
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]string{"text": strings.Join(lines, "\n")})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rep := decodeSequencerReport(t, rec)
	if rep.Tokens != 400 {
		t.Errorf("tokens = %d, want 400", rep.Tokens)
	}
	if rep.Encoding != "hex" {
		t.Errorf("encoding = %q, want hex", rep.Encoding)
	}
	if !rep.EncodingDetected {
		t.Errorf("encoding_detected = false, want true")
	}
	if rep.Characters.AlphabetSize != 16 {
		t.Errorf("alphabet_size = %d, want 16", rep.Characters.AlphabetSize)
	}
	if len(rep.Characters.Positions) != 8 {
		t.Errorf("positions = %d, want 8", len(rep.Characters.Positions))
	}
	if rep.Bits.Bits != 12800 {
		t.Errorf("bits = %d, want 12800", rep.Bits.Bits)
	}
	if rep.Grade != "insufficient" {
		t.Errorf("grade = %q, want insufficient", rep.Grade)
	}
	if rep.Fips.Tests != nil {
		t.Errorf("fips.tests = %v, want null", rep.Fips.Tests)
	}
	if rep.Fips.BitsUntested != 12800 {
		t.Errorf("bits_untested = %d, want 12800", rep.Fips.BitsUntested)
	}
}

// Paste mode is not traffic, so it needs no scope decision. Restricting scope
// and confirming the paste still works pins that a future gate cannot be added
// on the plausible-but-wrong theory that pasted tokens are a request.
func TestPasteModeAnalysesTokensForAHostThatIsWhollyOutOfScope(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": "authorised.test"}); rec.Code != http.StatusOK {
		t.Fatalf("restrict scope: status = %d, want 200", rec.Code)
	}
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]string{"text": "abcd\nefab\n1234"})
	if rec.Code != http.StatusOK {
		t.Fatalf("pasted text is not traffic and needs no authorisation: status = %d, want 200", rec.Code)
	}
	rep := decodeSequencerReport(t, rec)
	if rep.Tokens != 3 {
		t.Errorf("tokens = %d, want 3", rep.Tokens)
	}
}

// An empty paste is answered rather than refused: the report says "no tokens
// were supplied", and that is more useful than a 400 with no analysis in it.
func TestEmptyPasteGetsAReportThatSaysSoRatherThanAnError(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]string{"text": "  \n\n"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rep := decodeSequencerReport(t, rec)
	if rep.Tokens != 0 {
		t.Errorf("tokens = %d, want 0", rep.Tokens)
	}
	if rep.Grade != "insufficient" {
		t.Errorf("grade = %q, want insufficient", rep.Grade)
	}
	if !warnContains(rep.Warnings, "no tokens") {
		t.Errorf("warnings = %q, want one mentioning 'no tokens'", rep.Warnings)
	}
}

func TestPasteWithNeitherTextNorTokensIsRefused(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]interface{}{})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUnknownEncodingIsNamedRatherThanIgnored(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]string{"text": "ab\ncd", "encoding": "rot13"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rot13") {
		t.Errorf("body = %q, want it to name the bad encoding", rec.Body.String())
	}
}

// The pre-split tokens path, and the filtering rule that goes with it: an empty
// string is dropped rather than analysed, matching the Rust handler's filter.
func TestTokensArrayIsAcceptedAndEmptyEntriesAreDropped(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]interface{}{"tokens": []string{"abc", "", "def"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rep := decodeSequencerReport(t, rec)
	if rep.Tokens != 2 {
		t.Errorf("tokens = %d, want 2 (empty entry dropped)", rep.Tokens)
	}
	if !rep.EncodingDetected {
		t.Errorf("encoding_detected = false, want true (no encoding supplied)")
	}
}

// Forcing raw on hex tokens doubles the bit count and the report says the
// operator chose the view rather than claiming it was detected.
func TestForcedEncodingIsReportedAsChosen(t *testing.T) {
	s := newTestServer()
	tokens := hexSeqTokens(5, 40, 4)
	detected := postJSON(t, s, "/api/sequencer/analyse", map[string]string{"text": strings.Join(tokens, "\n")})
	forced := postJSON(t, s, "/api/sequencer/analyse", map[string]string{
		"text":     strings.Join(tokens, "\n"),
		"encoding": "raw",
	})
	det := decodeSequencerReport(t, detected)
	rec := decodeSequencerReport(t, forced)
	if rec.Encoding != "raw" {
		t.Errorf("encoding = %q, want raw", rec.Encoding)
	}
	if rec.EncodingDetected {
		t.Errorf("encoding_detected = true, want false for a forced view")
	}
	if rec.Bits.Bits != det.Bits.Bits*2 {
		t.Errorf("raw view = %d bits, want twice the %d of the hex view", rec.Bits.Bits, det.Bits.Bits)
	}
}

// The happy path over the wire: 1,250 x 8-hex tokens is 40,000 bits, two whole
// blocks, and a genuine random stream passes all four tests.
func TestHealthyPasteThatFillsABlockReportsAPass(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]string{"text": strings.Join(hexSeqTokens(1, 1250, 4), "\n")})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rep := decodeSequencerReport(t, rec)
	if rep.Fips.Tests == nil {
		t.Fatalf("fips.tests = null, want a suite for a whole-block sample")
	}
	if rep.Fips.BlocksTested != 2 {
		t.Errorf("blocks_tested = %d, want 2", rep.Fips.BlocksTested)
	}
	if rep.Grade != "pass" {
		t.Errorf("grade = %q, verdict = %q", rep.Grade, rep.Verdict)
	}
	if !strings.Contains(rep.Verdict, "All four FIPS 140-2 tests passed") {
		t.Errorf("verdict = %q, want the pass sentence", rep.Verdict)
	}
}

func warnContains(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
