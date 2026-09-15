package sequencer

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Burp's "Pad short tokens at start / end": the statistical tests can only run over tokens of one
// length, so a sample of variable-length tokens is padded up to the longest. WHERE the padding goes
// changes the answer — a token padded at the wrong end shifts every byte position the character and
// bit analyses are computed over, which is the whole reason Burp asks rather than choosing.
func TestPaddingFillsShortTokensAtTheChosenEndAndReportsHowMany(t *testing.T) {
	tokens := []string{"abcd", "ab", "a"}

	start, padStart := padTokens(tokens, PadStart, '0')
	if start[1] != "00ab" || start[2] != "000a" {
		t.Errorf("pad-start produced %q; a start-padded token must keep its own bytes at the END, or every position the analysis reads is shifted", start)
	}
	end, _ := padTokens(tokens, PadEnd, '0')
	if end[1] != "ab00" || end[2] != "a000" {
		t.Errorf("pad-end produced %q; an end-padded token must keep its own bytes at the START", end)
	}
	if start[0] != "abcd" || end[0] != "abcd" {
		t.Error("the longest token was padded; it defines the width and must be left exactly as supplied")
	}

	// The count is sample metadata Burp reports, and it has to be the number of tokens actually
	// touched — not the sample size — or it cannot answer "how much of this analysis is my padding?"
	if padStart.TokensPadded != 2 {
		t.Errorf("tokens_padded = %d, want 2: only the two short tokens were padded", padStart.TokensPadded)
	}
	if padStart.PadBytesAdded != 5 {
		t.Errorf("pad_bytes_added = %d, want 5 (2 + 3)", padStart.PadBytesAdded)
	}
	if padStart.OrigMinLen != 1 || padStart.OrigMaxLen != 4 {
		t.Errorf("orig len range = %d..%d, want 1..4", padStart.OrigMinLen, padStart.OrigMaxLen)
	}

	// Off is off: no padding, and nothing claimed.
	none, padNone := padTokens(tokens, PadNone, '0')
	if len(none[2]) != 1 || padNone.TokensPadded != 0 {
		t.Errorf("PadNone changed the sample (%q, padded=%d); the default must leave it exactly as supplied", none, padNone.TokensPadded)
	}
}

// Burp's "Base64-decode before analyzing": a base64 token's randomness lives in the bytes it
// encodes, not in the alphabet it is written with. Analysing the text instead measures the encoding.
func TestBase64DecodeAnalysesTheUnderlyingBytesAndSaysSo(t *testing.T) {
	raw := []string{"\x00\x01\x02\x03", "\xfe\xfd\xfc\xfb", "\x10\x20\x30\x40"}
	encoded := make([]string, len(raw))
	for i, r := range raw {
		encoded[i] = base64.StdEncoding.EncodeToString([]byte(r))
	}

	rep, err := AnalyseOpts(encoded, Options{Base64Decode: true, SignificancePercent: 1, SignificanceDefaulted: true})
	if err != nil {
		t.Fatalf("AnalyseOpts: %v", err)
	}
	if !rep.Base64Decoded {
		t.Error("the report does not say it decoded, so a reader cannot tell which sample the numbers describe")
	}
	// Four raw bytes per token, not the eight characters of their base64 text.
	if rep.Padding.OrigMaxLen != 0 && rep.Padding.OrigMaxLen != 4 {
		t.Errorf("token width after decoding = %d, want the 4 decoded bytes rather than the 8 encoded characters", rep.Padding.OrigMaxLen)
	}
}

// A sample that is not base64 must be refused by name rather than analysed as something else.
// Silently passing the undecodable token through would mean the report described a sample the
// operator never supplied — half decoded, half not — with nothing saying so.
func TestBase64DecodeRefusesATokenThatIsNotBase64AndNamesIt(t *testing.T) {
	_, err := AnalyseOpts([]string{"aGVsbG8=", "not valid base64!!"}, Options{
		Base64Decode: true, SignificancePercent: 1, SignificanceDefaulted: true,
	})
	if err == nil {
		t.Fatal("a non-base64 token was accepted while base64-decode was on; the report would describe a sample that was never supplied")
	}
	if !strings.Contains(err.Error(), "token 1") {
		t.Errorf("the refusal %q does not name WHICH token is at fault, so the operator cannot act on it", err)
	}
}
