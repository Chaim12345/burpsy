package sequencer

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// The web report carries the uniformity and duplicate statistics the CLI has
// always printed from the same package (burpsy-react-ui-3sq). The wire shape is
// the contract: extra_stats rides the report, each number labelled for what it
// measures, and serial correlation is explicitly NOT Burp's bit-position
// correlation test.

// A duplicated token shows up in the duplicate count and the list names it.
// A session-token sample with a repeat is a finding on its own; this is the
// number that says so.
func TestReportCarriesTheDuplicateTokenCount(t *testing.T) {
	tokens := make([]string, 0, 60)
	for i := range 20 {
		tokens = append(tokens, "abcdefgh"+fmt.Sprintf("%04x", i)+"0") // all distinct
		tokens = append(tokens, "abcdefgh"+fmt.Sprintf("%04x", i)+"1") // all distinct
		tokens = append(tokens, "abcdefgh99999999")                    // the one repeat
	}
	r := AnalyseReport(tokens)
	// DetectPatterns counts DISTINCT tokens that repeat: exactly the sentinel.
	if r.ExtraStats.RepeatedTokens != 1 {
		t.Fatalf("repeated tokens = %d, want 1 (the sentinel token)", r.ExtraStats.RepeatedTokens)
	}
	if len(r.ExtraStats.RepeatedList) != 1 || r.ExtraStats.RepeatedList[0] != "abcdefgh99999999" {
		t.Fatalf("repeated list = %v, want the sentinel token named", r.ExtraStats.RepeatedList)
	}
}

// A clean sample reports zero duplicates and an empty list.
func TestReportShowsZeroDuplicatesForDistinctTokens(t *testing.T) {
	tokens := make([]string, 0, 40)
	for i := range 40 {
		tokens = append(tokens, "token-"+fmt.Sprintf("%02d", i)+"-"+strings.Repeat("x", 4))
	}
	r := AnalyseReport(tokens)
	if r.ExtraStats.RepeatedTokens != 0 || len(r.ExtraStats.RepeatedList) != 0 {
		t.Fatalf("distinct tokens reported %d repeats %v", r.ExtraStats.RepeatedTokens, r.ExtraStats.RepeatedList)
	}
}

// Chi-square is 0 for a perfectly uniform corpus and rises with skew: larger
// means less uniform, which is the only claim the label may make (it is not a
// p-value, and the engine's own semantics — expected = total/distinct — give
// exactly 0 when every character appears equally often).
func TestReportCarriesChiSquareAndItRisesWithSkew(t *testing.T) {
	uniform := make([]string, 0, 160)
	skewed := make([]string, 0, 160)
	// 4-character tokens over the same 4-character alphabet; the skewed corpus
	// leans on 'a' overwhelmingly.
	for i := range 40 {
		for _, combo := range []string{"abcd", "bcda", "cdab", "dabc"} {
			uniform = append(uniform, combo)
			skewed = append(skewed, "aa"+string(rune('b'+i%2))+string(rune('b'+(i+1)%2)))
		}
	}
	ru, rs := AnalyseReport(uniform), AnalyseReport(skewed)
	if ru.ExtraStats.ChiSquare != 0 {
		t.Fatalf("perfectly uniform corpus chi-square = %f, want exactly 0 (every character equally often)", ru.ExtraStats.ChiSquare)
	}
	if rs.ExtraStats.ChiSquare <= ru.ExtraStats.ChiSquare {
		t.Fatalf("skewed chi-square (%f) did not exceed uniform (%f); larger must mean less uniform", rs.ExtraStats.ChiSquare, ru.ExtraStats.ChiSquare)
	}
}

// The serial-correlation caveat travels with the number, so the JSON can never
// be read as Burp's bit-position correlation test without the label saying it
// is not that.
func TestSerialCorrelationLabelNamesTheCaveat(t *testing.T) {
	r := AnalyseReport([]string{"abc", "def", "ghi"})
	if !strings.Contains(r.ExtraStats.SerialCorrelationLabel, "not Burp's") {
		t.Fatalf("serial correlation label = %q, must say it is not Burp's correlation test", r.ExtraStats.SerialCorrelationLabel)
	}
	if r.ExtraStats.SerialCorrelation < -1 || r.ExtraStats.SerialCorrelation > 1 {
		t.Fatalf("serial correlation = %f, outside [-1, 1]", r.ExtraStats.SerialCorrelation)
	}
}

// Monte-Carlo pi is reported with its deviation, and a known-good stream
// (alternating low/high codes) produces a deviation that is finite.
func TestReportCarriesMonteCarloPi(t *testing.T) {
	r := AnalyseReport([]string{"abc", "def", "ghi", "jkl"})
	if math.IsNaN(r.ExtraStats.MonteCarloPi) || math.IsInf(r.ExtraStats.MonteCarloPi, 0) {
		t.Fatalf("monte carlo pi = %f, want a finite estimate", r.ExtraStats.MonteCarloPi)
	}
	if r.ExtraStats.MonteCarloDeviation < 0 {
		t.Fatalf("deviation = %f, cannot be negative", r.ExtraStats.MonteCarloDeviation)
	}
}
