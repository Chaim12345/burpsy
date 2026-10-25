package scanner

// TE.0 / chunk-extension / 0.CL-Expect differentials and the post-timing canary confirmation
// (burpsy-react-ui-0vzb.40 remainder). RED: none of this exists yet - a timing-confirmed
// finding carries timing evidence only, the chunk-extension terminator is never tried, and
// the Expect fixture pair does not exist.

import (
	"strings"
	"testing"
)

// After a CL.TE timing hit confirms, the smuggled-prefix differential runs under the SAME
// framing: the canary's answer lands in the follow-up's slot, and the finding's evidence
// carries it. Today the evidence is timing-only.
func TestTimingHitIsConfirmedByTheCanaryDifferential(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-clte")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	f := onlySmugglingFinding(t, fs)
	if f.Param != "CL.TE plain" {
		t.Fatalf("param = %q, want the timing technique and spelling", f.Param)
	}
	if !strings.Contains(f.Evidence, "-canary-404") {
		t.Fatalf("a confirmed timing hit was not followed by the canary differential; evidence: %s", f.Evidence)
	}
}

// The confirmation runs under the spelling the timing hit named: on the obfuscated fixture
// the front end only falls back to Content-Length for the obfuscated spelling, so the canary
// differential lands under that spelling and the evidence says so.
func TestTimingHitConfirmationNamesTheObfuscatedSpelling(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-clte-obfuscated")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	f := onlySmugglingFinding(t, fs)
	if f.Param != "CL.TE space-before-colon" {
		t.Fatalf("param = %q, want CL.TE space-before-colon", f.Param)
	}
	if !strings.Contains(f.Evidence, "-canary-404") {
		t.Fatalf("no canary confirmation under the obfuscated spelling; evidence: %s", f.Evidence)
	}
}

// NO COVERAGE LOSS: where the differential cannot land (the back end reads the whole body, so
// nothing is left to re-parse), the timing-confirmed finding stands exactly as it does today.
func TestTimingHitStandsWhenTheDifferentialFindsNothing(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-tecl")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	f := onlySmugglingFinding(t, fs)
	if f.Param != "TE.CL plain" {
		t.Fatalf("param = %q, want TE.CL plain", f.Param)
	}
	if strings.Contains(f.Evidence, "-canary-404") {
		t.Fatalf("the differential claims a canary on a fixture whose back end consumes the whole body; evidence: %s", f.Evidence)
	}
	if !strings.HasPrefix(f.Evidence, "TE.CL via plain: the attack request got no response") {
		t.Fatalf("the timing evidence shape changed: %s", f.Evidence)
	}
}

// The extension-terminated zero chunk is tried first - it is the shape that slips past
// strict chunk parsers - and the evidence names it when it lands.
func TestChunkExtensionTerminatorIsTriedAndNamed(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-clte")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	f := onlySmugglingFinding(t, fs)
	if !strings.Contains(f.Evidence, "0;burpsy=") {
		t.Fatalf("the chunk-extension terminator was not tried first (or not named); evidence: %s", f.Evidence)
	}
}

// A back end that REFUSES the extension-terminated chunk (400, connection closed) makes that
// shape's batch unreadable: the check degrades to the plain terminator instead of erroring,
// and the evidence names the plain one.
func TestChunkExtensionRefusalDegradesToThePlainTerminator(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-chunkext-refused")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	f := onlySmugglingFinding(t, fs)
	if !strings.Contains(f.Evidence, "-canary-404") || strings.Contains(f.Evidence, "0;burpsy=") {
		t.Fatalf("expected the plain terminator named after the extension refusal; evidence: %s", f.Evidence)
	}
}

// 0.CL/Expect: the back end answers an Expect-bearing POST without reading its declared body;
// the body bytes parse as the next request and the canary's answer takes the follow-up's
// slot. The consistently framed control pair on the same keep-alive discipline answers
// normally.
func TestExpectSkipBodyDifferentialReports(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-expect")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	f := onlySmugglingFinding(t, fs)
	if f.Param != "0.CL Expect" {
		t.Fatalf("param = %q, want 0.CL Expect", f.Param)
	}
	if !strings.Contains(f.Evidence, "-canary-404") {
		t.Fatalf("no canary in the follow-up slot; evidence: %s", f.Evidence)
	}
}

// Safe twin: both hops read the declared body - nothing is left to re-parse, nothing is
// reported.
func TestDifferentialsStayQuietWhenBothHopsReadTheBody(t *testing.T) {
	fs, err, _ := runSmuggling(t, "desync-clcl")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	for _, x := range fs {
		if x.Name == smugglingRow {
			t.Fatalf("both-hops-CL twin reported: %+v", x)
		}
	}
}

func onlySmugglingFinding(t *testing.T, fs []*Finding) *Finding {
	t.Helper()
	var f *Finding
	for _, x := range fs {
		if x.Name == smugglingRow {
			if f != nil {
				t.Fatalf("more than one smuggling finding: %v", fs)
			}
			f = x
		}
	}
	if f == nil {
		t.Fatalf("no smuggling finding (got %v)", fs)
	}
	return f
}
