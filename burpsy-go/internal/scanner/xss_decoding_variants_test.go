package scanner

// burpsy-react-ui-79ld end to end and byte for byte: the five Burp decoding variants a
// reflected-XSS breakout is retried in when the plain payload failed, the Raw apply mode that
// carries their bytes to the wire verbatim, and the two findings a variant can produce —
// the breakout that names its decoding, and the transformation that did not break out.
//
// Burp's shape (Zwe8.java:11-34, Zp9v.java, Zguu.java:63-77) is CONFIRMED from the decompile;
// the URL/HTML/backslash payload literals are ZKM-stripped there, so burpsy's encoders are
// its own and the byte-level pins below are the contract. The overlong encoder's output for
// 'A' is pinned against Burp's own recovered marker bytes {0xC1, 0x81} (Zp9c.java:6) — the
// one place where a recovered literal exists to check against.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// variantPlain is the text-node breakout the check's context bank sends, with a fixed canary
// so the encoder pins are byte-exact rather than shape-only.
const variantPlain = "<svg id=zxss42 onload=alert(1)>"

// TestTheURIDecodingVariantIsDoubleEscapedOnTheWire pins the URL encoder's exact output: every
// non-literal byte percent-encoded once, then the percent signs escaped once more. The double
// escape is the point — a `k=v` container decodes once in transit, so the application receives
// the singly-encoded form, which is what IT must decode for the variant to differ from plain.
func TestTheURIDecodingVariantIsDoubleEscapedOnTheWire(t *testing.T) {
	got := urlDecodingEncode(variantPlain)
	want := "%253Csvg%2520id%253Dzxss42%2520onload%253Dalert%25281%2529%253E"
	if got != want {
		t.Fatalf("URL variant = %q, want %q: the wire form must be the single-encoded payload "+
			"with every percent escaped once more, or the container's own decode eats the variant", got, want)
	}
}

// TestTheHTMLDecodingVariantSpellsTheEntities pins the entity spelling, including the
// transport-unsafe `&` the Raw apply will escape for the container and the container will
// decode back — composed, the application receives exactly this string.
func TestTheHTMLDecodingVariantSpellsTheEntities(t *testing.T) {
	got := htmlDecodingEncode(variantPlain)
	want := "&lt;svg id=zxss42 onload=alert(1)&gt;"
	if got != want {
		t.Fatalf("HTML variant = %q, want %q", got, want)
	}
}

// TestTheBackslashVariantSpellsHexEscapes pins the \xHH spelling of the bytes that carry the
// markup. The `=` beside the canary is escaped too, which is what makes the variant's
// transformMarker (`=CANARY`) impossible in the wire form.
func TestTheBackslashVariantSpellsHexEscapes(t *testing.T) {
	got := backslashUnescapingEncode(variantPlain)
	want := "\\x3csvg id\\x3dzxss42 onload\\x3dalert(1)\\x3e"
	if got != want {
		t.Fatalf("backslash variant = %q, want %q", got, want)
	}
}

// TestTheOverlongVariantReproducesBurpsRecoveredMarker is the one byte-level cross-check
// against the decompile: Zp9c.java's overlong marker is {0xC1, 0x81}, the two-byte overlong
// encoding of 'A', and this encoder must produce exactly those bytes for that input — the
// evidence that the spelling is Burp's decoder population rather than an invention.
func TestTheOverlongVariantReproducesBurpsRecoveredMarker(t *testing.T) {
	// The formula this encoder applies — lead 0xC0|(c>>6), continuation 0x80|(c&0x3F) — over
	// 'A' is exactly Zp9c.java's recovered marker pair, which is the evidence that the
	// spelling is Burp's decoder population. Pinned by computing it here rather than by
	// running the encoder (which targets the markup-carrying bytes, and 'A' is not one).
	lead, cont := byte(0xC0|('A'>>6)), byte(0x80|('A'&0x3F))
	if lead != 0xC1 || cont != 0x81 {
		t.Fatalf("the overlong formula spells 'A' as %02X %02X, want C1 81 (Zp9c.java's "+
			"recovered marker bytes) — the formula has drifted from Burp's", lead, cont)
	}
	// And the payload's own tag bytes, spelled out so a drifted formula cannot pass as
	// shape: the angle brackets and the spaces are the bytes that carry the markup.
	if got := overlongUTF8Encode(variantPlain); got != string([]byte{
		0xC0, 0xBC, 's', 'v', 'g', 0xC0, 0xA0, 'i', 'd', '=', 'z', 'x', 's', 's', '4', '2',
		0xC0, 0xA0, 'o', 'n', 'l', 'o', 'a', 'd', '=', 'a', 'l', 'e', 'r', 't', '(', '1', ')',
		0xC0, 0xBE,
	}) {
		t.Fatalf("overlong encode of the breakout = %x", got)
	}
}

// TestTheInvalidVariantCarriesNoLiteralTargetByte pins the malformed three-byte spelling: the
// low six bits of each byte, with no continuation validation, and — the property the whole
// variant rests on — the literal '<' byte (0x3C) nowhere in the wire form, so a filter that
// strips the literal cannot see it.
func TestTheInvalidVariantCarriesNoLiteralTargetByte(t *testing.T) {
	got := invalidUTF8Encode(variantPlain)
	if strings.ContainsRune(got, '<') || strings.ContainsRune(got, '>') {
		t.Fatalf("invalid variant %q carries the literal byte it is meant to hide", got)
	}
	want := string([]byte{
		0xE0, 0x40, 0x7C, 's', 'v', 'g', 0xE0, 0x40, 0x60, 'i', 'd', '=', 'z', 'x', 's', 's', '4', '2',
		0xE0, 0x40, 0x60, 'o', 'n', 'l', 'o', 'a', 'd', '=', 'a', 'l', 'e', 'r', 't', '(', '1', ')',
		0xE0, 0x40, 0x7E,
	})
	if got != want {
		t.Fatalf("invalid encode of the breakout = %x, want %x", got, want)
	}
}

// rawFixture is a one-query-parameter request the Raw apply tests splice into.
const rawFixture = "GET /r?term=seed HTTP/1.1\r\nHost: target\r\n\r\n"

// termPoint enumerates the fixture's query point.
func termPoint(t *testing.T) bcheck.InsertionPoint {
	t.Helper()
	points, _ := bcheck.Enumerate([]byte(rawFixture), []string{"query"})
	for _, p := range points {
		if p.Name == "term" {
			return p
		}
	}
	t.Fatal("no query point named term was enumerated")
	return bcheck.InsertionPoint{}
}

// TestRawApplyLeavesTheVariantBytesUntouched is the transport half of the variant design: the
// percent-escape the application is meant to decode and the overlong UTF-8 bytes must reach
// the wire verbatim, where the ordinary apply would have rewritten both (the double-encoded
// URL variant, the ASCII text spelling of the UTF-8 bytes).
func TestRawApplyLeavesTheVariantBytesUntouched(t *testing.T) {
	p := termPoint(t)
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"percent escape", "%3Csvg%20id%3Dzxss42"},
		{"overlong bytes", string([]byte{0xC0, 0xBC, 's', 'v', 'g'})},
		{"invalid bytes", string([]byte{0xE0, 0x40, 0x7C, 's', 'v', 'g'})},
	} {
		mutated, err := p.ApplyOpts([]byte(rawFixture), tc.payload, false, bcheck.ApplyOptions{Raw: true})
		if err != nil {
			t.Fatalf("%s: apply: %v", tc.name, err)
		}
		if !strings.Contains(string(mutated), tc.payload) {
			t.Errorf("%s: the raw apply rewrote the payload — the variant cannot fire on bytes "+
				"that did not reach the target", tc.name)
		}
		// And the ordinary apply DOES rewrite them, which is why the option exists.
		plain, err := p.Apply([]byte(rawFixture), tc.payload, false)
		if err != nil {
			t.Fatalf("%s: apply: %v", tc.name, err)
		}
		if strings.Contains(string(plain), tc.payload) {
			t.Errorf("%s: the ordinary apply left %x untouched, so the Raw option is a no-op and "+
				"the test above pins nothing", tc.name, tc.payload)
		}
	}
}

// TestRawApplyStillEscapesTheContainerSeparators pins the half Raw keeps: the bytes that
// decide how a `k=v` container is read still leave escaped, or a variant payload would
// splice itself a second parameter and probe a different place than the one enumerated.
func TestRawApplyStillEscapesTheContainerSeparators(t *testing.T) {
	p := termPoint(t)
	mutated, err := p.ApplyOpts([]byte(rawFixture), "a&b=c d", false, bcheck.ApplyOptions{Raw: true})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if s := string(mutated); strings.Contains(s, "a&b=c d") || !strings.Contains(s, "a%26b%3Dc%20d") {
		t.Fatalf("raw apply produced %q: the separators and the space must stay escaped, or the "+
			"payload rewrites the request's own structure", s)
	}
}

// TestDecodingVariantsMarshalAsAnEmptyListNeverNull is the console half: a finding no variant
// produced must read as an empty list, never as a null an operator could mistake for one.
func TestDecodingVariantsMarshalAsAnEmptyListNeverNull(t *testing.T) {
	blob, err := json.Marshal(struct {
		Variants DecodingVariants `json:"decoding_variants"`
	}{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(blob), "[]") {
		t.Fatalf("a nil DecodingVariants marshalled as %s, want []: a console reading the "+
			"absence of a list as a clean one is the failure the MarshalJSON rule exists for", blob)
	}
	blob, err = json.Marshal(&Finding{Name: "row"})
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if !strings.Contains(string(blob), `"decoding_variants":[]`) {
		t.Fatalf("a finding without variant evidence marshalled as %s, want decoding_variants to "+
			"read [] rather than null", blob)
	}
}

// --- The AuditSession half: each decoding variant finds its endpoint, the safe twins stay
// silent, and the decode-then-encode endpoint reports the transformation, not the breakout. ---

// decodeVariantCase is one variant's end-to-end claim.
type decodeVariantCase struct {
	path       string // the vulnapp endpoint that performs this decoding
	wantVia    string // the decoding the finding's evidence must name
	wantMarker string // the byte marker that proves the decoding when no breakout confirmed
}

// decodingVariantCases are the five, one per variant, each against the endpoint whose decoder
// undoes that variant's spelling. The overlong endpoint REJECTS the invalid variant's
// malformed continuation bytes and the invalid endpoint REJECTS the overlong two-byte form, so
// each pair is isolated: the finding names the decoding that endpoint actually performs.
func decodingVariantCases() []decodeVariantCase {
	return []decodeVariantCase{
		{path: "/ij/xss/decode/url?term=seed", wantVia: "URL decoding", wantMarker: "=zxss"},
		{path: "/ij/xss/decode/html?term=seed", wantVia: "HTML decoding", wantMarker: ""},
		{path: "/ij/xss/decode/backslash?term=seed", wantVia: "backslash unescaping", wantMarker: "=zxss"},
		{path: "/ij/xss/decode/overlong?term=seed", wantVia: "overlong UTF-8 decoding", wantMarker: ""},
		{path: "/ij/xss/decode/invalid?term=seed", wantVia: "invalid UTF-8 decoding", wantMarker: ""},
	}
}

// TestReflectedXSSIsFoundThroughEachDecodingVariant drives the real audit dispatch: the plain
// payload is stripped by every one of these endpoints (that is what they exist to prove), so
// the XSS finding can only exist because a variant's encoded form was decoded — and the
// finding must say WHICH decoding carried it.
func TestReflectedXSSIsFoundThroughEachDecodingVariant(t *testing.T) {
	rt := startRuntimeTarget(t)
	for _, tc := range decodingVariantCases() {
		got := rt.findingsFor(t, tc.path, false)
		f, fired := got[xssReflectedIssue]
		if !fired {
			t.Errorf("%s: the XSS row did not fire; rows reported: %s — the plain payload is "+
				"stripped here, so only a decoded variant can have broken out, and silence means "+
				"the variant never reached the wire or was never decoded",
				tc.path, strings.Join(rowNames(got), ", "))
			continue
		}
		if len(f.DecodingVariants) == 0 {
			t.Errorf("%s: the XSS finding fired but names no decoding variant: %q — evidence "+
				"that does not say how the breakout was carried cannot be distinguished from a "+
				"plain one the endpoint was built to strip", tc.path, f.Evidence)
			continue
		}
		if !strings.Contains(strings.Join(f.DecodingVariants, ","), tc.wantVia) {
			t.Errorf("%s: the finding names %v, want %q: this endpoint's decoder only undoes "+
				"that one spelling, so any other name would mean the wrong variant fired",
				tc.path, f.DecodingVariants, tc.wantVia)
		}
		if !strings.Contains(f.Evidence, "via") {
			t.Errorf("%s: the evidence text %q does not name the decoding: the operator's next "+
				"step depends on knowing the application decodes this input", tc.path, f.Evidence)
		}
	}
}

// TestTheDecodingVariantsStaySilentOnTheSafeTwins is the false-positive half: the safe twins
// keep the strip and add the output encoding a real fix would have, and never decode. A
// variant firing there would mean the detector keyed on reflection rather than on the decode.
func TestTheDecodingVariantsStaySilentOnTheSafeTwins(t *testing.T) {
	rt := startRuntimeTarget(t)
	for _, tc := range decodingVariantCases() {
		path := strings.Replace(tc.path, "/xss/decode/", "/xss/safe/decode/", 1)
		got := rt.findingsFor(t, path, false)
		if f, fired := got[xssReflectedIssue]; fired {
			t.Errorf("%s reported %q with evidence %q: the endpoint output-encodes and never "+
				"decodes, so a breakout here is a false positive with a name attached",
				path, xssReflectedIssue, f.Evidence)
		}
		if f, fired := got["Suspicious input transformation (reflected)"]; fired {
			t.Errorf("%s reported the transformation row (%q): nothing is decoded here, so the "+
				"transformMarker fired on bytes the endpoint never produced", path, f.Evidence)
		}
	}
}

// TestADecodeThenEncodeEndpointReportsTheTransformationNotTheBreakout is the
// UNEXPECTED_TRANSFORMATION half of Burp's pairing: an application that decodes its input and
// then output-encodes the result is not XSS, but the decoding is itself worth the row that
// exists for it — and the XSS row must stay silent, or the variant is a false-positive
// generator against every correctly-escaping app that happens to decode.
func TestADecodeThenEncodeEndpointReportsTheTransformationNotTheBreakout(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/ij/xss/decode/url/escaped?term=seed", false)
	if f, fired := got[xssReflectedIssue]; fired {
		t.Fatalf("the XSS row fired on a decode-then-encode endpoint: %q — the markup is "+
			"neutralized here, so the variant is keying on the decode alone", f.Evidence)
	}
	f, fired := got["Suspicious input transformation (reflected)"]
	if !fired {
		t.Fatalf("the transformation row did not fire on an endpoint that URL-decodes its input "+
			"before output-encoding it; rows reported: %s", strings.Join(rowNames(got), ", "))
	}
	if !strings.Contains(f.Evidence, "URL decoding") {
		t.Errorf("the transformation evidence %q does not name the decoding", f.Evidence)
	}
}

// rowNames lists a finding map's rows for failure messages.
func rowNames(got map[string]*Finding) []string {
	var out []string
	for name := range got {
		out = append(out, name)
	}
	return out
}

// TestTheVulnappDecodingEndpointsAreDeclared ensures the manifest and the mux agree — a
// handler the mux serves but the manifest does not declare is invisible to the sweep, and the
// reverse is a row the sweep audits against a 404.
func TestTheVulnappDecodingEndpointsAreDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, e := range vulnapp.Vulnerabilities() {
		if strings.HasPrefix(e.Path, "/ij/xss/") {
			declared[strings.SplitN(strings.TrimPrefix(e.Path, "/ij/xss/"), "?", 2)[0]] = true
		}
	}
	for _, want := range []string{
		"decode/url", "safe/decode/url", "decode/html", "safe/decode/html",
		"decode/backslash", "safe/decode/backslash", "decode/overlong", "safe/decode/overlong",
		"decode/invalid", "safe/decode/invalid", "decode/url/escaped",
	} {
		if !declared[want] {
			t.Errorf("the manifest does not declare /ij/xss/%s", want)
		}
	}
}

// Burp's file-upload HTML variant (burpsy-react-ui-kzt7), through the real audit: the preview
// endpoint serves an upload by its extension, so only the file re-sent as .html renders, and the
// finding says the upload carried it. The safe twin serves every upload as text and stays silent.
func TestAnUploadServedAsHTMLIsFoundAndItsSafeTwinIsNot(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/ij/upload/preview", false)
	f, fired := got[xssReflectedIssue]
	if !fired {
		t.Fatalf("the upload preview reported no XSS; rows: %s", strings.Join(rowNames(got), ", "))
	}
	if !strings.Contains(strings.Join(f.DecodingVariants, ","), "file upload as notes.txt") ||
		!strings.Contains(strings.Join(f.DecodingVariants, ","), ".html") {
		t.Errorf("the finding names %v, want the .html upload that carried it", f.DecodingVariants)
	}
	if _, fired := rt.findingsFor(t, "/ij/safe/upload/preview", false)[xssReflectedIssue]; fired {
		t.Error("the safe twin, which serves every upload as text/plain, reported XSS")
	}
}
