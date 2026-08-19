package scanner

import (
	"strings"
	"testing"
)

// enclosureOfCanary is the common shape of these tests: find the canary, ask what encloses it.
func enclosureOfCanary(t *testing.T, script, canary string) (jsEnclosure, bool) {
	t.Helper()
	i := strings.Index(script, canary)
	if i < 0 {
		t.Fatalf("canary %q not present in %q", canary, script)
	}
	return jsEnclosureAt(script, i)
}

func TestJSEnclosureAtPlacesTheCanary(t *testing.T) {
	const c = "ZCAN"
	cases := []struct {
		name string
		src  string
		want jsEnclosure
	}{
		{"single-quoted string", `var a = 'ZCAN';`, jsEncSingleQuote},
		{"double-quoted string", `var a = "ZCAN";`, jsEncDoubleQuote},
		{"template literal", "var a = `ZCAN`;", jsEncTemplate},
		{"code position", `var a = 1; ZCAN();`, jsEncCode},
		{"line comment", `// ZCAN`, jsEncLineComment},
		{"block comment", `/* ZCAN */`, jsEncBlockComment},
		{"regex literal", `var re = /ZCAN/;`, jsEncRegex},
		{"after a closed string", `var a = 'x'; ZCAN();`, jsEncCode},
		{"second string on a line", `var a = 'x', b = "ZCAN";`, jsEncDoubleQuote},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := enclosureOfCanary(t, tc.src, c)
			if !ok {
				t.Fatalf("lexer declined to place the canary in %q", tc.src)
			}
			if got != tc.want {
				t.Errorf("enclosure = %v, want %v", got, tc.want)
			}
		})
	}
}

// The measured false positive, in full. json.Marshal doubles the payload's backslash, so the quote
// that was meant to terminate the literal is itself escaped and terminates nothing — while the
// marker substring the old check looked for is plainly present.
func TestJSONEscapedPayloadIsNotABreakout(t *testing.T) {
	const canary = "zxssdeadbeef"
	payload := scriptBreakoutPayload(canary)
	marker := xssScriptBreakoutMarker(canary)

	// What json.Marshal does to the payload: `\` becomes `\\`, `'` is left alone.
	escaped := strings.ReplaceAll(payload, `\`, `\\`)
	script := `var conf = "` + escaped + `";`

	if !strings.Contains(script, marker) {
		t.Fatalf("precondition failed: the old substring marker should still be present in %q", script)
	}
	if jsBreakoutConfirmed(script, canary) {
		t.Errorf("json.Marshal-escaped payload must NOT count as a breakout:\n  %s", script)
	}
}

// The other side of the same coin: when the quote really does terminate the literal and the canary
// reaches executable position, it is a breakout and must still be reported.
func TestRealBreakoutIsStillConfirmed(t *testing.T) {
	const canary = "zxssdeadbeef"
	script := `var a = ''; ` + canary + `_marker();`
	if !jsBreakoutConfirmed(script, canary) {
		t.Errorf("a canary in executable position is a real breakout: %q", script)
	}
}

// A payload that leaves the script unparseable executes nothing, so it is not evidence of
// execution either.
func TestUnparseableScriptIsNotABreakout(t *testing.T) {
	const canary = "zxssdeadbeef"
	script := `var a = ''; ` + canary + ` ((( ;`
	if jsBreakoutConfirmed(script, canary) {
		t.Errorf("a syntactically broken script must not be reported as a breakout: %q", script)
	}
}

// A canary that never leaves its literal is inert no matter how many quotes surround it.
func TestCanaryInsideLiteralIsNeverABreakout(t *testing.T) {
	const canary = "zxssdeadbeef"
	for _, script := range []string{
		`var a = '` + canary + `';`,
		`var a = "` + canary + `";`,
		"var a = `" + canary + "`;",
		`var a = '\'` + canary + `\'';`, // escaped quotes inside the literal
	} {
		if jsBreakoutConfirmed(script, canary) {
			t.Errorf("canary is still inside its literal, not a breakout: %q", script)
		}
	}
}

// Two occurrences, the first inert and the second in code position: that is a real breakout, and
// stopping at the first occurrence would miss it.
func TestSecondOccurrenceCanBeTheBreakout(t *testing.T) {
	const canary = "zxssdeadbeef"
	script := `var a = '` + canary + `'; ` + canary + `_marker();`
	if !jsBreakoutConfirmed(script, canary) {
		t.Errorf("the second occurrence reaches code position: %q", script)
	}
}

// A quote inside a regex literal must not be mistaken for a string delimiter — minified pages
// produce exactly this.
func TestQuoteInsideRegexDoesNotOpenAString(t *testing.T) {
	script := `var re = /['"]/; var a = 'ZCAN';`
	got, ok := enclosureOfCanary(t, script, "ZCAN")
	if !ok {
		t.Fatal("lexer declined")
	}
	if got != jsEncSingleQuote {
		t.Errorf("enclosure = %v, want single-quoted string (regex must not leak state)", got)
	}
}

// An unterminated literal is not something this lexer models, and it declines rather than guessing.
func TestUnterminatedLiteralDeclines(t *testing.T) {
	if _, ok := jsEnclosureAt(`var a = 'unterminated`, 100); ok {
		t.Error("an offset past the end must not be placed")
	}
	script := `var a = 'oops` + "\n" + `ZCAN`
	if _, ok := enclosureOfCanary(t, script, "ZCAN"); ok {
		t.Error("an unescaped newline in a string literal should make the lexer decline")
	}
}

func TestScriptBodiesExtractsEachScript(t *testing.T) {
	body := `<p>x</p><script>var a=1;</script><div></div><script type="text/javascript">var b=2;</script>`
	got := scriptBodies(body)
	if len(got) != 2 {
		t.Fatalf("want 2 scripts, got %d: %+v", len(got), got)
	}
	if got[0].Source != `var a=1;` || got[1].Source != `var b=2;` {
		t.Fatalf("wrong sources: %q / %q", got[0].Source, got[1].Source)
	}
	// The offsets must actually locate the source within the document.
	for i, sb := range got {
		if body[sb.Offset:sb.Offset+len(sb.Source)] != sb.Source {
			t.Errorf("script %d offset %d does not locate its source", i, sb.Offset)
		}
	}
}

func TestScriptBodiesHandlesUnterminatedScript(t *testing.T) {
	body := `<script>var a=1;`
	got := scriptBodies(body)
	if len(got) != 1 || got[0].Source != `var a=1;` {
		t.Fatalf("an unterminated <script> runs to end of document, got %+v", got)
	}
}
