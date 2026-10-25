package httputil

import "testing"

// The fixtures are the semantics: every case below is one the scanner's ingest gate and
// bcheck's insertion points already agree on, so a future refactor that drifts one copy fails
// here even though the other two are unexported.

func TestGraphQLPercentCodecRoundTripsTheSharedFixtures(t *testing.T) {
	cases := []struct{ decoded, encoded string }{
		{`{book(title:"Dune"){author}}`, "%7Bbook(title:%22Dune%22)%7Bauthor%7D%7D"},
		{"a+b", "a%2Bb"}, // '+' is data, not a space, in both directions
		{"a b", "a%20b"}, // space never travels as '+'
		{"x&y=z", "x%26y%3Dz"},
	}
	for _, c := range cases {
		if got := GraphQLPercentEncode(c.decoded); got != c.encoded {
			t.Errorf("escape %q = %q, want %q", c.decoded, got, c.encoded)
		}
		if got := GraphQLPercentDecode(c.encoded); got != c.decoded {
			t.Errorf("decode %q = %q, want %q", c.encoded, got, c.decoded)
		}
	}
	// Decode-only shapes: a partial hex scan decodes its valid prefix and the scan window is
	// consumed with it (Sscanf semantics, body-identical to the two unexported copies); an
	// escape with no hex digits at all survives as-is.
	if got := GraphQLPercentDecode("%2G"); got != "\x02" {
		t.Errorf("partial hex = %q, want %q", got, "\x02")
	}
	if got := GraphQLPercentDecode("100%"); got != "100%" {
		t.Errorf("lone percent = %q", got)
	}
}

func TestGraphQLJSONStringContentCodecRoundTrips(t *testing.T) {
	for _, s := range []string{
		`{book(title:"Dune"){author}}`,
		"line one\nline two",
		`back\slash`,
		"no escapes at all",
		`<html>&</html>`, // HTML bytes are NOT -escaped: the replacer changes nothing unasked
	} {
		if got := GraphQLJSONStringContentDecode(GraphQLJSONStringContentEncode(s)); got != s {
			t.Errorf("round trip changed %q to %q", s, got)
		}
	}
	// Content that does not unescape comes back unchanged, never an error.
	if got := GraphQLJSONStringContentDecode(`bad\escape`); got != `bad\escape` {
		t.Errorf("invalid escape = %q, want unchanged", got)
	}
}

// The console's looksLikeGraphQLDocument (message-views.ts) is the other spelling of this
// predicate; the two index one operation list, so the shared probe table must read the same
// on both sides. The TS test carries the same table.
func TestLooksLikeGraphQLDocumentMatchesTheConsolePredicate(t *testing.T) {
	probes := []struct {
		in   string
		want bool
	}{
		{"{ a }", true},
		{`{"a":1}`, false},
		{"query Q { a }", true},
		{"mutation M { a }", true},
		{"subscription S { a }", true},
		{"fragment F on T { a }", true},
		{"# a comment\nquery Q { a }", true},
		{"# a comment without a newline", false},
		{"", false},
		{"   ", false},
		{"https://example.test/graphql", false},
		// The keyword boundary is JavaScript's \b: ASCII \w only - '$' and non-ASCII
		// letters END the word there, so these read as the keyword.
		{"query$bad", true},
		{"queryé", true},
		{"queryx", false},
		{"query_2", false},
		{"query2", false},
		// Leading-whitespace parity: the BOM is JavaScript whitespace, NEL (U+0085) is
		// not, and neither is a raw 0x85 byte.
		{"\ufeff{a}", true},
		{"\u0085{a}", false},
		{"\u00a0{a}", true},
	}
	for _, probe := range probes {
		if got := LooksLikeGraphQLDocument(probe.in); got != probe.want {
			t.Errorf("LooksLikeGraphQLDocument(%q) = %v, want %v (the console reads %v)",
				probe.in, got, probe.want, probe.want)
		}
	}
}

// The console's graphQLPercentDecode is the TS spelling of this codec; these pin the Sscanf
// and UTF-8 edges the port must match byte-for-byte.
func TestGraphQLPercentDecodeSscanfAndUTF8Edges(t *testing.T) {
	cases := []struct{ in, want string }{
		{"% 2", "\x02"},  // Sscanf skips leading whitespace in the window
		{"%\t2", "\x02"}, // ... including tabs
		{"%2 ", "\x02"},  // one hex digit then a stop
		{"%2G", "\x02"},  // one hex digit then a non-hex stop
		{"%G2", "%G2"},   // no hex digit: the escape survives
		{"%C3%A9", "é"},  // a UTF-8 sequence decodes to its rune, not mojibake
		{"%FF", "\xff"},  // an undecodable byte stands alone
	}
	for _, c := range cases {
		if got := GraphQLPercentDecode(c.in); got != c.want {
			t.Errorf("GraphQLPercentDecode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
