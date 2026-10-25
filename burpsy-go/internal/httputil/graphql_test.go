package httputil

import "testing"

// The fixtures are the semantics: every case below is one the scanner's ingest gate and
// bcheck's insertion points already agree on, so a future refactor that drifts one copy fails
// here even though the other two are unexported.

func TestGraphQLPercentCodecRoundTripsTheSharedFixtures(t *testing.T) {
	cases := []struct{ decoded, encoded string }{
		{`{book(title:"Dune"){author}}`, "%7Bbook(title:%22Dune%22)%7Bauthor%7D%7D"},
		{"a+b", "a%2Bb"},   // '+' is data, not a space, in both directions
		{"a b", "a%20b"},   // space never travels as '+'
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
