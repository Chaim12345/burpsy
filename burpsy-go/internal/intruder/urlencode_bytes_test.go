package intruder

import (
	"testing"
)

// "URL-encode these characters" must not rewrite bytes it was not asked about
// (burpsy-react-ui-8dli).
//
// A payload set is a byte string. payload.go's "file" source reads a wordlist with os.ReadFile and
// no UTF-8 validation, so binary and extended-ASCII corpora are ordinary input to this pass — and
// the character box ships seeded non-empty, so the pass runs by default. Ranging the payload as
// runes decoded every invalid byte as utf8.RuneError and wrote back U+FFFD's three bytes, silently
// changing what went on the wire.
func TestURLEncodeSetLeavesNonUTF8BytesAlone(t *testing.T) {
	ps := &PayloadSet{Kind: "list", Items: []string{"a\xffb"}, Count: 1}
	URLEncodeSet(ps, "/")

	got := []byte(ps.Items[0])
	want := []byte{'a', 0xff, 'b'}
	if string(got) != string(want) {
		t.Fatalf("payload bytes = % x, want % x — the pass rewrote a byte it was not asked about", got, want)
	}
}

// The documented contract, stated as a table so the boundary is visible: only the named set and
// the always-encode safe set are touched.
func TestURLEncodeSetEncodesOnlyWhatItWasAskedFor(t *testing.T) {
	for _, c := range []struct {
		name  string
		chars string
		in    string
		want  string
	}{
		{"a named character is encoded", "/", "a/b", "a%2Fb"},
		{"an unnamed character is not", "/", "a:b", "a:b"},
		{"a space is always encoded, named or not", "", "a b", "a%20b"},
		{"DEL is always encoded", "", "a\x7fb", "a%7Fb"},
		{"a control character is always encoded", "", "a\nb", "a%0Ab"},
		// A multi-byte rune must match the named set as a unit and encode as all of its bytes —
		// which is why the decode stays per-rune rather than becoming a flat byte loop.
		{"a named multi-byte rune encodes every one of its bytes", "é", "aéb", "a%C3%A9b"},
		{"an unnamed multi-byte rune passes through whole", "/", "aéb", "aéb"},
		// The regression: an invalid byte is not a character, so it is in no set.
		{"an invalid byte passes through beside a named one", "/", "a\xff/b", "a\xff%2Fb"},
		{"a lone continuation byte passes through", "", "a\x80b", "a\x80b"},
		{"a truncated multi-byte sequence passes through", "", "a\xc3", "a\xc3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ps := &PayloadSet{Kind: "list", Items: []string{c.in}, Count: 1}
			URLEncodeSet(ps, c.chars)
			if ps.Items[0] != c.want {
				t.Errorf("in % x -> % x, want % x", c.in, ps.Items[0], c.want)
			}
		})
	}
}

// The off state still has to be honest: an empty named set skips the walk only when there is
// nothing in the safe set to encode, and that decision must not be confused by invalid bytes.
func TestURLEncodeSetOffStateStillEncodesTheSafeSetAndNothingElse(t *testing.T) {
	ps := &PayloadSet{Kind: "list", Items: []string{"a\xffb", "c d"}, Count: 2}
	URLEncodeSet(ps, "")

	if ps.Items[0] != "a\xffb" {
		t.Errorf("invalid byte was rewritten with the named set empty: % x", ps.Items[0])
	}
	if ps.Items[1] != "c%20d" {
		t.Errorf("the safe set must still be encoded with the named set empty: %q", ps.Items[1])
	}
}
