package intruder

import "testing"

// Burp's "URL-encode these characters" (burpsy-react-ui-8cbc): the final pass that
// percent-encodes a chosen character set in every payload, independent of payload type.
// The helper runs after the operator's rule chain, so an explicit encode rule and this
// compose rather than compete.

func TestURLEncodeSetEncodesOnlyTheNamedCharacters(t *testing.T) {
	ps := &PayloadSet{Items: []string{"a=b&c?d"}}
	URLEncodeSet(ps, "=&?")
	want := []string{"a%3Db%26c%3Fd"}
	for i, got := range ps.Items {
		if got != want[i] {
			t.Fatalf("payload %d = %q, want %q", i, got, want[i])
		}
	}
}

// Characters outside the set pass through untouched — this is a character-set encoding,
// not a whole-payload one, which is the existing encode rule's job.
func TestURLEncodeSetLeavesUnnamedCharactersAlone(t *testing.T) {
	ps := &PayloadSet{Items: []string{"<script>alert(1)</script>"}}
	URLEncodeSet(ps, "=&?")
	want := "<script>alert(1)</script>"
	if ps.Items[0] != want {
		t.Fatalf("got %q, want %q — < > ( ) are not in the default set and must pass through", ps.Items[0], want)
	}
}

// Spaces and control characters are encoded even when unnamed: a raw space breaks the
// request line, and reporting a transport error for a payload the operator wrote would
// read as a finding.
func TestURLEncodeSetAlwaysEncodesSpacesAndControlCharacters(t *testing.T) {
	ps := &PayloadSet{Items: []string{"a b\tc"}}
	URLEncodeSet(ps, "") // empty set named — yet the unrepresentable characters still go
	if ps.Items[0] != "a%20b%09c" {
		t.Fatalf("got %q, want %q — space and tab must encode even with an empty named set", ps.Items[0], "a%20b%09c")
	}
}

// Empty request with an empty set is a no-op, the off state.
func TestURLEncodeSetWithNoCharactersIsANoOp(t *testing.T) {
	ps := &PayloadSet{Items: []string{"a=b"}}
	URLEncodeSet(ps, "")
	if ps.Items[0] != "a=b" {
		t.Fatalf("got %q, want the payload unchanged", ps.Items[0])
	}
}

// Multi-byte characters encode as their UTF-8 bytes, so the wire stays byte-exact.
func TestURLEncodeSetEncodesMultiByteCharactersPerByte(t *testing.T) {
	ps := &PayloadSet{Items: []string{"café"}}
	URLEncodeSet(ps, "é")
	// é is two UTF-8 bytes 0xC3 0xA9.
	if ps.Items[0] != "caf%C3%A9" {
		t.Fatalf("got %q, want caf%%C3%%A9", ps.Items[0])
	}
}
