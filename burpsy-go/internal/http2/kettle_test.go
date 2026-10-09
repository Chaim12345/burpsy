package http2

import (
	"encoding/json"
	"strings"
	"testing"
)

// plainRequest is an HTTP/2 request HTTP/1 text carries exactly: the four pseudo-headers first, in the
// connection's own scheme, then lowercase regular fields.
func plainRequest() []HeaderField {
	return []HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":scheme", "https"),
		NewHeaderField(":authority", "example.test"),
		NewHeaderField(":path", "/a?b=c"),
		NewHeaderField("accept", "*/*"),
		NewHeaderField("cookie", "a=1; b=2"),
	}
}

func withField(fields []HeaderField, at int, f HeaderField) []HeaderField {
	out := append([]HeaderField{}, fields...)
	if at >= len(out) {
		return append(out, f)
	}
	out[at] = f
	return out
}

func kinds(reasons []KettleReason) []KettleKind {
	out := []KettleKind{}
	for _, r := range reasons {
		out = append(out, r.Kind)
	}
	return out
}

func TestKettleReasonsNotKettledIsEmptyNotNil(t *testing.T) {
	got := KettleReasons(plainRequest(), true)
	if got == nil || len(got) != 0 {
		t.Fatalf("a request HTTP/1 can carry must have no reasons and a non-nil slice, got %#v", got)
	}
	// One cookie field with "; " is a single Cookie line in HTTP/1 — not kettled.
	b, _ := json.Marshal(got)
	if string(b) != "[]" {
		t.Fatalf("marshalled reasons = %s, want []", b)
	}
	// A plain-HTTP connection with :scheme http is equally fine.
	plain := withField(plainRequest(), 1, NewHeaderField(":scheme", "http"))
	if got := KettleReasons(plain, false); len(got) != 0 {
		t.Fatalf("http on a plaintext connection is not kettled, got %v", got)
	}
}

// TestKettleReasonsEachKind drives every kind once, alone, so each check is proven to fire for its own
// construct and nothing else's.
func TestKettleReasonsEachKind(t *testing.T) {
	base := plainRequest()
	cases := []struct {
		name   string
		fields []HeaderField
		tls    bool
		want   KettleKind
		index  int
		phrase string
	}{
		{"uppercase name", withField(base, 4, NewHeaderField("Accept", "*/*")), true, KettleUppercaseName, 4, "uppercase"},
		{"colon in a regular name", withField(base, 4, NewHeaderField("x:y", "1")), true, KettleColonInName, 4, "colon"},
		{"unknown pseudo-header", withField(base, 4, NewHeaderField(":protocol", "websocket")), true, KettleColonInName, 4, "not a request pseudo-header"},
		{"CR in a name", withField(base, 4, NewHeaderField("x\rb", "1")), true, KettleNewlineInName, 4, "carriage return"},
		{"CRLF in a value", withField(base, 4, NewHeaderField("accept", "a\r\nb")), true, KettleNewlineInValue, 4, "a carriage return and a line feed"},
		{"LF alone in a value", withField(base, 4, NewHeaderField("accept", "a\nb")), true, KettleNewlineInValue, 4, "a line feed"},
		{"scheme modified", withField(base, 1, NewHeaderField(":scheme", "http")), true, KettleSchemeModified, 1, "on a connection that is https"},
		{"scheme modified on plaintext", base, false, KettleSchemeModified, 1, "on a connection that is http"},
		{"space in :path", withField(base, 3, NewHeaderField(":path", "/a b")), true, KettleSpaceInPseudoHeader, 3, ":path contains a space"},
		{"space in :method", withField(base, 0, NewHeaderField(":method", "GET X")), true, KettleSpaceInPseudoHeader, 0, ":method contains a space"},
		{"duplicate pseudo-header", append(append([]HeaderField{}, base[:4]...), append([]HeaderField{NewHeaderField(":path", "/x")}, base[4:]...)...), true, KettleDuplicatePseudoHeader, 4, "more than once"},
		{"cookie crumb separator", withField(base, 6, NewHeaderField("cookie", "c=3")), true, KettleCookieCrumbSeparator, 5, "2 cookie fields"},
		{"pseudo after regular", []HeaderField{base[0], base[1], base[2], base[4], base[3]}, true, KettlePseudoHeaderAfterRegular, 4, "comes after the regular header \"accept\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := KettleReasons(tc.fields, tc.tls)
			if len(got) != 1 {
				t.Fatalf("want exactly one reason (%v), got %d: %v", tc.want, len(got), kinds(got))
			}
			r := got[0]
			if r.Kind != tc.want || r.Index != tc.index {
				t.Fatalf("got kind %v at %d, want %v at %d", r.Kind, r.Index, tc.want, tc.index)
			}
			if !strings.Contains(r.Text, tc.phrase) {
				t.Fatalf("reason text %q does not say %q", r.Text, tc.phrase)
			}
		})
	}
}

// TestKettleKindSlugsAreDistinct keeps the wire names stable and unique; a UI branches on them.
func TestKettleKindSlugsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range KettleKindAll {
		slug := k.Slug()
		if slug == "unrecognised" || seen[slug] {
			t.Fatalf("kind %d has slug %q, which is unrecognised or repeated", k, slug)
		}
		seen[slug] = true
	}
}

// TestEncodeLiteralCarriesEveryOctet proves the encoding a kettled send relies on: the block decodes to
// exactly the list written — casing, CR/LF and order intact — and leaves the peer's dynamic table empty.
func TestEncodeLiteralCarriesEveryOctet(t *testing.T) {
	fields := []HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":path", "/"),
		NewHeaderField("Cookie", "a=1"),
		NewHeaderField("x-inject", "a\r\nb: c"),
		NewHeaderField("x-inject", "a\r\nb: c"),
	}
	block := EncodeLiteral(fields)
	d := NewDecoder(4096)
	got, err := d.Decode(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !HeaderFieldsEqual(got, fields) {
		t.Fatalf("decoded %q, want %q", got, fields)
	}
	if d.DynamicTableLen() != 0 {
		t.Fatalf("a literal-without-indexing block inserted %d entries into the peer's table", d.DynamicTableLen())
	}
	// "Cookie" is on the static table as "cookie"; an encoder that indexed the name would have sent it
	// lowercase. The literal octets must be on the wire.
	if !strings.Contains(string(block), "Cookie") {
		t.Fatal("the uppercase name was not written literally")
	}
}

// TestKettledValueStaysAuthorisable pins the boundary between kettled and refused: a CRLF in a regular
// value is kettled and sendable; a space in :path is kettled and refused by the classifier.
func TestKettledValueStaysAuthorisable(t *testing.T) {
	sendable := withField(plainRequest(), 4, NewHeaderField("x-inject", "a\r\nb"))
	program := NewH2FrameProgram(NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, EncodeLiteral(sendable)))
	if a := Authorise(program); a.Verdict != VerdictAuthorisable {
		t.Fatalf("CRLF in a regular value must stay authorisable, got %s", a.Explain())
	}
	refused := withField(plainRequest(), 3, NewHeaderField(":path", "/a b"))
	program = NewH2FrameProgram(NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, EncodeLiteral(refused)))
	if a := Authorise(program); a.Verdict != VerdictUndecidable || a.Refusals[0].Kind != RefusalUnauthorisablePseudoHeader {
		t.Fatalf("a space in :path must be refused by the classifier, got %s", a.Explain())
	}
}
