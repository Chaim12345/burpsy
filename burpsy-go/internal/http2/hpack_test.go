package http2

import (
	"errors"
	"testing"
)

// Ported one-for-one from crates/http2/src/hpack.rs's `mod tests`, including every RFC 7541 Appendix
// C byte vector. Rust test names are kept as the Go name in CamelCase so a reader can diff the two
// suites without a mapping table.

// hf is Rust's `h(name, value)` helper.
func hf(name, value string) HeaderField { return NewHeaderField(name, value) }

// wantFields fails unless got is exactly want, in order, including duplicates.
func wantFields(t *testing.T, got []HeaderField, want []HeaderField, what string) {
	t.Helper()
	if !HeaderFieldsEqual(got, want) {
		t.Fatalf("%s: got %s, want %s", what, showFields(got), showFields(want))
	}
}

func showFields(in []HeaderField) string {
	out := "["
	for i, f := range in {
		if i > 0 {
			out += ", "
		}
		out += string(f.Name) + ": " + string(f.Value)
	}
	return out + "]"
}

// wantHpackError fails unless err is an *HpackError equal to want field for field.
func wantHpackError(t *testing.T, err error, want HpackError, what string) {
	t.Helper()
	var got *HpackError
	if !errors.As(err, &got) {
		t.Fatalf("%s: error is %v, not an *HpackError", what, err)
	}
	if *got != want {
		t.Fatalf("%s: error = %+v, want %+v", what, *got, want)
	}
	if got.Error() == "" {
		t.Fatalf("%s: an error an operator cannot read is not a report", what)
	}
}

// ---- RFC 7541 Appendix C.2: independent representation examples ----

func TestC21ALiteralWithIndexingIsDecodedAndAddedToTheDynamicTable(t *testing.T) {
	block := []byte{
		0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63,
		0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	}
	d := NewDecoder(4096)
	out, err := d.Decode(block)
	if err != nil {
		t.Fatalf("C.2.1 must decode: %v", err)
	}
	wantFields(t, out, []HeaderField{hf("custom-key", "custom-header")}, "C.2.1")
	if d.DynamicTableLen() != 1 {
		t.Fatalf("the literal must be indexed; table holds %d", d.DynamicTableLen())
	}
	if d.DynamicTableBytes() != 55 {
		t.Fatalf("table size = %d, want 10 + 13 + 32 per RFC 7541 §4.1", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(), []HeaderField{hf("custom-key", "custom-header")},
		"C.2.1 table")
}

func TestC22ALiteralWithoutIndexingLeavesTheDynamicTableEmpty(t *testing.T) {
	block := []byte{
		0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68,
	}
	d := NewDecoder(4096)
	out, err := d.Decode(block)
	if err != nil {
		t.Fatalf("C.2.2 must decode: %v", err)
	}
	wantFields(t, out, []HeaderField{hf(":path", "/sample/path")}, "C.2.2")
	if d.DynamicTableLen() != 0 {
		t.Fatal("without-indexing must not touch the table")
	}
}

func TestC23ANeverIndexedLiteralLeavesTheDynamicTableEmpty(t *testing.T) {
	block := []byte{
		0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65, 0x63,
		0x72, 0x65, 0x74,
	}
	d := NewDecoder(4096)
	out, err := d.Decode(block)
	if err != nil {
		t.Fatalf("C.2.3 must decode: %v", err)
	}
	wantFields(t, out, []HeaderField{hf("password", "secret")}, "C.2.3")
	if d.DynamicTableLen() != 0 {
		t.Fatal("never-indexed must not touch the table")
	}
}

func TestC24AnIndexedHeaderFieldDecodesFromTheStaticTableAlone(t *testing.T) {
	d := NewDecoder(4096)
	out, err := d.Decode([]byte{0x82})
	if err != nil {
		t.Fatalf("C.2.4 must decode: %v", err)
	}
	wantFields(t, out, []HeaderField{hf(":method", "GET")}, "C.2.4")
	if d.DynamicTableLen() != 0 {
		t.Fatal("an indexed field must never be inserted")
	}
}

// ---- RFC 7541 Appendix C.3: a request sequence, one decoder throughout ----

func TestC3TheRequestSequenceIndexesAndEvictsExactlyAsTheRFCStates(t *testing.T) {
	d := NewDecoder(4096)

	// C.3.1
	req1 := []byte{
		0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
		0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}
	out1, err := d.Decode(req1)
	if err != nil {
		t.Fatalf("C.3.1 must decode: %v", err)
	}
	wantFields(t, out1, []HeaderField{
		hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/"),
		hf(":authority", "www.example.com"),
	}, "C.3.1")
	if d.DynamicTableBytes() != 57 {
		t.Fatalf("table size after C.3.1 = %d, want 57", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(),
		[]HeaderField{hf(":authority", "www.example.com")}, "C.3.1 table")

	// C.3.2 — references dynamic index 62 (:authority) via 0xbe.
	req2 := []byte{
		0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
	}
	out2, err := d.Decode(req2)
	if err != nil {
		t.Fatalf("C.3.2 must decode: %v", err)
	}
	wantFields(t, out2, []HeaderField{
		hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/"),
		hf(":authority", "www.example.com"), hf("cache-control", "no-cache"),
	}, "C.3.2")
	if d.DynamicTableBytes() != 110 {
		t.Fatalf("table size after C.3.2 = %d, want 110", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(), []HeaderField{
		hf("cache-control", "no-cache"), hf(":authority", "www.example.com"),
	}, "C.3.2 table — newest entry first")

	// C.3.3 — references dynamic index 63 (:authority, now shifted back one) via 0xbf.
	req3 := []byte{
		0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b,
		0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75,
		0x65,
	}
	out3, err := d.Decode(req3)
	if err != nil {
		t.Fatalf("C.3.3 must decode: %v", err)
	}
	wantFields(t, out3, []HeaderField{
		hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/index.html"),
		hf(":authority", "www.example.com"), hf("custom-key", "custom-value"),
	}, "C.3.3")
	if d.DynamicTableBytes() != 164 {
		t.Fatalf("table size after C.3.3 = %d, want 164", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(), []HeaderField{
		hf("custom-key", "custom-value"), hf("cache-control", "no-cache"),
		hf(":authority", "www.example.com"),
	}, "C.3.3 table")
}

// ---- RFC 7541 Appendix C.5: a response sequence with a 256-byte table, forcing eviction ----

func TestC5TheResponseSequenceEvictsUnderA256ByteTableExactlyAsTheRFCStates(t *testing.T) {
	d := NewDecoder(256)

	// C.5.1
	resp1 := []byte{
		0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
		0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20,
		0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20,
		0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
		0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}
	out1, err := d.Decode(resp1)
	if err != nil {
		t.Fatalf("C.5.1 must decode: %v", err)
	}
	wantFields(t, out1, []HeaderField{
		hf(":status", "302"), hf("cache-control", "private"),
		hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
		hf("location", "https://www.example.com"),
	}, "C.5.1")
	if d.DynamicTableBytes() != 222 {
		t.Fatalf("table size after C.5.1 = %d, want 222", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(), []HeaderField{
		hf("location", "https://www.example.com"),
		hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
		hf("cache-control", "private"), hf(":status", "302"),
	}, "C.5.1 table")

	// C.5.2 — inserting ":status: 307" evicts ":status: 302" to stay under 256.
	resp2 := []byte{0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf}
	out2, err := d.Decode(resp2)
	if err != nil {
		t.Fatalf("C.5.2 must decode: %v", err)
	}
	wantFields(t, out2, []HeaderField{
		hf(":status", "307"), hf("cache-control", "private"),
		hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
		hf("location", "https://www.example.com"),
	}, "C.5.2")
	if d.DynamicTableBytes() != 222 {
		t.Fatalf("table size after C.5.2 = %d, want 222", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(), []HeaderField{
		hf(":status", "307"), hf("location", "https://www.example.com"),
		hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"), hf("cache-control", "private"),
	}, "C.5.2 table — :status: 302 evicted")

	// C.5.3 — evicts cache-control:private, date(...21...), and :status:307 in turn.
	resp3 := []byte{
		0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63,
		0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
		0x32, 0x20, 0x47, 0x4d, 0x54, 0xc0, 0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70, 0x77, 0x38,
		0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53, 0x44, 0x4a, 0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a,
		0x58, 0x4f, 0x51, 0x57, 0x45, 0x4f, 0x50, 0x49, 0x55, 0x41, 0x58, 0x51, 0x57, 0x45,
		0x4f, 0x49, 0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, 0x33,
		0x36, 0x30, 0x30, 0x3b, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x31,
	}
	out3, err := d.Decode(resp3)
	if err != nil {
		t.Fatalf("C.5.3 must decode: %v", err)
	}
	const cookie = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
	wantFields(t, out3, []HeaderField{
		hf(":status", "200"), hf("cache-control", "private"),
		hf("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
		hf("location", "https://www.example.com"), hf("content-encoding", "gzip"),
		hf("set-cookie", cookie),
	}, "C.5.3")
	if d.DynamicTableBytes() != 215 {
		t.Fatalf("table size after C.5.3 = %d, want 215", d.DynamicTableBytes())
	}
	wantFields(t, d.DynamicTableEntries(), []HeaderField{
		hf("set-cookie", cookie), hf("content-encoding", "gzip"),
		hf("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
	}, "C.5.3 table")
}

// ---- negative tests: every one active, none skipped ----

func TestIndexZeroInAnIndexedHeaderFieldIsAnError(t *testing.T) {
	d := NewDecoder(4096)
	_, err := d.Decode([]byte{0x80})
	wantHpackError(t, err, HpackError{Kind: HpackZeroIndex, At: 0}, "index 0 must be refused")
}

func TestAnIndexPastTheCombinedTablesIsAnErrorNamingTheIndex(t *testing.T) {
	d := NewDecoder(4096)
	// 0xbe = indexed field, index 62 — the first dynamic-table slot, empty on a fresh decoder.
	_, err := d.Decode([]byte{0xbe})
	wantHpackError(t, err,
		HpackError{Kind: HpackIndexOutOfRange, At: 0, Index: 62, TableSize: 61},
		"index 62 must be refused when the dynamic table is empty")
}

func TestADeclaredStringLengthOverrunningTheBlockIsAnErrorWithTheOffset(t *testing.T) {
	// 0x04 = literal without indexing, indexed name (:path, static index 4).
	// 0x05 = value length 5, but only 2 octets follow.
	d := NewDecoder(4096)
	_, err := d.Decode([]byte{0x04, 0x05, 'a', 'b'})
	wantHpackError(t, err,
		HpackError{Kind: HpackStringLengthOverrun, At: 2, Declared: 5, Remaining: 2},
		"a length past the block must be refused")
}

func TestANonTerminatingMultiByteIntegerErrorsRatherThanLooping(t *testing.T) {
	// 0xff = indexed field, 7-bit prefix maxed (127). Six continuation octets follow, all with the
	// continuation bit set — one more than this decoder's bound, and it never supplies a terminator.
	d := NewDecoder(4096)
	_, err := d.Decode([]byte{0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80})
	wantHpackError(t, err, HpackError{Kind: HpackIntegerTooLong, At: 0},
		"an integer that never terminates must be refused, not looped on")
}

func TestASizeUpdateAboveTheNegotiatedMaximumIsAnError(t *testing.T) {
	// 0x3f 0x46 = dynamic table size update requesting 101 (31 + 70), against a 100-byte max.
	d := NewDecoder(100)
	_, err := d.Decode([]byte{0x3f, 0x46})
	wantHpackError(t, err,
		HpackError{Kind: HpackTableSizeTooLarge, At: 0, Requested: 101, Max: 100},
		"a size update above the negotiated maximum must be refused")
}

func TestAnEntryLargerThanTheWholeDynamicTableEmptiesItAndIsNotInserted(t *testing.T) {
	d := NewDecoder(50)

	// Literal with incremental indexing, new name: "a" -> "b" costs 1 + 1 + 32 = 34, fits.
	small := []byte{0x40, 0x01, 'a', 0x01, 'b'}
	if _, err := d.Decode(small); err != nil {
		t.Fatalf("a 34-byte entry must fit in a 50-byte table: %v", err)
	}
	if d.DynamicTableLen() != 1 || d.DynamicTableBytes() != 34 {
		t.Fatalf("table = %d entries / %d bytes, want 1 / 34",
			d.DynamicTableLen(), d.DynamicTableBytes())
	}

	// Literal with incremental indexing, new name: a 10-byte name and a 10-byte value cost
	// 10 + 10 + 32 = 52, which exceeds the 50-byte table outright.
	big := []byte{
		0x40, 0x0a, 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 0x0a, 'v',
		'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'v',
	}
	out, err := d.Decode(big)
	if err != nil {
		t.Fatalf("decoding still succeeds — the header is emitted, just not indexed: %v", err)
	}
	wantFields(t, out, []HeaderField{hf("nnnnnnnnnn", "vvvvvvvvvv")},
		"an oversized entry is still part of the decoded header list")
	if d.DynamicTableLen() != 0 || d.DynamicTableBytes() != 0 {
		t.Fatalf("an entry larger than the whole table empties it; table = %d entries / %d bytes",
			d.DynamicTableLen(), d.DynamicTableBytes())
	}
}

func TestAHuffmanFlaggedStringDecodes(t *testing.T) {
	// 0x14 = literal never indexed, indexed name (:path, static index 4). The value is RFC 7541
	// appendix C.4.1's worked example: 12 octets of Huffman coding for "www.example.com".
	d := NewDecoder(4096)
	fields, err := d.Decode([]byte{0x14, 0x8c,
		0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff})
	if err != nil {
		t.Fatalf("a real peer's Huffman-coded string must decode: %v", err)
	}
	if len(fields) != 1 || string(fields[0].Name) != ":path" || string(fields[0].Value) != "www.example.com" {
		t.Fatalf("decoded %+v, want :path: www.example.com", fields)
	}

	// A second vector (C.6.1's "no-cache") as a header NAME: 0x00 = literal without indexing, new
	// name; 0x86 = H=1, length 6; then a one-octet raw value.
	d2 := NewDecoder(4096)
	fields2, err := d2.Decode([]byte{0x00, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf, 0x01, 'x'})
	if err != nil {
		t.Fatalf("a Huffman-coded name must decode: %v", err)
	}
	if len(fields2) != 1 || string(fields2[0].Name) != "no-cache" || string(fields2[0].Value) != "x" {
		t.Fatalf("decoded %+v, want no-cache: x", fields2)
	}
}

func TestAnInvalidHuffmanStringIsRefusedByName(t *testing.T) {
	// 0x14 = literal never indexed, indexed name. 0x82 = H=1, length 2, at byte 1; two zero octets
	// are not a code with EOS-prefix padding, so this is malformed Huffman, not a value.
	d := NewDecoder(4096)
	_, err := d.Decode([]byte{0x14, 0x82, 0, 0})
	wantHpackError(t, err, HpackError{Kind: HpackHuffmanInvalid, At: 1},
		"malformed Huffman must be refused by name, and the offset must name the string's own "+
			"length octet rather than the representation's start")
}

// Defends the seam's ordering rule: bounds-checking happens before the Huffman refusal, so a
// too-long Huffman string is reported as a length overrun rather than masked by the
// not-implemented error. Not a Rust test — Rust states the rule in decode_string's doc comment and
// leaves it unasserted, and an untested ordering rule is one a later edit can silently reverse.
func TestATooLongHuffmanStringIsALengthOverrunNotTheHuffmanSeam(t *testing.T) {
	d := NewDecoder(4096)
	// 0x04 = literal without indexing, indexed name. 0x85 = H=1, length 5, but two octets follow.
	_, err := d.Decode([]byte{0x04, 0x85, 'a', 'b'})
	wantHpackError(t, err,
		HpackError{Kind: HpackStringLengthOverrun, At: 2, Declared: 5, Remaining: 2},
		"the bounds check must run before the Huffman flag is consulted")
}

// ---- order and duplicates are the caller's concern, not this decoder's to fix ----

func TestDuplicateFieldNamesBothSurviveInOrder(t *testing.T) {
	// Two "literal without indexing, new name" representations, both named "foo".
	block := []byte{
		0x00, 0x03, 'f', 'o', 'o', 0x04, 'b', 'a', 'r', '1',
		0x00, 0x03, 'f', 'o', 'o', 0x04, 'b', 'a', 'r', '2',
	}
	d := NewDecoder(4096)
	out, err := d.Decode(block)
	if err != nil {
		t.Fatalf("duplicate names are not an error: %v", err)
	}
	wantFields(t, out, []HeaderField{hf("foo", "bar1"), hf("foo", "bar2")},
		"a decoder must not deduplicate or merge repeated header names")
}

func TestAnUppercaseFieldNameDecodesUnchangedRatherThanBeingLowercased(t *testing.T) {
	// Literal without indexing, new name: "X-Test" -> "foo".
	block := []byte{0x00, 0x06, 'X', '-', 'T', 'e', 's', 't', 0x03, 'f', 'o', 'o'}
	d := NewDecoder(4096)
	out, err := d.Decode(block)
	if err != nil {
		t.Fatalf("an uppercase name is not this layer's error to raise: %v", err)
	}
	wantFields(t, out, []HeaderField{hf("X-Test", "foo")},
		"the caller, not the decoder, decides what to do with an invalid-for-HTTP/2 uppercase name "+
			"— silently lowercasing it would hide the very thing a smuggling probe needs to see")
}

// ---- table mechanics not already covered by the RFC sequences ----

func TestASizeUpdateAtOrBelowTheMaximumIsAcceptedAndLowersTheLimit(t *testing.T) {
	d := NewDecoder(4096)
	// Fill the table past what a lowered limit of 50 could hold.
	entry := []byte{0x40, 0x01, 'a', 0x01, 'b'} // cost 34
	if _, err := d.Decode(entry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := d.Decode(entry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if d.DynamicTableBytes() != 68 {
		t.Fatalf("table size = %d, want 68", d.DynamicTableBytes())
	}

	// 0x3f 0x13 = size update requesting 50 (31 + 19).
	if _, err := d.Decode([]byte{0x3f, 0x13}); err != nil {
		t.Fatalf("a size update at or below the max must be accepted: %v", err)
	}
	if d.DynamicTableBytes() != 34 || d.DynamicTableLen() != 1 {
		t.Fatalf("lowering the limit must evict from the back until the table fits; got %d entries "+
			"/ %d bytes", d.DynamicTableLen(), d.DynamicTableBytes())
	}
}

func TestASizeUpdateToZeroEmptiesTheTableWithoutErroring(t *testing.T) {
	d := NewDecoder(4096)
	if _, err := d.Decode([]byte{0x40, 0x01, 'a', 0x01, 'b'}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if d.DynamicTableLen() != 1 {
		t.Fatalf("table holds %d entries, want 1", d.DynamicTableLen())
	}
	// 0x20 = size update requesting 0.
	if _, err := d.Decode([]byte{0x20}); err != nil {
		t.Fatalf("a size update to zero must be accepted: %v", err)
	}
	if d.DynamicTableLen() != 0 || d.DynamicTableBytes() != 0 {
		t.Fatalf("table = %d entries / %d bytes, want 0 / 0",
			d.DynamicTableLen(), d.DynamicTableBytes())
	}
}

// ---- Encoder: RFC 7541 Appendix C round trips ----

// Defends: RFC 7541 Appendix C.2.1 — a novel field, encoded then decoded, is the same field and
// lands in the dynamic table exactly as a literal-with-incremental-indexing would.
func TestC21RoundTripANovelFieldSurvivesEncodeThenDecodeAndIsIndexed(t *testing.T) {
	fields := []HeaderField{hf("custom-key", "custom-header")}
	enc := NewEncoder(4096)
	block := enc.Encode(fields)
	dec := NewDecoder(4096)
	out, err := dec.Decode(block)
	if err != nil {
		t.Fatalf("encoder output must decode: %v", err)
	}
	wantFields(t, out, fields, "round trip must reproduce the original field")
	if enc.DynamicTableLen() != 1 {
		t.Fatalf("a field with no existing table match must be inserted, mirroring the decoder; "+
			"table holds %d", enc.DynamicTableLen())
	}
	if enc.DynamicTableBytes() != 55 {
		t.Fatalf("table size = %d, want 10 + 13 + 32 per RFC 7541 §4.1", enc.DynamicTableBytes())
	}
	wantFields(t, enc.DynamicTableEntries(), dec.DynamicTableEntries(), "tables must agree")
}

// Defends: RFC 7541 Appendix C.2.4 — a field with both name and value in the static table must
// round-trip AND take the one-byte indexed representation (§6.1), not a literal one; the byte length
// pins that the "prefer an exact match" rule in the module docs actually fires rather than merely
// happening to decode correctly.
func TestC24RoundTripAStaticTableExactMatchEncodesAsOneIndexedByte(t *testing.T) {
	fields := []HeaderField{hf(":method", "GET")}
	enc := NewEncoder(4096)
	block := enc.Encode(fields)
	if len(block) != 1 || block[0] != 0x82 {
		t.Fatalf("an exact static-table match must be a single indexed-field octet, not a literal; "+
			"got % x", block)
	}
	dec := NewDecoder(4096)
	out, err := dec.Decode(block)
	if err != nil {
		t.Fatalf("encoder output must decode: %v", err)
	}
	wantFields(t, out, fields, "C.2.4 round trip")
	if enc.DynamicTableLen() != 0 {
		t.Fatal("an indexed field must never be inserted into the dynamic table")
	}
}

// Defends: RFC 7541 Appendix C.3 — three requests on ONE encoder/decoder pair must round trip every
// field list, and the dynamic table must evolve on both sides exactly as the RFC states after each
// call: this is the "one instance per direction, not one per header block" invariant from the module
// docs, exercised across calls rather than within one.
func TestC3RoundTripThreeRequestsOnOneEncoderDecoderPairEvolveTheTableTogether(t *testing.T) {
	enc := NewEncoder(4096)
	dec := NewDecoder(4096)

	rounds := []struct {
		fields    []HeaderField
		wantBytes int
	}{
		{[]HeaderField{
			hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/"),
			hf(":authority", "www.example.com"),
		}, 57},
		{[]HeaderField{
			hf(":method", "GET"), hf(":scheme", "http"), hf(":path", "/"),
			hf(":authority", "www.example.com"), hf("cache-control", "no-cache"),
		}, 110},
		{[]HeaderField{
			hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/index.html"),
			hf(":authority", "www.example.com"), hf("custom-key", "custom-value"),
		}, 164},
	}
	for i, round := range rounds {
		block := enc.Encode(round.fields)
		out, err := dec.Decode(block)
		if err != nil {
			t.Fatalf("req%d must decode: %v", i+1, err)
		}
		wantFields(t, out, round.fields, "req round trip")
		if enc.DynamicTableBytes() != round.wantBytes {
			t.Fatalf("table size after req%d = %d, want %d",
				i+1, enc.DynamicTableBytes(), round.wantBytes)
		}
		wantFields(t, enc.DynamicTableEntries(), dec.DynamicTableEntries(),
			"encoder and decoder must agree on dynamic table contents after every call")
	}
}

// ---- Encoder: properties beyond the RFC vectors ----

// Defends the header-list-exactness guarantee — duplicate names and unusual casing are not something
// an encoder is allowed to normalise away, so they must survive encode → decode as the same ordered
// list.
func TestDuplicateNamesAndUnusualCasingSurviveEncodeThenDecodeInOrder(t *testing.T) {
	fields := []HeaderField{
		hf("foo", "bar1"), hf("foo", "bar2"), hf("X-Test", "value"), hf("foo", "bar1"),
	}
	enc := NewEncoder(4096)
	block := enc.Encode(fields)
	dec := NewDecoder(4096)
	out, err := dec.Decode(block)
	if err != nil {
		t.Fatalf("duplicate names and mixed casing must still decode: %v", err)
	}
	wantFields(t, out, fields, "an encoder must not deduplicate, merge, or lowercase fields")
}

// Defends: RFC 7541 §4.4 — an entry whose cost exceeds the table's entire budget must clear the table
// rather than being rejected or truncated, and must still be part of the emitted header list (only
// the *indexing* is refused, not the field itself). Mirrors the decoder's
// TestAnEntryLargerThanTheWholeDynamicTableEmptiesItAndIsNotInserted from the encoder's side of the
// wire, and confirms a decoder fed the same two blocks agrees the table ends up empty too.
func TestAnOversizedEntryClearsTheEncodersDynamicTableButStillReachesTheDecodedOutput(t *testing.T) {
	enc := NewEncoder(50)
	dec := NewDecoder(50)

	// "a" -> "b" costs 1 + 1 + 32 = 34, fits in a 50-byte table.
	small := []HeaderField{hf("a", "b")}
	if _, err := dec.Decode(enc.Encode(small)); err != nil {
		t.Fatalf("the small entry must decode: %v", err)
	}
	if enc.DynamicTableLen() != 1 || enc.DynamicTableBytes() != 34 {
		t.Fatalf("encoder table = %d entries / %d bytes, want 1 / 34",
			enc.DynamicTableLen(), enc.DynamicTableBytes())
	}

	// A 10-byte name and a 10-byte value cost 10 + 10 + 32 = 52, over the 50-byte budget.
	big := []HeaderField{hf("nnnnnnnnnn", "vvvvvvvvvv")}
	block2 := enc.Encode(big)
	if enc.DynamicTableLen() != 0 || enc.DynamicTableBytes() != 0 {
		t.Fatalf("an entry larger than the whole table must empty the encoder's table; got %d "+
			"entries / %d bytes", enc.DynamicTableLen(), enc.DynamicTableBytes())
	}
	out2, err := dec.Decode(block2)
	if err != nil {
		t.Fatalf("the oversized field must still decode: %v", err)
	}
	wantFields(t, out2, big,
		"an oversized entry is still part of the decoded header list, only unindexed")
	if dec.DynamicTableLen() != 0 {
		t.Fatalf("the decoder's table must end up empty too, in lockstep with the encoder's; got %d",
			dec.DynamicTableLen())
	}
}

// Defends: encoding must be deterministic — the representation strategy in the module docs has no
// hidden randomness or ordering dependency, so a fresh encoder given the same field list twice must
// produce byte-identical output both times.
func TestEncodingTheSameListTwiceOnAFreshEncoderIsDeterministic(t *testing.T) {
	fields := []HeaderField{hf(":method", "GET"), hf(":path", "/"), hf("x-custom", "value")}
	a := NewEncoder(4096).Encode(fields)
	b := NewEncoder(4096).Encode(fields)
	if string(a) != string(b) {
		t.Fatalf("the same input on a fresh encoder must produce identical bytes every time: "+
			"% x vs % x", a, b)
	}
}

// ---- integer and string primitives at their boundary values ----
//
// Rust exercises the primitives only through whole representations. These pin them directly at the
// boundaries the prefix encoding turns over at, which is where a transcription error in either
// direction would hide: a decoder that got the prefix-max case wrong still decodes every RFC vector,
// because none of them straddles a boundary.

func TestPrefixIntegersRoundTripAtEveryBoundaryValue(t *testing.T) {
	for _, prefixBits := range []uint{4, 5, 6, 7} {
		prefixMax := uint64(1)<<prefixBits - 1
		values := []uint64{
			0, 1, prefixMax - 1, prefixMax, prefixMax + 1,
			prefixMax + 0x7F, prefixMax + 0x80, prefixMax + 0x81,
			1337, 0x3FFF, 0x4000, 1 << 21, (1 << 28) - 1,
		}
		for _, want := range values {
			// Pattern 0 keeps the high bits clear so the round trip tests only the integer.
			block := encodeHpackInt(nil, want, prefixBits, 0x00)
			got, n, err := decodeHpackInt(block, 0, prefixBits)
			if err != nil {
				t.Fatalf("prefix %d value %d: decode failed: %v", prefixBits, want, err)
			}
			if got != want {
				t.Fatalf("prefix %d: round trip gave %d, want %d (block % x)",
					prefixBits, got, want, block)
			}
			if n != len(block) {
				t.Fatalf("prefix %d value %d: consumed %d of %d octets",
					prefixBits, want, n, len(block))
			}
		}
	}
}

// The RFC's own §5.1 worked example, so a hand-rolled prefix encoder cannot pass by being
// self-consistent while disagreeing with every real peer.
func TestTheRFCsOwnPrefixIntegerExamplesEncodeToTheDocumentedOctets(t *testing.T) {
	cases := []struct {
		value      uint64
		prefixBits uint
		pattern    byte
		want       []byte
	}{
		// §C.1.1: 10 in a 5-bit prefix is one octet.
		{10, 5, 0x00, []byte{0x0a}},
		// §C.1.2: 1337 in a 5-bit prefix is 31 then two continuation octets.
		{1337, 5, 0x00, []byte{0x1f, 0x9a, 0x0a}},
		// §C.1.3: 42 in an 8-bit prefix is one octet.
		{42, 8, 0x00, []byte{0x2a}},
	}
	for _, c := range cases {
		got := encodeHpackInt(nil, c.value, c.prefixBits, c.pattern)
		if string(got) != string(c.want) {
			t.Fatalf("encodeHpackInt(%d, %d bits) = % x, want % x",
				c.value, c.prefixBits, got, c.want)
		}
	}
}

func TestAPrefixIntegerTruncatedMidContinuationIsReportedTruncatedNotWrapped(t *testing.T) {
	// 0x1f = 5-bit prefix maxed, so a continuation octet must follow. None does.
	_, _, err := decodeHpackInt([]byte{0x1f}, 0, 5)
	wantHpackError(t, err, HpackError{Kind: HpackTruncated, At: 1, Need: 1, Have: 0},
		"a prefix integer that runs off the end must be reported, not completed")
	// And an empty block cannot even start one.
	_, _, err = decodeHpackInt(nil, 0, 7)
	wantHpackError(t, err, HpackError{Kind: HpackTruncated, At: 0, Need: 1, Have: 0},
		"an empty block cannot start an integer")
}

func TestStringLiteralsRoundTripAtTheLengthPrefixBoundary(t *testing.T) {
	// 126 and 127 straddle the 7-bit prefix boundary; 128 and 300 need continuation octets.
	for _, n := range []int{0, 1, 126, 127, 128, 129, 300} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte('a' + i%26)
		}
		block := encodeHpackString(nil, data)
		got, consumed, err := decodeHpackString(block, 0)
		if err != nil {
			t.Fatalf("a %d-octet string must round trip: %v", n, err)
		}
		if string(got) != string(data) {
			t.Fatalf("a %d-octet string came back as %d octets", n, len(got))
		}
		if consumed != len(block) {
			t.Fatalf("a %d-octet string consumed %d of %d octets", n, consumed, len(block))
		}
		if block[0]&0x80 != 0 {
			t.Fatalf("this encoder always writes H=0; length octet = %#x", block[0])
		}
	}
}

// A decoded header list must not be a window onto the table it came from: an operator editing a
// captured header would otherwise silently rewrite the dynamic table and desynchronise it from the
// peer's. Rust gets this from Bytes being immutable; Go has to copy, so the copy is pinned.
func TestADecodedFieldIsNotAWindowOntoTheDynamicTable(t *testing.T) {
	d := NewDecoder(4096)
	// Literal with incremental indexing, new name: "a" -> "b", then an indexed reference to it.
	out, err := d.Decode([]byte{0x40, 0x01, 'a', 0x01, 'b'})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	out[0].Value[0] = 'Z'
	again, err := d.Decode([]byte{0xbe}) // index 62 = the entry just inserted
	if err != nil {
		t.Fatalf("indexed reference: %v", err)
	}
	wantFields(t, again, []HeaderField{hf("a", "b")},
		"editing a decoded field must not reach the table it came from")
}
