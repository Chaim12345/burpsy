package tools

import (
	"bytes"
	"compress/flate"
	"strings"
	"testing"
)

func s(b []byte) string { return string(b) }

// TestURLDecodeLeavesPlusAloneSoBase64InAQuerySurvives ports
// crates/tools/src/decoder.rs url_decode_leaves_plus_alone_so_base64_in_a_query_survives.
// The context-free primitive never touches `+`; the smart scanner decides by context.
func TestURLDecodeLeavesPlusAloneSoBase64InAQuerySurvives(t *testing.T) {
	if got := s(URLDecode([]byte("a%2Bb+c"))); got != "a+b+c" {
		t.Fatalf("URLDecode(a%%2Bb+c) = %q, want %q", got, "a+b+c")
	}
	if got := s(URLDecode([]byte("%2f%41%7A"))); got != "/Az" {
		t.Fatalf("URLDecode(%%2f%%41%%7A) = %q, want %q", got, "/Az")
	}
}

// TestALonePercentIsLeftVerbatimRatherThanSwallowed ports
// a_lone_percent_is_left_verbatim_rather_than_swallowed.
func TestALonePercentIsLeftVerbatimRatherThanSwallowed(t *testing.T) {
	if got := s(URLDecode([]byte("100% sure %zz %4"))); got != "100% sure %zz %4" {
		t.Fatalf("got %q, want the input unchanged", got)
	}
}

// TestURLEncodeEscapesTheCharactersThatBreakOutOfAParameter ports
// url_encode_escapes_the_characters_that_break_out_of_a_parameter.
func TestURLEncodeEscapesTheCharactersThatBreakOutOfAParameter(t *testing.T) {
	if got := s(URLEncode([]byte("a&b=c/d e"))); got != "a%26b%3Dc%2Fd%20e" {
		t.Fatalf("got %q, want %q", got, "a%26b%3Dc%2Fd%20e")
	}
	if got := s(URLEncode([]byte("safe-_.~09Az"))); got != "safe-_.~09Az" {
		t.Fatalf("unreserved characters must survive: got %q", got)
	}
}

// TestHTMLDecodeHandlesNamedDecimalAndHexReferences ports
// html_decode_handles_named_decimal_and_hex_references.
func TestHTMLDecodeHandlesNamedDecimalAndHexReferences(t *testing.T) {
	in := "&lt;script&gt;alert&#40;&#x31;&#41;&lt;/script&gt;"
	if got := s(HTMLDecode([]byte(in))); got != "<script>alert(1)</script>" {
		t.Fatalf("got %q, want %q", got, "<script>alert(1)</script>")
	}
}

// TestAnUnknownEntityIsPreservedNotDropped ports
// an_unknown_entity_is_preserved_not_dropped. Losing `&unicorn;` would hide
// what a filter did with it.
func TestAnUnknownEntityIsPreservedNotDropped(t *testing.T) {
	if got := s(HTMLDecode([]byte("a &unicorn; b &amp; c"))); got != "a &unicorn; b & c" {
		t.Fatalf("got %q, want %q", got, "a &unicorn; b & c")
	}
}

// TestBase64RoundTripsAndToleratesMissingPaddingAndWhitespace ports
// base64_round_trips_and_tolerates_missing_padding_and_whitespace.
func TestBase64RoundTripsAndToleratesMissingPaddingAndWhitespace(t *testing.T) {
	if got := s(Base64Encode([]byte("Hello, world"), false, true)); got != "SGVsbG8sIHdvcmxk" {
		t.Fatalf("got %q, want %q", got, "SGVsbG8sIHdvcmxk")
	}
	if got := s(Base64Encode([]byte("ab"), false, true)); got != "YWI=" {
		t.Fatalf("got %q, want %q", got, "YWI=")
	}
	if got := s(Base64Decode([]byte("SGVs bG8"), false)); got != "Hello" {
		t.Fatalf("got %q, want %q", got, "Hello")
	}
	if got := s(Base64Decode([]byte("YWI="), false)); got != "ab" {
		t.Fatalf("got %q, want %q", got, "ab")
	}
}

// TestBase64URLUsesTheURLSafeAlphabetWithoutPadding ports
// base64url_uses_the_url_safe_alphabet_without_padding.
func TestBase64URLUsesTheURLSafeAlphabetWithoutPadding(t *testing.T) {
	raw := []byte{0xfb, 0xff, 0xbe}
	enc := Base64Encode(raw, true, false)
	if got := s(enc); got != "-_--" {
		t.Fatalf("got %q, want %q", got, "-_--")
	}
	if got := Base64Decode(enc, true); !bytes.Equal(got, raw) {
		t.Fatalf("round trip = %v, want %v", got, raw)
	}
}

// TestHexIgnoresSeparatorsButRefusesAStrayCharacter ports
// hex_ignores_separators_but_refuses_a_stray_character.
func TestHexIgnoresSeparatorsButRefusesAStrayCharacter(t *testing.T) {
	if got := s(mustHex(t, "48 65:6c 6c6f")); got != "Hello" {
		t.Fatalf("got %q, want %q", got, "Hello")
	}
	if _, err := HexDecode([]byte("4865z")); err == nil {
		t.Fatal("a stray 'z' must be an error, not a silent skip")
	}
	if _, err := HexDecode([]byte("486")); err == nil {
		t.Fatal("an odd digit count must be an error")
	}
	if got := s(HexEncode([]byte("Hi"))); got != "4869" {
		t.Fatalf("got %q, want %q", got, "4869")
	}
}

// TestOctalEncodesThreeDigitsPerByteAndDecodeTakesUnpaddedTokensToo pins the wire format
// (burpsy-react-ui-ku62): no primary source spells out Burp's exact octal spacing, so this fixes
// the choice this port makes — 3-digit zero-padded, space-separated, matching hexdump -b — and
// guards it against silent drift.
func TestOctalEncodesThreeDigitsPerByteAndDecodeTakesUnpaddedTokensToo(t *testing.T) {
	if got := s(OctalEncode([]byte("Hi"))); got != "110 151" {
		t.Fatalf("got %q, want %q", got, "110 151")
	}
	if got, err := OctalDecode([]byte("110 151")); err != nil || s(got) != "Hi" {
		t.Fatalf("OctalDecode(%q) = %q, %v; want %q, nil", "110 151", got, err, "Hi")
	}
	// Unpadded input must still decode: an operator pasting octal from elsewhere should not have
	// to zero-pad it back to three digits first. "40" is space (040 octal = 32 decimal) and "5" is
	// ENQ (005 octal = 5 decimal) — both shorter than the 3-digit form OctalEncode itself writes.
	if got, err := OctalDecode([]byte("40 5")); err != nil || s(got) != " \x05" {
		t.Fatalf("OctalDecode(%q) = %q, %v; want %q, nil", "40 5", got, err, " \x05")
	}
	if _, err := OctalDecode([]byte("400")); err == nil {
		t.Fatal("400 octal is 256, which does not fit a byte — must be refused")
	}
	if _, err := OctalDecode([]byte("18")); err == nil {
		t.Fatal("8 is not an octal digit — must be refused, not silently truncated")
	}
}

// TestBinaryEncodesEightDigitsPerByteAndDecodeTakesUnpaddedTokensToo is Octal's counterpart for
// LayerBinary.
func TestBinaryEncodesEightDigitsPerByteAndDecodeTakesUnpaddedTokensToo(t *testing.T) {
	if got := s(BinaryEncode([]byte("Hi"))); got != "01001000 01101001" {
		t.Fatalf("got %q, want %q", got, "01001000 01101001")
	}
	if got, err := BinaryDecode([]byte("01001000 01101001")); err != nil || s(got) != "Hi" {
		t.Fatalf("BinaryDecode(%q) = %q, %v; want %q, nil", "01001000 01101001", got, err, "Hi")
	}
	// Unpadded input must still decode, same rationale as Octal's: "100000" is space (0x20) with
	// its two leading zeros dropped, and "101" is ENQ (0x05) written with none of its five.
	if got, err := BinaryDecode([]byte("100000 101")); err != nil || s(got) != " \x05" {
		t.Fatalf("BinaryDecode(%q) = %q, %v; want %q, nil", "100000 101", got, err, " \x05")
	}
	if _, err := BinaryDecode([]byte("101010101")); err == nil {
		t.Fatal("9 bits do not fit a byte — must be refused")
	}
	if _, err := BinaryDecode([]byte("0102")); err == nil {
		t.Fatal("2 is not a binary digit — must be refused")
	}
}

// rawDeflate produces a raw deflate stream (no zlib wrapper), the framing some servers
// emit under `Content-Encoding: deflate`.
func rawDeflate(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter failed: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("flate write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close failed: %v", err)
	}
	return buf.Bytes()
}

func mustHex(t *testing.T, in string) []byte {
	t.Helper()
	out, err := HexDecode([]byte(in))
	if err != nil {
		t.Fatalf("HexDecode(%q) failed: %v", in, err)
	}
	return out
}

// TestGzipAndDeflateRoundTrip ports gzip_and_deflate_round_trip.
func TestGzipAndDeflateRoundTrip(t *testing.T) {
	body := bytes.Repeat([]byte("HTTP/1.1 200 OK\r\n\r\n<html>hello</html>"), 50)
	for _, layer := range []Layer{LayerGzip, LayerDeflate} {
		enc, err := Encode(layer, body)
		if err != nil {
			t.Fatalf("%v encode failed: %v", layer, err)
		}
		if len(enc) >= len(body) {
			t.Fatalf("%v should compress this: %d -> %d", layer, len(body), len(enc))
		}
		out, truncated, err := Decode(layer, enc)
		if err != nil {
			t.Fatalf("%v decode failed: %v", layer, err)
		}
		if truncated {
			t.Fatalf("%v round trip reported a truncated prefix", layer)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("%v round trip = %d bytes, want %d", layer, len(out), len(body))
		}
	}
}

// TestDeflateDecodesARawStreamAsWellAsAZlibWrappedOne ports
// deflate_decodes_a_raw_stream_as_well_as_a_zlib_wrapped_one.
func TestDeflateDecodesARawStreamAsWellAsAZlibWrappedOne(t *testing.T) {
	body := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog", 10))
	raw := rawDeflate(t, body)
	out, truncated, err := Decode(LayerDeflate, raw)
	if err != nil {
		t.Fatalf("raw deflate decode failed: %v", err)
	}
	if truncated {
		t.Fatal("a whole raw stream must not be reported as a prefix")
	}
	if !bytes.Equal(out, body) {
		t.Fatal("raw deflate decoded to the wrong bytes")
	}
}

// TestADecompressionBombIsCappedRatherThanExhaustingMemory ports
// a_decompression_bomb_is_capped_rather_than_exhausting_memory.
func TestADecompressionBombIsCappedRatherThanExhaustingMemory(t *testing.T) {
	// 100 MiB of zeros. The point of the fixture is a tiny input that inflates past MaxInflate,
	// and the assertion below is about the RATIO, not about a byte count: the old form hard-coded
	// `len(bomb) < 200_000`, which is a fact about one compressor's output rather than about the
	// bomb, and Go 1.27's compress/flate emits a larger stream for these inputs. It moved past the
	// bound and failed a test whose subject had not changed (burpsy-react-ui-jdgq). Comparing
	// against the DECOMPRESSED length is toolchain-independent and is the property the test is
	// actually named for: a 100 MiB expansion from an input orders of magnitude smaller.
	const decompressed = 100 * 1024 * 1024
	bomb, err := Encode(LayerGzip, make([]byte, decompressed))
	if err != nil {
		t.Fatalf("encode bomb failed: %v", err)
	}
	if len(bomb) >= decompressed/100 {
		t.Fatalf("the bomb itself is not small relative to what it inflates to: %d bytes of input for "+
			"%d bytes of output (%.4f%%), so this is not a decompression bomb",
			len(bomb), decompressed, 100*float64(len(bomb))/float64(decompressed))
	}
	out, truncated, err := Decode(LayerGzip, bomb)
	if err != nil {
		t.Fatalf("decode bomb failed: %v", err)
	}
	if len(out) != int(MaxInflate) {
		t.Fatalf("inflation stops at the cap: %d", len(out))
	}
	if !truncated {
		t.Fatal("a capped inflate must say the bytes are a prefix, not the whole body")
	}
}

// TestAValidButEmptyDeflateStreamDecodesToEmptyRatherThanErroring ports
// a_valid_but_empty_deflate_stream_decodes_to_empty_rather_than_erroring.
func TestAValidButEmptyDeflateStreamDecodesToEmptyRatherThanErroring(t *testing.T) {
	enc, err := Encode(LayerDeflate, nil)
	if err != nil {
		t.Fatalf("encode empty failed: %v", err)
	}
	out, truncated, err := Decode(LayerDeflate, enc)
	if err != nil {
		t.Fatalf("an empty body must decode, got error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("an empty body decodes to empty, got %q", out)
	}
	if truncated {
		t.Fatal("nothing was cut short")
	}
}

// TestWhenBothDeflateFramingsFailTheZlibErrorIsTheOneReported ports
// when_both_deflate_framings_fail_the_zlib_error_is_the_one_reported.
func TestWhenBothDeflateFramingsFailTheZlibErrorIsTheOneReported(t *testing.T) {
	// `78 9c` is a well-formed zlib header, so the input reaches the inflater and fails
	// there; the raw-deflate fallback then fails too. The operator must see a decompression
	// error, not a silently mangled buffer.
	bad := []byte("\x78\x9c not actually deflate data at all")
	if _, _, err := Decode(LayerDeflate, bad); err == nil {
		t.Fatal("garbage after a valid zlib header must be an error")
	}
}

// TestATruncatedGzipStreamReportsTruncatedAndKeepsTheRealPrefix ports
// a_truncated_gzip_stream_reports_truncated_and_keeps_the_real_prefix.
func TestATruncatedGzipStreamReportsTruncatedAndKeepsTheRealPrefix(t *testing.T) {
	body := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog, repeatedly, for good measure. ", 200))
	full, err := Encode(LayerGzip, body)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	cut := len(full) * 2 / 3
	out, truncated, err := Decode(LayerGzip, full[:cut])
	if err != nil {
		t.Fatalf("a truncated stream with real prefix must not error: %v", err)
	}
	if !truncated {
		t.Fatal("a stream broken mid-way must be reported as a prefix")
	}
	if len(out) == 0 {
		t.Fatal("some bytes must have decoded before the break")
	}
	if len(out) >= len(body) {
		t.Fatal("the prefix must be strictly shorter than the whole body")
	}
	if !bytes.HasPrefix(body, out) {
		t.Fatal("the recovered bytes must be the real prefix, not garbage")
	}
}

// TestATruncatedZlibStreamReportsTruncatedAndKeepsTheRealPrefix ports
// a_truncated_zlib_stream_reports_truncated_and_keeps_the_real_prefix.
func TestATruncatedZlibStreamReportsTruncatedAndKeepsTheRealPrefix(t *testing.T) {
	body := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog, repeatedly, for good measure. ", 200))
	full, err := Encode(LayerDeflate, body)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	cut := len(full) * 2 / 3
	out, truncated, err := Decode(LayerDeflate, full[:cut])
	if err != nil {
		t.Fatalf("a truncated zlib stream with real prefix must not error: %v", err)
	}
	if !truncated {
		t.Fatal("a zlib stream broken mid-way must be reported as a prefix")
	}
	if len(out) == 0 {
		t.Fatal("some bytes must have decoded before the break")
	}
	if len(out) >= len(body) {
		t.Fatal("the prefix must be strictly shorter than the whole body")
	}
	if !bytes.HasPrefix(body, out) {
		t.Fatal("the recovered bytes must be the real prefix, not garbage")
	}
}

// TestATruncatedRawDeflateStreamReportsTruncatedAndKeepsTheRealPrefix ports
// a_truncated_raw_deflate_stream_reports_truncated_and_keeps_the_real_prefix.
func TestATruncatedRawDeflateStreamReportsTruncatedAndKeepsTheRealPrefix(t *testing.T) {
	body := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog, repeatedly, for good measure. ", 200))
	full := rawDeflate(t, body)
	cut := len(full) * 2 / 3
	out, truncated, err := Decode(LayerDeflate, full[:cut])
	if err != nil {
		t.Fatalf("a truncated raw stream with real prefix must not error: %v", err)
	}
	if !truncated {
		t.Fatal("a raw deflate stream broken mid-way must be reported as a prefix")
	}
	if len(out) == 0 {
		t.Fatal("some bytes must have decoded before the break")
	}
	if len(out) >= len(body) {
		t.Fatal("the prefix must be strictly shorter than the whole body")
	}
	if !bytes.HasPrefix(body, out) {
		t.Fatal("the recovered bytes must be the real prefix, not garbage")
	}
}

// TestADeflateBodyLargerThanOneInflateChunkStillDecodesWhole ports
// a_deflate_body_larger_than_one_inflate_chunk_still_decodes_whole.
func TestADeflateBodyLargerThanOneInflateChunkStillDecodesWhole(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	for _, layer := range []Layer{LayerGzip, LayerDeflate} {
		enc, err := Encode(layer, body)
		if err != nil {
			t.Fatalf("%v encode failed: %v", layer, err)
		}
		out, truncated, err := Decode(layer, enc)
		if err != nil {
			t.Fatalf("%v decode failed: %v", layer, err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("%v must decode a multi-chunk body whole", layer)
		}
		if truncated {
			t.Fatalf("%v: a complete stream is not a prefix", layer)
		}
	}
}

// TestParseLayerRecognisesTheWireNamesAndAliases ports Layer::parse.
func TestParseLayerRecognisesTheWireNamesAndAliases(t *testing.T) {
	for _, s := range []string{"url", "URL", " urlencoded ", "percent"} {
		if l, ok := ParseLayer(s); !ok || l != LayerURL {
			t.Fatalf("ParseLayer(%q) = %v, %v; want url", s, l, ok)
		}
	}
	if l, ok := ParseLayer("b64"); !ok || l != LayerBase64 {
		t.Fatalf("b64 should parse as base64")
	}
	if l, ok := ParseLayer("b64url"); !ok || l != LayerBase64URL {
		t.Fatalf("b64url should parse as base64url")
	}
	if l, ok := ParseLayer("zlib"); !ok || l != LayerDeflate {
		t.Fatalf("zlib should parse as deflate")
	}
	if l, ok := ParseLayer("gz"); !ok || l != LayerGzip {
		t.Fatalf("gz should parse as gzip")
	}
	if l, ok := ParseLayer("jwt"); !ok || l != LayerJWT {
		t.Fatalf("jwt should parse as jwt")
	}
	if _, ok := ParseLayer("rot13"); ok {
		t.Fatal("an unknown layer must not parse")
	}
}

func TestLayerStringRoundTripsThroughParse(t *testing.T) {
	for _, l := range AllLayers() {
		if again, ok := ParseLayer(l.String()); !ok || again != l {
			t.Fatalf("%v.String() = %q must parse back to itself", l, l.String())
		}
	}
}
