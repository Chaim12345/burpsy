package httputil

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"strings"
	"testing"
)

// burpsy could not decompress a gzip or deflate HTTP message at all: the only inflate in the tree was
// WebSocket-only. These pin the decoder itself — the round trips, and every refusal being a named
// refusal rather than a body handed back undecoded.

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(s))
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func zlibbed(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte(s))
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func rawDeflate(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	fw.Write([]byte(s))
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeBodyRoundTrips(t *testing.T) {
	const body = `<html><body><script>tracker()</script></body></html>`
	cases := []struct {
		encoding string
		packed   []byte
		why      string
	}{
		{"gzip", gz(t, body), "gzip"},
		{"GZIP", gz(t, body), "the header value is case-insensitive"},
		{"x-gzip", gz(t, body), "the legacy spelling some origins still send"},
		{"deflate", zlibbed(t, body), "zlib-wrapped deflate, which is what the HTTP spec means"},
		{"deflate", rawDeflate(t, body), "raw deflate, which enough real servers send that " +
			"refusing it would fail on real traffic"},
		{" gzip ", gz(t, body), "surrounding whitespace"},
	}
	for _, tc := range cases {
		if !Unpackable(tc.encoding) {
			t.Errorf("Unpackable(%q) = false (%s)", tc.encoding, tc.why)
			continue
		}
		got, err := DecodeBody(tc.encoding, tc.packed)
		if err != nil {
			t.Errorf("DecodeBody(%q) [%s]: %v", tc.encoding, tc.why, err)
			continue
		}
		if string(got) != body {
			t.Errorf("DecodeBody(%q) [%s] = %q, want the original body", tc.encoding, tc.why, got)
		}
	}
}

func TestUnpackableRefusals(t *testing.T) {
	// Each of these must report false so the caller counts an honest skip instead of handing a rule a
	// body it never decompressed.
	for _, encoding := range []string{"", "identity", "br", "zstd", "compress", "gzip, br", "gzip,gzip"} {
		if Unpackable(encoding) {
			t.Errorf("Unpackable(%q) = true", encoding)
		}
	}
}

func TestDecodeBodyNamesAnUnsupportedEncoding(t *testing.T) {
	// br has no standard-library decoder. The error must be the named one, so a caller can count "we
	// cannot decode this encoding" apart from "this body did not decompress" — different facts about
	// the same skipped rule.
	_, err := DecodeBody("br", []byte("whatever"))
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("DecodeBody(br) error = %v, want ErrUnsupportedEncoding", err)
	}
	if _, err := DecodeBody("identity", []byte("plain")); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("DecodeBody(identity) error = %v: an identity encoding must be a refusal, not a "+
			"pass-through that hides a caller's bug", err)
	}
}

func TestDecodeBodyRefusesCorruptStreams(t *testing.T) {
	if _, err := DecodeBody("gzip", []byte("not gzip at all")); err == nil {
		t.Error("DecodeBody accepted bytes that are not gzip")
	}
	// A gzip stream cut in half. An HTTP body is a complete stream with an end marker, so a truncated
	// one is a fault, not a normal ending — a rule must never run over half a document.
	packed := gz(t, strings.Repeat("abcdefgh", 500))
	if _, err := DecodeBody("gzip", packed[:len(packed)/2]); err == nil {
		t.Error("DecodeBody accepted a truncated gzip stream")
	}
	if _, err := DecodeBody("deflate", []byte{0x78, 0x9c, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Error("DecodeBody accepted a corrupt zlib stream")
	}
}

func TestDecodeBodyBoundsTheOutput(t *testing.T) {
	// A decompression bomb: highly compressible input larger than the cap. The bound is reported
	// rather than truncating, because a rule applied to half a body rewrites the half it saw and hands
	// the client a document cut in the middle.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for written := 0; written <= MaxDecodedBody; written += len(chunk) {
		zw.Write(chunk)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	_, err := DecodeBody("gzip", buf.Bytes())
	if !errors.Is(err, ErrDecodedTooLarge) {
		t.Errorf("DecodeBody over the cap = %v, want ErrDecodedTooLarge", err)
	}
}

func TestDecodeBodyDoesNotMutateItsInput(t *testing.T) {
	packed := gz(t, "hello")
	before := string(packed)
	if _, err := DecodeBody("gzip", packed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(packed) != before {
		t.Error("DecodeBody mutated its input")
	}
}
