package httputil

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
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
	for _, encoding := range []string{"", "identity", "compress", "gzip, br", "gzip,gzip"} {
		if Unpackable(encoding) {
			t.Errorf("Unpackable(%q) = true", encoding)
		}
	}
}

func TestDecodeBodyNamesAnUnsupportedEncoding(t *testing.T) {
	// "compress" has no decoder in this build. The error must be the named one, so a caller can count "we
	// cannot decode this encoding" apart from "this body did not decompress" — different facts about
	// the same skipped rule.
	_, err := DecodeBody("compress", []byte("whatever"))
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("DecodeBody(compress) error = %v, want ErrUnsupportedEncoding", err)
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

// Fixed vectors, generated once with the two libraries this build links (andybalholm/brotli
// v1.2.0, klauspost/compress v1.18.0) over the same plaintext — a round trip through the encoder
// would pass even with the two cases swapped, a fixed vector cannot.
var (
	brVectorPlain = []byte("the quick brown fox jumps over the lazy dog, again and again and again")
	brVector      = []byte{
		0x1b, 0x45, 0x00, 0x00, 0x44, 0xf3, 0xa4, 0x69, 0x6d, 0x76, 0xeb, 0x42, 0x1c, 0x22, 0x4f, 0xe5,
		0xf8, 0x61, 0x22, 0x27, 0x06, 0x91, 0xb4, 0xd4, 0x2e, 0x7a, 0xd8, 0x18, 0x3b, 0x43, 0x10, 0x1c,
		0x33, 0x62, 0x26, 0x41, 0xf3, 0x84, 0x53, 0x9e, 0x86, 0xc0, 0x8b, 0xbc, 0x6a, 0x1f, 0xe0, 0x16,
		0x85, 0xb2, 0x8b, 0xfd, 0x0f, 0x9e, 0xd1, 0xcc, 0x33, 0xf8, 0x4b, 0x61, 0x11,
	}
	zstdVector = []byte{
		0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x00, 0x31, 0x02, 0x00, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69,
		0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d,
		0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79,
		0x20, 0x64, 0x6f, 0x67, 0x2c, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20,
		0x61, 0x67, 0x61, 0x69, 0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x33,
		0x7b, 0xa8, 0xa8,
	}
)

func TestDecodeBodyDecodesBrotli(t *testing.T) {
	out, err := DecodeBody("br", brVector)
	if err != nil {
		t.Fatalf("br decode: %v", err)
	}
	if !bytes.Equal(out, brVectorPlain) {
		t.Errorf("br decoded to %q, want %q", out, brVectorPlain)
	}
	if !Unpackable("br") {
		t.Error("Unpackable(br) = false")
	}
}

func TestDecodeBodyDecodesZstd(t *testing.T) {
	out, err := DecodeBody("zstd", zstdVector)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}
	if !bytes.Equal(out, brVectorPlain) {
		t.Errorf("zstd decoded to %q, want %q", out, brVectorPlain)
	}
	if !Unpackable("zstd") {
		t.Error("Unpackable(zstd) = false")
	}
}

func TestDecodeBodyRefusesCorruptBrotliAndZstd(t *testing.T) {
	if _, err := DecodeBody("br", []byte("not brotli at all, just prose")); err == nil {
		t.Error("corrupt brotli decoded without an error")
	}
	if _, err := DecodeBody("zstd", []byte("not zstd at all, just prose")); err == nil {
		t.Error("corrupt zstd decoded without an error")
	}
}

func TestDecodeBodyBoundsBrotliAndZstdOutput(t *testing.T) {
	// A bomb built with the real encoders, past the cap the way the gzip pin above builds it.
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	payload := bytes.Repeat(chunk, MaxDecodedBody/(1<<20)+1)
	bombBr := brotliEncode(t, payload)
	if _, err := DecodeBody("br", bombBr); !errors.Is(err, ErrDecodedTooLarge) {
		t.Errorf("br bomb error = %v, want ErrDecodedTooLarge", err)
	}
	bombZstd := zstdEncode(t, payload)
	if _, err := DecodeBody("zstd", bombZstd); !errors.Is(err, ErrDecodedTooLarge) {
		t.Errorf("zstd bomb error = %v, want ErrDecodedTooLarge", err)
	}
}

func brotliEncode(t *testing.T, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriter(&b)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zstdEncode(t *testing.T, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := zstd.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
