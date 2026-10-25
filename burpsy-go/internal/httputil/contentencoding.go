package httputil

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Decoding a Content-Encoding, so a compressed HTTP message can be read and rewritten.
//
// # The gap this closes
//
// burpsy could not decompress a gzip or deflate HTTP message at all. The only inflate anywhere in the
// tree was WebSocket-only and view-only (core.InflateWsMessage). The consequences were both visible
// and both honestly disclosed, which is why this is a gap and not a defect: a compressed response was
// unreadable in history, and every proxy response-modification rule skipped it — counted as
// Counters.SkippedCompressed and surfaced on the Proxy settings panel, with the panel's own copy
// naming the missing decompressor as the cause. The only workaround offered was
// strip_accept_encoding, which changes what the client asks the origin for and is detectable
// server-side, so the operator had to choose between reading the traffic and observing the traffic the
// client would really have received.
//
// Burp's Proxy → Miscellaneous panel has exactly two switches for this, "unpack gzip" and "unpack
// deflate" (proxyOptionsUnpackCompressedRequests / …Responses), which is the shape internal/proxy now
// mirrors.
//
// # What is supported, and why the rest is a refusal rather than a guess
//
// gzip and deflate, which are what Burp's own two switches name, plus br (Brotli) and zstd, which
// origins increasingly send and Burp decodes without a switch. br and zstd have no
// standard-library decoder, so they run through andybalholm/brotli and klauspost/compress/zstd —
// both already linked into this binary through gitleaks, made direct dependencies rather than
// adding anything new. What is left refused is what no decoder here can read (a chain like
// "gzip, br", the obsolete "compress"): Unpackable reports false so the caller counts an honest
// skip rather than handing a rule a body it could not decompress. Inventing a decode that
// "mostly works" for those would corrupt bodies on the wire.

// MaxDecodedBody bounds the output of one decode.
//
// A compressed body is a decompression bomb by construction: a few kilobytes of gzip can expand to
// gigabytes, and this runs on the proxy's own connection goroutine for every response while an unpack
// option is on. 64 MiB is far above any real page and far below anything that threatens the process.
// The bound is reported as ErrDecodedTooLarge rather than silently truncating, because a rule applied
// to half a body would rewrite the half it saw and hand the client a document cut in the middle.
const MaxDecodedBody = 64 << 20

// ErrDecodedTooLarge is returned when a decoded body exceeds MaxDecodedBody. Its own error because
// the caller must treat it differently from corruption: nothing is wrong with the data, there is
// simply too much of it, and the right response is to leave the message alone and say why.
var ErrDecodedTooLarge = errors.New("decoded body exceeds the cap")

// ErrUnsupportedEncoding is returned for a Content-Encoding this build cannot decode — an
// encoding chain or a name with no decoder here. Named so a caller can count "we cannot decode
// this encoding" apart from "this body did not decompress", which are different facts about the
// same skipped rule.
var ErrUnsupportedEncoding = errors.New("unsupported content encoding")

// Unpackable reports whether DecodeBody can handle this Content-Encoding value.
//
// An empty value, and "identity", are unpackable in the trivial sense — there is nothing to unpack —
// and report false, because a caller uses this to decide whether to *change* the message. A
// comma-joined list ("gzip, br") reports false: unwinding a chain means decoding it in the right
// order and re-encoding what is left, and getting that wrong corrupts a body. One encoding is what
// origins send in practice and is what this handles.
func Unpackable(encoding string) bool {
	switch normalizeEncoding(encoding) {
	case "gzip", "x-gzip", "deflate", "br", "zstd":
		return true
	}
	return false
}

// normalizeEncoding lowercases and trims one Content-Encoding value, returning "" for a value that
// names more than one encoding.
func normalizeEncoding(encoding string) string {
	e := strings.ToLower(strings.TrimSpace(encoding))
	if e == "" || e == "identity" {
		return ""
	}
	if strings.Contains(e, ",") {
		return ""
	}
	return e
}

// DecodeBody decompresses `body` according to `encoding`.
//
// Returns ErrUnsupportedEncoding for an encoding this build cannot decode, so a caller counts the
// refusal instead of receiving bytes that were never decompressed. An identity or empty encoding is
// also an ErrUnsupportedEncoding rather than a pass-through: a caller that reached here believing
// there was something to decode has a bug, and returning the input unchanged would hide it.
//
// The input is never modified.
func DecodeBody(encoding string, body []byte) ([]byte, error) {
	switch normalizeEncoding(encoding) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		return readCapped(zr)
	case "deflate":
		// "deflate" on the wire is zlib-wrapped deflate (RFC 1950), which is what the HTTP spec means
		// and what every correct server sends. Enough servers send raw deflate (RFC 1951) instead that
		// refusing it would fail on real traffic, so a zlib header failure falls back to raw. The
		// fallback is tried only when the zlib *header* is rejected, not when a valid stream fails
		// mid-way: re-reading a corrupt zlib stream as raw deflate would produce plausible garbage.
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err == nil {
			defer zr.Close()
			return readCapped(zr)
		}
		fr := flate.NewReader(bytes.NewReader(body))
		defer fr.Close()
		out, ferr := readCapped(fr)
		if ferr != nil {
			// The zlib error is the one reported: zlib-wrapped is what the encoding name means, so
			// that is the failure the operator should see, with the raw attempt named as also having
			// failed rather than silently swallowed.
			return nil, fmt.Errorf("deflate: %w (raw deflate also failed: %v)", err, ferr)
		}
		return out, nil
	case "br":
		out, err := readCapped(brotli.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, fmt.Errorf("br: %w", err)
		}
		return out, nil
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("zstd: %w", err)
		}
		defer zr.Close()
		out, rerr := readCapped(zr)
		if rerr != nil {
			return nil, fmt.Errorf("zstd: %w", rerr)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w %q", ErrUnsupportedEncoding, encoding)
	}
}

// readCapped reads at most MaxDecodedBody bytes, reporting ErrDecodedTooLarge when there was more.
//
// One byte over the cap is read, so landing exactly on the cap is distinguishable from exceeding it —
// otherwise a body of exactly MaxDecodedBody would be reported as too large.
func readCapped(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, MaxDecodedBody+1))
	if err != nil && !errors.Is(err, io.EOF) {
		// io.ErrUnexpectedEOF is a real fault here, unlike in core.InflateWsMessage: an HTTP body is
		// a complete stream with an end marker, not a sync-flushed frame, so a truncated one is
		// truncated and a rule must not run over a partial document.
		return nil, err
	}
	if len(out) > MaxDecodedBody {
		return nil, ErrDecodedTooLarge
	}
	return out, nil
}
