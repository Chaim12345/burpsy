package tools

// Byte-level encode/decode codecs, ported from burpsy-tools::decoder.
//
// This is the byte layer the payload-processing chain runs on. It deliberately lives
// alongside the string-based Decoder tool (tools.go) rather than replacing it: the
// Decoder is a human-facing convenience, while these codecs are exact byte transforms
// with the one property the intruder crate is built on — a partial or failed decode is
// named as such, never passed through as if the rule had run.
//
// The semantics (uppercase percent-encoding, `+` untouched, tolerant base64, the 64 MiB
// inflate cap, the truncated flag) are lifted straight from burpsy-tools::decoder so a
// payload encoded here is byte-identical to one encoded there.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Layer is one reversible (or, for LayerJWT, one-way) transformation.
type Layer int

const (
	// LayerURL is percent-encoding, as in a URL.
	LayerURL Layer = iota
	// LayerHTML is HTML character references.
	LayerHTML
	LayerBase64
	// LayerBase64URL is base64 over the URL-safe alphabet (`-` and `_`), as used by JWT.
	LayerBase64URL
	LayerHex
	LayerGzip
	// LayerDeflate is `Content-Encoding: deflate`. Decode tries zlib-wrapped first and
	// falls back to raw deflate, matching Burp and the Rust decoder.
	LayerDeflate
	// LayerJWT splits a JWT into pretty-printed header and payload. One-way: see Encode.
	LayerJWT
)

var layerNames = [...]string{"url", "html", "base64", "base64url", "hex", "gzip", "deflate", "jwt"}

// String is the canonical wire name of the layer.
func (l Layer) String() string {
	if int(l) < len(layerNames) {
		return layerNames[l]
	}
	return "unknown"
}

// ParseLayer parses the name used on the wire. Returns false rather than guessing.
func ParseLayer(s string) (Layer, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "url", "urlencoded", "percent":
		return LayerURL, true
	case "html", "htmlentity", "entity":
		return LayerHTML, true
	case "base64", "b64":
		return LayerBase64, true
	case "base64url", "b64url":
		return LayerBase64URL, true
	case "hex", "hexadecimal", "ascii-hex":
		return LayerHex, true
	case "gzip", "gz":
		return LayerGzip, true
	case "deflate", "zlib":
		return LayerDeflate, true
	case "jwt":
		return LayerJWT, true
	default:
		return 0, false
	}
}

// AllLayers returns every layer, in the order the UI should list them.
func AllLayers() []Layer {
	return []Layer{LayerURL, LayerHTML, LayerBase64, LayerBase64URL, LayerHex, LayerGzip, LayerDeflate, LayerJWT}
}

// MaxInflate refuses to inflate more than this from one input. A 46-byte gzip stream
// expands to a megabyte of zeroes, and a few kilobytes reach terabytes. The decoder runs
// on bytes an attacker chose, so an unbounded inflate is a remote OOM. 64 MiB is far past
// any response worth reading by hand and far short of hurting the process.
const MaxInflate = 64 * 1024 * 1024

// DecodeError is the refusal path for a codec that cannot do what was asked. The message
// mirrors burpsy-tools::decoder's DecodeError Display.
type DecodeError struct {
	msg string
}

func (e *DecodeError) Error() string { return e.msg }

func notReversible(l Layer) error {
	return &DecodeError{msg: fmt.Sprintf("%s cannot be encoded, only decoded", l.String())}
}

func compressionFailed(err error) error {
	return &DecodeError{msg: "decompression failed: " + err.Error()}
}

func malformed(msg string) error {
	return &DecodeError{msg: msg}
}

// Decode applies one layer to the whole input. This is the explicit "decode as" path.
//
// The bool is truncated: true when the bytes returned are a prefix of the real output
// rather than the whole of it, because the inflate cap cut the stream short or it broke
// mid-way. Only the compressed layers can set it. Returning partial output as an
// unqualified success is the defect this signature exists to prevent — an operator who
// searches 40 recovered bytes and concludes a string is absent has been misled when the
// string sat in the 3 960 that never decompressed.
func Decode(l Layer, input []byte) ([]byte, bool, error) {
	switch l {
	case LayerURL:
		return URLDecode(input), false, nil
	case LayerHTML:
		return HTMLDecode(input), false, nil
	case LayerBase64:
		return Base64Decode(input, false), false, nil
	case LayerBase64URL:
		return Base64Decode(input, true), false, nil
	case LayerHex:
		v, err := HexDecode(input)
		if err != nil {
			return nil, false, err
		}
		return v, false, nil
	case LayerGzip:
		return inflateGzip(input)
	case LayerDeflate:
		// `Content-Encoding: deflate` is specified as zlib-wrapped, and that is what
		// nearly every server sends — but a minority emit a raw deflate stream, and Burp
		// users hit both. Try the spec-compliant framing first and fall back.
		//
		// Including the empty case: a valid zlib stream that decodes to zero bytes is an
		// empty body, not a failure; sending it down the raw-deflate fallback would run
		// that decoder over zlib-framed bytes and report an error for a body that was
		// simply empty. Both framings failing is reported with the zlib error, because
		// zlib is what the header specifies and what nearly every server sends.
		out, trunc, err := inflateZlib(input, true)
		if err == nil {
			return out, trunc, nil
		}
		zlibErr := err
		out, trunc, rawErr := inflateZlib(input, false)
		if rawErr != nil {
			return nil, false, zlibErr
		}
		return out, trunc, nil
	case LayerJWT:
		v, err := JWTDecode(input)
		if err != nil {
			return nil, false, err
		}
		return v, false, nil
	default:
		return nil, false, malformed("unknown layer")
	}
}

// Encode applies one layer's inverse, where one exists. JWT has no inverse: re-encoding
// needs the signing key, and emitting an unsigned token that looks like the original
// would be worse than refusing.
func Encode(l Layer, input []byte) ([]byte, error) {
	switch l {
	case LayerURL:
		return URLEncode(input), nil
	case LayerHTML:
		return HTMLEncode(input), nil
	case LayerBase64:
		return Base64Encode(input, false, true), nil
	case LayerBase64URL:
		return Base64Encode(input, true, false), nil
	case LayerHex:
		return HexEncode(input), nil
	case LayerGzip:
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(input); err != nil {
			return nil, compressionFailed(err)
		}
		if err := w.Close(); err != nil {
			return nil, compressionFailed(err)
		}
		return buf.Bytes(), nil
	case LayerDeflate:
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(input); err != nil {
			return nil, compressionFailed(err)
		}
		if err := w.Close(); err != nil {
			return nil, compressionFailed(err)
		}
		return buf.Bytes(), nil
	case LayerJWT:
		return nil, notReversible(LayerJWT)
	default:
		return nil, malformed("unknown layer")
	}
}

// finishInflate decides what a raw inflate run produced: a whole output, a capped prefix,
// or nothing at all. The error semantics match burpsy-tools::decoder's inflate: a broken
// stream that already yielded bytes keeps them as a truncated prefix; only a stream that
// produced nothing is an error.
func finishInflate(out []byte, readErr error) ([]byte, bool, error) {
	capped := uint64(len(out)) > MaxInflate
	if capped {
		out = out[:MaxInflate]
	}
	if readErr != nil {
		if len(out) == 0 {
			return nil, false, compressionFailed(readErr)
		}
		return out, true, nil
	}
	return out, capped, nil
}

// inflateGzip decodes a gzip stream, capping output at MaxInflate+1 bytes so a
// decompression bomb is bounded and the truncation is visible.
func inflateGzip(input []byte) ([]byte, bool, error) {
	r, err := gzip.NewReader(bytes.NewReader(input))
	if err != nil {
		return nil, false, compressionFailed(err)
	}
	defer r.Close()
	out, readErr := io.ReadAll(io.LimitReader(r, MaxInflate+1))
	return finishInflate(out, readErr)
}

// inflateZlib decodes a zlib-wrapped or raw deflate stream, capping output exactly like
// inflateGzip. Go's compress/flate reports a truncated stream as io.ErrUnexpectedEOF,
// which finishInflate turns into a truncated prefix rather than a whole-looking decode.
func inflateZlib(input []byte, zlibHeader bool) ([]byte, bool, error) {
	var r io.ReadCloser
	if zlibHeader {
		zr, err := zlib.NewReader(bytes.NewReader(input))
		if err != nil {
			return nil, false, compressionFailed(err)
		}
		r = zr
	} else {
		r = flate.NewReader(bytes.NewReader(input))
	}
	defer r.Close()
	out, readErr := io.ReadAll(io.LimitReader(r, MaxInflate+1))
	return finishInflate(out, readErr)
}

// ---- percent encoding -------------------------------------------------------------------------

var hexUpper = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}
var hexLower = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// URLDecode decodes `%XX`. A `%` that is not followed by two hex digits is left alone.
//
// `+` is not turned into a space here. That conversion belongs to
// application/x-www-form-urlencoded, and applying it unconditionally corrupts a very
// common payload: base64 carried in a query string, where `+` is a data byte.
func URLDecode(input []byte) []byte {
	out := make([]byte, 0, len(input))
	i := 0
	for i < len(input) {
		if input[i] == '%' && i+2 < len(input) {
			if h, ok := hexVal(input[i+1]); ok {
				if l, ok2 := hexVal(input[i+2]); ok2 {
					out = append(out, h<<4|l)
					i += 3
					continue
				}
			}
		}
		out = append(out, input[i])
		i++
	}
	return out
}

// URLEncode percent-encodes everything outside RFC 3986's unreserved set.
//
// Aggressive on purpose: an encoder used for attack payloads should escape `&`, `=` and
// `/`, because leaving them raw is how a payload breaks out of the parameter it was meant
// to sit in. Uppercase hex digits, matching burpsy-tools::decoder.
func URLEncode(input []byte) []byte {
	out := make([]byte, 0, len(input)*3)
	for _, b := range input {
		if isUnreserved(b) {
			out = append(out, b)
		} else {
			out = append(out, '%', hexUpper[b>>4], hexUpper[b&0x0f])
		}
	}
	return out
}

func isUnreserved(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

// ---- HTML character references ----------------------------------------------------------------

// entities are the named references worth carrying. Injection testing lives on these five
// plus nbsp; the full HTML5 table is 2231 entries of mostly typography.
var entities = map[string]string{
	"amp":  "&",
	"lt":   "<",
	"gt":   ">",
	"quot": "\"",
	"apos": "'",
	"nbsp": "\u00a0",
}

// entityScan is how far past `&` a character reference may run before we stop looking.
const entityScan = 8

// HTMLDecode decodes named and numeric character references. An unrecognised `&...;` is
// left verbatim — swallowing it would lose the very bytes that reveal a filter's behaviour.
func HTMLDecode(input []byte) []byte {
	out := make([]byte, 0, len(input))
	i := 0
	for i < len(input) {
		if input[i] != '&' {
			out = append(out, input[i])
			i++
			continue
		}
		if c, n := entityAt(input, i); n > 0 {
			out = append(out, string(c)...)
			i += n
		} else {
			out = append(out, '&')
			i++
		}
	}
	return out
}

// entityAt returns the character reference starting at i and how many input bytes it spans.
func entityAt(b []byte, i int) (rune, int) {
	start := i + 1
	// A numeric reference can be longer than a named one; allow for &#x10FFFF;.
	limit := min(start+max(entityScan, 9), len(b))
	seg := b[start:limit]
	end := bytes.IndexByte(seg, ';')
	if end < 0 {
		return 0, 0
	}
	c, ok := entityChar(b[start : start+end])
	if !ok {
		return 0, 0
	}
	return c, end + 2
}

func entityChar(body []byte) (rune, bool) {
	if len(body) == 0 {
		return 0, false
	}
	if body[0] == '#' {
		digits := body[1:]
		radix := 10
		if len(body) > 1 && (body[1]|0x20) == 'x' {
			digits = body[2:]
			radix = 16
		}
		if len(digits) == 0 {
			return 0, false
		}
		n, err := strconv.ParseUint(string(digits), radix, 32)
		if err != nil {
			return 0, false
		}
		r := rune(n)
		if !utf8.ValidRune(r) {
			return 0, false
		}
		return r, true
	}
	name := string(body)
	if s, ok := entities[name]; ok {
		r, _ := utf8.DecodeRuneInString(s)
		return r, true
	}
	return 0, false
}

// HTMLEncode escapes the five characters that change how a browser parses the surrounding
// markup. Anything else is left as-is: escaping ordinary text to numeric references makes
// payloads unreadable without making them safer.
func HTMLEncode(input []byte) []byte {
	out := make([]byte, 0, len(input))
	for _, b := range input {
		switch b {
		case '&':
			out = append(out, "&amp;"...)
		case '<':
			out = append(out, "&lt;"...)
		case '>':
			out = append(out, "&gt;"...)
		case '"':
			out = append(out, "&quot;"...)
		case '\'':
			out = append(out, "&#39;"...)
		default:
			out = append(out, b)
		}
	}
	return out
}

// ---- base64 -----------------------------------------------------------------------------------

// Base64Decode decodes base64, tolerating absent padding, embedded whitespace and stray
// characters. Tolerant because the input is usually a value lifted out of a header or a
// cookie, where line wrapping and truncated padding are normal. Returns bytes, not text:
// a layer above may be gzip.
func Base64Decode(input []byte, urlAlphabet bool) []byte {
	out := make([]byte, 0, len(input)*3/4+3)
	var acc uint32
	var bits uint32
	for _, c := range input {
		if c == '=' {
			break
		}
		v, ok := b64Val(c, urlAlphabet)
		if !ok {
			continue
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out
}

func b64Val(c byte, urlAlphabet bool) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+' && !urlAlphabet:
		return 62, true
	case c == '/' && !urlAlphabet:
		return 63, true
	case c == '-' && urlAlphabet:
		return 62, true
	case c == '_' && urlAlphabet:
		return 63, true
	default:
		return 0, false
	}
}

var base64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
var base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// Base64Encode encodes bytes to base64, optionally over the URL-safe alphabet and
// optionally padded, matching burpsy-tools::decoder.
func Base64Encode(input []byte, urlAlphabet, pad bool) []byte {
	alpha := base64Std
	if urlAlphabet {
		alpha = base64URL
	}
	out := make([]byte, 0, (len(input)+2)/3*4)
	head := input
	for len(head) >= 3 {
		n := uint32(head[0])<<16 | uint32(head[1])<<8 | uint32(head[2])
		out = append(out, alpha[n>>18&63], alpha[n>>12&63], alpha[n>>6&63], alpha[n&63])
		head = head[3:]
	}
	if len(head) > 0 {
		b0 := uint32(head[0])
		var b1 uint32
		if len(head) > 1 {
			b1 = uint32(head[1])
		}
		n := b0<<16 | b1<<8
		out = append(out, alpha[n>>18&63], alpha[n>>12&63])
		if len(head) > 1 {
			out = append(out, alpha[n>>6&63])
		} else if pad {
			out = append(out, '=')
		}
		if len(head) > 2 {
			out = append(out, alpha[n&63])
		} else if pad {
			out = append(out, '=')
		}
	}
	return out
}

// ---- hex --------------------------------------------------------------------------------------

// HexDecode decodes ASCII hex, ignoring whitespace and `:` separators (the form tcpdump
// and Wireshark produce). Anything else is an error rather than a silent skip: a stray
// character in a hex dump means the selection was wrong, and quietly dropping it would
// produce plausible garbage.
func HexDecode(input []byte) ([]byte, error) {
	nibbles := make([]byte, 0, len(input))
	for _, c := range input {
		if isASCIISpace(c) || c == ':' {
			continue
		}
		v, ok := hexVal(c)
		if !ok {
			return nil, &DecodeError{msg: fmt.Sprintf("not a hex digit: %q", rune(c))}
		}
		nibbles = append(nibbles, v)
	}
	if len(nibbles)%2 != 0 {
		return nil, &DecodeError{msg: fmt.Sprintf("hex input has %d digits; a byte needs two", len(nibbles))}
	}
	out := make([]byte, len(nibbles)/2)
	for i := 0; i < len(out); i++ {
		out[i] = nibbles[2*i]<<4 | nibbles[2*i+1]
	}
	return out, nil
}

func isASCIISpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

// HexEncode encodes bytes as lowercase hex, matching burpsy-tools::decoder.
func HexEncode(input []byte) []byte {
	out := make([]byte, len(input)*2)
	for i, b := range input {
		out[2*i] = hexLower[b>>4]
		out[2*i+1] = hexLower[b&0x0f]
	}
	return out
}

// ---- JWT --------------------------------------------------------------------------------------

// JWTDecode renders a compact JWT as pretty JSON with header, payload and signature
// separated. A segment that is not JSON is shown as a string rather than dropped, because
// a malformed segment is itself the finding. Mirrors burpsy-tools::decoder's jwt_decode.
func JWTDecode(input []byte) ([]byte, error) {
	if !isASCII(input) {
		return nil, malformed("a JWT is ASCII; these bytes are not UTF-8")
	}
	s := strings.TrimSpace(string(input))
	// Tolerate the `Authorization: Bearer <token>` form.
	s = strings.TrimSpace(strings.TrimPrefix(s, "Bearer "))
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, malformed("not a compact JWT: expected header.payload.signature")
	}
	header := Base64Decode([]byte(parts[0]), true)
	payload := Base64Decode([]byte(parts[1]), true)
	asJSON := func(b []byte) any {
		var v any
		if json.Unmarshal(b, &v) == nil {
			return v
		}
		return strings.ToValidUTF8(string(b), "\uFFFD")
	}
	doc := map[string]any{
		"header":    asJSON(header),
		"payload":   asJSON(payload),
		"signature": parts[2],
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, malformed("could not render the decoded token")
	}
	return out, nil
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}
