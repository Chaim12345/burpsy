package httputil

// The head API (burpsy-react-ui-6858): the tree grew 97 separate "\r\n\r\n" searches and
// five headerValue copies across 19 packages. Slice A moved the proxy, sender and intruder
// copies here so their edge cases - bare-LF tolerance versus on-the-wire strictness, CRLF
// winning over an earlier bare LF, the start line not being a header - are stated and tested
// once; the searches remaining elsewhere in the tree are slice B.

import (
	"bytes"
	"strings"
)

var (
	crlfcrlf = []byte("\r\n\r\n")
	lflf     = []byte("\n\n")
)

// SplitHeadBody divides a message at its head terminator, tolerating both CRLF and bare LF,
// and returns the separator it found so a rebuild can put back the same line endings it found
// rather than normalising a message it was only asked to edit. CRLF wins when both shapes are
// present - even when a bare-LF terminator sits EARLIER in the bytes: the LF-only gap is not a
// terminator on the wire, so the text up to the CRLF terminator stays in the head. ok is false
// when the message has no terminator at all.
func SplitHeadBody(raw []byte) (head, body, sep []byte, ok bool) {
	if idx := bytes.Index(raw, crlfcrlf); idx >= 0 {
		return raw[:idx], raw[idx+4:], crlfcrlf, true
	}
	if idx := bytes.Index(raw, lflf); idx >= 0 {
		return raw[:idx], raw[idx+2:], lflf, true
	}
	return nil, nil, nil, false
}

// CutHead divides a message at its CRLF head terminator and nothing else. On the wire a bare
// LF is not a terminator - HTTP/1 framing says CRLF - so parsers reading a live stream use this
// and not the tolerant SplitHeadBody.
func CutHead(raw []byte) (head, body []byte, ok bool) {
	return bytes.Cut(raw, crlfcrlf)
}

// HeadEnd returns the index just past the head terminator, tolerating both CRLF and bare LF,
// or -1 when the message has none. Callers that insert headers want the terminator's START,
// not HeadEnd: the two differ by the separator, and putting a credential past the blank line
// writes it into the body (internal/proxy's requestHeaderInsertPoint keeps that distinction).
func HeadEnd(raw []byte) int {
	if idx := bytes.Index(raw, crlfcrlf); idx >= 0 {
		return idx + 4
	}
	if idx := bytes.Index(raw, lflf); idx >= 0 {
		return idx + 2
	}
	return -1
}

// HeadLines splits a head into its header lines, skipping the request or status line and
// tolerating both CRLF and bare LF. A head with only a start line has no header lines.
func HeadLines(head []byte) [][]byte {
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))
	if len(lines) <= 1 {
		return nil
	}
	return lines[1:]
}

// HeaderValue reads the first occurrence of one header, case-insensitively, with the value
// trimmed of surrounding whitespace. ok is false when the header is absent, so a caller cannot
// mistake "no length" for "length zero". The start line is skipped: an absolute-form request
// target carries a colon that is not a header's. A field name with whitespace before its colon
// still matches, because origins accept it. That is the LENIENT shape - the one proxy.go's
// retired headerValueFold always used. Reads whose recognition changes what the proxy unpacks,
// rewrites or routes on use HeaderValueExact instead.
func HeaderValue(head []byte, name string) (string, bool) {
	for _, line := range HeadLines(head) {
		field, value, ok := strings.Cut(string(line), ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(field), name) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// HeaderValueExact reads the first occurrence of one header under the STRICT shape proxy's
// retired headerValue used: the field name must start the line and meet its colon immediately,
// matched case-insensitively — no whitespace before the colon, no leading whitespace on the
// line, and no Unicode-space trimming. The value is trimmed, as the retired copy trimmed it.
//
// Recognition of Content-Encoding, Transfer-Encoding, Content-Type and Host changes what the
// proxy unpacks, rewrites or routes on, and a line a strict parser would not call that header
// must not have those effects — a sender who can pad "Content-Encoding : gzip" past the proxy
// while an origin reads it strictly has a smuggling channel (0vzb.40 works this ground). The
// reads with those effects use this function; convenience reads keep the lenient HeaderValue.
//
// The name is compared byte for byte with ASCII case folding only. Field names are ASCII tokens, and
// Unicode folding is both wrong and unsafe here: strings.ToLower maps "\u212a" (KELVIN SIGN) to "k",
// so a line the origin reads as some other field would be recognised as the named one, and it
// rewrites invalid UTF-8 to U+FFFD, changing the byte length the value was sliced at (a fuzzed
// "\n\x90:" head panicked with slice bounds out of range).
func HeaderValueExact(head []byte, name string) (string, bool) {
	n := len(name)
	for _, line := range HeadLines(head) {
		if len(line) > n && line[n] == ':' && asciiEqualFold(line[:n], name) {
			return strings.TrimSpace(string(line[n+1:])), true
		}
	}
	return "", false
}

// asciiEqualFold reports whether b and s are equal under ASCII case folding; any non-ASCII byte must
// match exactly.
func asciiEqualFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		x, y := b[i], s[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
