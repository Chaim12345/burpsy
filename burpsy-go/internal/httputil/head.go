package httputil

// The one head API (burpsy-react-ui-6858): the tree grew 97 separate "\r\n\r\n" searches and
// five headerValue copies across 19 packages; they converge here so the edge cases - bare-LF
// tolerance versus on-the-wire strictness, the FIRST terminator winning, the start line not
// being a header - are stated and tested exactly once.

import (
	"bytes"
	"strings"
)

var (
	crlfcrlf = []byte("\r\n\r\n")
	lflf     = []byte("\n\n")
)

// SplitHeadBody divides a message at its first head terminator, tolerating both CRLF and bare
// LF, and returns the separator it found so a rebuild can put back the same line endings it
// found rather than normalising a message it was only asked to edit. ok is false when the
// message has no terminator at all.
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
// still matches, because origins accept it.
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
