package core

import (
	"bytes"
	"strings"
)

// MimeEssence returns the media type of a raw HTTP response: the Content-Type value with every
// parameter stripped and the remainder lowercased, so `Content-Type: text/HTML; charset=utf-8`
// yields `text/html`.
//
// # Why this exists as one function rather than at each call site
//
// Five places construct a core.Exchange with response bytes in hand, and each of them needs the
// same one-line answer for Exchange.Mime. Five hand-rolled scans would drift the moment one of them
// forgot a case — and the cases here are exactly the ones a careless scan gets wrong, which is why
// each has a test: no Content-Type header at all, a header present with an empty value, a header
// carrying only parameters, several Content-Type headers on one response, and a header whose name
// is spelled in a case nobody expected. Being the single answer also means the filter in the UI and
// the value in the database cannot disagree about what a response's type is.
//
// # What "" means, and why the caller must not read it as one fact
//
// Empty is returned for a response that named no usable media type. It is deliberately *not*
// distinguishable here from "there was no response at all", because this function is never shown a
// missing response — it is handed bytes. The distinction lives with the caller, which knows whether
// it has a response: see the comment on Exchange.Mime.
//
// # Why it does not go through Parse
//
// Parse builds a full MessageShape — every header as a pair of spans — and the callers here already
// have the raw bytes and want one header. This walks the head once and stops at the first match, so
// it costs nothing on a large response body: the body is never touched, only the region before the
// header terminator.
func MimeEssence(raw []byte) string {
	headEnd, _ := findHeaderEnd(raw)
	head := raw[:headEnd]

	// Skip the status line. It is not a header, and on a request line an absolute-form target
	// ("GET http://host/p HTTP/1.1") contains a colon — so treating line one as a header could
	// match a "http" name and, worse, read a value out of a URL.
	pos := 0
	if eol := findLineEnd(head, 0); eol >= 0 {
		pos = nextLineStart(head, eol)
	} else {
		return ""
	}

	want := []byte("content-type")
	for pos < len(head) {
		eol := findLineEnd(head, pos)
		if eol < 0 {
			eol = len(head)
		}
		line := head[pos:eol]
		if colon := bytes.IndexByte(line, ':'); colon >= 0 {
			name := bytes.TrimSpace(line[:colon])
			if len(name) == len(want) && bytes.EqualFold(name, want) {
				// First match wins. A response with two Content-Type headers is malformed, and a
				// parser that picked the last one — or concatenated them — would give a different
				// answer than the recipient that stopped reading at the first, so "first" is chosen
				// to be deterministic rather than because it is more correct.
				return MimeFromContentType(string(line[colon+1:]))
			}
		}
		if eol >= len(head) {
			break
		}
		// Forward progress is guarded rather than assumed, and this is not defensive padding — the
		// unguarded version of this loop hung. nextLineStart looks for the LF after a CR, and when the
		// buffer ends on a lone CR that LF is not there, so it returns the CR's own index and `pos`
		// never moves. A response truncated mid-CRLF — a connection cut between the two bytes, which a
		// proxy sees — therefore spun here forever, wedging whichever capture called it with no error
		// and no output. Comparing against `pos` makes termination a property of the loop itself rather
		// than of every input it might be handed.
		next := nextLineStart(head, eol)
		if next <= pos {
			break
		}
		pos = next
	}
	return ""
}

// MimeFromContentType reduces one already-extracted Content-Type header value to its media type.
//
// Exported separately from MimeEssence for the callers that hold the header value rather than the
// whole response — a query row resolving a restored exchange through StoredMessage.Header, for
// instance. It exists so those callers do not each re-implement the reduction: two spellings of
// "strip the parameters" is how a filter and a column come to disagree about what a response's type
// is, and a `mime` comparison that folds case differently from the column beside it is a bug an
// operator diagnoses as flaky filtering.
//
// Parameters are cut at the first semicolon rather than parsed, because nothing downstream wants
// them: the History column shows a type and the History filter matches on one. Keeping the charset
// would split `text/html` into as many filter values as there are encodings in the capture.
func MimeFromContentType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	// Lowercased because media types are case-insensitive per RFC 9110 but are written every which
	// way in the wild, and an exact-match filter over mixed spellings shows one server's `text/HTML`
	// as a category of its own.
	return strings.ToLower(strings.TrimSpace(v))
}
