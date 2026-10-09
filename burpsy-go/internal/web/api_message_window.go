package web

// Windowed reads of a stored message: GET /api/message/{id}?byte_offset=&max_bytes=&pattern=
// (burpsy-react-ui-yahm).
//
// GET /api/message/{id} returns the whole message, and an MCP tool result is capped at 1 MiB, so a
// body past the cap was unreadable past the cut — the result said "truncated" and there was no way to
// ask for the rest. Burp's inspect_http_message reads a WINDOW of the body: headers always in full,
// then up to max_bytes (default 2048, at most 65536) from an anchor — byte_offset into the body, or
// the first match of a pattern, with byte_offset then relative to the match.
//
// This is that, with three things burpsy adds because its invariant is byte-exactness:
//
//   - window_base64 always carries the exact window bytes. window_text is the same bytes as UTF-8 text
//     for reading, and window_utf8 says whether that text IS the bytes; a JSON string cannot carry
//     invalid UTF-8, so a window that cuts a code point or covers binary is only exact in base64.
//   - next_offset is the absolute body offset to read from next, and null when the window reached the
//     end — "read to the last byte" is a loop on next_offset, not a guess.
//   - matches lists where the pattern matched (up to maxWindowMatches), so an agent can page to the
//     third match by its absolute offset instead of re-searching.
//
// The window is over the body as captured on the wire by default. decoded=true windows the body with
// its chunk framing and Content-Encoding undone instead (the same unwrapping messageViewOf does for
// MessageView.Decoded, held to it by a test); a decode that is not possible is a 400 naming why,
// never a silent fall-back to the wire bytes.
//
// With none of the window parameters, GET /api/message/{id} answers exactly as it always has: the
// console reads that shape.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

const (
	defaultWindowBytes = 2048
	maxWindowBytes     = 65536
	// maxWindowMatches bounds the matches list. The window's anchor is always the first match; the
	// list is for paging, and a pattern that matches every byte of a 3 MiB body must not turn into a
	// 3-million-row reply.
	maxWindowMatches = 100
	// maxWindowPatternLen bounds the regex an agent may send, like the suite search's term bound.
	maxWindowPatternLen = 4096
)

// windowParams are the query parameters that turn a message read into a windowed one.
var windowParams = []string{"byte_offset", "max_bytes", "pattern", "case_insensitive", "decoded"}

func wantsWindow(r *http.Request) bool {
	q := r.URL.Query()
	for _, p := range windowParams {
		if q.Has(p) {
			return true
		}
	}
	return false
}

type windowMatch struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// messageWindowView is the windowed read's reply.
type messageWindowView struct {
	ID uint64 `json:"id"`
	// Len is the whole stored message's byte length, head and body.
	Len int `json:"len"`
	// Head is the request/status line and every header, always in full, as text.
	Head string `json:"head"`
	// BodySource is "wire" (the bytes as captured) or "decoded" (chunking and Content-Encoding undone).
	BodySource      string `json:"body_source"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	Chunked         bool   `json:"chunked"`
	// TotalBodyBytes is the length of the body being windowed (wire or decoded).
	TotalBodyBytes int `json:"total_body_bytes"`
	// ByteOffset is the window's absolute start in that body; MaxBytes the size asked for.
	ByteOffset int `json:"byte_offset"`
	MaxBytes   int `json:"max_bytes"`
	// WindowBytes is how many bytes the window holds (fewer than MaxBytes at the end of the body).
	WindowBytes int `json:"window_bytes"`
	// NextOffset is where the next window starts, or null when this one reached the end of the body.
	NextOffset   *int   `json:"next_offset"`
	WindowBase64 string `json:"window_base64"`
	WindowText   string `json:"window_text"`
	// WindowUTF8 reports that WindowText is exactly the window's bytes. False means it is a lossy
	// rendering and WindowBase64 is the only exact copy.
	WindowUTF8 bool `json:"window_utf8"`
	// Pattern, Anchor and Matches describe a pattern read. Anchor is the first match's absolute start,
	// or null when the pattern matched nothing (the window is then empty). Matches is always an array.
	Pattern       string        `json:"pattern,omitempty"`
	Anchor        *int          `json:"anchor"`
	Matches       []windowMatch `json:"matches"`
	MatchesCapped bool          `json:"matches_capped"`
	Note          string        `json:"note,omitempty"`
}

// unwrapForWindow undoes chunk framing and Content-Encoding the way messageViewOf does, returning the
// plain body or the reason it cannot be had.
func unwrapForWindow(head, body []byte) ([]byte, string) {
	plain := body
	if strings.EqualFold(firstHeaderValue(head, "Transfer-Encoding"), "chunked") {
		unchunked, ok := dechunkForView(plain)
		if !ok {
			return nil, "the chunk framing did not parse"
		}
		plain = unchunked
	}
	encoding := firstHeaderValue(head, "Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return plain, ""
	}
	if !httputil.Unpackable(encoding) {
		return nil, "no decoder for Content-Encoding " + strconv.Quote(encoding) + " in this build"
	}
	decoded, err := httputil.DecodeBody(encoding, plain)
	if err != nil {
		return nil, "the body did not decode: " + err.Error()
	}
	return decoded, ""
}

// intParam reads an integer query parameter; ok is false (and a 400 has been written) when present and
// not an integer.
func intParam(w http.ResponseWriter, r *http.Request, name string, def int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s must be an integer; got %q", name, raw), http.StatusBadRequest)
		return 0, false
	}
	return n, true
}

func (s *Server) messageWindow(w http.ResponseWriter, r *http.Request, id uint64, raw []byte) {
	q := r.URL.Query()
	maxBytes, ok := intParam(w, r, "max_bytes", defaultWindowBytes)
	if !ok {
		return
	}
	if maxBytes < 1 || maxBytes > maxWindowBytes {
		http.Error(w, fmt.Sprintf("max_bytes must be 1..%d", maxWindowBytes), http.StatusBadRequest)
		return
	}
	offset, ok := intParam(w, r, "byte_offset", 0)
	if !ok {
		return
	}
	pattern := q.Get("pattern")
	if len(pattern) > maxWindowPatternLen {
		http.Error(w, fmt.Sprintf("pattern is longer than %d bytes", maxWindowPatternLen), http.StatusBadRequest)
		return
	}
	if pattern == "" && offset < 0 {
		http.Error(w, "a negative byte_offset is only meaningful relative to a pattern match", http.StatusBadRequest)
		return
	}

	head, body := splitHeadBody(raw)
	view := messageWindowView{
		ID:              id,
		Len:             len(raw),
		Head:            string(head),
		BodySource:      "wire",
		ContentEncoding: firstHeaderValue(head, "Content-Encoding"),
		Chunked:         strings.EqualFold(firstHeaderValue(head, "Transfer-Encoding"), "chunked"),
		MaxBytes:        maxBytes,
		Matches:         []windowMatch{},
	}
	if truthy(q.Get("decoded")) {
		plain, problem := unwrapForWindow(head, body)
		if problem != "" {
			http.Error(w, "decoded=true cannot be honoured: "+problem+"; read the wire bytes instead (omit decoded)", http.StatusBadRequest)
			return
		}
		body = plain
		view.BodySource = "decoded"
	}
	view.TotalBodyBytes = len(body)

	start := offset
	if pattern != "" {
		expr := pattern
		if truthy(q.Get("case_insensitive")) {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			http.Error(w, "pattern is not a valid regular expression (RE2 syntax): "+err.Error(), http.StatusBadRequest)
			return
		}
		view.Pattern = pattern
		locs := re.FindAllIndex(body, maxWindowMatches+1)
		if len(locs) > maxWindowMatches {
			locs = locs[:maxWindowMatches]
			view.MatchesCapped = true
		}
		for _, l := range locs {
			view.Matches = append(view.Matches, windowMatch{Start: l[0], End: l[1]})
		}
		if len(locs) == 0 {
			view.Note = "the pattern matched nothing in the body, so the window is empty"
			view.ByteOffset = 0
			view.WindowUTF8 = true
			writeJSON(w, http.StatusOK, view)
			return
		}
		anchor := locs[0][0]
		view.Anchor = &anchor
		start = anchor + offset
		if start < 0 {
			start = 0
		}
	}
	if start > len(body) {
		start = len(body)
	}
	end := start + maxBytes
	if end > len(body) {
		end = len(body)
	}
	window := body[start:end]
	view.ByteOffset = start
	view.WindowBytes = len(window)
	view.WindowBase64 = base64.StdEncoding.EncodeToString(window)
	view.WindowText = string(window)
	view.WindowUTF8 = utf8.Valid(window)
	if end < len(body) {
		next := end
		view.NextOffset = &next
	}
	writeJSON(w, http.StatusOK, view)
}
