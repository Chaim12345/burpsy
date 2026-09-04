package web

// Uninteresting headers — Burp's `configPanelUninterestingRequestHeaders` and
// `configPanelUninterestingResponseHeaders` (W6 #81, #82).
//
// Both were state 0: no capability at all. `grep -rin 'uninteresting'` over the tree returned
// nothing, with `passthrough` as the positive control at 20+ hits.
//
// # What the setting is for
//
// Comparing two responses is how an operator decides whether an input changed behaviour. The
// comparison is drowned by headers that differ on every request and mean nothing: `Date` always
// differs, `ETag` and `Age` usually do, and a request-id header differs by construction. An
// operator looking for "did my payload change the response" has to read past all of it every time.
//
// # Why this tags rather than strips
//
// Burp removes these headers before comparing. burpsy cannot: the Comparer is a byte-level diff and
// the console renders it by slicing the original text at the offsets the backend returns
// (see api_types.go's note on `len`). Deleting header lines would shift every later offset, and
// masking values in place is impossible because the two values differ in length — that is the whole
// reason they are noise.
//
// So each diff op is *tagged* when it falls inside an uninteresting header line, and the response
// carries both verdicts: `identical` as before, and `identical_ignoring_uninteresting`. This is
// strictly more informative than stripping — the operator can see that the only differences were in
// headers they chose to discount, rather than being shown two messages that appear identical while
// differing on the wire. Nothing is hidden; it is labelled.
//
// # Defaults
//
// The response defaults are headers that vary per-response by design. `Set-Cookie` is deliberately
// NOT among them even though Burp includes it: on a security tool a changed cookie can be the
// finding — a session fixated, a token rotated, a flag dropped — and defaulting it to "ignore"
// would hide exactly the difference an operator is hunting. Anyone who wants it ignored can add it;
// nobody gets it ignored without deciding to.
//
// The request defaults are empty. Nothing about a request this proxy sent is noise by default: the
// operator controls those bytes, so a difference in them is a difference they made.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// defaultUninterestingResponseHeaders vary per response by design.
var defaultUninterestingResponseHeaders = []string{
	"age",
	"cf-ray",
	"date",
	"etag",
	"expires",
	"last-modified",
	"x-correlation-id",
	"x-request-id",
}

// uninterestingHeaders holds the two lists. Names are stored lower-cased because HTTP field names
// are case-insensitive (RFC 9110 §5.1) and an operator who types "ETag" must not get different
// behaviour from one who types "etag".
type uninterestingHeaders struct {
	mu       sync.RWMutex
	request  map[string]bool
	response map[string]bool
}

func newUninterestingHeaders() *uninterestingHeaders {
	u := &uninterestingHeaders{
		request:  map[string]bool{},
		response: map[string]bool{},
	}
	for _, name := range defaultUninterestingResponseHeaders {
		u.response[name] = true
	}
	return u
}

// headers returns the sorted list for one direction. Sorted so the API and the UI are stable
// between reads — an unordered set rendered as a list reorders itself on every poll.
func (u *uninterestingHeaders) headers(response bool) []string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	set := u.request
	if response {
		set = u.response
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// set replaces one direction's list, returning the normalised result.
func (u *uninterestingHeaders) set(response bool, names []string) []string {
	normalised := map[string]bool{}
	for _, name := range names {
		// A header name with a colon is what you get from pasting a whole header line. Taking the
		// part before the colon is friendlier than refusing, and unambiguous: a field name cannot
		// contain a colon.
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		normalised[name] = true
	}

	u.mu.Lock()
	if response {
		u.response = normalised
	} else {
		u.request = normalised
	}
	u.mu.Unlock()
	return u.headers(response)
}

// isUninteresting reports whether a field name is on one of the lists.
func (u *uninterestingHeaders) isUninteresting(response bool, name string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if response {
		return u.response[strings.ToLower(name)]
	}
	return u.request[strings.ToLower(name)]
}

// uninterestingSpan is one half-open byte range [Start,End) covering a header line whose name is on
// the list, including the name, the colon, the value and the terminating CRLF.
type uninterestingSpan struct {
	Start int
	End   int
}

// uninterestingSpansIn finds the header lines to discount in one raw HTTP message.
//
// Deliberately not a full HTTP parse. This runs over two arbitrary blobs an operator pasted into the
// Comparer, which may be truncated, may not be HTTP at all, and must never be rejected — the
// Comparer's job is to diff whatever it is given. So the scan stops at the first blank line (the end
// of a header block, if there is one), skips the first line (a request or status line has no field
// name), and ignores anything that does not look like `name: value`.
//
// Both LF and CRLF line endings are handled, because a pasted message has usually been through a
// text editor.
func uninterestingSpansIn(raw []byte, u *uninterestingHeaders, response bool) []uninterestingSpan {
	if u == nil {
		return nil
	}
	var spans []uninterestingSpan

	pos := 0
	firstLine := true
	for pos < len(raw) {
		// Find this line's end.
		lineEnd := pos
		for lineEnd < len(raw) && raw[lineEnd] != '\n' {
			lineEnd++
		}
		// next is where the following line starts; lineEnd..next is the terminator.
		next := lineEnd
		if next < len(raw) {
			next++ // consume the \n
		}

		// The line's content, without its terminator.
		content := raw[pos:lineEnd]
		if n := len(content); n > 0 && content[n-1] == '\r' {
			content = content[:n-1]
		}

		if len(content) == 0 {
			// End of the header block. Anything after it is a body, where a line that looks like a
			// header is not one — a JSON body containing "date": ... must not be discounted.
			break
		}

		if firstLine {
			firstLine = false
			pos = next
			continue
		}

		if i := indexByteIn(content, ':'); i > 0 {
			name := strings.ToLower(strings.TrimSpace(string(content[:i])))
			if u.isUninteresting(response, name) {
				// The span covers the terminator too, so a diff in the line ending is discounted
				// with the line rather than surviving as a lone unexplained op.
				spans = append(spans, uninterestingSpan{Start: pos, End: next})
			}
		}

		pos = next
	}
	return spans
}

func indexByteIn(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// coveredBy reports whether [start,end) lies entirely within one span.
//
// Entirely, not partially: an op that straddles the boundary between an uninteresting header and the
// next line contains a real difference, and discounting it would hide that. Partial overlap is
// therefore treated as interesting, which is the direction that cannot mislead.
func coveredBy(spans []uninterestingSpan, start, length int) bool {
	if length <= 0 {
		return false
	}
	end := start + length
	for _, s := range spans {
		if start >= s.Start && end <= s.End {
			return true
		}
	}
	return false
}

/* --- the API ------------------------------------------------------------- */

type uninterestingHeadersResponse struct {
	Request  []string `json:"request"`
	Response []string `json:"response"`
	// Defaults lets the UI offer "restore defaults" without hard-coding the list in two places, and
	// lets an operator see what they have removed.
	DefaultResponse []string `json:"default_response"`
	// AppliesTo names every surface that consults these lists, so the panel cannot imply a wider
	// effect than it has. One entry today; the honest thing is to list it rather than describe the
	// setting in the abstract.
	AppliesTo []string `json:"applies_to"`
}

func (s *Server) uninterestingHeadersView() uninterestingHeadersResponse {
	return uninterestingHeadersResponse{
		Request:         s.uninteresting.headers(false),
		Response:        s.uninteresting.headers(true),
		DefaultResponse: defaultUninterestingResponseHeaders,
		AppliesTo:       []string{"Comparer"},
	}
}

// handleUninterestingHeaders serves GET and PUT /api/headers/uninteresting.
//
// PUT replaces both lists in one call, so a caller cannot end up with one direction saved and the
// other not — the same whole-or-nothing shape the config import uses.
func (s *Server) handleUninterestingHeaders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.uninterestingHeadersView())
	case http.MethodPut:
		var req struct {
			// Pointers so "not mentioned" and "explicitly empty" are different requests. Without
			// this, a caller updating only the response list would silently clear the request one.
			Request  *[]string `json:"request"`
			Response *[]string `json:"response"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.Request != nil {
			s.uninteresting.set(false, *req.Request)
		}
		if req.Response != nil {
			s.uninteresting.set(true, *req.Response)
		}
		writeJSON(w, http.StatusOK, s.uninterestingHeadersView())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
