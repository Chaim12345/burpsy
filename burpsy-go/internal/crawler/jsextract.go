package crawler

// JavaScript endpoint extraction (burpsy-react-ui-jwy5): a SPA's real routes live in its bundles, and
// before this an external .js response was fetched, stored, scanned — and then recorded as SkipNotHTML,
// with every path inside it unread.
//
// # Two extractors, and why the answer is their UNION
//
// jsluice (BishopFox; the CGO-free fork on the pure-Go tree-sitter runtime gotreesitter, the same fork
// Katana ships, so the binary stays CGO_ENABLED=0) parses the script and reads URLs out of the places
// a program puts them — $.ajax({url, type}), fetch/XHR/axios calls, location assignments, dynamic
// import() — which a text miner cannot: it knows a call's HTTP method, and it reads
// import("./chunk-" + n + ".js") as a location at all. burpsy's own speculativeURLFields mines
// root-shaped string tokens, and it finds what jsluice's matchers do not: a path inside a template
// literal (axios.get(`/api/v2/orders/${id}`)) is invisible to jsluice and plain text to the miner.
// Measured on the same sample before this was written, neither was a superset of the other.
//
// # What a candidate becomes
//
// A DISCOVERED LINK, through admit() like every other — scope, the destructive gate, depth, dedup —
// because a URL a script contains is exactly as untrusted as one a page links. The crawler sends GET;
// the method jsluice read (a POST endpoint) rides on the link text for the report and the audit
// enumerator, and is not sent, because issuing a script's POST is acting, not discovering.

import (
	"strings"

	"github.com/BishopFox/jsluice"
)

// jsCandidate is one location read out of a script.
type jsCandidate struct {
	raw string
	tag string
	// note carries what the extractor knew beyond the URL — the HTTP method a call used — for the
	// report and the audit enumerator. Empty when there is nothing more to say.
	note string
}

// extractJavaScript returns the union of both extractors over one script body, normalised into
// requestable locations and deduplicated. parseFailed reports that the AST pass panicked or could not
// run, in which case the miner's half still stands — a parser failure costs precision, not the file.
func extractJavaScript(body []byte) (cands []jsCandidate, parseFailed bool) {
	seen := map[string]int{}
	add := func(raw, tag, note string) {
		loc, ok := normaliseJSLocation(raw)
		if !ok {
			return
		}
		if i, dup := seen[loc]; dup {
			// The first extractor to name a location keeps it; a later one only adds what it knew.
			if cands[i].note == "" && note != "" {
				cands[i].note = note
			}
			return
		}
		seen[loc] = len(cands)
		cands = append(cands, jsCandidate{raw: loc, tag: tag, note: note})
	}

	urls, ok := jsluiceURLs(body)
	parseFailed = !ok
	for _, u := range urls {
		note := ""
		if m := strings.ToUpper(strings.TrimSpace(u.Method)); m != "" && m != "GET" {
			note = m + " (read from " + u.Type + ")"
		}
		add(u.URL, "js:jsluice:"+u.Type, note)
	}
	for _, raw := range speculativeURLFields(string(body)) {
		add(raw, "js:mined", "")
	}
	return cands, parseFailed
}

// jsluiceURLs runs the AST pass, recovering from a panic in the parser: hostile or merely unusual
// script is the expected input, and one malformed bundle must not take the crawl down.
func jsluiceURLs(body []byte) (urls []*jsluice.URL, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			urls, ok = nil, false
		}
	}()
	return jsluice.NewAnalyzer(body).GetURLs(), true
}

// normaliseJSLocation turns an extracted string into a location the crawler can request, or refuses
// it.
//
// Scripts build URLs from parts, so an extracted string often carries a placeholder where a runtime
// value goes: jsluice writes EXPR, a template literal keeps ${...}. Requesting the placeholder
// literally asks the target for a path nobody uses. The honest location is everything BEFORE the
// first placeholder, cut back to the last whole path segment — `/api/v2/orders/${id}` is a real
// directory, `/api/v2/orders/` — and a placeholder in the query drops the query, keeping the path.
// What is left must still name something: a bare "/", "./" or a fragment like ".js" is refused.
func normaliseJSLocation(raw string) (string, bool) {
	s := strings.TrimSpace(strings.Trim(strings.TrimSpace(raw), "'\"`"))
	if s == "" {
		return "", false
	}
	cut := -1
	for _, marker := range []string{"EXPR", "${"} {
		if i := strings.Index(s, marker); i >= 0 && (cut < 0 || i < cut) {
			cut = i
		}
	}
	if cut >= 0 {
		head := s[:cut]
		if q := strings.IndexByte(head, '?'); q >= 0 {
			// The placeholder is a query value: the path before the query is whole.
			s = head[:q]
		} else if slash := strings.LastIndexByte(head, '/'); slash >= 0 {
			// Cut back to the last whole segment: "/orders/abc${x}" names "/orders/", not "/orders/abc".
			s = head[:slash+1]
		} else {
			return "", false
		}
	}
	// A literal that ENDS a query mid-assignment ("/users?id=", "/x?a=1&") is the left half of a
	// concatenation — the value is appended at run time — so its query is a placeholder too.
	if q := strings.IndexByte(s, '?'); q >= 0 && strings.ContainsAny(s[len(s)-1:], "=&?") {
		s = s[:q]
	}
	if looksLikeCode(s) {
		return "", false
	}
	switch {
	case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"):
	case strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//"):
	case strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"):
	default:
		// A bare token ("users", ".js", "EXPR") is not a location; guessing that a word is a path is how
		// a crawler invents URLs nobody observed.
		return "", false
	}
	if s == "/" || s == "./" || s == "../" {
		return "", false
	}
	return s, true
}

// LooksLikeJavaScript reports whether a response is a script to read for locations: a JavaScript
// content type, or a .js/.mjs path served as text or octet-stream (servers routinely mislabel bundles).
func LooksLikeJavaScript(contentType, path string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}
	p := strings.ToLower(path)
	if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") {
		return ct == "" || strings.HasPrefix(ct, "text/plain") || strings.HasPrefix(ct, "application/octet-stream")
	}
	return false
}

// looksLikeCode reports a candidate that is JavaScript rather than a location (burpsy-react-ui-8lpc).
//
// Measured by the dvi7 benchmark: a large share of what the extractors produced on a real SPA bundle
// was code read as a path — regex literals (/\*/g, /:/g, /^), statements (/g;var), expressions with
// && and spaces, unrendered {{templates}}. Each admitted one is a request spent on a URL nobody serves.
// The test is on characters a URL path does not carry unescaped and code always does, applied after
// placeholders are cut, so a real route built from a template (/orders/${id} -> /orders/) survives.
func looksLikeCode(s string) bool {
	if strings.ContainsAny(s, " \t\n;\\^`{}[]()<>|") || strings.Contains(s, "&&") {
		return true
	}
	// A trailing regex-flag segment after a segment that is not a word: "/:/g", "/\\*/gi". A real
	// route can end in a short word ("/blog/g"), so the segment before it decides.
	segs := strings.Split(strings.TrimPrefix(s, "/"), "/")
	if n := len(segs); n >= 2 {
		last, prev := segs[n-1], segs[n-2]
		if last != "" && len(last) <= 4 && strings.Trim(last, "gimsuy") == "" && prev != "" &&
			strings.TrimFunc(prev, isPathWordRune) != "" {
			return true
		}
	}
	return false
}

func isPathWordRune(r rune) bool {
	return r == '-' || r == '_' || r == '.' || r == '~' ||
		(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
