package crawler

import (
	"encoding/json"
	"sort"
	"strings"
)

// JSON location extraction (burpsy-react-ui-mz1n).
//
// Burp reads non-HTML documents for locations — its action kinds include API and
// DISCOVERED_CONTENT, gated by a `parse_api_definitions` key — so a JSON payload that names its
// own endpoints contributes them to the crawl. burpsy's crawler admitted four content types as
// HTML (crawler.go isHTML) and recorded everything else as SkipNotHTML, so an API-heavy target
// came back with only the pages that happened to carry anchors.
//
// # Why this is a SIBLING of the HTML gate, not a relaxation of it
//
// The HTML gate exists for HTML extraction: the link walk, form submission, base-href
// resolution. Admitting JSON through it would hand the markup extractor a document with no
// tags in it and teach it rules about a grammar it does not read. This module reads one
// document shape and returns locations; it never touches the HTML path.
//
// # What is read
//
// Every string value that is a URL, at any depth, up to a hard bound. JSON has no link
// vocabulary — unlike HTML's href/src/action — so the shape has to be inferred from the
// values themselves rather than from the keys, and the honest rule is the narrow one:
//
//   - a value that parses as an absolute http/https URL, or
//   - a value that begins with "/" and is not a scheme-relative "//host", or
//   - a value under a key that names a link (uri, url, href, link, endpoint, path, next,
//     self, …) that parses as a relative reference.
//
// A bare word like "users" is NOT a location: guessing that an arbitrary string is a path is
// how a crawler invents URLs nobody observed, which is the failure mode the whole refusal-first
// design exists to avoid. The key-name rule exists because `{"next": "page/2"}` is a link by
// any reading, while `{"name": "page/2"}` is data.
//
// # Bounds
//
// The document size, the nesting depth, the number of strings examined and the number of
// locations returned are all capped. A crawler that reads an arbitrarily large JSON blob is a
// denial-of-service against its own operator, and the caps are REPORTED rather than silent.

const (
	// jsonMaxBytes bounds the document. Beyond it the body is not scanned at all: a response
	// this large is a data dump, not a routing table.
	jsonMaxBytes = 2 << 20 // 2 MiB
	// jsonMaxDepth bounds recursion. Real API payloads nest a handful of levels; a document
	// deeper than this is more likely to be adversarial than descriptive.
	jsonMaxDepth = 32
	// jsonMaxStrings bounds how many string values are examined, so a wide array of scalars
	// cannot cost unbounded time.
	jsonMaxStrings = 20000
	// jsonMaxLocations bounds what one document may contribute, so a single response cannot
	// dominate the frontier.
	jsonMaxLocations = 500
)

// jsonLocation is one admitted string, with the key that named it.
type jsonLocation struct {
	Raw  string
	Key  string
	Path string // dotted path to the value, for the skip record's Detail
}

// LooksLikeJSON reports whether a content type is JSON, or whether the body announces itself as
// one. The content type is a hint rather than a gate: APIs are served as text/plain and as
// application/octet-stream routinely, and a body that opens with `{` or `[` says what it is.
func LooksLikeJSON(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/json", "text/json", "application/ld+json",
		"application/vnd.api+json", "application/hal+json":
		return true
	}
	if strings.HasSuffix(ct, "+json") {
		return true
	}
	trimmed := strings.TrimLeft(string(body), " \t\r\n\ufeff")
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// linkKeys are object keys whose string values are read as relative references.
//
// Deliberately small and named: each entry is a word that means "this points somewhere" in a
// JSON document, so a value under it can be a path even without a leading slash. A key not on
// this list still yields a location when the value is unmistakably a URL (absolute, or
// slash-rooted) — the rule is about what may be INFERRED, not about what may be seen.
var linkKeys = map[string]bool{
	"href": true, "url": true, "uri": true, "link": true, "links": true,
	"next": true, "previous": true, "prev": true, "self": true, "first": true, "last": true,
	"endpoint": true, "endpoints": true, "path": true, "action": true, "resource": true,
	"redirect": true, "location": true, "canonical": true, "source": true, "target": true,
	"api": true, "apis": true, "callback": true, "webhook": true, "spec": true, "schema": true,
}

// ParseJSONLocations returns the locations a JSON document names, plus a failure string when the
// document is not JSON at all.
//
// A document that parses but names nothing returns no locations and NO failure: "this JSON has
// no URLs in it" is a real answer, and reporting it as a parse failure would tell an operator
// their API is broken when it is merely not a routing table.
func ParseJSONLocations(body []byte) (locs []jsonLocation, failure string) {
	if len(body) == 0 {
		return nil, ""
	}
	if len(body) > jsonMaxBytes {
		return nil, "the document is larger than the scan bound"
	}
	var root any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, "not a JSON document: " + err.Error()
	}

	seen := map[string]bool{}
	examined := 0
	var walk func(v any, key, path string, depth int)
	walk = func(v any, key, path string, depth int) {
		if depth > jsonMaxDepth || len(locs) >= jsonMaxLocations || examined >= jsonMaxStrings {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			// Sorted so the same document always yields the same order, and the caps
			// therefore truncate the same way on every run.
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := path + "." + k
				if path == "" {
					child = k
				}
				walk(t[k], k, child, depth+1)
			}
		case []any:
			for i, item := range t {
				walk(item, key, path+"["+itoa(i)+"]", depth+1)
			}
		case string:
			examined++
			if loc, ok := locationFromString(t, key); ok && !seen[loc] {
				seen[loc] = true
				locs = append(locs, jsonLocation{Raw: loc, Key: key, Path: path})
			}
		}
	}
	walk(root, "", "", 0)
	return locs, ""
}

// locationFromString decides whether one string value is a location, and in which form.
func locationFromString(s, key string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2048 {
		return "", false
	}
	// Template and interpolation syntax is not a URL: "/api/{id}" and "/api/${id}" name an
	// endpoint SHAPE, and fetching either would produce a 404 for a URL nobody observed.
	if strings.ContainsAny(s, "{}<>$`") {
		return "", false
	}
	lower := strings.ToLower(s)
	// An absolute URL is a location on its face, whatever key it arrived under.
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return s, true
	}
	// Anything else with a scheme is a different namespace (mailto:, tel:, urn:, data:) and
	// belongs to the existing scheme gate, not here.
	if i := strings.IndexByte(s, ':'); i > 0 && !strings.ContainsAny(s[:i], "/?#") {
		// "//host/path" is scheme-relative: the resolver handles it, so it is a location.
		if !strings.HasPrefix(s, "//") {
			return "", false
		}
	}
	if strings.HasPrefix(s, "//") {
		return s, true
	}
	// A slash-rooted value is a path on any reading.
	if strings.HasPrefix(s, "/") {
		return s, true
	}
	// A bare word is NOT a path — unless the key names a link, which is the one case where the
	// document has told us this value points somewhere.
	if linkKeys[strings.ToLower(key)] && !strings.ContainsAny(s, " \t") {
		return s, true
	}
	return "", false
}

// itoa is strconv.Itoa without the import, kept local so this file's only dependency is JSON.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
