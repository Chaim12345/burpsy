// Two fingerprints: one that identifies a *request* so the frontier does not queue it twice, and
// one that identifies a *location* by what came back, so two URLs that render the same page are not
// crawled as two pages.
//
// # Why URL-keyed deduplication is not enough
//
// This is PortSwigger's central design insight about their own crawler, and it is worth restating
// because it is counter-intuitive: **a location is identified by its contents, not by the URL used
// to reach it.** A URL-keyed crawler is defeated by ordinary applications, not adversarial ones:
//
//   - A per-request CSRF token in every form action means every link on every page is a URL the
//     crawler has never seen.
//   - A cache-busting `?_=1712...` on a navigation link means the same page is a new URL each visit.
//   - A session id in the path — `/(S(abc123))/Default.aspx`, the classic ASP.NET form — means the
//     entire application is new after every login.
//   - A pagination or calendar parameter means an unbounded supply of URLs behind a bounded number
//     of distinct pages.
//
// In each case a URL-keyed crawler spends its whole budget re-fetching one part of the application
// and reports having found hundreds of locations. Fingerprinting the *response* collapses them.
//
// # The two fingerprints do different jobs and neither replaces the other
//
// requestFingerprint is computed *before* the fetch and answers "have I already sent this request".
// It has to be URL-derived, because there is nothing else to go on yet. What it can do is normalise
// away the parts of a URL that are known to be ephemeral — see volatileParams — so that two links
// differing only in a CSRF token are one queue entry rather than two.
//
// The location fingerprint is computed *after* the fetch — see locationFingerprint in discover.go,
// which is where the walk that produces it lives. It hashes four components: a depth-annotated tag
// skeleton with attribute values dropped except name/type/method/action/rel; each form's
// method/action/sorted-field-names signature; the page's outgoing link targets, sorted and **raw**;
// and a log2 bucket of visible-text length. Text content, class and id attributes, inline script
// bodies and comments are all excluded, because those are where per-render data lives.
//
// # The bias: false-split over false-merge
//
// The single most important decision in this file is that the link targets stay raw. `/users/1` and
// `/users/2` have identical tag skeletons, identical form signatures and text of the same order of
// magnitude — the *only* thing distinguishing them is that one links to `/users/1/edit` and the
// other to `/users/2/edit`. Templating those targets would merge the two, and the crawler would then
// fetch one row of a fifty-thousand-row table, never scan the rest, and report a completed crawl.
//
// So the rule is: **a false merge is invisible lost coverage and a false split is a visible
// re-fetch.** Always prefer the split. Splits are contained by the per-template visit quota
// (urlTemplate below), never by loosening this hash.
//
// # What that still costs, stated plainly
//
//   - **A page whose links carry a CSRF token or cache-buster splits per render.** Each render is a
//     new location, so the same page can be fetched more than once. Visible in the location and
//     duplicate counters, bounded by the template quota.
//   - **Two pages with no outgoing links, the same structure and similarly-sized text merge.** A pair
//     of leaf pages differing only in prose is one location. This is the residual false merge the
//     text-length bucket narrows but does not remove.
//   - **A single-page application collapses to one location.** Its skeleton is one shell document;
//     everything else is built by script this crawler does not run. That is a limit of a
//     non-executing crawler, not of the fingerprint.
//   - **A non-HTML response is fingerprinted byte-exactly.** There is no structure to skeletonise,
//     so the hash covers the content type and the body as it stands. A JSON endpoint that embeds a
//     timestamp therefore looks like a new location on every fetch — a false split, which is the
//     side of the trade this file deliberately errs towards.
package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// volatileParams are query parameter names whose *values* are dropped from a request fingerprint.
//
// The names are the ones that in practice carry per-request data: CSRF tokens, cache busters,
// session ids, and the framework-specific spellings of each. Dropping the value rather than the
// whole parameter is deliberate — `?csrf=` present and absent are still different requests, and a
// crawler that erased the distinction would merge a form's GET target with its plain link.
//
// This list is necessarily incomplete: an application can name its CSRF token anything. When it
// does, the request fingerprint fails to merge the duplicates and the *location* fingerprint
// catches them after the fetch instead — one wasted request per duplicate rather than an unbounded
// crawl. That layering is why this list not being exhaustive is survivable.
var volatileParams = map[string]bool{
	"_":                          true,
	"__requestverificationtoken": true,
	"_csrf":                      true,
	"_token":                     true,
	"asp.net_sessionid":          true,
	"authenticity_token":         true,
	"cache":                      true,
	"cachebuster":                true,
	"cache_buster":               true,
	"cb":                         true,
	"csrf":                       true,
	"csrfmiddlewaretoken":        true,
	"csrf_token":                 true,
	"csrftoken":                  true,
	"jsessionid":                 true,
	"nonce":                      true,
	"phpsessid":                  true,
	"rand":                       true,
	"random":                     true,
	"requestverificationtoken":   true,
	"session":                    true,
	"sessionid":                  true,
	"session_id":                 true,
	"sid":                        true,
	"state":                      true,
	"timestamp":                  true,
	"ts":                         true,
	"xsrf":                       true,
	"xsrf_token":                 true,
}

// volatilePlaceholder replaces a dropped value, so the parameter's presence still registers.
const volatilePlaceholder = "\x00volatile"

// requestFingerprint is the frontier's deduplication key: the method plus a normalised URL.
//
// Normalisation is scheme and host lowercased, the port made explicit (so `http://h/` and
// `http://h:80/` are one entry), the fragment dropped (it never reaches the server), and the query
// sorted by key with volatile values replaced. Sorting matters because `?a=1&b=2` and `?b=2&a=1` are
// the same request to every server that has ever existed, and treating them as two would double the
// cost of any page that builds links in a non-deterministic order.
//
// The path is *not* case-folded and *not* cleaned of `.` or `..` segments. Path case is significant
// on most servers, and resolving dot segments is url.URL.ResolveReference's job, already done by the
// time a link reaches here.
//
// A non-empty body contributes a hash of itself. Without it two submissions of the same form with
// different field values would be one queue entry, and a crawl with form submission on would cover
// one of them — the wrong kind of deduplication, since the body is the request here in the way the
// query string is for a GET.
func requestFingerprint(method string, u *url.URL, body []byte) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(method))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(u.Scheme))
	b.WriteString("://")
	b.WriteString(strings.ToLower(u.Hostname()))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(portOf(u))))
	if u.Path == "" {
		b.WriteByte('/')
	} else {
		b.WriteString(u.Path)
	}
	if q := normalisedQuery(u); q != "" {
		b.WriteByte('?')
		b.WriteString(q)
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		b.WriteByte(0)
		b.WriteString(hex.EncodeToString(sum[:8]))
	}
	return b.String()
}

// normalisedQuery renders the query sorted by key, with volatile values replaced. Values for
// non-volatile keys are kept: `?page=1` and `?page=2` are genuinely different pages.
func normalisedQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	// ParseQuery drops malformed pairs and returns an error; the values it did parse are still the
	// best available reading, and the raw string is the fallback so a fingerprint is never empty for
	// a URL that had a query.
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil && len(values) == 0 {
		return u.RawQuery
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(values))
	for _, k := range keys {
		vs := values[k]
		if volatileParams[strings.ToLower(k)] {
			parts = append(parts, k+"="+volatilePlaceholder)
			continue
		}
		sorted := make([]string, len(vs))
		copy(sorted, vs)
		sort.Strings(sorted)
		for _, v := range sorted {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "&")
}

// hashSkeleton turns a skeleton string into the fingerprint an operator sees. SHA-256 truncated to
// 16 bytes: the skeleton of a large page is tens of kilobytes and holding it per location would make
// the location map the memory problem, while 128 bits of hash makes an accidental collision between
// two genuinely different page shapes not worth reasoning about.
func hashSkeleton(skeleton string) string {
	sum := sha256.Sum256([]byte(skeleton))
	return hex.EncodeToString(sum[:16])
}

// ---- URL templates: the cutoff that actually stops an infinite application ----------------------

// idPlaceholder replaces a path segment that looks like an identifier.
const idPlaceholder = "{id}"

// urlTemplate collapses a URL to its shape: the authority, the path with id-shaped segments replaced,
// and the sorted names of its query parameters with every value dropped. The method and, for a form
// submission, the sorted names of the body's fields are included, because those are part of what
// makes two requests the same *kind* of request.
//
// # Why the frontier needs this as well as an exact-request key
//
// The exact key (requestFingerprint) answers "have I sent precisely this". On an application that
// generates URLs it never answers yes: `/orders/1`, `/orders/2`, … `/orders/90000` are ninety
// thousand distinct exact keys, so SkipAlreadyQueued stays at zero and the crawl runs until some
// *other* bound stops it. The bound that would eventually stop it is the frontier's capacity, which
// is a memory bound — so the operator would be told their crawl ended because the queue filled up,
// when what actually happened is that the application has an unbounded id space. That is a true
// statement about the wrong thing.
//
// A per-template quota says the honest thing instead: this shape was sampled N times and there are
// more. It is also the mechanism that makes the location fingerprint's deliberate bias towards
// false-splitting safe — see fingerprint.go's docs on that trade.
//
// # What counts as an id-shaped segment
//
// All digits; a UUID; a hex run of 12 or more; or a 24-or-more-character run with no separator that
// is not a dictionary-looking word (approximated as: contains a digit). Deliberately conservative:
// merging two genuinely different sections of an application under one template would apply one
// quota to both and cut the crawl short in a way the operator cannot see. Failing to recognise an id
// only costs quota granularity, which the exact key and the location fingerprint both still cover.
func urlTemplate(method string, u *url.URL, bodyFields []string) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(method))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(u.Scheme))
	b.WriteString("://")
	b.WriteString(strings.ToLower(u.Hostname()))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(portOf(u))))
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "" {
			continue
		}
		b.WriteByte('/')
		if looksLikeID(seg) {
			b.WriteString(idPlaceholder)
		} else {
			b.WriteString(seg)
		}
	}
	if u.RawQuery != "" {
		values, _ := url.ParseQuery(u.RawQuery)
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, strings.ToLower(k))
		}
		sort.Strings(keys)
		b.WriteByte('?')
		b.WriteString(strings.Join(keys, "&"))
	}
	if len(bodyFields) > 0 {
		names := make([]string, len(bodyFields))
		copy(names, bodyFields)
		sort.Strings(names)
		b.WriteByte('#')
		b.WriteString(strings.Join(names, ","))
	}
	return b.String()
}

// looksLikeID reports whether one path segment is an identifier rather than a name.
func looksLikeID(seg string) bool {
	if seg == "" {
		return false
	}
	if isAllDigits(seg) {
		return true
	}
	if isUUID(seg) {
		return true
	}
	if len(seg) >= 12 && isHex(seg) {
		return true
	}
	// A long opaque run carrying a digit: a slug, a signed token, a base64-ish id. The digit
	// requirement is what keeps a long hyphen-free English word from being mistaken for an id.
	if len(seg) >= 24 && strings.IndexFunc(seg, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20 // fold case for a-f
		if !(s[i] >= '0' && s[i] <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// isUUID matches the canonical 8-4-4-4-12 hyphenated form, which is what appears in a path.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, want := range [...]int{8, 13, 18, 23} {
		_ = i
		if s[want] != '-' {
			return false
		}
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i] | 0x20
		if !(s[i] >= '0' && s[i] <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// rawBodyFingerprint is the non-HTML case: content type plus the body, byte for byte. See the
// package docs for why this is deliberately the weaker of the two.
func rawBodyFingerprint(contentType string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(contentType))))
	h.Write([]byte{0})
	h.Write(body)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// portOf is the URL's port, or the scheme's default. A URL with an unparseable port yields the
// scheme default rather than zero: zero is not a port, and passing it to a scope check would ask a
// question about a target that cannot exist.
func portOf(u *url.URL) uint16 {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			return uint16(n)
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// resolveAgainst resolves raw against base, or parses it absolutely when base is nil. The fragment
// is stripped here rather than at each call site, because a fragment never reaches the server and a
// crawler that treated `#top` as a new location would fetch every page once per anchor on it.
func resolveAgainst(base *url.URL, raw string) (*url.URL, error) {
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	out := ref
	if base != nil {
		out = base.ResolveReference(ref)
	}
	out.Fragment = ""
	out.RawFragment = ""
	return out, nil
}
