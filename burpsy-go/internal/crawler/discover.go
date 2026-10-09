// Reading one response for links and forms (CRAWL-01), and building the location skeleton in the
// same pass.
//
// # Why golang.org/x/net/html and not a regex
//
// Link extraction by regular expression fails on the two things every real page does: attributes in
// an unexpected order and markup that is not well-formed. A crawler that misses links is a crawler
// that under-reports coverage silently, which is the one failure this package is organised against.
// golang.org/x/net/html is the tokeniser and tree builder the WHATWG parsing algorithm specifies,
// it never rejects a document, and it is already in this module's dependency graph — internal/http2
// and internal/sender both use golang.org/x/net/http2 out of the same module — so using it adds no
// requirement.
//
// # One walk, four outputs
//
// The links, the forms, the location skeleton and the visible-text length all come from the same tree
// walk. Walking twice would be twice the cost on the crawl's hottest path, and worse, would let the
// skeleton and the link list disagree about what the document contained.
//
// # What is discovered and what is deliberately not
//
// Discovered and queued: `a[href]`, `area[href]`, `iframe[src]`, `frame[src]`, and every `form`.
//
// Queued but not fingerprinted: the subresources `img`, `link` (stylesheets, icons, preloads, the
// manifest), `source`, `video` and `audio` (burpsy-react-ui-4ocj), plus `script` (jwy5) and
// `object`/`embed` (u967). Burp's crawler fetches them, so a crawl can report that `/static/app.js`
// returned 500 or that a page loads an asset from outside scope, and the site map shows the assets.
// Config.NoSubresources turns the media and stylesheet ones off to save request budget. Their URLs
// are kept out of the location skeleton, because a rebuilt asset hash in a bundle filename would
// otherwise make every page a new location on every deploy: two pages differing only in their images
// are one location.
//
// Not discovered at all: URLs built by script, URLs in CSS, `srcset` candidate lists, `<meta
// http-equiv=refresh>` targets, and anything behind a `data-*` convention. The first is the
// non-executing crawler's fundamental limit (see the package docs); the rest are individually small
// and named here so their absence is a decision on the record.
//
// # Link text is more than the text
//
// The destructive-action check (CRAWL-04) is only as good as the text it is given, and the modern
// spelling of a delete button is `<a href="/x/8814" aria-label="Delete"><svg/></a>` — no text at
// all. So the "text" of a link is its descendant text plus its `title` and `aria-label`, normalised
// to single spaces. Without that, icon-only destructive controls are invisible to the check, which
// is the case it most needs to catch.
package crawler

import (
	"bytes"
	"encoding/json"
	"math/bits"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// maxLinkTextBytes bounds the text kept per link. A pathological document can put a megabyte of
// prose inside one anchor; the destructive check needs a label, not an essay, and this is what stops
// the frontier's memory from being decided by the target.
const maxLinkTextBytes = 512

// discoveredLink is one navigational target found in a document.
type discoveredLink struct {
	// raw is the attribute exactly as written, before resolution — kept so a link that fails to
	// resolve can still be reported by what the page said.
	raw string
	// text is the link's descendant text plus its title and aria-label, whitespace-normalised.
	text string
	// tag is the element it came from, for reporting.
	tag string
	// foundAtRendered marks a link that existed only in the DOM a browser built for the page
	// (Config.Render) — invisible to the wire markup the static parse reads (nx7b). The frontier
	// item carries it onto the Fetch edge, so the crawl-paths view can say which edges a
	// browser-less crawl would not have found at all.
	foundAtRendered bool
	// speculative marks a candidate the speculative-hidden-link phase mined from a comment
	// or script body (burpsy-react-ui-t5m0) rather than a navigational element. It changes
	// nothing about which gates the link passes — only that the crawl-wide cap counts it.
	speculative bool
}

// formField is one name/value pair a submitted form would carry.
type formField struct {
	name  string
	value string
}

// discoveredForm is one form found in a document, with the fields a submission would send.
type discoveredForm struct {
	// action is the form's action attribute as written; empty means the document's own URL, which is
	// what the HTML specification says and what every browser does.
	action string
	// method is the uppercased method, defaulting to GET as the specification does.
	method string
	// enctype is the lowercased enctype, empty meaning the urlencoded default.
	enctype string
	// fields are the name/value pairs a submission would carry, in document order.
	fields []formField
	// label is the submit control's text or value, plus the form's own title and aria-label — the
	// string the destructive check reads. See the package docs for why a form needs one at all.
	label string
	// hasFileInput records that the form carries a file input, which is why a urlencoded submission
	// of it would not be the submission the application expects.
	hasFileInput bool
	// isLoginForm identifies this form as a login form (burpsy-react-ui-uzil): contains an input
	// element with type=password. This is Burp's own rule for identifying login forms.
	isLoginForm bool
}

// signature is the form's identity for the per-form submission cap (burpsy-react-ui-u0k3).
//
// Method, the action resolved but untemplated, and the field NAMES sorted. discover.go:282-285 puts
// the same three parts in the location skeleton, and for the same reason: a search box submitted with
// a different query is still the SAME form, and a cap that counted those separately would bound nothing
// on exactly the page that needs a bound.
//
// The field's input TYPE is not in the signature. The location skeleton reads it from the DOM
// attribute; formField carries only name and value, because the values are what a submission sends and
// this package does not keep the rest. A form whose only difference is text-vs-number input would
// therefore share a cap — which is the conservative direction, since one cap is tighter than two.
//
// Values are excluded. A CSRF token or a session id is a value, and counting on it would make every
// submission look like a different form.
func (f discoveredForm) signature(base *url.URL) string {
	var b strings.Builder
	b.WriteString(f.method)
	b.WriteByte(' ')
	if f.action == "" {
		// An empty action submits to the document's own URL (admitForm says the same), so two forms
		// with empty actions on different pages are different forms.
		if base != nil {
			b.WriteString(base.String())
		}
	} else if u, err := resolveAgainst(base, f.action); err == nil {
		b.WriteString(u.String())
	} else {
		// Unresolvable: admitForm will refuse it as malformed, and a signature that cannot be
		// computed must not collide with every other unresolvable form's.
		b.WriteString(f.action)
	}
	names := make([]string, 0, len(f.fields))
	for _, fld := range f.fields {
		names = append(names, fld.name)
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteByte('!')
		b.WriteString(n)
	}
	return b.String()
}

// pageStructure is everything one response contributed.
type pageStructure struct {
	links []discoveredLink
	forms []discoveredForm
	// fingerprint identifies the location by its structure — see fingerprint.go.
	fingerprint string
	// shape is the same four components EXCEPT the link targets, hashed. Two pages that agree on
	// it differ only in where they point, which is the one axis the tolerance band may tolerate —
	// see location_band.go. Empty when the body could not be parsed, which is why an empty shape
	// can never be folded into anything.
	shape string
	// linkTargets are the outgoing navigation targets, sorted and RAW — the same slice the
	// fingerprint is built over, kept so the band can compare it against a known location's
	// without walking the document a second time.
	linkTargets []string
	// dropped counts links and forms discarded at the per-page bound. Counted, never silently
	// absent.
	dropped int
	// truncated records that the body was longer than the parse bound, so its tail was not walked.
	truncated bool
	// sourceMap is the //# sourceMappingURL a SCRIPT named, relative to that script, or empty.
	//
	// Kept as a reference rather than fetched during the parse, because parsePage is pure: it reads a
	// body and returns locations, and a parse that sent a request would make every caller of it
	// responsible for the egress. The fetch happens once per script in the crawl loop, through the
	// ordinary perform() path, so the map is scope-authorised, rate-limited and captured like any
	// other request — which is what keeps criterion 3 of jwy5 honest.
	sourceMap string
}

// parsePage walks one HTML body for links, forms and the location skeleton.
//
// base is the URL the body came from, used to resolve relative references and honoured through a
// `<base href>` element if the document carries one. limits bounds the bytes walked and the links
// taken.
//
// html.Parse only fails on a read error, which a bytes.Reader cannot produce, so there is no
// malformed-document path here: a broken document yields whatever the parsing algorithm's error
// recovery produces, which is what a browser would have seen.
// parsePage walks one response body for navigational links and forms. speculative
// additionally collects the non-visible text a browser never renders — HTML comments and
// script bodies — and mines it for URL-shaped candidates: the speculative-hidden-link
// phase (burpsy-react-ui-t5m0), Burp's "Follow hidden links in comments and JavaScript".
//
// The candidates are returned as ordinary discoveredLinks and admitted through the same
// gates as a navigational link (scope, destructive, query, depth), never as privileged
// seeds — a comment that says /logout is still a logout. What distinguishes them is only
// their provenance (the tag) and the crawl-wide cap that bounds how many are admitted.
func parsePage(body []byte, base *url.URL, limits Limits, speculative bool) pageStructure {
	out := pageStructure{}
	if len(body) > limits.MaxParseBytes {
		body = body[:limits.MaxParseBytes]
		out.truncated = true
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		// Unreachable with a bytes.Reader; a zero structure with an empty fingerprint is the honest
		// answer rather than a fingerprint over nothing, since an empty fingerprint is never equal to
		// a real one and so cannot make a page look like a duplicate.
		return out
	}

	// A `<base href>` retargets every relative reference in the document. Resolved before the walk
	// because it applies to links that appear textually above it.
	effective := base
	if bh := findBaseHref(doc); bh != "" {
		if resolved, rerr := resolveAgainst(base, bh); rerr == nil && resolved.Host != "" {
			effective = resolved
		}
	}

	var skeleton strings.Builder
	// linkTargets are the outgoing navigation targets, resolved but otherwise untouched — see the
	// location-fingerprint contract below for why these must stay raw.
	var linkTargets []string
	textLen := 0
	admitted := 0
	// specText collects the non-visible text the speculative phase mines (burpsy-react-ui-t5m0):
	// HTML comments and script bodies. Only collected when the phase is on — a crawl that
	// declined it has no business reading the bytes.
	var specText strings.Builder
	// admit reports whether one more link or form may be taken, counting the refusals.
	admit := func() bool {
		if admitted >= limits.MaxLinksPerPage {
			out.dropped++
			return false
		}
		admitted++
		return true
	}

	var walk func(n *html.Node, depth int)
	walk = func(n *html.Node, depth int) {
		if n.Type == html.CommentNode {
			// An HTML comment is invisible to a browser and is exactly where a hidden path
			// leaks: `<!-- /adminpanel -->`. Mined only when the speculative phase is on.
			if speculative {
				specText.WriteString(n.Data)
				specText.WriteByte(' ')
			}
		}
		if n.Type == html.TextNode {
			// Visible text length only, and only as a coarse bucket later. Text *content* is the most
			// ephemeral thing on a page, and its length is the least ephemeral thing about it.
			textLen += len(strings.TrimSpace(n.Data))
		}
		if n.Type == html.ElementNode {
			// Depth-annotated: two documents with the same tag multiset in a different nesting are
			// different pages, and a flat tag sequence cannot tell them apart.
			skeleton.WriteString(strconv.Itoa(depth))
			skeleton.WriteByte(':')
			skeleton.WriteString(n.Data)
			// Only the attributes that describe structure keep their values. Everything else — class,
			// id, style, data-*, src, and every href on a non-navigational element — is dropped,
			// because that is where per-render data lives.
			for _, name := range structuralAttrs {
				if v, ok := attr(n, name); ok {
					skeleton.WriteByte(' ')
					skeleton.WriteString(name)
					skeleton.WriteByte('=')
					skeleton.WriteString(v)
				}
			}
			skeleton.WriteByte('|')

			switch n.Data {
			case "a", "area":
				if href, ok := attr(n, "href"); ok {
					linkTargets = append(linkTargets, resolvedTarget(effective, href))
					if admit() {
						out.links = append(out.links, discoveredLink{
							raw:  href,
							text: linkText(n),
							tag:  n.Data,
						})
					}
				}
			// <meta http-equiv="refresh" content="N; url=..."> (burpsy-react-ui-q0qr), Burp's
			// DELAYED_REDIRECT edge. A landing page that only meta-refreshes into the app was a one-page
			// crawl, because the target is in an attribute no navigational tag carries.
			case "meta":
				if equiv, ok := attr(n, "http-equiv"); ok && strings.EqualFold(strings.TrimSpace(equiv), "refresh") {
					if content, ok := attr(n, "content"); ok {
						if target, ok := refreshTarget(content); ok {
							linkTargets = append(linkTargets, resolvedTarget(effective, target))
							if admit() {
								out.links = append(out.links, discoveredLink{raw: target, tag: tagMetaRefresh})
							}
						}
					}
				}
			case "iframe", "frame":
				if src, ok := attr(n, "src"); ok {
					linkTargets = append(linkTargets, resolvedTarget(effective, src))
					if admit() {
						out.links = append(out.links, discoveredLink{raw: src, text: linkText(n), tag: n.Data})
					}
				}
			// button/input[formaction] (burpsy-react-ui-u967). A styled button carrying its form
			// target in formaction is how a modern app submits without a form element, so a page
			// whose only action is such a button contributed no link at all. `formaction`
			// OVERRIDES the enclosing form's action for that control, which is why it is read as a
			// navigation target in its own right rather than folded into the form signature.
			case "button", "input":
				if fa, ok := attr(n, "formaction"); ok && fa != "" {
					linkTargets = append(linkTargets, resolvedTarget(effective, fa))
					if admit() {
						out.links = append(out.links, discoveredLink{raw: fa, text: linkText(n), tag: n.Data + "[formaction]"})
					}
				}
			// math[href] — MathML's own link element, which the HTML walk never saw.
			case "math":
				if href, ok := attr(n, "href"); ok {
					linkTargets = append(linkTargets, resolvedTarget(effective, href))
					if admit() {
						out.links = append(out.links, discoveredLink{raw: href, text: linkText(n), tag: "math"})
					}
				}
			// object[data] and embed[src] carry embedded documents — a PDF viewer, an SVG, a
			// Flash-era movie. They are fetches the crawler never made, and the embedded document
			// has its own locations.
			case "object":
				if data, ok := attr(n, "data"); ok && data != "" {
					linkTargets = append(linkTargets, resolvedTarget(effective, data))
					if admit() {
						out.links = append(out.links, discoveredLink{raw: data, text: linkText(n), tag: "object"})
					}
				}
			case "embed":
				if src, ok := attr(n, "src"); ok && src != "" {
					linkTargets = append(linkTargets, resolvedTarget(effective, src))
					if admit() {
						out.links = append(out.links, discoveredLink{raw: src, text: linkText(n), tag: "embed"})
					}
				}
			// Subresources (4ocj): fetched like any discovered link, but kept out of linkTargets so asset
			// hashes cannot split a location. srcset is not read: it names alternatives of one image.
			case "img", "source", "audio", "track":
				if src, ok := attr(n, "src"); ok && strings.TrimSpace(src) != "" && admit() {
					out.links = append(out.links, discoveredLink{raw: src, tag: n.Data})
				}
			case "video":
				for _, a := range []string{"src", "poster"} {
					if v, ok := attr(n, a); ok && strings.TrimSpace(v) != "" && admit() {
						out.links = append(out.links, discoveredLink{raw: v, tag: "video"})
					}
				}
			case "link":
				if href, ok := attr(n, "href"); ok && strings.TrimSpace(href) != "" && isAssetRel(n) && admit() {
					out.links = append(out.links, discoveredLink{raw: href, tag: "link"})
				}
			case "script":
				// An EXTERNAL script is fetched so its contents can be read for locations
				// (burpsy-react-ui-jwy5): a SPA's routes live in its bundles, and before this a
				// <script src> was never followed at all, so the JavaScript reader had nothing to read.
				// It is admitted as a discovered link through the same gates as any other — scope,
				// dedup, depth — and deliberately NOT added to linkTargets: a page's location
				// fingerprint is its navigational structure, and folding its asset list into it would
				// make two identical pages look different whenever a bundle hash changed.
				if src, ok := attr(n, "src"); ok && strings.TrimSpace(src) != "" && admit() {
					out.links = append(out.links, discoveredLink{raw: src, tag: "script"})
				}
				// A script body is the other place a hidden path lives — a single-page app's
				// router table is a list of URL strings inside a <script> block. The script's
				// own text is not rendered, so it is invisible to the wire read and to the
				// location fingerprint alike. Mined only when the speculative phase is on.
				if speculative {
					specText.WriteString(nodeText(n))
					specText.WriteByte(' ')
					// A script's own source map — the one artifact in a minified bundle that
					// recovers the original paths and source.
					//
					// The BASE differs by script kind and getting it wrong is a 404 either way:
					// an INLINE script has no src of its own, so its reference resolves against
					// the PAGE; an EXTERNAL one resolves against ITS OWN url, so a bundle served
					// from /static/js/main.js naming "main.js.map" is /static/js/main.js.map and
					// not /main.js.map.
					//
					// An absolute reference is taken AS WRITTEN. It names a host the crawl may not
					// cover, and rewriting it against the page would invent a same-host URL that does
					// not exist. Whether that host may be fetched is the scope gate's decision, made
					// later, on the real URL.
					if out.sourceMap == "" {
						// scriptBody, not n.Data: n is the ELEMENT node and its text lives in a
						// child, so an element with several children needs them all joined rather than
						// reading one. A script body split across several text nodes — which is what an
						// HTML parser produces for a minified bundle with an inline map — still yields
						// its marker.
						if ref := sourceMapReference(scriptBody(n)); ref != "" {
							base := effective
							if src, ok := attr(n, "src"); ok && src != "" {
								if scriptURL, rerr := resolveAgainst(effective, src); rerr == nil {
									base = scriptURL
								}
							}
							if resolved, merr := resolveAgainst(base, ref); merr == nil {
								out.sourceMap = resolved.String()
							}
						}
					}
				}
			case "form":
				f := readForm(n)
				// A form's signature: method, its action resolved but untemplated, and its field
				// name:type pairs sorted. Values excluded — a CSRF token is a value.
				skeleton.WriteByte('!')
				skeleton.WriteString(f.method)
				skeleton.WriteByte('@')
				skeleton.WriteString(resolvedTarget(effective, f.action))
				skeleton.WriteByte('#')
				skeleton.WriteString(strings.Join(sortedFieldSignature(f), ","))
				skeleton.WriteByte('|')
				if admit() {
					out.forms = append(out.forms, f)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, depth+1)
		}
	}
	walk(doc, 0)

	// Sorted ONCE and handed to both the fingerprint and the tolerance band, so neither re-sorts
	// the crawl's hottest list and the band compares the same order the fingerprint hashed.
	sort.Strings(linkTargets)
	out.linkTargets = linkTargets
	skel := skeleton.String()
	out.fingerprint = locationFingerprint(skel, linkTargets, textLen)
	out.shape = shapeDigest(skel, textLen)
	// The speculative phase (burpsy-react-ui-t5m0): mine the non-visible text for
	// URL-shaped candidates and admit them as ordinary links — same gates, same
	// frontier, distinguished only by the tag and bounded by the crawl-wide cap.
	if speculative {
		for _, raw := range speculativeURLFields(specText.String()) {
			out.links = append(out.links, discoveredLink{raw: raw, tag: "speculative", speculative: true})
		}
	}
	return out
}

// structuralAttrs are the only attributes whose *values* enter the location skeleton.
//
// name, type, method, action and rel describe what an element is and where it points. Everything
// else an element carries — class, id, style, title, value, src, data-* — either changes per render
// or per user, and including it would split one location into as many as the target has renderings.
// `action` is here rather than in the raw target list because a form's action is part of its
// signature; the raw list covers navigational links.
var structuralAttrs = [...]string{"name", "type", "method", "action", "rel"}

// What is deliberately NOT read (burpsy-react-ui-u967), and why:
//
//   - `onclick` and the other inline handlers. Burp's own handling of an inline handler is not
//     recoverable from the evidence base, and a guessed JavaScript URL parser would invent
//     locations: `onclick="doThing()"` is not a URL, `onclick="location='/x'"` is. Reading some
//     and not others, on a heuristic this project cannot cite, is exactly the fabrication the
//     refusal-first design exists to prevent. A handler-delivered link is found by the rendered
//     pass instead (nx7b), which executes the page and reads the DOM a browser produced.
//   - `classid`, `archive` and `codebase` on `<object>`. They name plugin binaries and Java
//     archives, not web locations, and a crawl that fetched them would be requesting files the
//     application never exposed as URLs.

// sortedFieldSignature is a form's `name:type` pairs, sorted, with no values.
//
// Sorted rather than in document order: a page that renders its fields in a map-iteration order would
// otherwise be a new location on every request, which is the exact failure this fingerprint exists
// to prevent.
func sortedFieldSignature(f discoveredForm) []string {
	out := make([]string, 0, len(f.fields))
	for _, fl := range f.fields {
		out = append(out, fl.name)
	}
	sort.Strings(out)
	return out
}

// resolvedTarget is a link target resolved against the page and otherwise left exactly as written —
// full path, full query, values and all.
//
// **Raw and untemplated is load-bearing.** `/user/1` and `/user/2` have identical tag skeletons,
// identical form signatures and text of the same order of magnitude. The only thing that
// distinguishes them is where they point: the first links to `/user/1/edit`, the second to
// `/user/2/edit`. Normalise those targets — template the ids, or drop the query values — and the two
// detail pages become one location. The crawler would then fetch exactly one row of a fifty-thousand
// row table, never scan the rest, and report a completed crawl. That is a silent hole across an
// entire application, and it is the single worst failure this file can have.
//
// The cost is the mirror image and it is deliberate: a link carrying a CSRF token or a cache-buster
// makes each render a *different* location, so the same page is fetched more than once. That is a
// false split. It is bounded, it is visible in the location and duplicate counters, and the
// per-template visit quota stops it from running away — see urlTemplate. The rule is **bias to false
// splitting over false merging**: a false split costs a re-fetch the operator can see, a false merge
// costs coverage the operator cannot.
func resolvedTarget(base *url.URL, raw string) string {
	u, err := resolveAgainst(base, raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return u.String()
}

// locationFingerprint combines the four components into one hash.
//
// sortedLinkTargets must already be sorted, and the tolerance band needs that same sorted slice to
// compare against a known location (see location_band.go), so parsePage sorts once and both read
// it. Sorting again here would be a second pass over the crawl's hottest list for no gain, and two
// readers disagreeing about the order is the kind of thing that reads as a duplicate-location bug
// later.
//
// The text-length bucket is log2, so a page whose body grew by a paragraph is the same location and a
// page with ten times the content is not. Coarse on purpose: exact length would make every render
// with a different user name a new location.
func locationFingerprint(skeleton string, sortedLinkTargets []string, textLen int) string {
	var b strings.Builder
	b.WriteString(skeleton)
	b.WriteString("\n>>")
	b.WriteString(strings.Join(sortedLinkTargets, "\n"))
	b.WriteString(shapeSeparator)
	b.WriteString(strconv.Itoa(bits.Len(uint(textLen))))
	return hashSkeleton(b.String())
}

// findBaseHref returns the first `base[href]` in the document, or "".
func findBaseHref(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "base" {
		if href, ok := attr(n, "href"); ok {
			return href
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if v := findBaseHref(c); v != "" {
			return v
		}
	}
	return ""
}

// attr returns an attribute's value, and whether the attribute was present. Presence is reported
// separately from emptiness because `href=""` is a link to the current document while a missing
// href is not a link at all.
func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

// linkText is what the destructive check reads: the element's descendant text, plus its title and
// aria-label. See the package docs for why the accessible names are included.
// nodeText is an element's descendant text, whitespace-normalised. Used for the
// speculative phase's script bodies — the element's own text is what a browser would
// have executed, and what a hidden-path scan reads.
func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(m *html.Node) {
		if m.Type == html.TextNode {
			b.WriteString(m.Data)
		}
		for c := m.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// speculativeURLFields splits non-visible text into URL-shaped candidates: absolute
// http(s) URLs and root-relative paths. The two shapes are what a comment or a script
// body actually carries when it leaks a location (`<!-- /adminpanel -->`,
// `var base = "https://internal.example"`); anything else in a script — a JS string,
// a number, an identifier — is not a location, and reading it as one would flood the
// frontier with the application's own vocabulary.
//
// Tokens are cut on whitespace and the characters that frame a URL in prose or code,
// then trailing punctuation is trimmed (a sentence's period is not part of the path).
// Absolute URLs are matched by scheme; a path is only read when it starts with "/" and
// is not the scheme-relative "//" — those resolve against the page like any other
// relative target, which is the same gate a navigational link passes.
func speculativeURLFields(text string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' ||
			r == '"' || r == '\'' || r == '<' || r == '>' ||
			r == '(' || r == ')' || r == ',' || r == '`'
	}) {
		// Trailing punctuation is trimmed — a sentence's period is not part of the path — but `}`
		// must NOT be: it closes the `{id}` segment every SPA router uses, and trimming it turned
		// `/orders/{id}` into `/orders/{id`, which is a URL that does not exist. A `}` is only stripped
		// when the token has no unclosed `{` before it, so prose ending in a brace keeps its
		// punctuation and a route keeps its segment.
		raw := strings.TrimRight(tok, ".,;:!?]")
		if strings.HasSuffix(raw, "}") && strings.Count(raw, "{") > strings.Count(raw, "}") {
			raw = strings.TrimRight(raw, ".,;:!?") + "}"
		}
		if raw == "" {
			continue
		}
		isAbs := strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
		isPath := strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//")
		if !isAbs && !isPath {
			continue
		}
		if !seen[raw] {
			seen[raw] = true
			out = append(out, raw)
		}
	}
	return out
}

func linkText(n *html.Node) string {
	var b strings.Builder
	collectText(n, &b)
	if v, ok := attr(n, "title"); ok {
		b.WriteByte(' ')
		b.WriteString(v)
	}
	if v, ok := attr(n, "aria-label"); ok {
		b.WriteByte(' ')
		b.WriteString(v)
	}
	return normaliseSpace(b.String())
}

// collectText appends descendant text, stopping once maxLinkTextBytes is exceeded. Script and style
// contents are excluded: they are not text a user would read, and a minified bundle inside a
// `<noscript>` fallback would otherwise become a link's label.
func collectText(n *html.Node, b *strings.Builder) {
	if b.Len() > maxLinkTextBytes {
		return
	}
	if n.Type == html.TextNode {
		b.WriteString(n.Data)
		return
	}
	if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectText(c, b)
		if b.Len() > maxLinkTextBytes {
			return
		}
	}
}

// normaliseSpace collapses every run of whitespace to one space and trims the ends, so a label
// split across source lines matches a signal phrase written with single spaces.
func normaliseSpace(s string) string {
	out := strings.Join(strings.Fields(s), " ")
	if len(out) > maxLinkTextBytes {
		out = out[:maxLinkTextBytes]
	}
	return out
}

// readForm reads one form element into the request a submission of it would make.
func readForm(n *html.Node) discoveredForm {
	f := discoveredForm{method: "GET"}
	if v, ok := attr(n, "action"); ok {
		f.action = v
	}
	if v, ok := attr(n, "method"); ok && strings.TrimSpace(v) != "" {
		f.method = strings.ToUpper(strings.TrimSpace(v))
	}
	if v, ok := attr(n, "enctype"); ok {
		f.enctype = strings.ToLower(strings.TrimSpace(v))
	}

	var label strings.Builder
	if v, ok := attr(n, "title"); ok {
		label.WriteString(v)
		label.WriteByte(' ')
	}
	if v, ok := attr(n, "aria-label"); ok {
		label.WriteString(v)
		label.WriteByte(' ')
	}

	var walk func(c *html.Node)
	walk = func(c *html.Node) {
		if c.Type == html.ElementNode {
			switch c.Data {
			case "input":
				readInput(c, &f, &label)
			case "textarea":
				if name, ok := attr(c, "name"); ok && name != "" {
					var text strings.Builder
					collectText(c, &text)
					value := strings.TrimSpace(text.String())
					if value == "" {
						value = fillerText
					}
					f.fields = append(f.fields, formField{name: name, value: value})
				}
			case "select":
				if name, ok := attr(c, "name"); ok && name != "" {
					f.fields = append(f.fields, formField{name: name, value: firstOptionValue(c)})
				}
			case "button":
				// A button's own text is the strongest label a form has: "Delete account" lives here
				// far more often than in the form's attributes.
				typ, _ := attr(c, "type")
				if strings.EqualFold(typ, "submit") || typ == "" {
					var text strings.Builder
					collectText(c, &text)
					label.WriteString(text.String())
					label.WriteByte(' ')
					if v, ok := attr(c, "aria-label"); ok {
						label.WriteString(v)
						label.WriteByte(' ')
					}
				}
			}
		}
		for k := c.FirstChild; k != nil; k = k.NextSibling {
			walk(k)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c)
	}
	f.label = normaliseSpace(label.String())
	return f
}

// readInput folds one input element into the form, either as a field or as part of its label.
func readInput(n *html.Node, f *discoveredForm, label *strings.Builder) {
	typ := ""
	if v, ok := attr(n, "type"); ok {
		typ = strings.ToLower(strings.TrimSpace(v))
	}
	existing, _ := attr(n, "value")

	switch typ {
	case "submit", "image":
		// The submit control's caption is label material, and a named submit button is also a field
		// the application reads — `<input type=submit name=action value=Delete>` is both at once,
		// which is precisely the shape the destructive check must catch.
		label.WriteString(existing)
		label.WriteByte(' ')
		if name, ok := attr(n, "name"); ok && name != "" {
			f.fields = append(f.fields, formField{name: name, value: existing})
		}
		return
	case "button", "reset":
		label.WriteString(existing)
		label.WriteByte(' ')
		return
	case "file":
		// Recorded rather than filled: a urlencoded submission cannot carry a file, and pretending
		// otherwise would send the application a request no browser would produce.
		f.hasFileInput = true
		return
	case "password":
		// Login form detection (burpsy-react-ui-uzil): Burp identifies login forms as those
		// containing an input with type=password. Mark the form accordingly.
		f.isLoginForm = true
		name, ok := attr(n, "name")
		if !ok || name == "" {
			return
		}
		f.fields = append(f.fields, formField{name: name, value: fillValue(typ, existing)})
		return
	}

	name, ok := attr(n, "name")
	if !ok || name == "" {
		return
	}
	if typ == "checkbox" || typ == "radio" {
		// Unchecked controls are not submitted by a browser, and a crawler that submitted them all
		// would be sending a form no user could produce. `value` defaults to "on", as it does in
		// every browser.
		if _, checked := attr(n, "checked"); !checked {
			return
		}
		if existing == "" {
			existing = "on"
		}
		f.fields = append(f.fields, formField{name: name, value: existing})
		return
	}
	f.fields = append(f.fields, formField{name: name, value: fillValue(typ, existing)})
}

// firstOptionValue is the value a browser submits for an untouched select: the first option, by its
// value attribute or, absent one, its text.
func firstOptionValue(sel *html.Node) string {
	var found string
	var walk func(n *html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode && n.Data == "option" {
			if v, ok := attr(n, "value"); ok {
				found = v
				return true
			}
			var text strings.Builder
			collectText(n, &text)
			found = strings.TrimSpace(text.String())
			return true
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if walk(c) {
				return true
			}
		}
		return false
	}
	walk(sel)
	return found
}

// fillerText is the value put in an empty free-text field.
//
// Deliberately the tool's own name rather than a plausible-looking human value: an operator who
// finds these rows in the target's database knows immediately what wrote them, and a support ticket
// reading "burpsy" is answerable in a way one reading "John Smith" is not. Everything below follows
// the same rule — inert, syntactically valid for the field's type, and unmistakably synthetic. The
// `.invalid` TLD is reserved by RFC 2606 and can never resolve, so a filled email or URL field
// cannot cause the application to contact a third party.
const fillerText = "burpsy"

// fillValue is the value a filled field carries: whatever the page already put there, or a typed
// filler when the page left it empty.
//
// An existing value is preserved verbatim and unconditionally — that is what keeps a form's CSRF
// token, its object id and its hidden state intact, which is the difference between a submission the
// application accepts and one it rejects at the first validator.
func fillValue(typ, existing string) string {
	if existing != "" {
		return existing
	}
	switch typ {
	case "email":
		return "burpsy@example.invalid"
	case "url":
		return "http://example.invalid/"
	case "tel":
		return "5550100"
	case "number", "range":
		return "1"
	case "date":
		return "2000-01-01"
	case "month":
		return "2000-01"
	case "week":
		return "2000-W01"
	case "time":
		return "00:00"
	case "datetime-local":
		return "2000-01-01T00:00"
	case "color":
		return "#000000"
	case "password":
		// Shaped to pass an ordinary complexity rule, so a registration form's validator does not
		// reject the submission before the application logic under test ever runs.
		return "Burpsy-Test-1"
	case "hidden":
		// A hidden field the page left empty is one the application means to be empty.
		return ""
	}
	return fillerText
}

// sourceMapReference extracts a //# sourceMappingURL from a script body.
//
// The LAST such comment wins, not the first. A build that concatenates several bundles into one file
// emits one per input, and the last is the one describing the combined output — the file the operator
// actually has. Taking the first would fetch a map for a component that is not there.
//
// An INLINE map (data:application/json;base64,...) is deliberately not returned: it is already in the
// body the caller holds, so there is nothing to fetch, and handing a multi-kilobyte data URL back as a
// "URL" would put it through the resolver and the scope gate for no reason.
func sourceMapReference(script string) string {
	// Both spellings, because both ship: "//# sourceMappingURL=x.map" is the common one and
	// "/*# sourceMappingURL=x.map */" appears in builds that wrap the bundle. Looking only for the
	// first missed every such build, which is what the table test caught.
	i := strings.LastIndex(script, "//# sourceMappingURL=")
	tail := "//# sourceMappingURL="
	if j := strings.LastIndex(script, "/*# sourceMappingURL="); j > i {
		i, tail = j, "/*# sourceMappingURL="
	}
	if i < 0 {
		return ""
	}
	ref := strings.TrimSpace(script[i+len(tail):])
	// The comment runs to the end of its LINE, not of the file — a bundle with code after the marker
	// would otherwise hand back everything that follows it as one "path".
	if nl := strings.IndexAny(ref, "\r\n"); nl >= 0 {
		ref = strings.TrimSpace(ref[:nl])
	}
	// The block-comment form exists in the wild and is the same fact written differently.
	ref = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(ref, "/*"), "*/"))
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return ""
	}
	return ref
}

// scriptBody returns the concatenated TEXT of a script element.
//
// Its own walk rather than nodeText, which deliberately EXCLUDES script contents
// (discover.go:554-556 — a minified bundle inside a <noscript> fallback must not become a link's
// label). That exclusion is right for a link label and wrong here: the sourceMappingURL marker lives
// in exactly the text nodeText refuses to read.
func scriptBody(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// sourceMapSourcesContent returns one source map's sourcesContent entries joined as one text, or
// "" when the map carries none.
//
// A source map is JSON, and this reader is deliberately minimal: it asks for the `sourcesContent`
// array only, and each entry contributes its text. Nothing else in the map is read — `sources` is a
// file list, never a set of URLs (see mineSourceMapBody for why admitting those would flood the
// frontier), `names` is a symbol table, `mappings` is VLQ soup no string miner should try to
// interpret.
//
// encoding/json rather than a hand parser, because the one thing this reader must not do is invent
// content a malformed map does not carry. Unmarshal into a struct with the one field that matters: a
// truncated or non-JSON body yields the zero value, which is the honest empty — the map was fetched,
// the report counts it, and there was nothing in it to find.
func sourceMapSourcesContent(body []byte) string {
	var m struct {
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if len(m.SourcesContent) == 0 {
		return ""
	}
	var b strings.Builder
	for _, src := range m.SourcesContent {
		if src == "" {
			continue
		}
		b.WriteString(src)
		b.WriteByte('\n')
	}
	return b.String()
}

// tagMetaRefresh and tagRefreshHeader name the two delayed-redirect sources (q0qr), Burp's
// DELAYED_REDIRECT edge kind.
const (
	tagMetaRefresh   = "meta[refresh]"
	tagRefreshHeader = "refresh-header"
)

// refreshTarget reads the URL out of a refresh value, the same grammar for the meta element's content
// and the Refresh response header (HTML's "shared declarative refresh steps"): a delay, then a ';' or
// ',', then an optional "url=", then the URL, optionally quoted. A value that is only a delay reloads
// the page itself and names no new location.
func refreshTarget(value string) (string, bool) {
	v := strings.TrimSpace(value)
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.') {
		i++
	}
	if i == 0 {
		return "", false
	}
	v = strings.TrimLeft(v[i:], " \t")
	if v == "" || (v[0] != ';' && v[0] != ',') {
		return "", false
	}
	v = strings.TrimLeft(v[1:], " \t")
	if len(v) >= 3 && strings.EqualFold(v[:3], "url") {
		rest := strings.TrimLeft(v[3:], " \t")
		if strings.HasPrefix(rest, "=") {
			v = strings.TrimLeft(rest[1:], " \t")
		}
	}
	if v != "" && (v[0] == '\'' || v[0] == '"') {
		q := v[0]
		v = v[1:]
		if j := strings.IndexByte(v, q); j >= 0 {
			v = v[:j]
		}
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// subresourceTags are the tags whose targets a page loads rather than links to (4ocj).
var subresourceTags = map[string]bool{"img": true, "source": true, "audio": true, "track": true, "video": true, "link": true}

// isAssetRel reports whether a <link> loads an asset the page needs: a stylesheet, an icon, a preload
// or module preload, or the web app manifest. A rel=alternate, canonical or next link names another
// document and is not fetched as a subresource.
func isAssetRel(n *html.Node) bool {
	rel, _ := attr(n, "rel")
	for _, r := range strings.Fields(strings.ToLower(rel)) {
		switch r {
		case "stylesheet", "icon", "apple-touch-icon", "preload", "modulepreload", "manifest", "mask-icon":
			return true
		}
	}
	return false
}

// navigationalTags are the tags whose targets a person navigates to, as opposed to assets a page loads.
var navigationalTags = map[string]bool{
	"a": true, "area": true, "iframe": true, "frame": true, "math": true,
	"button[formaction]": true, "input[formaction]": true, tagMetaRefresh: true,
}

// LinkTargets returns the absolute http(s) navigational targets an HTML body links to, resolved
// against base, deduplicated, in document order (burpsy-react-ui-t3zk: the live passive crawl). It is
// the crawler's own parse, so a link the proxy observes is the link a crawl would have followed.
func LinkTargets(body []byte, base *url.URL) []*url.URL {
	page := parsePage(body, base, DefaultLimits(), false)
	seen := map[string]bool{}
	var out []*url.URL
	for _, l := range page.links {
		if !navigationalTags[l.tag] {
			continue
		}
		u, err := resolveAgainst(base, l.raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		u.Fragment = ""
		if k := u.String(); !seen[k] {
			seen[k] = true
			out = append(out, u)
		}
	}
	return out
}
