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
// Neither queued nor fingerprinted: `img`, `script`, `link`, `source`, `embed`, `video`, `audio`.
// These are subresources. Burp's crawler does fetch them; this slice does not, because fetching them
// spends the request budget on bytes no application logic is behind. Their `src` values are also kept
// out of the location skeleton, because a rebuilt asset hash in a bundle filename would otherwise
// make every page a new location on every deploy. Two named consequences: a crawl of this application
// will not tell you that `/static/app.js` returned 500, and two pages differing only in their images
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
}

// pageStructure is everything one response contributed.
type pageStructure struct {
	links []discoveredLink
	forms []discoveredForm
	// fingerprint identifies the location by its structure — see fingerprint.go.
	fingerprint string
	// dropped counts links and forms discarded at the per-page bound. Counted, never silently
	// absent.
	dropped int
	// truncated records that the body was longer than the parse bound, so its tail was not walked.
	truncated bool
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
			case "script":
				// A script body is the other place a hidden path lives — a single-page app's
				// router table is a list of URL strings inside a <script> block. The script's
				// own text is not rendered, so it is invisible to the wire read and to the
				// location fingerprint alike. Mined only when the speculative phase is on.
				if speculative {
					specText.WriteString(nodeText(n))
					specText.WriteByte(' ')
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

	out.fingerprint = locationFingerprint(skeleton.String(), linkTargets, textLen)
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
//   - `<meta http-equiv="refresh">`. Redirect handling here is explicit (`understand_meta_refresh_tag`
//     is a Burp config key burpsy does not implement), and following it would make the crawl's
//     fetch list disagree with the redirect policy the rest of the tree enforces.
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
// The text-length bucket is log2, so a page whose body grew by a paragraph is the same location and a
// page with ten times the content is not. Coarse on purpose: exact length would make every render
// with a different user name a new location.
func locationFingerprint(skeleton string, linkTargets []string, textLen int) string {
	sorted := make([]string, len(linkTargets))
	copy(sorted, linkTargets)
	sort.Strings(sorted)
	var b strings.Builder
	b.WriteString(skeleton)
	b.WriteString("\n>>")
	b.WriteString(strings.Join(sorted, "\n"))
	b.WriteString("\n##")
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
		raw := strings.TrimRight(tok, ".,;:!?]}")
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
