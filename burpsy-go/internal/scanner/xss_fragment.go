package scanner

// Reflected and stored XSS in a response that is an HTML FRAGMENT served as non-markup.
//
// # The gap
//
// The server-side check refuses a breakout in any response a browser would not parse as markup
// (rendersAsMarkup), and it is right to: a text/plain echo is not XSS when the browser loads it.
// A large class of applications never lets the browser load it. The page's own script fetches the
// endpoint and assigns the answer to innerHTML, so the response is labelled text/plain but its
// product is markup and the page turns it into live markup. The route-driven confirmation
// (xss_browser_confirm.go) covers that only for a target a caller has described page by page;
// every other target fell through as "Input returned in response".
//
// # What qualifies a response as a fragment
//
// The endpoint's OWN output has to be markup: the body opens with an element, and that element
// is the application's, not the probe's (the observation probe carries a bare alphanumeric
// canary, so every tag in its answer came from the application). A plain-text echo endpoint —
// the case the content-type gate exists for — is not a fragment and stays exactly as gated as it
// was. A JSON body is never a fragment itself; one of its string values can be, when it opens with
// the application's own element (the envelope a page unwraps before innerHTML: xssFragmentSite).
//
// # The evidence
//
// A fragment's context is classified like a document's, and the context's payloads are sent. A
// payload whose own parse-level confirmation holds in the answer is then RENDERED: the exact
// response body is assigned to a div's innerHTML in an isolated, network-less about:blank tab
// (domexec.RenderFragment), and the finding needs the browser to have executed the payload's
// handler with this probe's canary — a dialog call carrying it, an event on the element it names,
// or the engine evaluating it as an identifier ("<canary> is not defined"). An escaped answer, a
// handler a browser never dispatches on that element, or markup a sanitiser rewrote produces none
// of these, which is what keeps a sanitising control quiet. No browser, no finding: the point is
// declined by name rather than reported clean.
//
// # Stored versus reflected
//
// A fragment endpoint is often also the store: the same request saves the value and answers with
// every saved value. Once a payload executed, the request is sent again with the parameter back at
// its original value. If the confirmed payload is in THAT answer and executes there too, the value
// was stored and is served to a request that never carried it, which is stored XSS and is filed
// as such; otherwise the finding is the reflected one.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const xssStoredIssue = "Cross-site scripting (stored)"

// maxXSSFragmentRenders bounds the browser renders one insertion point may cost. Each render is an
// isolated tab with no network, so the bound is about time, not traffic.
const maxXSSFragmentRenders = 4

// xssFragmentCandidate is a payload whose parse-level confirmation held in a non-markup answer.
type xssFragmentCandidate struct {
	payload xssPayload
	canary  string
	// body is the fragment itself: the whole answer, or the JSON string value site names.
	body string
	site xssFragmentSite
	// contentType is the answer's declared type, cited in the finding.
	contentType string
}

// xssIsMarkupFragment reports whether a non-markup response body is an HTML fragment whose markup
// is the application's own: its first token is a start tag of a known HTML element. canary is the
// observation probe's bare alphanumeric token, which cannot open a tag, so that tag was written by
// the application whatever the canary's position; it is required to be present in the body so the
// classification describes the answer to this probe.
func xssIsMarkupFragment(body, canary string) bool {
	if canary == "" || !strings.Contains(body, canary) {
		return false
	}
	trimmed := strings.TrimLeft(body, " \t\r\n\f")
	if len(trimmed) < 2 || trimmed[0] != '<' || !isASCIILetter(trimmed[1]) {
		return false
	}
	z := html.NewTokenizer(strings.NewReader(trimmed))
	switch z.Next() {
	case html.StartTagToken, html.SelfClosingTagToken:
		name, _ := z.TagName()
		return atom.Lookup(name) != 0
	}
	return false
}

// xssFragmentSite is where a non-markup answer carries the application's HTML fragment: the whole
// body (jsonPath nil), or one string value of a JSON document.
//
// # The JSON envelope
//
// A page script that inserts server-built markup very often receives it wrapped: `{"content":
// "<section>…</section>", "ok": true}`, then `el.innerHTML = data.content`. The body opens with `{`,
// so it is never a fragment by xssIsMarkupFragment, and the reflected value inside it was invisible
// to the fragment path. The rule for the value is the same rule as for a body: the string must
// itself open with a start tag of a known element and must carry the observation canary — a bare
// alphanumeric token that cannot open a tag, so the markup is the application's. A JSON field that
// merely echoes the value (`{"q": "<canary>"}`) is not markup and is not entered, and neither is a
// markup field the value never reaches.
//
// What the JSON layer does to the payload is undone by decoding it, which is exactly what the page
// does before assigning the value; the render then decides, as for a body.
type xssFragmentSite struct {
	jsonPath []any // string keys and int indices; nil for the whole body
}

func (s xssFragmentSite) isJSON() bool { return s.jsonPath != nil }

// String names the site for a finding: "the response body" or "JSON value content[0].html".
func (s xssFragmentSite) String() string {
	if !s.isJSON() {
		return "the response body"
	}
	var b strings.Builder
	for i, p := range s.jsonPath {
		switch v := p.(type) {
		case string:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(v)
		case int:
			fmt.Fprintf(&b, "[%d]", v)
		}
	}
	if b.Len() == 0 {
		return "the JSON string value"
	}
	return "JSON value " + b.String()
}

// extract returns the fragment at this site in body. A JSON site whose path no longer leads to a
// string (the answer changed shape) is not found.
func (s xssFragmentSite) extract(body string) (string, bool) {
	if !s.isJSON() {
		return body, true
	}
	doc, ok := decodeJSONDocument(body)
	if !ok {
		return "", false
	}
	cur := doc
	for _, p := range s.jsonPath {
		switch k := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return "", false
			}
			if cur, ok = m[k]; !ok {
				return "", false
			}
		case int:
			a, ok := cur.([]any)
			if !ok || k < 0 || k >= len(a) {
				return "", false
			}
			cur = a[k]
		}
	}
	v, ok := cur.(string)
	return v, ok
}

// decodeJSONDocument parses body when it is a JSON object or array.
func decodeJSONDocument(body string) (any, bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	return doc, true
}

// xssLocateFragment finds where a non-markup answer carries an application-built HTML fragment that
// the observation canary reached: the body itself, else the first JSON string value (keys in sorted
// order, so the choice is stable) that qualifies. ok=false when neither does.
func xssLocateFragment(body, canary string) (xssFragmentSite, string, bool) {
	if xssIsMarkupFragment(body, canary) {
		return xssFragmentSite{}, body, true
	}
	doc, ok := decodeJSONDocument(body)
	if !ok {
		return xssFragmentSite{}, "", false
	}
	var found []any
	var view string
	var walk func(v any, path []any) bool
	walk = func(v any, path []any) bool {
		switch t := v.(type) {
		case string:
			if xssIsMarkupFragment(t, canary) {
				found, view = append([]any{}, path...), t
				return true
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if walk(t[k], append(path, k)) {
					return true
				}
			}
		case []any:
			for i, e := range t {
				if walk(e, append(path, i)) {
					return true
				}
			}
		}
		return false
	}
	if !walk(doc, []any{}) || len(found) == 0 {
		return xssFragmentSite{}, "", false
	}
	return xssFragmentSite{jsonPath: found}, view, true
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// xssFragmentExecuted reports whether a render's calls show this canary's payload executing, and
// names how.
func xssFragmentExecuted(calls []domexec.FragmentCall, canary string) (string, bool) {
	for _, c := range calls {
		switch {
		case c.Func == "throw" && strings.Contains(c.Args, canary+" is not defined"):
			return fmt.Sprintf("the inserted handler evaluated the canary as code (%q)", c.Args), true
		case c.Func != "throw" && strings.Contains(c.Args, canary):
			return fmt.Sprintf("the inserted handler called %s(%s)", c.Func, c.Args), true
		case c.Func != "throw" && c.TargetID == canary:
			return fmt.Sprintf("the injected element's %s handler called %s", c.Event, c.Func), true
		}
	}
	return "", false
}

// xssFragmentFindings renders the candidates and returns the finding for the first that executes,
// or nil. A nil return with no browser, or with every render failing, is recorded as a decline.
func xssFragmentFindings(ctx context.Context, cc *CheckContext, h *ProbeHarness, point bcheck.InsertionPoint, cands []xssFragmentCandidate) *Finding {
	if len(cands) == 0 {
		return nil
	}
	browser, err := cc.Scanner.BrowserForRender(ctx)
	if err != nil || browser == nil {
		reason := "no browser available"
		if err != nil {
			reason += ": " + err.Error()
		}
		recordXSSBrowserDecline(cc, point, "the response is an HTML fragment served as non-markup and the payload's markup survived, but it was not rendered: "+reason)
		return nil
	}
	renders, failures := 0, 0
	for _, c := range cands {
		if renders >= maxXSSFragmentRenders {
			break
		}
		renders++
		calls, err := browser.RenderFragment(ctx, c.body, 0)
		if err != nil {
			failures++
			continue
		}
		how, ok := xssFragmentExecuted(calls, c.canary)
		if !ok {
			continue
		}
		return xssFragmentFinding(ctx, cc, h, browser, point, c, how)
	}
	if failures > 0 && failures == renders {
		recordXSSBrowserDecline(cc, point, "the response is an HTML fragment served as non-markup, but every browser render of it failed")
	}
	return nil
}

// xssFragmentFinding builds the finding for an executed candidate, after asking whether the value
// was stored.
func xssFragmentFinding(ctx context.Context, cc *CheckContext, h *ProbeHarness, browser *domexec.Browser, point bcheck.InsertionPoint, c xssFragmentCandidate, how string) *Finding {
	contentType := c.contentType
	if contentType == "" {
		contentType = "a non-markup content type"
	}
	name, severity := xssReflectedIssue, "high"
	shape := "the response is an HTML fragment"
	if c.site.isJSON() {
		shape = "the response's " + c.site.String() + " is an HTML fragment"
	}
	detail := fmt.Sprintf("%s %q: %s served as %q, so it is live only once a page's script inserts it; "+
		"rendered the way such a script does (innerHTML, isolated, no network), the payload executed: %s",
		point.Kind, point.Name, shape, contentType, how)
	evidence := fmt.Sprintf("payload %q (%s); browser-confirmed on fragment insertion: %s", c.payload.build(c.canary), c.payload.note, how)

	if later, ok := xssStoredReplay(ctx, h, c.canary, c.site); ok {
		if calls, err := browser.RenderFragment(ctx, later, 0); err == nil {
			if how2, ok := xssFragmentExecuted(calls, c.canary); ok {
				name = xssStoredIssue
				detail = fmt.Sprintf("%s %q: the payload was stored — a later request carrying the parameter's original value was answered with it, "+
					"and that answer, rendered the way a page's script inserts it, executed it: %s. The submitting response carried it too: %s",
					point.Kind, point.Name, how2, how)
				evidence += "; replayed with the original value, the stored payload executed again: " + how2
			}
		}
	}
	solution := ""
	if def, ok := ByName(name); ok {
		severity = def.TypicalSeverity
		solution = def.Remediation
	}
	return &Finding{
		Name:        name,
		Severity:    severity,
		Confidence:  "firm",
		Description: detail,
		URL:         cc.Exchange.Path,
		Method:      cc.Exchange.Method,
		Evidence:    evidence,
		Solution:    solution,
		ExchangeID:  cc.Exchange.ID,
		Timestamp:   nowUTC(),
	}
}

// xssStoredReplay re-sends the captured request unmodified — the point at its original value — and
// returns the answer when it carries the canary. A request that never carried the canary can only
// answer with it if the application kept it.
//
// The fragment returned is the one at site, so a JSON-wrapped fragment is rendered as the page would
// render it. Behind a shared cache the harness sends this replay with a fresh buster
// (probe_cache_isolation.go), so an answer served from the probe's own cache entry cannot pass for a
// stored value.
func xssStoredReplay(ctx context.Context, h *ProbeHarness, canary string, site xssFragmentSite) (string, bool) {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := h.send(rctx, h.RequestBytes())
	if err != nil || !strings.Contains(res.Body, canary) {
		return "", false
	}
	view, ok := site.extract(res.Body)
	if !ok || !strings.Contains(view, canary) {
		return "", false
	}
	return view, true
}
