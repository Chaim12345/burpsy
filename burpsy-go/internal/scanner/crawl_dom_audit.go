package scanner

// The rendered-DOM audit over a crawl's locations (burpsy-react-ui-xuim).
//
// A crawl captures wire bytes, and the audit half audits exactly those bytes — so script-created
// content is never audited by a crawl: nothing renders it. A single-page application's rendered
// DOM can carry links, text and forms that no wire check ever sees, which is why Burp's crawl IS
// a browser session in browser-based navigation mode and its crawl-paths view carries a Rendered
// DOM tab per node.
//
// This pass is the smallest honest shape for the same capability: after a crawl, render each
// distinct location URL in a headless browser and diff the rendered document against the wire
// body the crawl captured. A finding exists only when script-created content is present that the
// raw response never contained — an INFO row, because content existing is not a vulnerability by
// itself; it is a visibility fact that changes what the rest of the scan can honestly claim to
// have covered.
//
// Gated on the browser exactly like the stored render pass: no provider means the pass declines
// with an explanation, and the CALLER records the omission in its own accounting (the crawl's
// skip ledger), because the crawler is the one whose coverage claim narrows.

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// MaxRenderedLocations bounds how many locations one rendered-DOM audit pass loads.
//
// Every render is a real browser tab against a real page, so an unbounded pass over a large
// crawl would be the slowest thing in the scan by an order of magnitude. The cap is recorded
// rather than silent (Capped), so a clean result is not mistaken for a complete one. The same
// value as the stored render pass's cap, for the same reason: one shape, one bound, one
// vocabulary in the two reports.
const MaxRenderedLocations = 120

// renderedLocationsConcurrency is how many tabs the pass drives at once. Renders are
// independent and dominated by waiting for page script, so a small pool turns a serial minute
// into a few seconds. Mirrors storedRenderConcurrency.
const renderedLocationsConcurrency = 4

// RenderedLocationFinding is one location whose rendered DOM carried content the wire response
// never contained.
type RenderedLocationFinding struct {
	// URL is the location that was rendered.
	URL string
	// WireBodyLength and RenderedBodyLength are the two sizes compared, so the finding can say
	// how much of the page existed only after script ran rather than only that some of it did.
	WireBodyLength     int
	RenderedBodyLength int
	// ExchangeID is the crawl fetch whose wire response this location was captured by, so the
	// finding can cite the request that produced the page.
	ExchangeID core.ExchangeID
}

// AuditCrawlLocations renders each distinct location URL in a browser, diffs the rendered
// document against the wire body, and reports the locations where script created content the
// wire response never contained.
//
// wireByURL is the crawl's own captured bodies keyed by location URL — the caller holds the
// crawl's Report, so the pass does not reach back into the store for them; the ids ride along
// so a finding names the exchange whose wire bytes were the comparison's other half.
func (s *ActiveScanner) AuditCrawlLocations(ctx context.Context, locations map[string]core.ExchangeID, wireByURL map[string][]byte) (RenderedAuditSummary, []RenderedLocationFinding, error) {
	var out RenderedAuditSummary
	out.Candidates = len(locations)
	if s == nil {
		out.Declined = "no scanner is wired to this crawl"
		return out, nil, nil
	}
	if !s.hasBrowsers() {
		// Not an error. A crawl that wanted the rendered view and has no browser looked at
		// nothing, and the caller must be told that rather than shown an empty result —
		// the same rule stored_dom_render.go applies.
		out.Declined = "no DOM execution capability is configured for this scan"
		return out, nil, nil
	}
	// The crawl's audit runs under the scanner's audit configuration (api_crawl.go's feed reads the
	// same one), so its use_dynamic_analysis governs this browser pass too (burpsy-react-ui-9mti).
	if cfg := s.AuditConfig(); !cfg.dynamicJavaScriptOn() {
		out.Declined = "use_dynamic_analysis is false in the scanner's audit configuration, so no location was rendered"
		return out, nil, nil
	}
	browser, err := s.browsers.Browser(ctx)
	if err != nil {
		return out, nil, err
	}

	// Sort the URLs so the pass is deterministic run to run; a map's iteration order would
	// make which locations got capped a coin toss.
	urls := make([]string, 0, len(locations))
	for u := range locations {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	// Skip script-free pages before rendering: a page with no script renders to what it already
	// was, so a browser cannot reveal anything the wire pass did not see, and the render would
	// be pure cost. Counted as NoScript, never silent.
	var renderTargets []string
	for _, u := range urls {
		if wire, ok := wireByURL[u]; ok && !hasScript(wire) {
			out.NoScript++
			continue
		}
		renderTargets = append(renderTargets, u)
	}
	if len(renderTargets) > MaxRenderedLocations {
		out.Capped = len(renderTargets) - MaxRenderedLocations
		renderTargets = renderTargets[:MaxRenderedLocations]
	}

	var (
		mu       sync.Mutex
		findings []RenderedLocationFinding
		wg       sync.WaitGroup
		work     = make(chan string)
	)
	for i := 0; i < renderedLocationsConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range work {
				// Gated on the engagement scope: the location was authorised by the crawl, but the
				// requests its page makes while it renders were not (burpsy-react-ui-browser-render-unscoped).
				rendered, oc, rerr := gatedRenderer{browser: browser, scope: s.scope}.RenderedDOMWithOptions(ctx, u, domexec.RenderOptions{})
				mu.Lock()
				switch {
				case rerr != nil:
					out.Failed++
				default:
					out.Rendered++
					if len(oc.Blocked) > 0 {
						out.ScopeBlocked++
					}
					if scriptOnlyContent(wireByURL[u], []byte(rendered)) {
						out.ScriptOnly++
						findings = append(findings, RenderedLocationFinding{
							URL: u, WireBodyLength: len(wireByURL[u]), RenderedBodyLength: len(rendered),
							ExchangeID: locations[u],
						})
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, u := range renderTargets {
		select {
		case work <- u:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()

	return out, findings, nil
}

// RenderedAuditSummary is the counters half of AuditCrawlLocations' result. It mirrors the
// crawler's RenderedAuditReport field for field, so the crawl's Report can carry it without a
// translation layer — the two packages answer the same question, and an operator reading both
// should not have to learn two vocabularies.
type RenderedAuditSummary struct {
	Candidates int
	NoScript   int
	Capped     int
	Rendered   int
	Failed     int
	ScriptOnly int
	// ScopeBlocked counts rendered pages that tried to load something the scope gate refused, so
	// their rendered DOM is what an in-scope-only browser saw, not the whole page.
	ScopeBlocked int
	Declined     string
}

// hasScript reports whether a wire body carries a <script> element at all. A page with no
// script renders to what it already was, so the rendered pass skips it as pure cost.
func hasScript(body []byte) bool {
	return strings.Contains(strings.ToLower(string(body)), "<script")
}

// scriptOnlyContent reports whether the rendered document carries visible content the wire body
// never contained.
//
// The comparison is deliberately textual and conservative in BOTH directions:
//
//   - A rendered document that is byte-identical to the wire body (plus the browser's own
//     normalisations) says nothing new, so no finding.
//   - The rendered DOM always contains browser-added chrome (<html>, <head>, <body> tags the
//     wire fragment omitted, or the reverse), so raw set-difference over the whole document
//     would fire on every page. Instead the rendered document's visible text is extracted and
//     compared: text the wire body also contains (anywhere — script-built content is usually a
//     copy of data the wire carried elsewhere, and that is NOT new content) is subtracted, and
//     only rendered text with no counterpart in the wire body counts.
//
// A page whose script merely *moves* wire text around is therefore silent, and a page whose
// script *creates* text — the client-side template rendering data the wire response did not
// carry, the SPA route labels, the fetched-and-inlined API content — is the finding.
func scriptOnlyContent(wire, rendered []byte) bool {
	if len(rendered) == 0 {
		return false
	}
	// The wire body is stripped of script and style spans BEFORE it becomes the comparison's
	// other half, exactly as the rendered document is below. Without this, a fixture whose
	// script *creates* its text (route.textContent = '…') has that text present in the wire
	// body's script source, and a page that genuinely renders script-created content would be
	// read as wire-carried — the exact page this pass exists to find. Script source in either
	// reading is code, not content, in both directions.
	wireLower := strings.ToLower(stripTagged(stripTagged(string(wire), "script"), "style"))
	for _, chunk := range visibleTextChunks(rendered) {
		if len(chunk) < 8 {
			continue // single characters and stray whitespace are browser chrome, not content
		}
		if !strings.Contains(wireLower, strings.ToLower(chunk)) {
			return true
		}
	}
	return false
}

// visibleTextChunks extracts the rendered document's text content, split into chunks at
// element boundaries. A hand-rolled walk rather than a full HTML parse: the question is only
// "does this text exist in the wire body", so the tree structure is irrelevant and the
// tokenizer would be pure cost on the crawl's hottest post-pass.
func visibleTextChunks(doc []byte) []string {
	lower := strings.ToLower(string(doc))
	// Strip script and style bodies first: their contents are code, not visible text, and
	// script source that exists only in the rendered DOM is the RENDER pass's business, not
	// this content question.
	stripped := stripTagged(lower, "script")
	stripped = stripTagged(stripped, "style")

	var chunks []string
	for {
		lt := strings.IndexByte(stripped, '<')
		if lt < 0 {
			break
		}
		gt := strings.IndexByte(stripped[lt:], '>')
		if gt < 0 {
			break
		}
		if text := strings.TrimSpace(stripped[:lt]); text != "" {
			chunks = append(chunks, text)
		}
		stripped = stripped[lt+gt+1:]
	}
	if text := strings.TrimSpace(stripped); text != "" {
		chunks = append(chunks, text)
	}
	return chunks
}

// stripTagged removes one element's open-to-close span from doc, tag name matched
// case-insensitively (the caller lower-cases). The wire body is stripped the same way before
// comparison, so script source present in BOTH readings is not read as rendered content.
func stripTagged(doc, tag string) string {
	open := "<" + tag
	close := "</" + tag
	for {
		start := strings.Index(doc, open)
		if start < 0 {
			return doc
		}
		end := strings.Index(doc[start:], close)
		if end < 0 {
			return doc
		}
		doc = doc[:start] + doc[start+end+len(close):]
	}
}
