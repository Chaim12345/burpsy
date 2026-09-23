package crawler

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// ---- crawl paths: which way, not how far (burpsy-react-ui-tix) ---------------------------------
//
// Depth already answered "how far from a seed is this page". Fetch.FoundAt answers "which way did
// the crawler get here", and that is the question an operator actually has when a page they expected
// is missing: not how deep it is, but what should have linked to it.
//
// The data was thrown away on success. frontierItem.foundAt existed and was documented "reporting
// only" — every refusal carried it, so the crawler could explain a URL it declined, while the graph
// it actually walked was reconstructible only for the parts it did not walk.

// fetchByPath finds the fetch whose URL ends in the given path.
func fetchByPath(t *testing.T, fetches []Fetch, path string) Fetch {
	t.Helper()
	for _, f := range fetches {
		if strings.HasSuffix(f.URL, path) {
			return f
		}
	}
	var urls []string
	for _, f := range fetches {
		urls = append(urls, f.URL)
	}
	t.Fatalf("no fetch for %q; fetched %v", path, urls)
	return Fetch{}
}

// The edge is recorded for a page the crawl actually fetched, which is the whole gap.
func TestASuccessfulFetchRecordsThePageItWasFoundOn(t *testing.T) {
	pages := map[string]string{
		"/":      `<html><body><a href="/alpha">Go to alpha</a></body></html>`,
		"/alpha": `<html><body><a href="/beta">Onward to beta</a></body></html>`,
		"/beta":  `<html><body><p>end</p></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	rep := run(t, h.config(tg.URL+"/"))

	seed := fetchByPath(t, rep.Fetches, "/")
	alpha := fetchByPath(t, rep.Fetches, "/alpha")
	beta := fetchByPath(t, rep.Fetches, "/beta")

	// A seed has no referring page, and empty means exactly that — not "unknown".
	if seed.FoundAt != "" {
		t.Errorf("the seed reports FoundAt = %q; a seed has no referring page", seed.FoundAt)
	}

	if !strings.HasSuffix(alpha.FoundAt, "/") {
		t.Errorf("/alpha reports FoundAt = %q, want the seed page — without this the crawl graph is "+
			"reconstructible only for the URLs the crawler refused", alpha.FoundAt)
	}
	if !strings.HasSuffix(beta.FoundAt, "/alpha") {
		t.Errorf("/beta reports FoundAt = %q, want /alpha. Depth alone cannot say this: two pages at "+
			"depth 2 can be reached through entirely different parents", beta.FoundAt)
	}

	// The chain has to be walkable, which is the property a crawl-paths view renders.
	if beta.Depth != 2 || alpha.Depth != 1 {
		t.Errorf("depths are alpha=%d beta=%d, want 1 and 2", alpha.Depth, beta.Depth)
	}
}

// The link text, because "which of the three links to /logout was followed" is not answerable from
// the URL, and an edge in a rendering needs a label.
func TestTheLinkTextTheUrlWasReachedThroughIsRecorded(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":      `<html><body><a href="/admin">Administrator console</a></body></html>`,
		"/admin": `<html><body><p>admin</p></body></html>`,
	})
	h := newHarness()
	rep := run(t, h.config(tg.URL+"/"))

	admin := fetchByPath(t, rep.Fetches, "/admin")
	if admin.LinkText != "Administrator console" {
		t.Errorf("LinkText = %q, want the anchor text — it is what distinguishes a seed (no text, no "+
			"FoundAt) from a link whose text happened to be empty", admin.LinkText)
	}
}

// Every fetch that is not a seed must name a parent. A fetch with neither FoundAt nor depth 0 would
// be an orphan in any rendering, and silently dropping it is how a view understates coverage.
func TestEveryNonSeedFetchNamesAParent(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":       `<html><body><a href="/a">A</a><a href="/b">B</a></body></html>`,
		"/a":      `<html><body><a href="/a/deep">Deep</a></body></html>`,
		"/b":      `<html><body><p>b</p></body></html>`,
		"/a/deep": `<html><body><p>deep</p></body></html>`,
	})
	h := newHarness()
	rep := run(t, h.config(tg.URL+"/"))

	if len(rep.Fetches) < 4 {
		t.Fatalf("expected at least four fetches, got %d", len(rep.Fetches))
	}
	for _, f := range rep.Fetches {
		if f.Depth == 0 {
			continue // a seed
		}
		if f.FoundAt == "" {
			t.Errorf("%s is at depth %d and names no parent; a crawl-paths view would have to either "+
				"drop it — understating coverage — or invent a parent for it", f.URL, f.Depth)
		}
	}
}

// A form submission is an edge too, and it is the one most likely to be forgotten: it travels a
// different admission path than a link.
func TestAFormSubmissionRecordsItsOriginPage(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/": `<html><body>
			<form action="/search" method="get"><input name="q" value="x"><input type="submit" value="Search"></form>
			</body></html>`,
		"/search": `<html><body><p>results</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.SubmitForms = true
	rep := run(t, cfg)

	var search *Fetch
	for i := range rep.Fetches {
		if strings.Contains(rep.Fetches[i].URL, "/search") {
			search = &rep.Fetches[i]
			break
		}
	}
	if search == nil {
		t.Skip("the form was not submitted in this configuration; the link case above covers the field")
	}
	if search.FoundAt == "" {
		t.Error("a submitted form's fetch names no origin page, though a form is discovered on a page " +
			"exactly as a link is")
	}
}

// ---- rendered-DOM discovery (burpsy-react-ui-nx7b) ----------------------------------------------
//
// A single-page application's routes and script-built hrefs exist only after the page's own
// script has run, so a parser over the wire response cannot see them — that is the whole
// reason Burp has a browser-based navigation mode, and the reason Config.Render exists: the
// crawl gets one hook that returns the DOM a browser builds, and a second pass reads it for
// links the wire markup never carried.

// renderedStub is a Render hook whose answer is fixed per URL, so the rendered pass is driven
// without a browser: the fixture decides what "the browser built", exactly the way the DOM
// check tests stub their provider. A nil map entry means "the render failed for this URL",
// which is the SkipRenderUnavailable case.
type renderedStub map[string]string

func (r renderedStub) render(_ context.Context, targetURL string) (string, error) {
	if doc, ok := r[targetURL]; ok {
		return doc, nil
	}
	return "", fmt.Errorf("no rendered document for %q", targetURL)
}

// A script-built href is discovered ONLY by the rendered pass, and the edge says so.
func TestAScriptBuiltHrefIsDiscoveredOnlyByTheRenderedPass(t *testing.T) {
	tg := newTarget(t, map[string]string{
		// The wire markup: no link to /rendered-route at all.
		"/": `<html><body><a href="/wired">Wired link</a></body></html>`,
		// The page the crawl reaches via the wired link: its wire bytes link nowhere new...
		"/wired":          `<html><body><p>the router builds the next link in script</p></body></html>`,
		"/rendered-route": `<html><body><p>end</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	// ...but the DOM a browser builds for it carries the SPA's route, built by script.
	cfg.Render = renderedStub{
		tg.URL + "/wired": `<html><body><p>the router builds the next link in script</p>` +
			`<a href="/rendered-route">Rendered route</a></body></html>`,
	}.render
	rep := run(t, cfg)

	rendered := fetchByPath(t, rep.Fetches, "/rendered-route")
	if !rendered.FoundByRender {
		t.Errorf("/rendered-route has FoundByRender=false: a link that exists only after the page's " +
			"script runs must name the rendering as its origin, or a crawl-paths view cannot say which " +
			"edges a browser-less crawl would have missed entirely")
	}
	if !strings.HasSuffix(rendered.FoundAt, "/wired") {
		t.Errorf("/rendered-route FoundAt = %q, want /wired — the rendered pass discovers on the page "+
			"it rendered, like any other link", rendered.FoundAt)
	}
	// The wired link is NOT marked: it was in the wire bytes, and mislabeling it would inflate
	// the rendered pass's claim.
	if wired := fetchByPath(t, rep.Fetches, "/wired"); wired.FoundByRender {
		t.Error("/wired is marked FoundByRender, but it was in the wire markup — the rendered pass " +
			"must not claim discoveries the static parse already made")
	}
	// LinksFound counts the rendered discovery like any other: the count is what the pane
	// reports, and a rendered link that did not count would be invisible in the totals.
	if rep.LinksFound != 2 {
		t.Errorf("LinksFound = %d, want 2 (one wired, one rendered)", rep.LinksFound)
	}
}

// A nil Render is the previous crawl to the byte: no rendered pass, no skip, nothing declined.
func TestANilRenderIsThePreviousCrawl(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":     `<html><body><a href="/only">Only</a></body></html>`,
		"/only": `<html><body><p>end</p></body></html>`,
	})
	h := newHarness()
	rep := run(t, h.config(tg.URL+"/"))

	if rep.Skips.Count(SkipRenderUnavailable) != 0 {
		t.Errorf("render-unavailable = %d on a crawl with no Render hook; a nil hook declines "+
			"nothing and must not record a skip", rep.Skips.Count(SkipRenderUnavailable))
	}
	// The crawl's own robots.txt probe is a fetch too, so count by path rather than by total.
	paths := fetchedPaths(rep)
	if paths["/"] != 1 || paths["/only"] != 1 {
		t.Errorf("fetched / %d times and /only %d times, want 1 and 1: a nil Render must change "+
			"nothing about what the crawl walks", paths["/"], paths["/only"])
	}
}

// A render that fails is SkipRenderUnavailable, counted and sampled — the rendered view is the
// only place these links exist, so a crawl that wanted it and did not get it must say so.
func TestAFailedRenderIsCountedNotSilent(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":    `<html><body><a href="/spa">SPA</a></body></html>`,
		"/spa": `<html><body><p>script builds everything</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.Render = renderedStub{}.render // no entry for /spa: the render fails
	rep := run(t, cfg)

	// The stub answers for no URL, so every HTML page the crawl *parses as a page* gets a failed
	// render: the seed and /spa — two declines, none silent. The robots.txt 404 is metadata the
	// crawler reads as a path list, deliberately not a location, so it is exempt exactly like
	// its static parse is. The page that MATTERS is /spa, checked by name below.
	if got := rep.Skips.Count(SkipRenderUnavailable); got != 2 {
		t.Errorf("render-unavailable = %d, want 2 (the seed and /spa): a "+
			"failed render is the one decline that narrows coverage invisibly if it is not counted", got)
	}
	recs := rep.Skips.Records
	var found bool
	for _, r := range recs {
		if r.Reason == SkipRenderUnavailable && strings.HasSuffix(r.URL, "/spa") {
			found = true
		}
	}
	if !found {
		t.Error("no sampled record for the failed render: the sample exists so a refusal names the " +
			"thing it refused, and a URL-level render failure is exactly that")
	}
}

// A rendered link the wire parse also carried is discovered once, by the wire parse, and
// attributed to it — the rendered pass adds, it never double-counts.
func TestARenderedLinkTheWireAlreadyHadIsNotDoubleCounted(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":              `<html><body><a href="/both">Both</a></body></html>`,
		"/both":          `<html><body><a href="/only-rendered">Only rendered</a></body></html>`,
		"/only-rendered": `<html><body><p>end</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.Render = renderedStub{
		// The rendered DOM carries BOTH the wire's link and the script-built one.
		tg.URL + "/both": `<html><body><a href="/only-rendered">Only rendered</a>` +
			`<a href="/end">End</a></body></html>`,
	}.render
	rep := run(t, cfg)

	end := fetchByPath(t, rep.Fetches, "/end")
	if !end.FoundByRender {
		t.Error("/end should be marked FoundByRender — it exists only in the rendered DOM")
	}
	// exactly one fetch for /end
	count := 0
	for _, f := range rep.Fetches {
		if strings.HasSuffix(f.URL, "/end") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("fetches for /end = %d, want 1: the dedup the frontier already does must keep a "+
			"link discovered twice (once per reading) from being fetched twice", count)
	}
	// And the rendered pass did not re-offer what the wire pass had: without the pass's own
	// dedup against the static reading, the second discovery would be laundered through the
	// frontier's queued-set as a spurious SkipAlreadyQueued — the URL reported as a repeat
	// when each reading found it once. The frontier keeps the fetch count right; this keeps
	// the skip ledger honest.
	if got := rep.Skips.Count(SkipAlreadyQueued); got != 0 {
		t.Errorf("already-queued = %d, want 0: a link the wire pass discovered and the rendered "+
			"pass saw again must be filtered as already-carried, not re-queued and declined as a "+
			"duplicate — the two are different facts about the page", got)
	}
}
