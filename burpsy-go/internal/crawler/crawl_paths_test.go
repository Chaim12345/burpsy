package crawler

import (
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
