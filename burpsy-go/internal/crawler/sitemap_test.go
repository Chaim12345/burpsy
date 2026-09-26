package crawler

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// burpsy-react-ui-qjtx: a robots.txt may name its own URL list (`Sitemap: https://x/sitemap.xml`).
// The crawler admitted that URL and fetched it — then discarded the response as non-HTML, because
// there was no `encoding/xml` in the package. A target that publishes exactly where to go had its
// answer fetched, stored, scanned and thrown away (crawler.go:1332-1341, SkipNotHTML).

// The parser, on the two document shapes Burp publishes.
func TestASitemapYieldsItsLocations(t *testing.T) {
	doc := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://a.test/one</loc><lastmod>2026-09-01</lastmod></url>
  <url><loc>https://a.test/two</loc></url>
  <url><loc>  https://a.test/three  </loc></url>
  <url><lastmod>2026-09-02</lastmod></url>
</urlset>`)
	entries, kind, failure := ParseSitemap(doc)
	if failure != "" {
		t.Fatalf("parse failure: %s", failure)
	}
	if kind != SitemapURLSet {
		t.Errorf("kind = %q, want urlset", kind)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3: a <url> with no <loc> names nothing and must not be counted",
			len(entries))
	}
	// Trimmed, because a loc written with surrounding whitespace still names the page and an
	// untrimmed one would be refused downstream as a malformed URL.
	if entries[0].Loc != "https://a.test/one" || entries[2].Loc != "https://a.test/three" {
		t.Errorf("locs = %q, %q; the whitespace around a <loc> is not part of the URL",
			entries[0].Loc, entries[2].Loc)
	}
	// lastmod is CARRIED, not interpreted. It is what tells an operator which page changed this
	// morning, and it is not used to order the frontier: coverage that depends on a date the target
	// may have written wrong is coverage the crawl cannot stand behind.
	if entries[0].LastMod != "2026-09-01" {
		t.Errorf("LastMod = %q, want the value the publisher wrote, verbatim", entries[0].LastMod)
	}
}

// A sitemapindex is a sitemap OF sitemaps, so its entries are marked. A large site publishes a
// handful of sitemaps pointing at the rest, and reading only the index would find every one of them
// empty.
func TestASitemapIndexMarksItsEntriesAsSitemaps(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://a.test/sitemap-1.xml</loc><lastmod>2026-09-01</lastmod></sitemap>
  <sitemap><loc>https://a.test/sitemap-2.xml</loc></sitemap>
</sitemapindex>`)
	entries, kind, failure := ParseSitemap(doc)
	if failure != "" {
		t.Fatalf("parse failure: %s", failure)
	}
	if kind != SitemapIndex {
		t.Errorf("kind = %q, want sitemapindex", kind)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	for _, e := range entries {
		if !e.IsIndex {
			t.Errorf("entry %q is not marked as an index entry; a caller would fetch it as a PAGE "+
				"and find no links, which is the failure this flag exists to prevent", e.Loc)
		}
	}
}

// A parse failure is a FAILURE, not an empty result. A gzipped sitemap, a truncated fetch and a
// document that was never a sitemap are three different facts, and "0 locations" cannot tell them
// apart.
func TestAMalformedSitemapReportsWhyItFailed(t *testing.T) {
	_, _, failure := ParseSitemap([]byte(`<urlset><url><loc>https://a.test/one</loc></urlset>`))
	if failure == "" {
		t.Fatal("an unclosed <urlset> parsed as an empty sitemap; the operator would see 0 locations " +
			"and conclude the target publishes none")
	}
}

// A non-XML body is not a failure here: the caller has already decided this response is worth trying
// as a sitemap, and an HTML page served at /sitemap.xml is a real if unhelpful answer.
func TestAnHTMLBodyAtASitemapURLIsNotAParseFailure(t *testing.T) {
	entries, _, failure := ParseSitemap([]byte(`<html><body>not a sitemap</body></html>`))
	if failure != "" {
		t.Errorf("an HTML body reported a parse failure (%s); it is a document that is not a sitemap, "+
			"which is a different thing from one that could not be read", failure)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
}

// The content type is a HINT, not a gate. A great many servers serve a sitemap as octet-stream or
// text/plain, and requiring the right header would drop the document on exactly the sites that
// publish one.
func TestASitemapIsRecognisedWithoutTheRightContentType(t *testing.T) {
	body := []byte(`<urlset><url><loc>https://a.test/one</loc></url></urlset>`)
	for _, ct := range []string{
		"application/xml",
		"text/xml",
		"application/octet-stream", // the common lie
		"text/plain",               // the other common lie
		"",                         // and no header at all
	} {
		if !LooksLikeSitemap(ct, body) {
			t.Errorf("content type %q was not recognised as a sitemap; the body says <urlset> plainly "+
				"and a site that publishes its URL list is exactly the one this must not miss", ct)
		}
	}
	// And a real non-sitemap is not mistaken for one.
	for _, ct := range []string{"application/pdf", "image/png", "text/html"} {
		if LooksLikeSitemap(ct, []byte("%PDF-1.4 binary")) {
			t.Errorf("content type %q was treated as a sitemap", ct)
		}
	}
}

type servedPage struct {
	body        string
	contentType string
}

// sitemapTarget serves pages with explicit content types.
//
// The existing newTarget hardcodes text/html, and the content type is the whole question here: a
// sitemap served as octet-stream is the case this must not miss, and a fixture that cannot produce
// one cannot test it.
func sitemapTarget(t *testing.T, pages map[string]servedPage) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, page := range pages {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", page.contentType)
			_, _ = w.Write([]byte(page.body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fetchLog reports every URL the crawl actually requested, from the run's own record.
func fetchLog(rep Report) []string {
	out := make([]string, 0, len(rep.Fetches))
	for _, f := range rep.Fetches {
		out = append(out, f.URL)
	}
	return out
}

func fetchedAny(rep Report, substr string) bool {
	for _, u := range fetchLog(rep) {
		if strings.Contains(u, substr) {
			return true
		}
	}
	return false
}

// skippedWith reads the ledger COUNTS, which is the total per reason rather than the bounded
// sample of records: a test asking whether a reason ever fired must not depend on whether that
// decline happened to fit the sample.
func skippedWith(rep Report, reason Skip) bool {
	for _, c := range rep.Skips.Counts {
		if c.Reason == reason && c.Count > 0 {
			return true
		}
	}
	return false
}

// A self-naming target: built after the listener exists so the fixture can contain the server's own
// address, which is what a real sitemap does and what makes the end-to-end test meaningful.
func selfNamingTarget(t *testing.T, pages func(base string) map[string]servedPage) *httptest.Server {
	t.Helper()
	// A placeholder listener to learn the address, then the real server serving the resolved pages.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	base := "http://" + probe.Addr().String()
	probe.Close()

	mux := http.NewServeMux()
	for path, page := range pages(base) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", page.contentType)
			_, _ = w.Write([]byte(page.body))
		})
	}
	srv := &httptest.Server{
		Listener: mustListen(t, base),
		Config:   &http.Server{Handler: mux},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func mustListen(t *testing.T, addr string) net.Listener {
	t.Helper()
	host := strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
	ln, err := net.Listen("tcp", host)
	if err != nil {
		t.Fatalf("listen on the address the probe reserved: %v", err)
	}
	return ln
}

// The end-to-end claim: a sitemap named by robots.txt is parsed and its locations FETCHED.
func TestARobotsNamedSitemapYieldsFetchableLocations(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/robots.txt": {`Sitemap: ` + base + `/sitemap.xml` + "\n", "text/plain"},
			"/sitemap.xml": {`<urlset><url><loc>` + base + `/from-sitemap-1</loc></url>` +
				`<url><loc>` + base + `/from-sitemap-2</loc></url></urlset>`, "application/xml"},
			"/from-sitemap-1": {"<html><body>page one</body></html>", "text/html"},
			"/from-sitemap-2": {"<html><body>page two</body></html>", "text/html"},
		}
	})

	// Seeded at the ORIGIN, not at robots.txt itself: the crawler asks for a seed's authority's
	// robots.txt (admitRobots), so seeding the file directly makes the test assert on a path no
	// crawl takes.
	rep := run(t, newHarness().config(srv.URL+"/"))
	if rep.SitemapsParsed == 0 {
		t.Fatalf("a sitemap named by robots.txt was not parsed; fetches were %v", fetchLog(rep))
	}
	if rep.SitemapLocationsFound < 2 {
		t.Errorf("SitemapLocationsFound = %d, want the 2 the sitemap names", rep.SitemapLocationsFound)
	}
	// Counted AND fetched. A count the crawl did not act on is a number an operator cannot use, and
	// it is what the defect would look like if the parse had been added but the admission not.
	if !fetchedAny(rep, "from-sitemap-1") || !fetchedAny(rep, "from-sitemap-2") {
		t.Errorf("the sitemap's locations were counted but not fetched; fetch list: %v", fetchLog(rep))
	}
}

// A sitemap served with the wrong content type is still read, because a great many servers serve one
// as octet-stream and requiring the right header would drop the document on exactly the sites that
// publish it.
func TestASitemapServedAsOctetStreamIsStillParsed(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/sitemap.xml": {`<urlset><url><loc>` + base + `/deep</loc></url></urlset>`, "application/octet-stream"},
			"/deep":        {"<html><body>deep</body></html>", "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/sitemap.xml"))
	if rep.SitemapsParsed == 0 || !fetchedAny(rep, "/deep") {
		t.Errorf("a sitemap served as octet-stream was not read; parsed=%d fetches=%v",
			rep.SitemapsParsed, fetchLog(rep))
	}
}

// A SIBLING of the HTML gate, not a relaxation of it. A PDF still records SkipNotHTML exactly as
// before — admitting XML through that gate would hand every non-HTML response to the HTML extractor
// looking for anchors it will never find.
func TestANonSitemapNonHTMLResponseIsStillSkippedAsNotHTML(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/manual.pdf": {"%PDF-1.4 binary", "application/pdf"},
	})
	rep := run(t, newHarness().config(srv.URL+"/manual.pdf"))
	if rep.SitemapsParsed != 0 {
		t.Errorf("SitemapsParsed = %d for a PDF; the sitemap branch must not swallow the not-HTML path",
			rep.SitemapsParsed)
	}
	if !skippedWith(rep, SkipNotHTML) {
		t.Error("a PDF no longer records SkipNotHTML; the HTML gate must be unchanged for everything " +
			"that is not a sitemap")
	}
}

// A sitemap that will not parse records ITS OWN reason, which is the whole reason the value exists.
func TestAnUnparseableSitemapIsReportedAsSuchRatherThanAsNotHTML(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/broken.xml": {"<urlset><url><loc>https://a.test/one</loc></urlset>", "application/xml"},
	})
	rep := run(t, newHarness().config(srv.URL+"/broken.xml"))
	if !skippedWith(rep, SkipSitemapUnparsed) {
		t.Error("a body that looked like a sitemap and could not be read did not say so; it is " +
			"indistinguishable from a target that published no URL list, which is the defect")
	}
	if skippedWith(rep, SkipNotHTML) {
		t.Error("the unparseable sitemap was ALSO recorded as not-HTML; the two are different findings " +
			"and the operator's remedy for them is different")
	}
}

// A sitemap URL is TARGET-SUPPLIED input, exactly as a link is, so its locations pass the same gates.
// A sitemap naming a destructive action must not become a privileged request because the target
// wrote it down.
func TestASitemapLocationIsStillDestructivenessChecked(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/sitemap.xml": {`<urlset><url><loc>` + base + `/fine</loc></url>` +
				`<url><loc>` + base + `/admin/delete-all</loc></url></urlset>`, "application/xml"},
			"/fine":             {"<html><body>fine</body></html>", "text/html"},
			"/admin/delete-all": {"<html><body>deleted</body></html>", "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/sitemap.xml"))
	if fetchedAny(rep, "delete-all") {
		t.Error("a destructive path named in a sitemap was fetched; a sitemap is untrusted " +
			"target-supplied input exactly as a link is")
	}
	if !skippedWith(rep, SkipDestructiveDelete) && !skippedWith(rep, SkipDestructivePurge) {
		// The refusal may be recorded under whichever destructive class the pattern matches, so this
		// asserts the ACTION rather than a specific reason: it must not have been fetched.
		if !fetchedAny(rep, "delete-all") {
			t.Error("the destructive sitemap entry was neither fetched nor recorded as refused")
		}
	}
}

// A sitemapindex is followed: a large site publishes a handful of sitemaps pointing at the rest, and
// reading only the index would find every one of them empty.
func TestASitemapIndexIsFollowedToItsChildren(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/index.xml": {`<sitemapindex><sitemap><loc>` + base + `/a.xml</loc></sitemap>` +
				`<sitemap><loc>` + base + `/b.xml</loc></sitemap></sitemapindex>`, "application/xml"},
			"/a.xml":  {`<urlset><url><loc>` + base + `/page-a</loc></url></urlset>`, "application/xml"},
			"/b.xml":  {`<urlset><url><loc>` + base + `/page-b</loc></url></urlset>`, "application/xml"},
			"/page-a": {"<html><body>a</body></html>", "text/html"},
			"/page-b": {"<html><body>b</body></html>", "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/index.xml"))
	if rep.SitemapIndexesFollowed < 1 {
		t.Errorf("SitemapIndexesFollowed = %d; the index names two sitemaps and reading only it finds "+
			"every one of them empty", rep.SitemapIndexesFollowed)
	}
	if !fetchedAny(rep, "/a.xml") || !fetchedAny(rep, "page-a") {
		t.Errorf("the index's children were not followed; fetches: %v", fetchLog(rep))
	}
}

// The counters are reported together because either alone is unreadable: documents with no
// locations says the target publishes empty sitemaps, locations with no documents says nothing
// about where they came from.
func TestTheSitemapReportSeparatesDocumentsFromLocations(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/index.xml": {`<sitemapindex><sitemap><loc>` + base + `/a.xml</loc></sitemap></sitemapindex>`, "application/xml"},
			"/a.xml":     {`<urlset><url><loc>` + base + `/only-page</loc></url></urlset>`, "application/xml"},
			"/only-page": {"<html><body>one</body></html>", "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/index.xml"))
	if rep.SitemapsParsed < 2 {
		t.Errorf("SitemapsParsed = %d, want the index plus the one it names", rep.SitemapsParsed)
	}
	if rep.SitemapLocationsFound < 1 {
		t.Errorf("SitemapLocationsFound = %d, want the one page the child names", rep.SitemapLocationsFound)
	}
}
