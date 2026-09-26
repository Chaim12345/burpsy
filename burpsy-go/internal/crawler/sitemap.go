package crawler

import (
	"encoding/xml"
	"strings"
)

// Sitemap parsing: the `<loc>` entries of a sitemap or a sitemap index, as locations.
//
// # Why this exists
//
// A robots.txt may name its own URL list (`Sitemap: https://x/sitemap.xml`). The crawler admits
// that URL and fetches it — then discards the response as non-HTML, because there is no
// `encoding/xml` anywhere in this package. So a target that publishes exactly where to go has its
// answer fetched, stored, scanned and thrown away, and the crawl maps only what it linked into
// (burpsy-react-ui-qjtx).
//
// Burp parses it: Zgkz.java:13,18,22-24, and the SITEMAP entry in Zb8w's action vocabulary
// (Zb8w.java:15) is the record of having done so.
//
// # Why a branch beside the HTML gate rather than a widened one
//
// `isHTML` exists for HTML EXTRACTION — the link walk, the form submit, the base-href resolution.
// None of that applies to a sitemap, and admitting XML through it would hand every non-HTML
// response to the HTML extractor looking for anchors it will never find. The branch below is a
// sibling of the gate, not a relaxation of it, so a PDF still records SkipNotHTML exactly as before.
//
// # What is read, and what is not
//
// Every <loc> is a location. <lastmod> is carried because it is free next to the loc and it is what
// distinguishes a URL an operator changed this morning from one untouched since 2019, but it is NOT
// used to order the frontier: a crawl's job is coverage, and ordering by a date an operator may have
// written wrong would make coverage depend on a value the crawl cannot verify.
//
// A <sitemapindex> is a sitemap OF sitemaps, so its <loc> entries are sitemaps rather than pages.
// They are returned too, flagged, so a caller can follow them — a site with 50,000 URLs publishes a
// handful of sitemaps pointing at the rest, and reading only the index would find every one of them
// empty.

// SitemapEntry is one URL a sitemap names, with the two facts a crawl can read off it.
type SitemapEntry struct {
	// Loc is the URL, as published. Not normalised: a sitemap is an operator's own list and
	// rewriting it would make the report disagree with the file.
	Loc string
	// LastMod is the w3c datetime the publisher wrote, verbatim. Carried, not interpreted — see the
	// note above.
	LastMod string
	// IsIndex marks a <loc> that names a SITEMAP rather than a page, from a <sitemapindex> document.
	// A caller following it must treat the entry as another sitemap to parse, not as a page to fetch.
	IsIndex bool
}

// sitemapDocument is the shape of both a <urlset> and a <sitemapindex>: the same <url>/<loc> nesting,
// differing only in what the <loc> means.
type sitemapDocument struct {
	XMLName xml.Name
	URLs    []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"sitemap"`
}

// SitemapKind names which of the two documents this is, because the meaning of a <loc> differs and
// the report has to say which it parsed.
type SitemapKind string

const (
	// SitemapURLSet is a <urlset>: its <loc> entries are pages.
	SitemapURLSet SitemapKind = "urlset"
	// SitemapIndex is a <sitemapindex>: its <loc> entries are sitemaps.
	SitemapIndex SitemapKind = "sitemapindex"
)

// ParseSitemap reads a sitemap document, returning its entries, its kind, and why a parse failed.
//
// The failure string matters: a sitemap that arrives gzipped, truncated, or with a Content-Type the
// sender disagreed with is a document the operator can fix, and a crawl that reports "0 locations" for
// one looks exactly like a site with no pages. The caller reports this string.
//
// A non-XML body is NOT an error here — it returns no entries and no failure, because the caller has
// already decided this response is worth parsing as a sitemap and an HTML page served at
// /sitemap.xml is a real (if unhelpful) answer, not a malformed one.
func ParseSitemap(body []byte) (entries []SitemapEntry, kind SitemapKind, failure string) {
	// The XML declaration and any leading whitespace/BOM are what trip a strict decoder on an
	// otherwise-fine document, and a sitemap served with one is the normal case.
	trimmed := strings.TrimLeft(string(body), " \t\r\n\ufeff")
	if !strings.Contains(trimmed, "<") {
		return nil, "", ""
	}
	var doc sitemapDocument
	if err := xml.Unmarshal([]byte(trimmed), &doc); err != nil {
		return nil, "", err.Error()
	}
	kind = SitemapURLSet
	if strings.EqualFold(doc.XMLName.Local, "sitemapindex") {
		kind = SitemapIndex
	}
	for _, s := range doc.Sitemaps {
		if loc := strings.TrimSpace(s.Loc); loc != "" {
			entries = append(entries, SitemapEntry{Loc: loc, LastMod: strings.TrimSpace(s.LastMod), IsIndex: true})
		}
	}
	for _, u := range doc.URLs {
		if loc := strings.TrimSpace(u.Loc); loc != "" {
			entries = append(entries, SitemapEntry{Loc: loc, LastMod: strings.TrimSpace(u.LastMod)})
		}
	}
	return entries, kind, ""
}

// LooksLikeSitemap reports whether a content type is one a sitemap is served as, or whether the body
// announces itself as one.
//
// The content type is a hint, not a gate: a great many servers serve a sitemap as
// application/octet-stream or as text/plain, and requiring the right header would drop the document
// on exactly the sites that publish one. So this is "worth trying", and a failed parse is reported
// rather than treated as a non-sitemap — which is what makes a mislabelled sitemap recoverable
// instead of silent.
func LooksLikeSitemap(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "xml") {
		return true
	}
	// A body-level sniff, for the octet-stream and text/plain cases. Cheap and bounded: the prefix
	// only, and only the two element names that identify the document.
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	lowered := strings.ToLower(string(head))
	return strings.Contains(lowered, "<urlset") || strings.Contains(lowered, "<sitemapindex")
}
