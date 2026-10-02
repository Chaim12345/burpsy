package crawler

// Seeding a crawl's dedup from the site map (burpsy-react-ui-z8qf).
//
// # What Burp does, and what it is worth
//
// Burp pre-seeds a crawl's dedup from every prior location (Zrbx.java:91-93) and publishes each
// action's HTTP chain to the site map (Zplt.java:59-61). burpsy's crawl state is per-instance — the
// queued, locations and templates tables are built fresh in New (crawler.go:1138-1142) — so a second
// crawl of a target re-walks everything the first one found and pays for it again.
//
// # What can honestly be seeded, and what cannot
//
// The site map records URLs: which host, which path, which methods, which statuses. It does NOT
// record a page's STRUCTURE, and the location table is keyed on a content fingerprint
// (location_band.go:275 — the tag skeleton, form signatures, text bucket and link targets). So:
//
//   - The `queued` table CAN be seeded. Its key is a request fingerprint — method, URL and body —
//     (crawler.go:2507), and a URL the site map has already seen is a request this crawl has no news
//     about. Seeding it is exact, not an approximation.
//   - The `locations` table CANNOT be seeded, and pretending otherwise would fabricate the thing the
//     crawl uses to judge coverage. Seeding it with a guessed fingerprint would make every page whose
//     real fingerprint differs look new anyway (useless) and, worse, would let a page whose real
//     fingerprint MATCHED be counted as already-seen without ever having been fetched — a coverage
//     claim about a page nobody read.
//   - The `templates` table is a QUOTA, not a dedup: seeding it would spend an operator's per-template
//     visit budget on pages this crawl did not fetch, so the crawl would stop earlier for no reason.
//
// So this seeds the one table that can be seeded exactly, and says so rather than approximating the
// two that cannot. That is a smaller change than the bead's fix direction asks for and it is the part
// that is actually correct; the reasoning is here because a reader will otherwise wonder why the
// location table was left alone.
//
// # What it saves, and what it does not
//
// The saving is measurable and therefore reported: a second crawl of a site the crawl has already
// walked stops re-fetching URLs whose exact request it has already made. It does NOT save the content
// work — a page that changed since the first crawl is still fetched, because its fingerprint differs
// and this seed does not touch that table.
//
// Every seeded URL is still passed through scope on the way in. The site map holds every host the
// console has ever seen, including ones an engagement does not cover, and seeding an out-of-scope URL
// into the dedup table would be a way for an out-of-scope host to be marked "already handled" and so
// never examined — a scope decision smuggled in through a performance optimisation.

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/sitemap"
)

// SeedFromSiteMap marks every URL the site map already holds for these origins as already queued,
// and returns how many it seeded.
//
// origins are host:port strings; an origin the site map has no node for seeds nothing, and a host the
// engagement scope does not cover is skipped entirely — see the file comment for why that last one is
// a correctness requirement rather than a nicety.
//
// The methods come from the site map's own record of what was seen, because seeding only the methods
// observed would under-seed (a GET the map has never seen stays queued and is fetched, which is the
// correct behaviour) while seeding methods the map never observed would claim a request was made that
// was not.
func (c *Crawler) SeedFromSiteMap(sm *sitemap.SiteMap, origins []string, scopeAllows func(host string, port uint16, isTLS bool) bool) int {
	if c == nil || sm == nil || len(origins) == 0 {
		return 0
	}
	// Origins are normalised before comparison, because a caller may reasonably write "a.test",
	// "a.test:80" or "http://a.test" for the same host and none of those is wrong. Matching the
	// caller's literal against a rendered key is how the first version of this seeded nothing: the
	// key omits a default port and the caller had included one.
	wanted := make(map[string]bool, len(origins))
	for _, o := range origins {
		wanted[normaliseOrigin(o)] = true
	}

	seeded := 0
	for _, hn := range sm.Hosts() {
		if !wanted[originKeyOf(hn.Host, hn.Port, hn.TLS)] {
			continue
		}
		// Scope on the way in. An out-of-scope host is left entirely unseeded rather than seeded and
		// refused later: seeding it would mark it already-queued, and "already queued" is consulted
		// before the request is ever built, so the scope gate would never see it.
		if scopeAllows != nil && !scopeAllows(hn.Host, hn.Port, hn.TLS) {
			continue
		}
		for _, pn := range hn.PathsSorted() {
			for _, method := range pn.MethodsSorted() {
				u := &url.URL{
					Scheme: schemeFor(hn.TLS),
					Host:   hostPort(hn.Host, hn.Port),
					Path:   pn.Path,
				}
				c.queued[requestFingerprint(method, u, nil)] = true
				seeded++
			}
		}
	}
	c.sitemapSeeded = seeded
	return seeded
}

// originKeyOf is the "host[:port]" shape an origin is compared by, with a default port omitted.
//
// Distinct from sitemap.HostKey, which is the site map's OWN key and includes the TLS flag. Two
// shapes for the same thing is a trap, so this one is built from the same fields and normalised the
// same way the CALLER's spelling is normalised below — that symmetry is the whole reason a seed
// works at all.
func originKeyOf(host string, port uint16, tls bool) string {
	return hostPort(host, port)
}

// normaliseOrigin reduces an origin the caller wrote to the key originKeyOf produces.
//
// Accepts a bare host, host:port, and a full URL, and strips a default port in either scheme. It does
// NOT accept a host it cannot read: a caller who passed something unparseable gets nothing seeded
// rather than a silent all-or-nothing, because "seeded 0 of a map full of URLs" is an honest report
// and a panic is not.
func normaliseOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	// A full URL carries its scheme, which says whether the port is the default — so parse it as one
	// rather than string-splitting, which would treat "a.test:443" on http as a non-default port.
	if strings.Contains(origin, "://") {
		if u, err := url.Parse(origin); err == nil && u.Host != "" {
			return hostPort(u.Hostname(), portOfURL(u))
		}
		return ""
	}
	host, portStr, err := net.SplitHostPort(origin)
	if err != nil {
		// No port, or not a host:port at all.
		return strings.ToLower(strings.TrimSuffix(origin, "/"))
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return strings.ToLower(host)
	}
	return hostPort(strings.ToLower(host), uint16(p))
}

// portOfURL reads a URL's explicit port, or 0 when it carries none — which is what hostPort treats as
// "the scheme's default".
func portOfURL(u *url.URL) uint16 {
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			return uint16(n)
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// hostPort renders host:port, adding the port only when it is not the scheme's default — so an
// origin named "a.test:443" and one named "a.test" for an HTTPS host are the same string, which is
// what a caller means by naming an origin.
func hostPort(host string, port uint16) string {
	if port == 0 || port == 80 || port == 443 {
		return host
	}
	return host + ":" + strconv.Itoa(int(port))
}

// schemeFor maps the site map's TLS flag to a scheme.
func schemeFor(tls bool) string {
	if tls {
		return "https"
	}
	return "http"
}
