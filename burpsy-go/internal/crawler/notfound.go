package crawler

// Not-found detection (burpsy-react-ui-s92h), Burp's not-found-detection edge: before a crawl trusts a
// 200 page as a location, it learns what the directory answers for a name that cannot exist.
//
// A site that serves its "page not found" with status 200 (a custom error page, a SPA shell, a
// catch-all route) makes every mistyped or invented link look like a real location. Each one was
// audited, and each one's links grew the frontier. One request per directory buys the answer: a
// random sibling is fetched, and a 200 page that matches its shape is that directory's soft 404.
//
// The probe goes through the same limiters, scope-checked sender and capture as every other fetch, so
// it is rate-limited, refused out of scope, and visible in history. Its row's note says it was a
// probe. The number of directories probed is bounded (maxNotFoundProbes), and a directory past the
// bound is simply not checked: the crawl behaves as it did before for those pages.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// maxNotFoundProbes bounds the directories probed in one crawl.
const maxNotFoundProbes = 64

// notFoundShape is what one directory answers for a nonexistent name. hard is true when that answer
// was a real 404 or 410, in which case nothing in the directory can be a soft 404.
type notFoundShape struct {
	hard        bool
	fingerprint string
}

// notFoundKey is the directory a URL's not-found shape is learned for: scheme, authority, and the path
// up to its last slash.
func notFoundKey(u *url.URL) string {
	dir := u.EscapedPath()
	if i := strings.LastIndexByte(dir, '/'); i >= 0 {
		dir = dir[:i+1]
	} else {
		dir = "/"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + dir
}

// isSoftNotFound reports whether a 2xx page is this directory's "not found" page, probing the
// directory first if it has not been probed.
//
// A seed is never judged: the operator chose it, and a site that serves one page for every path (a
// SPA shell, a catch-all route) answers the probe with the seed itself, which must still be walked.
// The match is on the exact location fingerprint, not the looser shape: pages built from one template
// share a shape, and a soft 404 is the same page for every missing name.
func (c *Crawler) isSoftNotFound(ctx context.Context, item frontierItem, page pageStructure, rep *Report) bool {
	if c.cfg.NoNotFoundProbe || page.fingerprint == "" || item.depth == 0 {
		return false
	}
	key := notFoundKey(item.url)
	known, ok := c.notFound[key]
	if !ok {
		if c.notFoundProbes >= maxNotFoundProbes || rep.Fetched >= c.limits.MaxRequests {
			// Past the probe bound, or the request budget is spent: the probe would be a request the
			// crawl may not send, so this directory is not judged.
			return false
		}
		c.notFoundProbes++
		known = c.probeNotFound(ctx, item, rep)
		c.notFound[key] = known
	}
	if known == nil || known.hard {
		return false
	}
	return page.fingerprint == known.fingerprint
}

// probeNotFound fetches a random sibling of item and returns the shape of the answer, or nil when the
// probe could not be sent or read (in which case the directory is not judged at all).
func (c *Crawler) probeNotFound(ctx context.Context, item frontierItem, rep *Report) *notFoundShape {
	var r [6]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil
	}
	name := "burpsy-nf-" + hex.EncodeToString(r[:]) + path.Ext(item.url.Path)
	probeURL := *item.url
	probeURL.Path = path.Join(path.Dir(item.url.Path+"x"), name)
	if strings.HasSuffix(item.url.Path, "/") {
		probeURL.Path = item.url.Path + name
	}
	probeURL.RawPath, probeURL.RawQuery, probeURL.Fragment = "", "", ""
	probe := frontierItem{url: &probeURL, method: "GET", foundAt: item.url.String(), text: "not-found probe"}
	raw := c.buildRequest(probe)

	as := c.senderFor(&probeURL)
	global := c.limiter.Acquire()
	host := c.limiterFor(&probeURL).Acquire()
	res, err := as.Send(ctx, raw)
	host.Release()
	global.Release()
	if err != nil {
		return nil
	}
	c.noteSent()
	note := "crawler not-found probe: a nonexistent sibling, fetched to learn what this directory answers for a missing page"
	ex, cerr := c.cfg.Capture.Record(scanner.CapturedExchange{
		Host:     probeURL.Hostname(),
		Port:     portOf(&probeURL),
		TLS:      strings.EqualFold(probeURL.Scheme, "https"),
		Method:   "GET",
		Path:     probeURL.RequestURI(),
		Request:  raw,
		Response: res.Raw,
		Started:  time.Now().Add(-res.Duration),
		Duration: res.Duration,
		Protocol: core.ProtocolHTTP1,
		ServerIP: res.Outcome.ServerIP,
		Source:   core.SourceCrawl,
		Notes:    &note,
	})
	if cerr != nil || ex == nil || ex.Response == nil {
		return nil
	}
	status := 0
	if ex.Status != nil {
		status = int(*ex.Status)
	}
	// A fetch like any other: counted against the request budget, announced through OnFetch, and in
	// the report, so every exchange the crawl created is one of its fetches.
	rep.Fetched++
	rep.NotFoundProbes++
	fetch := Fetch{
		URL: probeURL.String(), Method: "GET", Status: status, ExchangeID: ex.ID,
		Depth: item.depth, FoundAt: item.url.String(), LinkText: "not-found probe", NotFoundProbe: true,
	}
	if c.cfg.OnFetch != nil {
		c.cfg.OnFetch(fetch)
	}
	rep.Fetches = append(rep.Fetches, fetch)
	if status < 200 || status > 299 {
		// A 404 or 410 is an honest not-found; a redirect or an error for a missing name says nothing
		// about what a 200 page here means. Either way no page in this directory is judged a soft 404.
		return &notFoundShape{hard: true}
	}
	msg, gerr := c.cfg.Capture.Store.Get(*ex.Response)
	if gerr != nil {
		return nil
	}
	p := parsePage(msg.Body(), &probeURL, c.limits, false)
	return &notFoundShape{fingerprint: p.fingerprint}
}
