package crawler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---- Config.OnFetch: the crawl→audit bridge (burpsy-react-ui-7suo) -----------------------------
//
// Burp's bridge is per-URL and event-driven — a newly-reached URL goes to the audit bus as it is
// reached — so audit work overlaps the crawl. burpsy's caller audited the finished Report.Fetches
// after Run returned, which meant "crawl and audit" was a crawl *then* an audit: no finding could
// appear before the last page was fetched, and a crawl stopped early produced none at all.
//
// These pin what the callback promises the caller, because the caller's whole design rests on it:
// one call per completed fetch, every branch, during the run.

// fetchRecorder collects what OnFetch was told. Mutex-guarded rather than a plain slice because the
// contract only says "on the crawl goroutine", and a test that assumed a specific goroutine would
// start passing for the wrong reason the day the crawl fetches concurrently.
type fetchRecorder struct {
	mu       sync.Mutex
	seen     []Fetch
	afterRun bool
	late     int
}

func (r *fetchRecorder) record(f Fetch) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.afterRun {
		r.late++
	}
	r.seen = append(r.seen, f)
}

// closeRun marks the point Run returned, so a callback arriving later is counted as late.
func (r *fetchRecorder) closeRun() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.afterRun = true
}

func (r *fetchRecorder) fetches() []Fetch {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Fetch(nil), r.seen...)
}

// The core claim: every fetch is announced, exactly once, and the announcement matches Report.Fetches
// id for id and in order. Anything less and the audit half covers less than the crawl fetched with
// nothing on screen saying which.
func TestOnFetchAnnouncesEveryFetchOnceInReportOrder(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":      `<html><body><a href="/alpha">Alpha</a><a href="/beta">Beta</a></body></html>`,
		"/alpha": `<html><body><a href="/gamma">Gamma</a></body></html>`,
		"/beta":  `<html><body><p>beta</p></body></html>`,
		"/gamma": `<html><body><p>gamma</p></body></html>`,
	})
	h := newHarness()
	rec := &fetchRecorder{}
	cfg := h.config(tg.URL + "/")
	cfg.OnFetch = rec.record
	rep := run(t, cfg)
	rec.closeRun()

	seen := rec.fetches()
	if len(seen) != len(rep.Fetches) {
		t.Fatalf("OnFetch fired %d time(s) for %d fetch(es) in the report; a bridge that announces "+
			"fewer fetches than the crawl made audits less than the crawl covered", len(seen), len(rep.Fetches))
	}
	if len(seen) != rep.Fetched {
		t.Errorf("OnFetch fired %d time(s), Report.Fetched = %d; the callback and the crawl's own "+
			"count must be the same number or the audit's task total is a different scan's size",
			len(seen), rep.Fetched)
	}
	for i := range seen {
		if seen[i].ExchangeID != rep.Fetches[i].ExchangeID {
			t.Errorf("announcement %d is exchange %d, Report.Fetches[%d] is %d; the callback must "+
				"carry the id the report does, or a consumer audits an exchange the report never names",
				i, seen[i].ExchangeID, i, rep.Fetches[i].ExchangeID)
		}
		if seen[i].URL != rep.Fetches[i].URL {
			t.Errorf("announcement %d is %q, Report.Fetches[%d] is %q", i, seen[i].URL, i, rep.Fetches[i].URL)
		}
	}
}

// The whole deliverable: the announcement happens *during* the crawl. A callback that only arrived
// once Run returned would be the end-of-crawl batch wearing a different shape.
func TestOnFetchFiresWhileTheCrawlIsStillRunning(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":      `<html><body><a href="/alpha">Alpha</a></body></html>`,
		"/alpha": `<html><body><a href="/beta">Beta</a></body></html>`,
		"/beta":  `<html><body><p>beta</p></body></html>`,
	})
	h := newHarness()
	rec := &fetchRecorder{}

	// Announced before the *last* page was even requested, which is the property an incremental audit
	// needs: the seed's announcement must be observable while later pages are still being fetched.
	seenBeforeBeta := -1
	cfg := h.config(tg.URL + "/")
	cfg.OnFetch = func(f Fetch) {
		rec.record(f)
		if strings.HasSuffix(f.URL, "/alpha") {
			seenBeforeBeta = len(rec.fetches())
		}
	}
	rep := run(t, cfg)
	rec.closeRun()

	if rec.late != 0 {
		t.Errorf("%d announcement(s) arrived after Run returned; the point of the callback is that "+
			"audit work starts mid-crawl, and one that only fires at the end delivers none of it", rec.late)
	}
	if seenBeforeBeta < 2 {
		t.Fatalf("/alpha was announced after %d fetch(es); the seed and /alpha must both be announced "+
			"before /beta is fetched, or nothing is overlapping", seenBeforeBeta)
	}
	if len(rep.Fetches) < 3 {
		t.Fatalf("the crawl fetched %d page(s), want 3 — the timing claim above is only meaningful "+
			"over a crawl with pages left to fetch", len(rep.Fetches))
	}
}

// A redirect, a non-HTML body and a 404 each reach a different return branch of perform, and all of
// them are still fetches the audit must be told about. The callback fires where the record is built
// rather than beside each of the ten Report.Fetches appends precisely so a branch cannot be forgotten.
func TestOnFetchCoversTheBranchesThatAreNotAnOrdinaryHtmlPage(t *testing.T) {
	// Its own server rather than newTarget's map, because these branches are about headers and status
	// codes rather than about page contents.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>` +
				`<a href="/redirect">Redirect</a>` +
				`<a href="/data.json">Data</a>` +
				`<a href="/missing">Missing</a>` +
				`</body></html>`))
		case "/redirect":
			w.Header().Set("Location", "/landing")
			w.WriteHeader(http.StatusFound)
		case "/landing":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><p>landed</p></body></html>`))
		case "/data.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<html><body>not found</body></html>`))
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	rec := &fetchRecorder{}
	cfg := h.config(srv.URL + "/")
	cfg.OnFetch = rec.record
	rep := run(t, cfg)

	seen := rec.fetches()
	if len(seen) != len(rep.Fetches) {
		t.Fatalf("OnFetch fired %d time(s) for %d report fetch(es); a branch that appends to "+
			"Report.Fetches without announcing is exactly the drift one call site exists to prevent",
			len(seen), len(rep.Fetches))
	}
	for _, want := range []string{"/redirect", "/data.json", "/missing", "/landing"} {
		found := false
		for _, f := range seen {
			if strings.HasSuffix(f.URL, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s was fetched but never announced; a redirect, a non-HTML body and a 404 are "+
				"all auditable exchanges and none of them takes the ordinary HTML return", want)
		}
	}
}

// A crawl with no callback is the crawl that existed before this field, byte for byte. A nil check
// the caller has to make would be a nil check the caller can forget.
func TestANilOnFetchIsTheCrawlThatExistedBefore(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":      `<html><body><a href="/alpha">Alpha</a></body></html>`,
		"/alpha": `<html><body><p>alpha</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	if cfg.OnFetch != nil {
		t.Fatal("the harness config sets OnFetch; this test is about the zero value")
	}
	rep := run(t, cfg)
	if rep.Fetched < 2 {
		t.Errorf("Fetched = %d, want at least 2; a nil callback must change nothing about the crawl", rep.Fetched)
	}
}

// The snapshot's documented shape: the fields decided before the announcement are final, and the
// ones decided after it are zero. A consumer reading Fingerprint off the callback would silently get
// "" for every page and have no way to know it was reading too early.
func TestTheAnnouncedFetchIsACaptureTimeSnapshot(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":      `<html><body><a href="/alpha">Alpha</a></body></html>`,
		"/alpha": `<html><body><p>alpha</p></body></html>`,
	})
	h := newHarness()
	rec := &fetchRecorder{}
	cfg := h.config(tg.URL + "/")
	cfg.OnFetch = rec.record
	rep := run(t, cfg)

	for _, f := range rec.fetches() {
		if f.ExchangeID == 0 && f.URL == "" {
			t.Error("an announcement carried neither an id nor a URL; the id is the only thing the audit needs")
		}
		if f.Fingerprint != "" {
			t.Errorf("%s was announced with Fingerprint %q; the doc promises it is decided after the "+
				"announcement, and a consumer told otherwise would branch on a value that is never set",
				f.URL, f.Fingerprint)
		}
	}
	// The completed record does carry it, which is what makes the two distinguishable rather than
	// the feature simply being absent.
	alpha := fetchByPath(t, rep.Fetches, "/alpha")
	if alpha.Fingerprint == "" {
		t.Error("Report.Fetches carries no fingerprint either; then the snapshot claim above is vacuous")
	}
}
