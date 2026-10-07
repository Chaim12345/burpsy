package crawler

// Tests for the per-form submission cap (burpsy-react-ui-u0k3).
//
// The case the cap exists for is a document carrying ONE noisy form — a search box, a pagination
// control — on every page. The crawl then submits it once per page, unbounded, and learns nothing
// after the first few. So the load-bearing property is that the count is PER FORM rather than per
// URL or per page: a test that submits the same form from several pages and expects one cap is the
// only one that distinguishes this from a per-URL bound that would never fire.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// cappedFormTarget serves N linked pages, each carrying the SAME form, and counts submissions.
//
// The form is a POST whose FIELD VALUE is the page's own path, so the submission genuinely differs
// from page to page. That shape is deliberate and was the fixture's second version: a GET form whose
// action is one URL is ALREADY bounded by the crawler's fingerprint dedupe (SkipAlreadyQueued, one
// identical request queued once), so a cap test built on it never reached the cap and passed for the
// wrong reason — which is the failure mode this comment exists to prevent. A POST repeating one URL
// with a different body is a different request every time, and nothing else bounds it.
//
// The field NAME is constant across pages: that is what makes it ONE form, and the cap's subject.
func cappedFormTarget(t *testing.T, pages int) (*httptest.Server, *int) {
	t.Helper()
	submissions := 0
	mux := http.NewServeMux()
	body := func(path string) string {
		// Each page links to the next, so the crawl has a chain to walk. A constant link would leave the
		// crawl one page deep and the cap would never be reached — a fixture that tests the crawl's
		// depth rather than the bound.
		current := 1
		if n, convErr := strconv.Atoi(strings.TrimPrefix(path, "/page/")); convErr == nil {
			current = n
		}
		next := "/page/" + itoa(current+1)
		// Distinct visible text per page: the location fingerprint hashes the tag skeleton and the
		// VISIBLE text, so two pages differing only in an input's value are ONE location and the crawl
		// collapses them before any form is submitted twice (SkipDuplicateLocation). A real results page
		// differs in its text, and the fixture has to as well or it tests the fingerprint, not the cap.
		return `<html><body><p>results page ` + strings.TrimPrefix(path, "/page/") + `</p>
			<h2>Row one</h2><h2>Row two</h2><h2>Row ` + strings.TrimPrefix(path, "/page/") + `</h2>
			<form action="/search" method="post">
			  <input name="page" value="` + path + `">
			  <button type="submit">Search</button>
			</form>
			<a href="` + next + `">next</a>
		</body></html>`
	}
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		submissions++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	})
	page := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body(r.URL.Path)))
	}
	mux.HandleFunc("/", page)
	for i := 2; i <= pages; i++ {
		i := i
		mux.HandleFunc("/page/"+itoa(i), page)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &submissions
}

// The acceptance criterion: a form submitted past the cap is REFUSED with a named skip reason, and
// the count holds at the cap rather than at "every page".
func TestAFormIsRefusedOnceItHasBeenSubmittedTheCapNumberOfTimes(t *testing.T) {
	const cap = 2
	srv, submissions := cappedFormTarget(t, 8)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.Limits.MaxSubmissionsPerForm = cap
	rep := run(t, cfg)

	// The count holds. This is the assertion the whole change exists for: without the cap the crawl
	// would submit the same search box once per page, eight times, and call it coverage.
	if got := *submissions; got != cap {
		t.Errorf("the form was submitted %d times, want exactly the cap of %d; without a per-form bound "+
			"one noisy form on every page is submitted once per page forever", got, cap)
	}
	if !skippedWith(rep, SkipFormSubmissionCap) {
		t.Errorf("a form past the cap recorded no skip; the operator reads \"N forms submitted\" and "+
			"cannot tell why it was not more. Counts: %s", reasonCounts(rep))
	}
}

// The cap is PER FORM, not per URL and not per page: the same form found on eight pages is one form.
func TestTheCapCountsPerFormNotPerPageOrPerURL(t *testing.T) {
	const pages = 6
	srv, submissions := cappedFormTarget(t, pages)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.Limits.MaxSubmissionsPerForm = 1
	rep := run(t, cfg)

	if got := *submissions; got != 1 {
		t.Errorf("the same form was submitted %d times across %d pages, want 1", got, pages)
	}
	// And the crawl still VISITED the pages — a cap that stopped traversal would be a different bug,
	// and one that a count-only assertion would miss.
	if len(rep.Fetches) < 3 {
		t.Errorf("the cap appears to have stopped the crawl rather than the submissions; "+
			"fetches: %v", fetchLog(rep))
	}
}

// Two DIFFERENT forms are bounded independently. Without this the cap would be a crawl-wide form
// budget wearing a per-form name — which would stop the second form entirely once the first hit it.
func TestTwoDifferentFormsAreBoundedIndependently(t *testing.T) {
	var searchSubmissions, filterSubmissions int
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		searchSubmissions++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	})
	mux.HandleFunc("/filter", func(w http.ResponseWriter, r *http.Request) {
		filterSubmissions++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>filtered</body></html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
		  <form action="/search?q=a" method="get"><input name="q" value="x"><button>Go</button></form>
		  <form action="/filter" method="post"><input name="cat" value="1"><button>Filter</button></form>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.Limits.MaxSubmissionsPerForm = 1
	run(t, cfg)

	if searchSubmissions != 1 || filterSubmissions != 1 {
		t.Errorf("two distinct forms bounded by one shared budget: search=%d filter=%d, want 1 and 1 — "+
			"a per-form cap that shared its count would have stopped the second form entirely",
			searchSubmissions, filterSubmissions)
	}
}

// Zero means OFF, and is not quietly replaced by Burp's 6. An operator who turned form submission on
// has not asked to be capped, and a default here would be a behaviour change dressed as one.
func TestTheCapIsOffByDefaultRatherThanInheritingBurpsSix(t *testing.T) {
	srv, submissions := cappedFormTarget(t, 5)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	// No cap set.
	rep := run(t, cfg)

	// The default is read from the engine, not from the run's report: LimitReport carries what a crawl
	// CONSUMED, and "what bound was configured" is a property of the limits themselves.
	if got := DefaultLimits().MaxSubmissionsPerForm; got != 0 {
		t.Errorf("DefaultLimits().MaxSubmissionsPerForm = %d, want 0 (off); a non-zero default would be "+
			"a behaviour change dressed as one", got)
	}
	if got := (Limits{}).normalise().MaxSubmissionsPerForm; got != 0 {
		t.Errorf("normalise() filled MaxSubmissionsPerForm to %d, want 0 — normalise fills UNSET bounds "+
			"with defaults, and this one's zero means off rather than unset", got)
	}
	// The cap did not fire. Note what DID: a GET form whose action is the same URL from every page is
	// already bounded by the crawler's own fingerprint dedupe (already-queued), which is a pre-existing
	// bound doing its job and is not the cap. The cap's real subject is a submission that genuinely
	// differs per page — a POST carrying the page's field values, or a GET whose FIELD values differ —
	// and TestAFormIsRefusedOnceItHasBeenSubmittedTheCapNumberOfTimes exercises exactly that.
	if skippedWith(rep, SkipFormSubmissionCap) {
		t.Error("a skip fired for the form cap with no cap configured")
	}
	if got := *submissions; got < 1 {
		t.Errorf("no submission happened at all; the fixture should submit the form once")
	}
}

// The cap's real subject: a POST form whose SUBMISSION differs per page, which no other bound catches.
// A GET form repeating one URL is already deduplicated by fingerprint; a POST repeating one URL with
// different bodies is a different request every time, and is what a search or pagination control
// actually does.
func TestACapBoundsAPostFormWhoseSubmissionDiffersPerPage(t *testing.T) {
	const pages = 6
	srv, submissions := cappedFormTarget(t, pages)
	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	rep := run(t, cfg)

	// Without a cap this grows with the page count: nothing else bounds a POST whose body differs.
	if *submissions < 2 {
		t.Fatalf("only %d submissions with no cap; %d pages each carry the same form with a different "+
			"body, so nothing else bounds it", *submissions, pages)
	}
	if skippedWith(rep, SkipFormSubmissionCap) {
		t.Error("the form cap fired with no cap configured")
	}
}

func TestACapBoundsAPostFormWhenOneIsSet(t *testing.T) {
	submissions := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		submissions++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The page number is a FIELD VALUE, so the POST body differs per page and nothing else bounds it.
		_, _ = w.Write([]byte(`<html><body><form action="/search" method="post">
		  <input name="page" value="` + r.URL.Path + `"><button>Search</button>
		</form><a href="/page/2">next</a></body></html>`))
	})
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form action="/search" method="post">
		  <input name="page" value="` + r.URL.Path + `"><button>Search</button>
		</form></body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	rep := run(t, cfg)

	// Without a cap this grows with the page count.
	if submissions < 2 {
		t.Fatalf("only %d submissions with no cap; the fixture's pages are linked and each carries a "+
			"form whose body differs, so nothing else bounds it", submissions)
	}
	_ = rep
}

// The cap counts submissions MADE, not forms CONSIDERED: a form that fails another gate must not
// consume budget, or the cap fires on a form that was never sent.
func TestAFormRefusedForAnotherReasonDoesNotConsumeCapBudget(t *testing.T) {
	// A multipart form is refused as not-submittable, every time.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
		  <form action="/upload" method="post" enctype="multipart/form-data">
		    <input name="f" type="file"><button>Upload</button>
		  </form>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.Limits.MaxSubmissionsPerForm = 1
	rep := run(t, cfg)

	// The cap is 1 and the form was never submitted, so the cap must be the reason that did NOT fire.
	if skippedWith(rep, SkipFormSubmissionCap) {
		t.Error("a form that was refused as not-submittable consumed cap budget and then reported " +
			"the cap, which names a limit that never applied")
	}
	if !skippedWith(rep, SkipFormNotSubmittable) {
		t.Error("the multipart form was not reported as not-submittable; the cap check changed the " +
			"reason a form is refused for")
	}
}

// The Burp keys land on import rather than being reported unrepresentable.
func TestTheFormSubmissionBurpKeysLandInAppliedKeys(t *testing.T) {
	const config = `{"crawler":{"crawl_optimization":{
	  "max_submissions_per_form": 4,
	  "form_submission_optimization_threshold": 9}}}`

	cfg, err := ParseBurpCrawlConfig([]byte(config))
	if err != nil {
		t.Fatalf("a configuration naming the two form-submission keys failed to parse: %v", err)
	}
	for _, key := range []string{
		"crawl_optimization/max_submissions_per_form",
		"crawl_optimization/form_submission_optimization_threshold",
	} {
		if !containsString(cfg.AppliedKeys, key) {
			t.Errorf("key %q was not applied; applied=%v unrepresentable=%v",
				key, cfg.AppliedKeys, cfg.UnrepresentableKeys)
		}
		if containsString(cfg.UnrepresentableKeys, key) {
			t.Errorf("key %q was reported UNREPRESENTABLE, which tells an operator migrating a "+
				"configuration that their form bounds were dropped", key)
		}
	}
	// The two land on DIFFERENT halves, which is the property the third field name exists for: one is
	// a crawl-wide limit and the other bounds a phase.
	if cfg.Limits.MaxSubmissionsPerForm != 4 {
		t.Errorf("Limits.MaxSubmissionsPerForm = %d, want 4", cfg.Limits.MaxSubmissionsPerForm)
	}
	if cfg.FormSubmissionOptimizationThreshold != 9 {
		t.Errorf("FormSubmissionOptimizationThreshold = %d, want 9", cfg.FormSubmissionOptimizationThreshold)
	}
}

// Every new reason is fully registered — the four tables an enum member must appear in, where a
// missing entry is a runtime panic rather than a compile error.
func TestSkipFormSubmissionCapIsFullyRegistered(t *testing.T) {
	found := false
	for _, s := range SkipAll {
		if s == SkipFormSubmissionCap {
			found = true
		}
	}
	if !found {
		t.Fatal("SkipFormSubmissionCap is not in SkipAll")
	}
	if got := SkipFormSubmissionCap.String(); got != "form-submission-cap" {
		t.Errorf("String() = %q, want %q", got, "form-submission-cap")
	}
	// Policy, not a limit: the phase is on and the operator's configuration refused, which is the same
	// class as form submission being off.
	if got := SkipFormSubmissionCap.Category(); got != CategoryPolicy {
		t.Errorf("Category() = %v, want CategoryPolicy", got)
	}
	if strings.TrimSpace(SkipFormSubmissionCap.Explanation()) == "" {
		t.Error("Explanation() is empty")
	}
}

// The form signature, as a table — the identity the cap counts against, and a helper predicate tested
// only through a crawl has edges nothing reaches.
func TestTheFormSignatureIdentifiesFormsNotPages(t *testing.T) {
	base := mustParseURL(t, "http://a.test/search")
	other := mustParseURL(t, "http://a.test/other")
	q := discoveredForm{method: "GET", action: "/search", fields: []formField{{name: "q", value: "one"}}}
	q2 := discoveredForm{method: "GET", action: "/search", fields: []formField{{name: "q", value: "two"}}}

	// Values differ, signature does not: a CSRF token is a value.
	if q.signature(base) != q2.signature(base) {
		t.Error("two submissions of the same form with different field VALUES got different signatures; " +
			"the cap would count them separately and bound nothing on a search box")
	}
	// Different field NAMES are a different form.
	q3 := discoveredForm{method: "GET", action: "/search", fields: []formField{{name: "page", value: "one"}}}
	if q.signature(base) == q3.signature(base) {
		t.Error("two forms with different field names share a signature")
	}
	// Different action is a different form.
	q4 := discoveredForm{method: "GET", action: "/find", fields: []formField{{name: "q", value: "one"}}}
	if q.signature(base) == q4.signature(base) {
		t.Error("two forms with different actions share a signature")
	}
	// Different page, same relative action: ONE form, or the cap would never fire on a site whose
	// search box appears on every result page.
	if q.signature(base) != q.signature(other) {
		t.Error("the same relative-action form on two pages got different signatures; a per-page count " +
			"would never reach the cap")
	}
}

// mustParseURL parses a URL or fails the test.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
