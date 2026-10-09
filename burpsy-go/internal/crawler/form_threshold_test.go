package crawler

// Tests for the form-submission optimization threshold (burpsy-react-ui-ddln).
//
// The case the bound exists for is the one the per-form submission CAP cannot see: a form whose
// submissions each reach a DIFFERENT destination. A pagination or search control whose field value
// walks forward forever passes max_submissions_per_form with its count untouched, because no two
// submissions are the same request — but the crawl learns nothing after the first few, and without
// this bound it walks the destination space forever. Burp ships the setting as
// crawler.crawl_optimization.form_submission_optimization_threshold, whose decompiled name is
// minimumFormInputStrategyChainLengthBeforeDiscontinuationStrategyApplied.
//
// The load-bearing property is therefore that the bound counts DESTINATIONS rather than
// submissions: a test that submits the same form to one destination many times and expects the
// threshold to fire would pass for the wrong reason, because that shape is already bounded by the
// per-form cap and the crawler's own request dedupe.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// pagingFormTarget serves N linked pages, each carrying the SAME form whose field value is the
// page's own number, so every submission reaches a distinct destination. Nothing else bounds it:
// the POST bodies differ, so neither the request fingerprint nor the per-form cap fires.
func pagingFormTarget(t *testing.T, pages int) (*httptest.Server, *int) {
	t.Helper()
	submissions := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		submissions++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	})
	page := func(w http.ResponseWriter, r *http.Request) {
		current := 1
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/page/")); err == nil {
			current = n
		}
		next := "/page/" + itoa(current+1)
		w.Header().Set("Content-Type", "text/html")
		// The visible text differs per page so the location fingerprint does not fold them into one,
		// exactly as cappedFormTarget's own comment explains.
		_, _ = w.Write([]byte("<html><body><p>page " + strconv.Itoa(current) + "</p>" +
			"<form action=\"/search\" method=\"post\"><input name=\"page\" value=\"" + strconv.Itoa(current) + "\"><button>Go</button></form>" +
			"<a href=\"" + next + "\">next</a></body></html>"))
	}
	mux.HandleFunc("/", page)
	for i := 2; i <= pages; i++ {
		mux.HandleFunc("/page/"+itoa(i), page)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &submissions
}

// The acceptance criterion: a form whose destinations reach the threshold is REFUSED with a named
// skip reason, and the number of submissions holds at the threshold rather than growing with the
// page count.
func TestAFormIsRefusedOnceItsDistinctDestinationsReachTheThreshold(t *testing.T) {
	const threshold = 2
	srv, submissions := pagingFormTarget(t, 8)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.FormSubmissionOptimizationThreshold = threshold
	rep := run(t, cfg)

	if got := *submissions; got != threshold {
		t.Errorf("the form was submitted %d times, want the threshold of %d: every submission reached a "+
			"NEW destination, so max_submissions_per_form never fired and only this bound stops the "+
			"crawl walking the form's destination space forever", got, threshold)
	}
	if !skippedWith(rep, SkipFormDestinationExhausted) {
		t.Errorf("a form past the threshold recorded no skip; the operator reads N forms submitted "+
			"and cannot tell why it was not more. Counts: %s", reasonCounts(rep))
	}
	// The cap is a DIFFERENT bound and must not be what fired: it was never configured, and reading
	// the threshold's refusal as the cap's would name a limit that is not the one in effect.
	if skippedWith(rep, SkipFormSubmissionCap) {
		t.Error("the per-form submission cap fired although none was configured; the two form " +
			"bounds are being conflated, which reports the threshold under a limit that never applied")
	}
}

// The bound is on DISTINCT DESTINATIONS, not on submissions: re-submitting a destination already
// counted must not spend the budget again. Without this the threshold and the per-form cap would
// double-count one submission and the threshold would fire before its number says.
func TestTheThresholdCountsDistinctDestinationsNotSubmissions(t *testing.T) {
	const threshold = 3
	submissions := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		submissions++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	})
	// Six pages, each carrying the same form with the SAME field value, so every submission reaches
	// one destination. The crawl's own request dedupe is what stops the repeat — and the threshold
	// must not claim credit for a bound it did not apply.
	page := func(w http.ResponseWriter, r *http.Request) {
		current := 1
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/page/")); err == nil {
			current = n
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>page " + strconv.Itoa(current) + "</p>" +
			"<form action=\"/search\" method=\"post\"><input name=\"q\" value=\"constant\"><button>Go</button></form>" +
			"<a href=\"/page/" + strconv.Itoa(current+1) + "\">next</a></body></html>"))
	}
	mux.HandleFunc("/", page)
	for i := 2; i <= 6; i++ {
		mux.HandleFunc("/page/"+itoa(i), page)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.FormSubmissionOptimizationThreshold = threshold
	rep := run(t, cfg)

	if skippedWith(rep, SkipFormDestinationExhausted) {
		t.Errorf("the threshold refused a form that had reached only one distinct destination: it is "+
			"counting submissions rather than destinations, so it fires at a fraction of its number. "+
			"Submissions seen: %d. Counts: %s", submissions, reasonCounts(rep))
	}
}

// Zero means OFF, and is not quietly replaced by Burp's own default. An operator who turned form
// submission on has not asked for their form space to be bounded.
func TestTheThresholdIsOffByDefaultRatherThanInheritingBurpsDefault(t *testing.T) {
	srv, _ := pagingFormTarget(t, 5)

	cfg := newHarness().config(srv.URL + "/")
	cfg.SubmitForms = true
	// No threshold set.
	rep := run(t, cfg)

	if got := (Config{}).FormSubmissionOptimizationThreshold; got != 0 {
		t.Errorf("Config{}.FormSubmissionOptimizationThreshold = %d, want 0 (off); a non-zero "+
			"default would be a behaviour change dressed as one", got)
	}
	if skippedWith(rep, SkipFormDestinationExhausted) {
		t.Error("a skip fired for the optimization threshold with no threshold configured")
	}
}

// The setting is carried by a named configuration, so the Burp key must land on the field the
// crawl reads — the same claim TestTheFormSubmissionBurpKeysLandInAppliedKeys makes for the cap,
// and the one that would have caught the original defect (imported and reported, never enforced).
func TestTheOptimizationThresholdLandsInAppliedKeys(t *testing.T) {
	const config = `{"crawler":{"crawl_optimization":{"form_submission_optimization_threshold": 7}}}`

	cfg, err := ParseBurpCrawlConfig([]byte(config))
	if err != nil {
		t.Fatalf("a configuration naming the optimization threshold failed to parse: %v", err)
	}
	if !containsString(cfg.AppliedKeys, "crawl_optimization/form_submission_optimization_threshold") {
		t.Errorf("the key was not reported applied; applied=%v unrepresentable=%v",
			cfg.AppliedKeys, cfg.UnrepresentableKeys)
	}
	if cfg.FormSubmissionOptimizationThreshold != 7 {
		t.Errorf("FormSubmissionOptimizationThreshold = %d, want 7", cfg.FormSubmissionOptimizationThreshold)
	}
}

// Every new reason is fully registered — the four tables an enum member must appear in, where a
// missing entry is a runtime panic rather than a compile error.
func TestSkipFormDestinationExhaustedIsFullyRegistered(t *testing.T) {
	found := false
	for _, s := range SkipAll {
		if s == SkipFormDestinationExhausted {
			found = true
		}
	}
	if !found {
		t.Fatal("SkipFormDestinationExhausted is not in SkipAll")
	}
	if got := SkipFormDestinationExhausted.String(); got != "form-destination-exhausted" {
		t.Errorf("String() = %q, want %q", got, "form-destination-exhausted")
	}
	// Policy, not a limit: the phase is on and the operator's configuration refused, the same class
	// as the cap and form submission being off.
	if got := SkipFormDestinationExhausted.Category(); got != CategoryPolicy {
		t.Errorf("Category() = %v, want CategoryPolicy", got)
	}
	if SkipFormDestinationExhausted.Explanation() == "unknown skip" {
		t.Error("Explanation() fell through to the unknown default")
	}
}
