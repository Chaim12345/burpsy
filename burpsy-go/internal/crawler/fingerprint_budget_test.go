package crawler

import (
	"strings"
	"testing"
)

// The size of the tables the crawl keeps in RAM is reported on every crawl, not only when a bound is
// reached — a consumption nobody can see is a bound nobody can plan around.
func TestFingerprintSetSizeIsReportedUnderTheBound(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":    `<html><body><a href="/one">1</a><a href="/two">2</a></body></html>`,
		"/one": `<html><body>one</body></html>`,
		"/two": `<html><body>two</body></html>`,
	})
	h := newHarness()
	rep := run(t, h.config(tg.URL+"/"))

	if rep.Limits.Fingerprints == 0 {
		t.Fatal("the crawl reports no fingerprints at all, so nothing says how much it is remembering")
	}
	// Every fetch was a queued item, and every queued item is one entry, so the set cannot be smaller
	// than the number of requests sent.
	if rep.Limits.Fingerprints < rep.Fetched {
		t.Errorf("fingerprints=%d for %d fetches; every fetched request must be remembered as sent",
			rep.Limits.Fingerprints, rep.Fetched)
	}
	if rep.Limits.Templates == 0 {
		t.Error("the crawl reports no URL templates, so the other table's size is invisible")
	}
	// Reporting a size is not a stop: an under-bound crawl is still complete.
	if rep.Limits.Hit(StopFingerprintBudget) {
		t.Errorf("a crawl well under the bound recorded %s", StopFingerprintBudget)
	}
	if !rep.Complete() {
		t.Errorf("the crawl reports incomplete: %s", rep.Caveat())
	}
}

// A crawl that runs out of room to remember request identities says so with its own stop reason, and
// cannot be rendered as a complete crawl.
//
// Both tables are covered because both used to be able to grow without a bound of their own: the
// template table outright, and the fingerprint set only derivatively (at MaxFrontier + MaxRequests,
// which moves whenever either of those does and was never reported).
func TestFingerprintBudgetStopsTheCrawlAndSaysSo(t *testing.T) {
	// Three URLs sharing one template, so the template table stays small and the *fingerprint set* is the
	// table that fills. Ids are digits, which urlTemplate collapses to {id}.
	itemPages := map[string]string{
		"/": `<html><body>
			<a href="/items/1">1</a><a href="/items/2">2</a><a href="/items/3">3</a>
			</body></html>`,
		"/items/1": `<html><body>one</body></html>`,
		"/items/2": `<html><body>two</body></html>`,
		"/items/3": `<html><body>three</body></html>`,
	}
	// Distinct path shapes, so the template table is what fills first.
	shapePages := map[string]string{
		"/": `<html><body>
			<a href="/alpha">a</a><a href="/beta">b</a><a href="/gamma">c</a>
			</body></html>`,
		"/alpha": `<html><body>a</body></html>`,
		"/beta":  `<html><body>b</body></html>`,
		"/gamma": `<html><body>c</body></html>`,
	}

	for _, tc := range []struct {
		name  string
		pages map[string]string
		// bound is chosen so the seed and its robots.txt fit and the discovered links do not: the seed
		// itself must never be refused, or the test would be about a crawl that never started.
		bound int
		names string
	}{
		{"the fingerprint set fills", itemPages, 4, "request-fingerprint set"},
		{"the template table fills", shapePages, 2, "URL-template table"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg := newTarget(t, tc.pages)
			h := newHarness()
			cfg := h.config(tg.URL + "/")
			cfg.Limits.MaxFingerprints = tc.bound
			rep := run(t, cfg)

			if !rep.Limits.Hit(StopFingerprintBudget) {
				t.Fatalf("the crawl hit the bound of %d and recorded stops %v; %s is missing",
					tc.bound, rep.Limits.Stops, StopFingerprintBudget)
			}
			// Truncated is derived from the stop list, so recording the stop is what makes the crawl
			// unrenderable as a complete one — there is no separate flag that could disagree.
			if !rep.Limits.Truncated() {
				t.Error("Truncated() is false with a stop recorded")
			}
			if rep.Complete() {
				t.Error("a crawl that stopped at a bound reports itself complete")
			}
			if got := rep.Skips.Count(SkipFingerprintBudget); got == 0 {
				t.Error("no URL was counted as refused for the identity tables being full, so the stop " +
					"names a bound nothing was attributed to")
			}
			if rep.Limits.FingerprintDropped == 0 {
				t.Error("FingerprintDropped is zero, so Unfetched() understates what the crawl did not reach")
			}
			if rep.Limits.Unfetched() < rep.Limits.FingerprintDropped {
				t.Errorf("Unfetched()=%d does not include the %d refused URLs",
					rep.Limits.Unfetched(), rep.Limits.FingerprintDropped)
			}
			caveat := rep.Caveat()
			if caveat == "" {
				t.Fatal("a truncated crawl has no caveat")
			}
			if !strings.Contains(caveat, "identity tables full") {
				t.Errorf("the caveat does not account for the refused URLs: %s", caveat)
			}
			// The refusal names which of the two tables filled, so an operator raising the bound knows what
			// they are raising, and a URL is named rather than only counted.
			var detail, url string
			for _, rec := range rep.Skips.Records {
				if rec.Reason == SkipFingerprintBudget {
					detail, url = rec.Detail, rec.URL
					break
				}
			}
			if !strings.Contains(detail, tc.names) {
				t.Errorf("the refusal detail is %q; it must name the %s", detail, tc.names)
			}
			if url == "" {
				t.Error("the refusal records no URL, so nothing says which page was not fetched")
			}
			// Not laundered through the frontier bound, which is the neighbouring resource limit and would
			// tell the operator to raise the wrong number.
			if rep.Limits.Hit(StopFrontierCapacity) {
				t.Errorf("the crawl also blamed %s; the frontier was nowhere near its bound of %d",
					StopFrontierCapacity, cfg.Limits.MaxFrontier)
			}
		})
	}
}

// The bound refuses admission rather than evicting: a URL the crawl declined is *counted* as
// unfetched, and the crawl never re-fetches something it already sent because a fingerprint went
// missing. See StopFingerprintBudget for the argument.
func TestFingerprintBudgetRefusesRatherThanForgetting(t *testing.T) {
	// Every page links back to the seed, which is the shape that punishes a lossy dedup set: with
	// eviction the crawl would fetch "/" again and again.
	pages := map[string]string{
		"/":    `<html><body><a href="/one">1</a><a href="/two">2</a></body></html>`,
		"/one": `<html><body><a href="/">home</a></body></html>`,
		"/two": `<html><body><a href="/">home</a></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.Limits.MaxFingerprints = 4
	rep := run(t, cfg)

	if n := tg.timesAskedFor("/"); n != 1 {
		t.Fatalf("the seed was fetched %d times; a full identity table must not make the crawl forget "+
			"what it has already sent", n)
	}
	// The refusals are visible as a number, which is the property eviction cannot offer: nothing can
	// count the pages an evicting crawl failed to reach because its budget went on repeats.
	if rep.Limits.FingerprintDropped+rep.Limits.Fingerprints == 0 {
		t.Fatal("neither the table size nor the refusals were reported")
	}
}
