package crawler

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ---- unit: the band itself -----------------------------------------------------------------------

// The first claim is about the RELAXED key, not the raw target: two URLs are the same link for
// this band when they agree on everything except the query values. If the key kept the values, the
// band would be unreachable — nothing would ever reduce to anything.
func TestARelaxedLinkKeyDropsTheQueryValuesAndNothingElse(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"no query", "http://h/a", "http://h/a"},
		{"one value dropped", "http://h/a?id=7", "http://h/a?id"},
		{"two values dropped", "http://h/a?id=7&b=2", "http://h/a?b&id"},
		{"parameter order is not a difference", "http://h/a?b=2&id=7", "http://h/a?b&id"},
		{"an empty value is still the parameter", "http://h/a?id=", "http://h/a?id"},
		{"a differing value is the SAME key", "http://h/a?id=8", "http://h/a?id"},
		// The three refusals. Each of these is a different LINK, and a band that loosened any of
		// them would be the false merge discover.go's header calls the worst failure this package
		// can have.
		{"a differing path is a different link", "http://h/b?id=7", "http://h/b?id"},
		{"a differing parameter name is a different link", "http://h/a?j=7", "http://h/a?j"},
		{"a differing port is a different link", "http://h:81/a?id=7", "http://h:81/a?id"},
	} {
		if got := relaxedLinkKey(tc.raw); got != tc.want {
			t.Errorf("%s: relaxedLinkKey(%q) = %q, want %q", tc.name, tc.raw, got, tc.want)
		}
	}
	// A query that will not parse is kept whole rather than dropped: dropping it would make two
	// differently-mangled queries compare equal, and a mangled query IS a difference.
	if got := relaxedLinkKey("http://h/a?%zz=1"); got != "http://h/a?%zz=1" {
		t.Errorf("an unparseable query must be kept whole, got %q", got)
	}
}

// The boundary, and the refusal that is the whole point of the band. `changed` is the number of the
// candidate's raw targets absent from the known location's — the number of query values that moved.
//
// At the edge: exactly `band` folds, one more does not. A band that was off by one in either
// direction is either wasting the requests the band exists to save, or folding a page whose links
// moved further than the tolerance allows.
func TestTheBandFoldsAtItsEdgeAndNoFurther(t *testing.T) {
	// One link per possible value-move, so the "one past the edge" case always has a candidate to
	// build. The fixture is SIZED to the band rather than assuming its width, so a band changed
	// later fails this test with a message instead of panicking the suite on a slice index.
	const band = locationToleranceBand
	known := make([]string, 0, band+2)
	for i := range band + 2 {
		known = append(known, "http://h/"+string(rune('a'+i))+"?id=1")
	}
	entry := locationEntry{at: "http://h/known", targets: known, keys: relaxedLinkKeys(known)}

	// One value moved, and two: inside the band. The candidate's TARGETS differ, so the fold is
	// decided by the count and not by an accidental exact match.
	for moved := 1; moved <= band; moved++ {
		candidate := append([]string(nil), known...)
		for i := 0; i < moved; i++ {
			candidate[i] = "http://h/" + string(rune('a'+i)) + "?id=99"
		}
		sortStrings(candidate)
		keys := relaxedLinkKeys(candidate)
		if !withinTolerance(candidate, keys, entry, band) {
			t.Fatalf("%d value(s) moved is within the band of %d, so it must fold", moved, band)
		}
	}

	// One past the edge.
	moved := band + 1
	candidate := append([]string(nil), known...)
	for i := 0; i < moved; i++ {
		candidate[i] = "http://h/" + string(rune('a'+i)) + "?id=99"
	}
	sortStrings(candidate)
	if withinTolerance(candidate, relaxedLinkKeys(candidate), entry, band) {
		t.Fatalf("%d values moved is past the band of %d, so it must NOT fold", moved, band)
	}

	// A band of 0 is the pre-9x67 behaviour: nothing folds, because any moved value exceeds it.
	if withinTolerance(candidate, relaxedLinkKeys(candidate), entry, 0) {
		t.Error("a band of 0 must fold nothing; that is the exact-hash behaviour this file relaxes")
	}
}

// The width itself is a DECISION, and a decision that is not pinned gets widened by whoever is
// chasing a coverage number. The bead names 2 from Burp's shipped default; this pins it, so a
// change to the constant has to be a deliberate edit to this line and a re-derivation of the
// evidence in location_band.go, rather than something the suite waves through.
//
// Nothing else in the file can catch it: every fixture here moves at most two values, so a band of
// 3 would satisfy all of them and report a crawl the band no longer describes.
func TestTheBandWidthIsTheBeadsNumber(t *testing.T) {
	if locationToleranceBand != 2 {
		t.Fatalf("locationToleranceBand = %d, want 2 (burp.Zmqs.NORMAL's shipped "+
			"totalUnmatchedActionDescriptorTolerance and unmatchedAnchorTolerance, "+
			"deobf_merged/burp/Zmqs.java:243)", locationToleranceBand)
	}
}

// The refusal, in isolation from any count: a page whose links point SOMEWHERE ELSE is never folded,
// however wide the band is. This is the assertion that keeps discover.go's documented false-split
// bias from being quietly reversed into a false merge.
func TestABandOfAnyWidthNeverFoldsADifferentLinkPath(t *testing.T) {
	known := []string{"http://h/users/1/edit", "http://h/users/2/edit"}
	entry := locationEntry{at: "http://h/users/1", targets: known, keys: relaxedLinkKeys(known)}
	// A candidate linking to a different user entirely. Every one of its values moved, so only the
	// key comparison can refuse it.
	candidate := []string{"http://h/users/9/edit", "http://h/users/8/edit"}
	sortStrings(candidate)
	for _, band := range []int{2, 10, 1_000} {
		if withinTolerance(candidate, relaxedLinkKeys(candidate), entry, band) {
			t.Fatalf("a band of %d folded a page whose links point at different paths; that merges "+
				"detail pages and is the one thing the band must never do", band)
		}
	}
	// And the same page twice is still one location, which is the claim the band is not breaking.
	same := []string{"http://h/users/1/edit", "http://h/users/2/edit"}
	if !withinTolerance(same, relaxedLinkKeys(same), entry, locationToleranceBand) {
		t.Error("an unchanged link set must stay foldable; the band relaxes values, not identity")
	}
}

// A page that gained or lost a link is a new location, not a rotated one. Counted against a band
// wide enough to swallow the difference, because the length check is what refuses it and it must
// refuse for the right reason.
func TestTheBandNeverFoldsAPageThatGainedOrLostALink(t *testing.T) {
	known := []string{"http://h/a", "http://h/b"}
	entry := locationEntry{at: "http://h/known", targets: known, keys: relaxedLinkKeys(known)}
	for _, tc := range []struct {
		name      string
		candidate []string
	}{
		{"gained one", []string{"http://h/a", "http://h/b", "http://h/c"}},
		{"lost one", []string{"http://h/a"}},
	} {
		if withinTolerance(tc.candidate, relaxedLinkKeys(tc.candidate), entry, 1_000) {
			t.Errorf("a page that %s a link must be a new location", tc.name)
		}
	}
}

// ---- unit: the admission path ---------------------------------------------------------------------

// bandCrawler is a Crawler with only the two structures recordStructuredLocation touches, so these
// tests exercise the admission decision itself and not a whole crawl's incidental ordering.
func bandCrawler() *Crawler {
	return &Crawler{
		locations:      make(map[string]locationEntry),
		locationShapes: make(map[string][]string),
		skips:          newSkipLedger(len(SkipAll)),
	}
}

func bandPage(t *testing.T, body string) pageStructure {
	t.Helper()
	return parsePage([]byte(body), mustURL(t, "http://h/view"), DefaultLimits(), false)
}

// TestAFoldedPageIsADuplicateAndIsCountedAsAFold pins the two claims the report makes. A fold is a
// duplicate — the caller must not walk the links again — and it is a duplicate the operator can
// distinguish, because the location count it contributes rests on a tolerance rather than on
// identical bytes.
func TestAFoldedPageIsADuplicateAndIsCountedAsAFold(t *testing.T) {
	c := bandCrawler()
	var rep Report
	first := bandPage(t, `<html><body><p>view</p><a href="/a?id=1">A</a><a href="/b?id=1">B</a></body></html>`)
	second := bandPage(t, `<html><body><p>view</p><a href="/a?id=2">A</a><a href="/b?id=1">B</a></body></html>`)

	// The ledger is snapshotted into the report by Run at the end of a crawl. These call
	// recordStructuredLocation directly, so the same snapshot is taken here — reading rep.Skips
	// without it would count nothing, and the assertions below would pass for the wrong reason.
	snapshotSkips := func() { rep.Skips = c.skips.Snapshot() }

	var f0, f1 Fetch
	if !c.recordStructuredLocation(first, "http://h/view?id=1", &f0, &rep) {
		t.Fatal("the first page must be admitted as a new location")
	}
	if c.recordStructuredLocation(second, "http://h/view?id=2", &f1, &rep) {
		t.Fatal("a page one value away from a known location must NOT be admitted as new")
	}
	if f1.DuplicateOf != "http://h/view?id=1" {
		t.Errorf("the fold must name the location it folded into, got %q", f1.DuplicateOf)
	}
	snapshotSkips()
	if rep.LocationFolds != 1 {
		t.Errorf("the fold must be visible on the report as one fold, got %d", rep.LocationFolds)
	}
	if rep.DuplicateLocations != 1 {
		t.Errorf("a fold is a duplicate for the counter that counts them, got %d", rep.DuplicateLocations)
	}
	if n := rep.Skips.Count(SkipLocationFolded); n != 1 {
		t.Errorf("a fold must carry its OWN skip reason rather than an exact duplicate's; got %d "+
			"location-folded, and the operator cannot tell a tolerance from an identity this way", n)
	}
	if n := rep.Skips.Count(SkipDuplicateLocation); n != 0 {
		t.Errorf("an exact-duplicate count for a fold misreports the crawl as exact, got %d", n)
	}
	// A fold changes nothing about the LOCATION count: the fold is a duplicate, so it is not
	// admitted and cannot inflate the total.
	if got := len(c.locations); got != 1 {
		t.Errorf("the location map holds %d entries, want 1: a folded page is not a location", got)
	}
}

// An EXACT duplicate must not be reported as a fold. The two counters answer different questions
// and an operator reading a crawl has to be able to trust that `location_folds` is the number of
// locations that rest on a tolerance, with nothing else in it.
func TestAnExactDuplicateIsNotCountedAsAFold(t *testing.T) {
	c := bandCrawler()
	var rep Report
	page := bandPage(t, `<html><body><p>view</p><a href="/a?id=1">A</a></body></html>`)
	var f0, f1 Fetch
	c.recordStructuredLocation(page, "http://h/one", &f0, &rep)
	if c.recordStructuredLocation(page, "http://h/two", &f1, &rep) {
		t.Fatal("the same document at a second URL is a duplicate, not a new location")
	}
	if rep.LocationFolds != 0 {
		t.Errorf("an exact duplicate was counted as a fold (%d); the fold counter must mean the band "+
			"fired, or an operator cannot audit how much of the location count is tolerance", rep.LocationFolds)
	}
	if rep.DuplicateLocations != 1 {
		t.Errorf("the exact duplicate must still be counted, got %d", rep.DuplicateLocations)
	}
}

// A structurally different page is a new location — and the refusal happens at the INDEX, not in
// the comparison. Its shape digest differs, so the band is never asked about it, which is why no
// band width can make this fold.
func TestAStructurallyDifferentPageIsNeverFolded(t *testing.T) {
	c := bandCrawler()
	var rep Report
	flat := bandPage(t, `<html><body><p>view</p><a href="/a?id=1">A</a><a href="/b?id=1">B</a></body></html>`)
	nested := bandPage(t, `<html><body><p>view</p><a href="/a?id=2">A</a><a href="/b?id=2">B</a>`+
		`<table><tr><td>extra</td></tr></table></body></html>`)
	if flat.shape == nested.shape {
		t.Fatal("setup: a different skeleton must produce a different shape digest, or this test " +
			"proves nothing about the index")
	}
	var f0, f1 Fetch
	c.recordStructuredLocation(flat, "http://h/flat", &f0, &rep)
	if !c.recordStructuredLocation(nested, "http://h/nested", &f1, &rep) {
		t.Fatal("a page with a different tag skeleton is a different page and must be a new location")
	}
	if rep.LocationFolds != 0 {
		t.Errorf("a structural difference was folded (%d); the band must never cross a shape boundary",
			rep.LocationFolds)
	}
	if rep.DuplicateLocations != 0 {
		t.Errorf("a structural difference was counted as a duplicate (%d)", rep.DuplicateLocations)
	}
	if got := len(c.locations); got != 2 {
		t.Errorf("the location map holds %d entries, want 2", got)
	}
}

// The index-level half of the structural refusal, pinned separately because it is a DIFFERENT
// mechanism from the comparison. The two pages below have IDENTICAL link sets apart from one query
// value, so `withinTolerance` would fold them at any band width — the only thing that keeps them
// apart is that the shape digest is the bucket key and a different skeleton is a different bucket.
//
// The first assertion is that the index really does separate them. Without it, a future change
// that made the bucket key coarser (say, dropping the text bucket) would be caught by nothing else
// here: the fold tests would still pass, because they all compare pages that differ in the value
// rather than in the shape.
func TestAShapeIndexKeepsDifferentlyShapedPagesInDifferentBuckets(t *testing.T) {
	flat := bandPage(t, `<html><body><p>view</p><a href="/a?id=1">A</a><a href="/b?id=1">B</a></body></html>`)
	nested := bandPage(t, `<html><body><p>view</p><a href="/a?id=2">A</a><a href="/b?id=1">B</a>`+
		`<ul><li>one</li><li>two</li></ul></body></html>`)

	// The comparison alone would fold them, which is why the index — not the comparison — is what
	// carries the structural guarantee. Asserted directly so the next reader is not left guessing
	// which of the two mechanisms is load-bearing.
	known := newLocationEntry("http://h/flat", flat.linkTargets)
	if !withinTolerance(nested.linkTargets, relaxedLinkKeys(nested.linkTargets), known,
		locationToleranceBand) {
		t.Fatal("setup: these two pages differ only in a link value and in the skeleton, and the " +
			"band would tolerate the value — so the shape index is the only thing separating them")
	}

	c := bandCrawler()
	var rep Report
	var f0, f1 Fetch
	c.recordStructuredLocation(flat, "http://h/flat", &f0, &rep)
	if !c.recordStructuredLocation(nested, "http://h/nested", &f1, &rep) {
		t.Fatal("a page with a different skeleton is a different page and must be admitted")
	}
	// And the index is what refused it: two entries under two buckets, and the candidate's bucket
	// never contained the location it would otherwise have matched.
	if len(c.locationShapes) != 2 {
		t.Errorf("expected two shape buckets, got %d — a bucket that held locations of different "+
			"shapes would put the structural decision back into withinTolerance", len(c.locationShapes))
	}
	if got := len(c.locationShapes[nested.shape]); got != 1 {
		t.Errorf("the nested page is in its own bucket, got %d locations there", got)
	}
}

// A document that failed to parse has no shape, and the empty shape is the band REFUSAL rather than
// a bucket that happens to be empty. The test therefore PLANTS a location under the empty key
// first: without one, `foldWithinTolerance` would return false on an empty map and prove nothing
// about the refusal at all. A parse failure that folded into a real location would be a fabricated
// identity — the exact defect this package is organised against.
func TestAPageWithNoStructureIsNeverFolded(t *testing.T) {
	if shapeDigest("", 0) == "" {
		t.Error("setup: a shape digest is a hash and is never empty, so the refusal must be the " +
			"zero VALUE left by a failed parse rather than the digest itself")
	}
	// A structure whose SHAPE is empty but whose link set is real. With the links present,
	// withinTolerance would happily match the planted location below, so the shape refusal is the
	// ONLY thing standing between this and a fabricated identity — which is the point of pinning
	// it separately.
	broken := pageStructure{linkTargets: []string{"http://h/a?id=1"}}
	if broken.shape != "" {
		t.Fatal("setup: a page structure with no parsed document must have no shape")
	}
	// A real location, indexed under the EMPTY shape, whose links are exactly the broken page's
	// would be an exact match if the band consulted the map at all. It never does.
	seed := bandPage(t, `<html><body><p>view</p><a href="/a?id=1">A</a></body></html>`)
	c := bandCrawler()
	var rep Report
	var f0, f1 Fetch
	if !c.recordStructuredLocation(seed, "http://h/real", &f0, &rep) {
		t.Fatal("setup: the seed page must be admitted as a location")
	}
	// Move the seed under the empty shape, so the ONLY thing stopping a fold is the refusal.
	delete(c.locationShapes, seed.shape)
	c.locationShapes[""] = []string{seed.fingerprint}

	if _, folded := c.foldWithinTolerance(broken); folded {
		t.Error("a page with no shape folded into a real location; the empty shape is the refusal, " +
			"and a response that parsed into nothing has no identity to offer")
	}

	// And it must not be admitted either: an empty fingerprint means nothing was fingerprinted,
	// so nothing is recorded. Asserted through the same map, so it cannot pass for the wrong reason.
	if !c.recordStructuredLocation(broken, "http://h/broken", &f1, &rep) {
		t.Error("a response with no fingerprint must be left alone, not recorded as a location")
	}
	if len(c.locations) != 1 {
		t.Errorf("an unfingerprintable response was recorded as a location: %v", c.locations)
	}
}

// ---- end to end: the whole crawl -------------------------------------------------------------------

// rotatingLinkTarget serves a site whose seed page re-renders with a different link value on every
// visit, which is the case the exact hash could not stop: /view?id=1 and /view?id=2 are distinct
// requests, so both are fetched, and before this change each was a brand-new location.
//
// The page's LINK SET is identical by path and parameter name; only the value on one link moves.
// The three other seeds are the controls, and each differs from /view in exactly one way:
//
//   - /other links somewhere else entirely (same shape, different paths)
//   - /struct carries one extra element (different shape)
//   - /plain is the same page with the same value, for the exact-duplicate case
func rotatingLinkTarget(t *testing.T) *httptest.Server {
	t.Helper()
	view := func(links string) string {
		return `<html><body><p>view page</p>` + links + `</body></html>`
	}
	mux := http.NewServeMux()
	// The rotation itself: /view?render=N serves the same page with the VALUE on the /c link set
	// to N. Every render therefore differs from the first in exactly one query value and in
	// nothing else — same skeleton, same text, same link paths, same parameter names.
	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(view(
			`<a href="/a?v=1">A</a><a href="/b?v=1">B</a><a href="/c?v=` + r.URL.Query().Get("render") + `">C</a>`)))
	})
	// The control: identical to render 1 except that the THIRD link points somewhere else. Same
	// skeleton, same text length, different paths — which is exactly the case the band must refuse.
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(view(`<a href="/a?v=1">A</a><a href="/b?v=1">B</a><a href="/z?v=1">Z</a>`)))
	})
	// The other control: render 1's page plus one more element, so the skeleton differs.
	mux.HandleFunc("/struct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(view(`<a href="/a?v=1">A</a><a href="/b?v=1">B</a><a href="/c?v=1">C</a>`) +
			`<table><tr><td>extra</td></tr></table></body></html>`))
	})
	// A page with nothing rotating, for the exact-duplicate case.
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><p>plain page</p><a href="/leaf">Leaf</a></body></html>`))
	})
	// Every leaf is a DIFFERENT PAGE SHAPE, one nesting level deeper than the last, because the
	// location fingerprint's job here is to keep them apart. Four leaves sharing one skeleton would
	// be one location and the other three would be exact DUPLICATES — which is the correct
	// fingerprint behaviour and would make every assertion below measure the fixture instead of the
	// band. The nesting is what makes them four locations.
	leaf := func(depth int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			open, close := "", ""
			for range depth {
				open += "<div>"
				close += "</div>"
			}
			_, _ = w.Write([]byte(`<html><body>` + open + body + close + `</body></html>`))
		}
	}
	mux.HandleFunc("/a", leaf(1, `<h1>leaf a</h1>`))
	mux.HandleFunc("/b", leaf(2, `<h1>leaf b</h1>`))
	mux.HandleFunc("/c", leaf(3, `<h1>leaf c</h1>`))
	mux.HandleFunc("/z", leaf(4, `<h1>leaf z</h1>`))
	mux.HandleFunc("/leaf", leaf(5, `<h1>plain leaf</h1>`))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// The acceptance criterion, end to end: two URLs rendering the same page with a rotating link value
// are ONE location, and the fold that makes that true is visible on the crawl's own report.
func TestARotatingLinkValueFoldsIntoTheKnownLocationAndIsReported(t *testing.T) {
	srv := rotatingLinkTarget(t)
	first, second := srv.URL+"/view?render=1", srv.URL+"/view?render=2"
	rep := run(t, newHarness().config(
		first,
		second,
		srv.URL+"/other?render=1",
		srv.URL+"/struct?render=1",
	))

	// Both renders were actually FETCHED. Without this the assertions below could pass because the
	// frontier never reached the second render at all, which is a different test entirely.
	if got := fetchedPaths(rep)["/view"]; got != 2 {
		t.Fatalf("setup: /view was fetched %d times, want 2 — the rotating value is in a LINK, not in "+
			"the URL being crawled, so the request fingerprint must let both renders through", got)
	}

	// The claim. Exactly one fold, from the one pair that is a value rotation.
	if rep.LocationFolds != 1 {
		t.Errorf("a page differing from a known location only in one link VALUE must fold into it; "+
			"LocationFolds = %d (skips: %s)", rep.LocationFolds, reasonCounts(rep))
	}
	if n := rep.Skips.Count(SkipLocationFolded); n != 1 {
		t.Errorf("the fold must be recorded under its own reason, got %d", n)
	}
	// And it is not laundered as an exact duplicate: an operator reading "duplicate" would conclude
	// the crawl is exact, which is not what the band does.
	if n := rep.Skips.Count(SkipDuplicateLocation); n != 0 {
		t.Errorf("%d exact duplicate(s) reported, but no two pages in this fixture are identical; "+
			"the fold must not be reported as one", n)
	}

	// The fold is VISIBLE, in the sentence a reader actually sees and not only in a JSON field the
	// location count cannot be audited from.
	if !strings.Contains(rep.Summary(), "location tolerance band") {
		t.Errorf("the summary must say how much of the location count rests on a tolerance, got %q",
			rep.Summary())
	}

	// The controls, each fetched exactly once and each admitted as its own location: /other links
	// somewhere else (same shape, different paths), /struct has a different skeleton. Neither may
	// fold into /view at any band width, and neither may fold into the other.
	byPath := fetchedPaths(rep)
	for _, want := range []string{"/other", "/struct"} {
		if got := byPath[want]; got != 1 {
			t.Errorf("%s must be fetched exactly once as its own location, got %d", want, got)
		}
	}
	// Seven locations, exactly: /view (ONE — its two renders are one location), /other, /struct,
	// and the four leaves the three view-shaped pages link to. The second /view render is NOT an
	// eighth, which is the claim; and neither /other nor /struct is folded into /view, which is
	// the refusal. A lower count would be a false merge and a higher one the band not firing, so
	// only this exact number tells the two apart.
	if rep.Locations != 7 {
		t.Errorf("got %d locations for seven genuinely distinct pages (fetches: %v)", rep.Locations,
			fetchLog(rep))
	}
	// The folded fetch names what it folded into, so an operator reading the crawl paths sees the
	// page as present-but-not-traversed rather than absent.
	var folded *Fetch
	for i := range rep.Fetches {
		if rep.Fetches[i].URL == second {
			folded = &rep.Fetches[i]
		}
	}
	if folded == nil {
		t.Fatalf("the folded fetch is missing from the report: %v", fetchLog(rep))
	}
	if folded.DuplicateOf != first {
		t.Errorf("the folded fetch must name the location it folded into, got %q", folded.DuplicateOf)
	}
}

// The exact-duplicate half, so the two counters cannot be confused: a page served twice with
// NOTHING changed is a duplicate location, and specifically not a fold.
func TestAnUnchangedRepeatIsAnExactDuplicateAndNotAFold(t *testing.T) {
	srv := rotatingLinkTarget(t)
	h := newHarness()
	rep := run(t, h.config(srv.URL+"/plain?v=1", srv.URL+"/plain?v=2"))

	if rep.LocationFolds != 0 {
		t.Errorf("a byte-identical page is an exact duplicate, not a tolerance fold; got %d",
			rep.LocationFolds)
	}
	if rep.DuplicateLocations != 1 {
		t.Errorf("the identical repeat must still be counted as a duplicate, got %d",
			rep.DuplicateLocations)
	}
	if n := rep.Skips.Count(SkipLocationFolded); n != 0 {
		t.Errorf("no fold was available, so the fold reason must not have fired: %d", n)
	}
}

// The band's value is that the frontier does not fill: a page whose value rotates is walked once
// rather than once per render, and the second render's links are not queued again. Asserted on the
// crawl's own admission, not on a count of pages that happened to be small.
func TestAFoldKeepsTheRotatedPagesLinksOutOfTheFrontier(t *testing.T) {
	// A chain: each render of /view links to a value-distinct /c, and every /c leads somewhere new.
	// Without the band the chain is walked once per value; with it, once.
	renders := 4
	mux := http.NewServeMux()
	page := func(n int) string {
		return `<html><body><p>view page ` + strconv.Itoa(n) + `</p>` +
			`<a href="/a?v=1">A</a><a href="/b?v=1">B</a><a href="/c?v=` + strconv.Itoa(n) + `">C</a></body></html>`
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page(1)))
	})
	for n := 2; n <= renders; n++ {
		n := n
		mux.HandleFunc("/page/"+strconv.Itoa(n), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(page(n)))
		})
	}
	for _, leaf := range []string{"/a", "/b", "/c"} {
		mux.HandleFunc(leaf, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body><h1>` + leaf + `</h1><p>leaf</p></body></html>`))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	seeds := []string{srv.URL + "/"}
	for n := 2; n <= renders; n++ {
		seeds = append(seeds, srv.URL+"/page/"+strconv.Itoa(n))
	}
	rep := run(t, newHarness().config(seeds...))

	// Every render differs from the first in one link VALUE, so all but the first fold.
	if want := renders - 1; rep.LocationFolds != want {
		t.Errorf("%d renders each one link value apart from the first: want %d folds, got %d",
			renders, want, rep.LocationFolds)
	}
	// The point of the band: /c was ADMITTED once, from the first render. Each render would have
	// admitted its own /c?v=N without it, and the crawl would carry renders-1 extra requests that
	// lead to pages already covered.
	fetched := fetchedPaths(rep)
	if got := fetched["/c"]; got != 1 {
		t.Errorf("the rotated link led to a distinct URL per render (%d fetches of /c); a fold must "+
			"keep those out of the frontier", got)
	}
	// And the crawl converged: the request budget was nowhere near spent, so the assertion above is
	// about the band rather than about a bound that cut the crawl short.
	if rep.Limits.Hit(StopRequestBudget) {
		t.Errorf("the crawl hit a bound rather than converging: %v", rep.Limits.Stops)
	}
}
