package crawler

// Tests for the speculative-hidden-link phase (burpsy-react-ui-t5m0): mining URL-shaped
// candidates from HTML comments and script bodies — the places single-page apps and
// comment-leaked admin paths live — and admitting them through the same gates as a
// navigational link, bounded by a crawl-wide cap.

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// TestSpeculativePhaseFetchesACommentBorneURLWhenOn is the acceptance pair's first half:
// a path that exists ONLY inside an HTML comment is invisible to a crawl that declines
// the speculative phase, and followed by one that turns it on.
func TestSpeculativePhaseFetchesACommentBorneURLWhenOn(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body>
			<h1>home</h1>
			<!-- /adminpanel -->
			</body></html>`,
		"/adminpanel": `<html><body><h1>admin panel</h1></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if !tg.sawPath("/adminpanel") {
		t.Fatalf("with the phase on, the comment-borne /adminpanel must be fetched; fetched %v", tg.recorded())
	}
	if !rep.RequestSpeculative {
		t.Error("the report must record that the speculative phase ran")
	}
	if rep.SpeculativeAdmitted != 1 {
		t.Errorf("SpeculativeAdmitted = %d, want 1 — the one hidden link the phase followed", rep.SpeculativeAdmitted)
	}
}

// TestSpeculativePhaseLeavesTheSameURLUnfetchedWhenOff is the pair's second half: the
// same page with the phase off never mines the comment, so the hidden path is not
// fetched — the honest decline, reported as "not discovered" rather than as a refusal
// of something the crawl never looked for.
func TestSpeculativePhaseLeavesTheSameURLUnfetchedWhenOff(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body>
			<h1>home</h1>
			<!-- /adminpanel -->
			</body></html>`,
		"/adminpanel": `<html><body><h1>admin panel</h1></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RequestSpeculative = false
	rep := run(t, cfg)

	if tg.sawPath("/adminpanel") {
		t.Fatal("with the phase off, the comment must not be mined — /adminpanel was fetched")
	}
	if rep.RequestSpeculative {
		t.Error("the report must record that the phase did NOT run")
	}
	if rep.SpeculativeAdmitted != 0 {
		t.Errorf("SpeculativeAdmitted = %d, want 0 when the phase is off", rep.SpeculativeAdmitted)
	}
}

// TestSpeculativePhaseMinesScriptBodies covers the second source: a single-page app's
// router table is a list of URL strings inside a <script> block, invisible to the
// wire read and to the location fingerprint.
func TestSpeculativePhaseMinesScriptBodies(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body><h1>home</h1>
			<script>
				var routes = ["/dashboard", "/settings/profile"];
			</script>
			</body></html>`,
		"/dashboard":        `<html><body><h1>dashboard</h1></body></html>`,
		"/settings/profile": `<html><body><h1>profile</h1></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	for _, want := range []string{"/dashboard", "/settings/profile"} {
		if !tg.sawPath(want) {
			t.Errorf("script-borne %q must be fetched when the phase is on; fetched %v", want, tg.recorded())
		}
	}
	if rep.SpeculativeAdmitted != 2 {
		t.Errorf("SpeculativeAdmitted = %d, want 2 (the two router paths)", rep.SpeculativeAdmitted)
	}
}

// TestSpeculativeCapIsHonouredAndNamed proves the crawl-wide cap: past it, candidates
// are refused with their own skip reason (SkipSpeculativeLimit), the stop is recorded
// (StopSpeculativeLinks), and the drop is counted in the report — the same honest
// accounting every other bound gets.
func TestSpeculativeCapIsHonouredAndNamed(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body>
			<!-- /one -->
			<!-- /two -->
			<!-- /three -->
			</body></html>`,
		"/one":   `<html><body>one</body></html>`,
		"/two":   `<html><body>two</body></html>`,
		"/three": `<html><body>three</body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RequestSpeculative = true
	cfg.Limits.MaxSpeculativeLinks = 2
	rep := run(t, cfg)

	if n := rep.Skips.Count(SkipSpeculativeLimit); n != 1 {
		t.Errorf("skip records at the speculative cap = %d, want 1 (the third candidate)", n)
	}
	foundStop := false
	for _, s := range rep.Limits.Stops {
		if s == StopSpeculativeLinks {
			foundStop = true
		}
	}
	if !foundStop {
		t.Errorf("stops = %v, want StopSpeculativeLinks recorded — a cap is a bound like any other and must surface", rep.Limits.Stops)
	}
	// The cap's drops are reflected in the caveat string, the report's own summary —
	// and in Unfetched, which counts every discovered-never-fetched URL.
	if !strings.Contains(rep.Caveat(), "speculative") {
		t.Errorf("caveat = %q, want it to name the speculative cap", rep.Caveat())
	}
	if rep.Limits.Unfetched() != 1 {
		t.Errorf("Unfetched = %d, want 1 — the cap-refused candidate is a discovered-never-fetched URL", rep.Limits.Unfetched())
	}
	if rep.SpeculativeAdmitted != 2 {
		t.Errorf("SpeculativeAdmitted = %d, want exactly the cap", rep.SpeculativeAdmitted)
	}
	// The two admitted paths were fetched; the third was refused at the cap.
	if tg.timesAskedFor("/one")+tg.timesAskedFor("/two")+tg.timesAskedFor("/three") != 2 {
		t.Errorf("fetched %v — exactly two of the three candidates should be admitted", tg.recorded())
	}
}

// TestSpeculativeCandidatesPassTheDestructiveGate is the invariant that makes the phase
// safe: a candidate mined from a comment is not privileged — it is a discovered link
// like any other, so a comment that says /logout is still a logout.
func TestSpeculativeCandidatesPassTheDestructiveGate(t *testing.T) {
	pages := map[string]string{
		"/":          `<html><body><!-- /logout --></body></html>`,
		"/logout":    `<html><body>logged out</body></html>`,
		"/nothidden": `<html><body>plain</body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if tg.sawPath("/logout") {
		t.Fatal("a comment-borne /logout must be refused by the destructive gate like any other logout link")
	}
	if n := rep.Skips.Count(SkipDestructiveLogout); n != 1 {
		t.Errorf("destructive refusals = %d, want 1 — the mined candidate must reach the same gate", n)
	}
}

// TestSpeculativeCandidatesPassTheScopeGate is the second half of the same invariant:
// an out-of-scope candidate is refused as out of scope, never admitted as a seed.
func TestSpeculativeCandidatesPassTheScopeGate(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body><!-- http://other.example/secret --></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()
	// A scope that allows only the target host: the mined cross-host candidate must stop there.
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(tg.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if n := rep.Skips.Count(SkipOutOfScope); n != 1 {
		t.Errorf("out-of-scope refusals = %d, want 1 — the mined candidate must reach the scope gate", n)
	}
}

// TestSpeculativeURLFieldsReadsTheTwoShapesIs the unit test for the extractor itself:
// absolute URLs and root-relative paths are read; everything else a script carries —
// identifiers, numbers, JS strings — is not a location and must not be read as one.
func TestSpeculativeURLFieldsReadsTheTwoShapes(t *testing.T) {
	text := `var base = "https://internal.example/v2"; // see /adminpanel
				router.map("/dashboard", handler); var x = 42; "not a path"; /also-not-a-path/x`
	got := speculativeURLFields(text)
	// Every root-shaped token is a candidate — the scope and destructive gates decide
	// which are followed, the extractor only refuses to invent paths from prose.
	want := []string{"https://internal.example/v2", "/adminpanel", "/dashboard", "/also-not-a-path/x"}
	if len(got) != len(want) {
		t.Fatalf("speculativeURLFields returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("speculativeURLFields returned %v, want %v", got, want)
		}
	}
}

// TestSpeculativeURLFieldsIgnoresSchemeRelativeAndJunk bounds the extractor from the
// other side: "//" is a scheme-relative URL (the crawler's supportedScheme refuses it,
// but the extractor should not emit it as a path), and trailing punctuation is not part
// of the path.
func TestSpeculativeURLFieldsIgnoresSchemeRelativeAndJunk(t *testing.T) {
	got := speculativeURLFields(`<!-- //cdn.example/lib.js --> <a href="/path.">`)
	want := []string{"/path"}
	if len(got) != len(want) {
		t.Fatalf("speculativeURLFields returned %v, want %v", got, want)
	}
	if got[0] != want[0] {
		t.Fatalf("speculativeURLFields returned %v, want %v", got, want)
	}
}

// TestBurpConfigSpeculativeKeysLandInAppliedKeys is acceptance criterion 2: a Burp
// configuration carrying crawler/customization/request_speculative and
// crawler/customization/maximum_speculative_links applies both rather than reporting
// them unrepresentable — a migrated configuration must not silently lose the phase.
func TestBurpConfigSpeculativeKeysLandInAppliedKeys(t *testing.T) {
	doc := `{"crawler": {"customization": {"request_speculative": true, "maximum_speculative_links": 250}}}`
	cfg, err := ParseBurpCrawlConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBurpCrawlConfig: %v", err)
	}
	if !cfg.RequestSpeculative {
		t.Error("request_speculative must land on the config, not in UnrepresentableKeys")
	}
	if cfg.Limits.MaxSpeculativeLinks != 250 {
		t.Errorf("maximum_speculative_links = %d, want 250", cfg.Limits.MaxSpeculativeLinks)
	}
	for _, k := range cfg.AppliedKeys {
		if strings.Contains(k, "speculative") {
			return // both keys applied
		}
	}
	t.Errorf("AppliedKeys = %v, want both speculative keys present", cfg.AppliedKeys)
	for _, k := range cfg.UnrepresentableKeys {
		if strings.Contains(k, "speculative") {
			t.Errorf("speculative key %q must be applied, not unrepresentable", k)
		}
	}
}
