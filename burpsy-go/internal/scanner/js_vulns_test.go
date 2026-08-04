package scanner

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// The vendored corpus's shape, pinned. A refreshed snapshot that changes any of these numbers must
// change them here too — which is the point: a corpus that quietly shrank would make every negative
// result weaker without any test noticing.
func TestVendoredCorpusLoadsAndReportsWhatItCouldNotUse(t *testing.T) {
	d := VendoredJsVulnDb().Summary()
	if !d.State.IsAvailable() {
		t.Fatalf("vendored corpus not available: %s", d.Summary())
	}
	if d.Components != 76 {
		t.Errorf("components = %d, want 76", d.Components)
	}
	if d.Vulnerabilities != 683 {
		t.Errorf("vulnerabilities = %d, want 683", d.Vulnerabilities)
	}
	if d.URLPatterns != 120 {
		t.Errorf("url patterns = %d, want 120 (76 uri + 44 filename)", d.URLPatterns)
	}
	// 208 filecontent patterns in the corpus, 2 of which no RE2 engine can compile.
	if d.ContentPatterns != 206 {
		t.Errorf("content patterns = %d, want 206", d.ContentPatterns)
	}
	// Every one of the corpus's 1,182 version bounds parses, so no vulnerability entry is dropped. If
	// a refreshed corpus introduces an unparsable bound this fails loudly rather than quietly
	// narrowing what gets compared.
	if len(d.UnusableRanges) != 0 {
		t.Errorf("unusable ranges: %v", d.UnusableRanges)
	}
	if len(d.UnusableComponents) != 0 {
		t.Errorf("unusable components: %v", d.UnusableComponents)
	}
	// `func` extractors are refused (they need a JavaScript engine) and counted, not silently
	// skipped. `hashes` are implemented here, so they are counted as loaded instead.
	if d.UnsupportedFuncExtractors != 49 {
		t.Errorf("func extractors = %d, want 49", d.UnsupportedFuncExtractors)
	}
	if d.UnsupportedReplaceExtractors != 8 {
		t.Errorf("filecontentreplace extractors = %d, want 8", d.UnsupportedReplaceExtractors)
	}
	if d.HashEntries != 18 {
		t.Errorf("hash entries = %d, want 18", d.HashEntries)
	}
	if !strings.Contains(d.Summary(), "retirejs_repository.json (Burp Suite 2026.7.1") {
		t.Errorf("summary does not name the corpus: %s", d.Summary())
	}
}

// The RE2 divergence, measured rather than assumed. Two corpus regexes no RE2 engine can compile
// (the same two the Rust module refuses) and seven that RE2 rejects only for their repeat bound.
func TestRE2IncompatibleCorpusPatternsAreNamedNotSilentlyDropped(t *testing.T) {
	d := VendoredJsVulnDb().Summary()
	if len(d.UnusablePatterns) != 2 {
		t.Fatalf("unusable patterns = %d, want 2: %v", len(d.UnusablePatterns), d.UnusablePatterns)
	}
	joined := strings.Join(d.UnusablePatterns, " | ")
	for _, want := range []string{"jquery filecontent", "lodash filecontent"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unusable patterns do not name %q: %s", want, joined)
		}
	}
	// Seven patterns compile only after their bounded repeat is clamped to RE2's ceiling. Each is
	// named, because each now matches less than the corpus says it should.
	if len(d.NarrowedPatterns) != 7 {
		t.Fatalf("narrowed patterns = %d, want 7: %v", len(d.NarrowedPatterns), d.NarrowedPatterns)
	}
	narrowed := strings.Join(d.NarrowedPatterns, " | ")
	for _, want := range []string{"nextjs", "react", "select2", "tinyMCE", "underscore.js", "vue"} {
		if !strings.Contains(narrowed, want) {
			t.Errorf("narrowed patterns do not name %q: %s", want, narrowed)
		}
	}
	if !strings.Contains(narrowed, "narrowed to {0,1000}") && !strings.Contains(narrowed, "narrowed to {1,1000}") {
		t.Errorf("narrowed patterns do not say what was clamped: %s", narrowed)
	}
}

func TestNarrowBoundedRepeatsOnlyTouchesAnOverLargeUpperBound(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		{"over the ceiling is clamped", `a.{1,1500}b`, `a.{1,1000}b`, true},
		{"lazy repeat keeps its ?", `a[\s\S]{0,1800}?b`, `a[\s\S]{0,1000}?b`, true},
		{"at the ceiling is untouched", `a{0,1000}`, `a{0,1000}`, false},
		{"fixed repeat is refused, not clamped", `a{5000}`, `a{5000}`, false},
		{"open-ended repeat is fine for RE2", `a{2,}`, `a{2,}`, false},
		{"a lower bound above the ceiling cannot be narrowed", `a{1500,2000}`, `a{1500,2000}`, false},
		{"a brace inside a class is a literal", `[{1,5000}]`, `[{1,5000}]`, false},
		{"an escaped brace is a literal", `\{1,5000}`, `\{1,5000}`, false},
		{"only the offending repeat changes", `a{1,2}b{1,4000}`, `a{1,2}b{1,1000}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, notes := narrowBoundedRepeats(c.in)
			if got != c.want {
				t.Errorf("narrowBoundedRepeats(%q) = %q, want %q", c.in, got, c.want)
			}
			if (len(notes) > 0) != c.changed {
				t.Errorf("notes = %v, changed should be %v", notes, c.changed)
			}
		})
	}
}

func TestAKnownVulnerableVersionInTheFilenameIsFlaggedAtTheCorpusSeverity(t *testing.T) {
	c := VendoredJsLibraryCheck()
	f := c.Scan("/static/jquery-1.4.2.min.js", "", nil)
	vulns := findingsNamed(f, jsIssue)
	if len(vulns) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(vulns), renderFindings(f))
	}
	if vulns[0].Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative (a filename is a claim about naming)", vulns[0].Confidence)
	}
	if !strings.Contains(vulns[0].Description, "jquery 1.4.2") {
		t.Errorf("detail does not name the library and version: %s", vulns[0].Description)
	}
	if !strings.Contains(vulns[0].Description, "CVE-2011-4969") {
		t.Errorf("detail does not carry the corpus's advisory ids: %s", vulns[0].Description)
	}
	cov := c.Coverage()
	if cov.DetectionsVulnerable != 1 || cov.DetectionsCleared != 0 {
		t.Errorf("coverage vulnerable=%d cleared=%d, want 1/0", cov.DetectionsVulnerable, cov.DetectionsCleared)
	}
}

func TestAPatchedVersionOfTheSameLibraryProducesNoFindingButIsCountedAsCleared(t *testing.T) {
	c := VendoredJsLibraryCheck()
	if f := c.Scan("/static/jquery-3.7.1.min.js", "", nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.DetectionsCleared != 1 || cov.DetectionsVulnerable != 0 || cov.AssetsIdentified != 1 {
		t.Errorf("coverage cleared=%d vulnerable=%d identified=%d, want 1/0/1",
			cov.DetectionsCleared, cov.DetectionsVulnerable, cov.AssetsIdentified)
	}
	if cov.Inconclusive() {
		t.Errorf("a comparable, cleared version is the one case that really is clean: %s", cov.Summary())
	}
}

func TestAnUnknownVersionIsReportedAsUndeterminedRatherThanClean(t *testing.T) {
	c := VendoredJsLibraryCheck()
	f := c.Scan("/js/jquery-latest.min.js", "", nil)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(f), renderFindings(f))
	}
	if f[0].Name != jsUndeterminedIssue {
		t.Errorf("issue = %q, want %q", f[0].Name, jsUndeterminedIssue)
	}
	if f[0].Severity != "info" {
		t.Errorf("severity = %q, want info", f[0].Severity)
	}
	if !strings.Contains(f[0].Description, "not a clean result") {
		t.Errorf("detail must refuse to read as clean: %s", f[0].Description)
	}
	if !strings.Contains(f[0].Description, `"latest"`) {
		t.Errorf("detail must name the token it could not compare: %s", f[0].Description)
	}
	cov := c.Coverage()
	if cov.DetectionsUndetermined != 1 || cov.DetectionsCleared != 0 || cov.DetectionsVulnerable != 0 {
		t.Errorf("coverage undetermined=%d cleared=%d vulnerable=%d, want 1/0/0",
			cov.DetectionsUndetermined, cov.DetectionsCleared, cov.DetectionsVulnerable)
	}
	if !cov.Inconclusive() {
		t.Error("an uncompared version must make the result inconclusive")
	}
}

func TestAnInContentVersionMarkerIsFirmWhereAFilenameIsOnlyTentative(t *testing.T) {
	c := VendoredJsLibraryCheck()
	body := []byte("/*! jQuery v1.7.1 | (c) jQuery Foundation */ var x = 1;")
	f := c.Scan("/bundle.js", "application/javascript", body)
	vulns := findingsNamed(f, jsIssue)
	if len(vulns) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(vulns), renderFindings(f))
	}
	if vulns[0].Confidence != "firm" {
		t.Errorf("confidence = %q, want firm (a marker inside the file is a claim about the file)", vulns[0].Confidence)
	}
	if !strings.Contains(vulns[0].Description, "jquery 1.7.1") {
		t.Errorf("detail = %s", vulns[0].Description)
	}
}

// The `hashes` extractor kind, which the Rust module refuses and this port implements. A whole-file
// SHA-1 is the only signal that earns certain confidence.
func TestAWholeFileHashIdentifiesTheExactVersionWithCertainConfidence(t *testing.T) {
	body := []byte("/* a build of libfoo nobody can pattern-match */\n")
	sum := sha1.Sum(body)
	corpus := fmt.Sprintf(`{
	  "libfoo": {
	    "extractors": {
	      "filename": ["libfoo-(§§version§§)\\.js"],
	      "hashes": {%q: "1.2.3"}
	    },
	    "vulnerabilities": [
	      {"below": "2.0.0", "severity": "high", "identifiers": {"summary": "a hole", "CVE": ["CVE-2020-0001"]}}
	    ]
	  }
	}`, hex.EncodeToString(sum[:]))
	db := parseJsVulnDb(corpus, "unit test")
	if db.Summary().HashEntries != 1 {
		t.Fatalf("hash entries = %d, want 1: %s", db.Summary().HashEntries, db.Summary().Summary())
	}
	c := NewJsLibraryCheck(db)
	// The filename carries a version too; the hash supersedes it, so exactly one finding comes back.
	f := c.Scan("/assets/libfoo-9.9.9.js", "", body)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(f), renderFindings(f))
	}
	if f[0].Confidence != "certain" {
		t.Errorf("confidence = %q, want certain for a whole-file hash match", f[0].Confidence)
	}
	if !strings.Contains(f[0].Description, "libfoo 1.2.3") {
		t.Errorf("the hash names the exact version, not the filename's: %s", f[0].Description)
	}
	if cov := c.Coverage(); cov.DetectionsByFileHash != 1 {
		t.Errorf("hash detections = %d, want 1", cov.DetectionsByFileHash)
	}
}

func TestAScriptNoPatternRecognisesIsCountedUnidentifiedNotClean(t *testing.T) {
	c := VendoredJsLibraryCheck()
	if f := c.Scan("/app.bundle.js", "", []byte("console.log('hand written');")); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.AssetsSeen != 1 || cov.AssetsUnidentified != 1 || cov.AssetsIdentified != 0 {
		t.Errorf("coverage seen=%d unidentified=%d identified=%d, want 1/1/0",
			cov.AssetsSeen, cov.AssetsUnidentified, cov.AssetsIdentified)
	}
	if !cov.Inconclusive() {
		t.Error("an unidentified asset is not evidence that the page ships no vulnerable library")
	}
}

func TestANonJavaScriptResponseIsCountedSeparatelyFromACleanScript(t *testing.T) {
	c := VendoredJsLibraryCheck()
	if f := c.Scan("/index.html", "text/html", []byte("<html>")); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.NotJavaScript != 1 || cov.AssetsSeen != 0 {
		t.Errorf("coverage not_js=%d assets=%d, want 1/0", cov.NotJavaScript, cov.AssetsSeen)
	}
}

func TestLooksLikeJavaScriptAcceptsEitherSignalAlone(t *testing.T) {
	cases := []struct {
		path, ct string
		want     bool
	}{
		{"/a/b.js", "", true},
		{"/a/b.mjs", "", true},
		{"/a/b.js?v=3", "", true},
		{"/a/b.js#x", "", true},
		{"/a/b.JS", "", true},
		{"/a/b", "application/javascript; charset=utf-8", true},
		{"/a/b", "text/ecmascript", true},
		{"/a/b.json", "application/json", false},
		{"/a/b", "", false},
	}
	for _, c := range cases {
		if got := looksLikeJavaScript(c.path, c.ct); got != c.want {
			t.Errorf("looksLikeJavaScript(%q, %q) = %v, want %v", c.path, c.ct, got, c.want)
		}
	}
}

func TestAnAbsentDatasetReportsTheCheckUnavailableRatherThanFindingNothing(t *testing.T) {
	c := NewJsLibraryCheck(LoadJsVulnDb("/nonexistent/retirejs_repository.json"))
	if f := c.Scan("/static/jquery-1.4.2.min.js", "", nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.Dataset.State.IsAvailable() {
		t.Fatal("a missing file must not report a loaded dataset")
	}
	if !strings.Contains(cov.Dataset.Summary(), "UNAVAILABLE") {
		t.Errorf("summary must say so out loud: %s", cov.Dataset.Summary())
	}
	if cov.SkippedDatasetUnavailable != 1 {
		t.Errorf("skipped = %d, want 1", cov.SkippedDatasetUnavailable)
	}
	if cov.AssetsSeen != 0 {
		t.Errorf("nothing was examined, so nothing is clean: assets seen = %d", cov.AssetsSeen)
	}
	if !cov.Inconclusive() {
		t.Error("no corpus means no conclusion")
	}
}

func TestADatasetThatIsNotJsRepositoryJSONIsUnavailableWithTheParseReason(t *testing.T) {
	db := parseJsVulnDb("[1,2,3]", "unit test")
	if db.Summary().State.IsAvailable() {
		t.Fatal("a JSON array is not a component map")
	}
	if !strings.Contains(db.Summary().UnavailableReason, "top level is not a JSON object") {
		t.Errorf("reason = %q", db.Summary().UnavailableReason)
	}
	broken := parseJsVulnDb("{not json", "unit test")
	if !strings.Contains(broken.Summary().UnavailableReason, "not parsable as jsrepository JSON") {
		t.Errorf("reason = %q", broken.Summary().UnavailableReason)
	}
}

func TestAComponentWhoseShapeIsNotTheCorpusIsNamedRatherThanSkipped(t *testing.T) {
	db := parseJsVulnDb(`{"good":{"extractors":{"uri":["good-(§§version§§)\\.js"]},"vulnerabilities":[{"below":"2.0.0"}]},"bad":{"extractors":{"uri":[42]}}}`, "unit test")
	if got := db.Summary().Components; got != 1 {
		t.Errorf("components = %d, want 1 (the malformed one is not loaded)", got)
	}
	if len(db.Summary().UnusableComponents) != 1 || !strings.Contains(db.Summary().UnusableComponents[0], "bad") {
		t.Errorf("unusable components = %v, want the malformed one named", db.Summary().UnusableComponents)
	}
}

func TestVersionComparisonIsArithmeticNotAStringPrefix(t *testing.T) {
	v := func(s string) Version {
		out, ok := ParseVersion(s)
		if !ok {
			t.Fatalf("ParseVersion(%q) refused", s)
		}
		return out
	}
	// The exact trap a prefix test falls into: "1.4" is a textual prefix of "1.40.0".
	if v("1.4.2").Compare(v("1.9.0")) >= 0 {
		t.Error("1.4.2 < 1.9.0")
	}
	if v("1.40.0").Compare(v("1.9.0")) <= 0 {
		t.Error("1.40.0 > 1.9.0")
	}
	if v("1.9.0").Compare(v("1.10.0")) >= 0 {
		t.Error("9 < 10 numerically, but '9' > '1' textually")
	}
	if v("2.0").Compare(v("2.0.0")) != 0 {
		t.Error("the shorter side is zero-padded, so 2.0 == 2.0.0")
	}
	if v("3.0.0-rc1").Compare(v("3.0.0")) >= 0 {
		t.Error("a release candidate is not the release")
	}
	if v("1.11.0b1").Compare(v("1.11.0")) >= 0 {
		t.Error("1.11.0b1 < 1.11.0")
	}
	if v("2.2.4-lite").Compare(v("2.2.4")) >= 0 {
		t.Error("2.2.4-lite < 2.2.4")
	}
	if got := v("1.11.0b1").Parts(); len(got) != 3 || got[0] != 1 || got[1] != 11 || got[2] != 0 {
		t.Errorf("parts of 1.11.0b1 = %v, want [1 11 0]", got)
	}
	if got := v("1.11.0b1").String(); got != "1.11.0-b1" {
		t.Errorf("String() = %q, want 1.11.0-b1", got)
	}
}

// The prefix trap, end to end: one rule, two versions whose *text* both start with the bound.
func TestTheSameRuleFlagsAVulnerable142AndClearsAnUnaffected1400(t *testing.T) {
	corpus := `{
	  "libbar": {
	    "extractors": {"filename": ["libbar-(§§version§§)\\.js"]},
	    "vulnerabilities": [
	      {"atOrAbove": "1.4", "below": "1.5", "severity": "high", "identifiers": {"summary": "only the 1.4 line"}}
	    ]
	  }
	}`
	db := parseJsVulnDb(corpus, "unit test")
	c := NewJsLibraryCheck(db)

	vuln := c.Scan("/js/libbar-1.4.2.js", "", nil)
	if len(findingsNamed(vuln, jsIssue)) != 1 {
		t.Fatalf("1.4.2 is inside [1.4, 1.5) and must be flagged: %s", renderFindings(vuln))
	}
	clean := c.Scan("/js/libbar-1.40.0.js", "", nil)
	if len(clean) != 0 {
		t.Fatalf("1.40.0 is above 1.5 and must not be flagged — a prefix test would have: %s", renderFindings(clean))
	}
	cov := c.Coverage()
	if cov.DetectionsVulnerable != 1 || cov.DetectionsCleared != 1 {
		t.Errorf("coverage vulnerable=%d cleared=%d, want 1/1", cov.DetectionsVulnerable, cov.DetectionsCleared)
	}
}

func TestAVersionStringWithNoLeadingDigitIsRefusedRatherThanGuessedAt(t *testing.T) {
	for _, s := range []string{"latest", "", "  ", "v", "x.y.z", "-1.0"} {
		if _, ok := ParseVersion(s); ok {
			t.Errorf("ParseVersion(%q) should refuse", s)
		}
	}
	// Wider than uint32: refused, because a wrapped comparison is worse than no comparison.
	if _, ok := ParseVersion("99999999999.0"); ok {
		t.Error("a component wider than uint32 must be refused")
	}
}

func TestARangeBoundaryIsExclusiveBelowAndInclusiveAtOrAbove(t *testing.T) {
	lo, hi := "1.2.0", "1.4.0"
	r, ok := rangeOf(retireVuln{AtOrAbove: &lo, Below: &hi})
	if !ok {
		t.Fatal("a two-sided range must load")
	}
	v := func(s string) Version {
		out, ok := ParseVersion(s)
		if !ok {
			t.Fatalf("ParseVersion(%q) refused", s)
		}
		return out
	}
	if r.Contains(v("1.1.9")) {
		t.Error("below the lower bound is outside")
	}
	if !r.Contains(v("1.2.0")) {
		t.Error("atOrAbove includes its bound")
	}
	if !r.Contains(v("1.3.9")) {
		t.Error("inside is inside")
	}
	if r.Contains(v("1.4.0")) {
		t.Error("below excludes its bound")
	}
	if r.Text() != "atOrAbove 1.2.0, below 1.4.0" {
		t.Errorf("text = %q", r.Text())
	}

	above, atOrBelow := "2.0.0", "2.5.0"
	r2, ok := rangeOf(retireVuln{Above: &above, AtOrBelow: &atOrBelow})
	if !ok {
		t.Fatal("above/atOrBelow must load")
	}
	if r2.Contains(v("2.0.0")) {
		t.Error("above excludes its bound")
	}
	if !r2.Contains(v("2.5.0")) {
		t.Error("atOrBelow includes its bound")
	}
}

func TestAVulnerabilityEntryWithNoBoundsIsRefusedRatherThanMatchingEveryVersion(t *testing.T) {
	if _, ok := rangeOf(retireVuln{Severity: "high"}); ok {
		t.Error("a bound-free range would flag every sighting of the library")
	}
	bad := "not-a-version"
	if _, ok := rangeOf(retireVuln{Below: &bad}); ok {
		t.Error("an unparsable bound must be refused, not guessed at")
	}
}

// A component with an unevaluable range never reports a clean version, because it was only compared
// against part of what is known about it.
func TestAComponentWithADroppedRangeCannotClearAVersion(t *testing.T) {
	corpus := `{
	  "libbaz": {
	    "extractors": {"filename": ["libbaz-(§§version§§)\\.js"]},
	    "vulnerabilities": [
	      {"below": "1.0.0", "severity": "low"},
	      {"below": "not-a-version", "severity": "high"}
	    ]
	  }
	}`
	db := parseJsVulnDb(corpus, "unit test")
	if len(db.Summary().UnusableRanges) != 1 {
		t.Fatalf("unusable ranges = %v, want the malformed bound named", db.Summary().UnusableRanges)
	}
	c := NewJsLibraryCheck(db)
	f := c.Scan("/js/libbaz-9.9.9.js", "", nil)
	if len(f) != 1 || f[0].Name != jsUndeterminedIssue {
		t.Fatalf("want one undetermined finding, got: %s", renderFindings(f))
	}
	if !strings.Contains(f[0].Description, "cannot evaluate") {
		t.Errorf("detail must say what was not evaluated: %s", f[0].Description)
	}
	if cov := c.Coverage(); cov.DetectionsCleared != 0 {
		t.Errorf("cleared = %d, want 0: a partly-evaluated component cannot be cleared", cov.DetectionsCleared)
	}
}

func TestTheSameLibraryAtTheSameVersionIsReportedOnce(t *testing.T) {
	c := VendoredJsLibraryCheck()
	// jQuery has eleven filecontent patterns; a real banner matches more than one of them.
	body := []byte("/*! jQuery v1.7.1 jquery.com | jquery.org/license */\n/*! jQuery v1.7.1 */")
	f := c.Scan("/jquery-1.7.1.js", "application/javascript", body)
	if got := len(findingsNamed(f, jsIssue)); got != 1 {
		t.Fatalf("got %d findings for one library at one version, want 1: %s", got, renderFindings(f))
	}
	if cov := c.Coverage(); cov.DetectionsVulnerable != 1 {
		t.Errorf("detections = %d, want 1 — overlapping patterns must not double-count", cov.DetectionsVulnerable)
	}
}

// The adapter on ActiveScanner: findings carry the exchange's identity and remediation comes from
// Burp's catalogue, never from this package.
func TestTheActiveScannerAdapterAttributesAndEnrichesJsFindings(t *testing.T) {
	s, ex := scannerWithResponse(t,
		"/static/jquery-1.4.2.min.js",
		"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 0\r\n\r\n")
	s.config.CheckJSVulns = true

	f := s.checkJSVulns(nil, ex)
	vulns := findingsNamed(f, jsIssue)
	if len(vulns) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(vulns), renderFindings(f))
	}
	if vulns[0].URL != ex.Path || vulns[0].Method != ex.Method || vulns[0].ExchangeID != ex.ID {
		t.Errorf("finding not attributed to its exchange: %+v", vulns[0])
	}
	def, ok := ByName(jsIssue)
	if !ok {
		t.Fatalf("%q is not in the shipped catalogue, so no remediation can be wired", jsIssue)
	}
	if vulns[0].Solution != def.Remediation {
		t.Errorf("remediation is not the catalogue's text:\n got %q\nwant %q", vulns[0].Solution, def.Remediation)
	}
	if cov := s.JsLibraryCoverage(); cov.DetectionsVulnerable != 1 {
		t.Errorf("scanner coverage vulnerable = %d, want 1", cov.DetectionsVulnerable)
	}
}

func TestTheJsCheckIsSkippedWhenItsConfigFlagIsOff(t *testing.T) {
	s, ex := scannerWithResponse(t, "/static/jquery-1.4.2.min.js", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	s.config.CheckJSVulns = false
	if f := s.checkJSVulns(nil, ex); len(f) != 0 {
		t.Fatalf("a disabled check must produce nothing: %s", renderFindings(f))
	}
}

func findingsNamed(findings []*Finding, name string) []*Finding {
	var out []*Finding
	for _, f := range findings {
		if f.Name == name {
			out = append(out, f)
		}
	}
	return out
}

func renderFindings(findings []*Finding) string {
	if len(findings) == 0 {
		return "<no findings>"
	}
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "\n  [%s/%s] %s: %s", f.Severity, f.Confidence, f.Name, f.Description)
	}
	return b.String()
}
