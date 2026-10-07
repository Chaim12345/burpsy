// SCAN-01 — known-vulnerable JavaScript libraries, matched by **version range**.
//
// A port of crates/scanner/src/js_vulns.rs. Named divergences are at the bottom of this comment;
// everything else below is the Rust module's reasoning, which the port preserves.
//
// # Why this is not a BCheck
//
// The BCheck DSL can say "this body matches that regex". It cannot say "the version this regex
// captured is at or above 3.0.0 and below 3.4.1", and a check that cannot do version arithmetic
// cannot answer the only question that matters here. Writing 683 BChecks — one per known
// vulnerability, each with a hand-expanded set of literal version strings — is the shape this file
// exists to avoid: it would be wrong the day upstream publishes 3.4.2.
//
// So the range comparison is real arithmetic on parsed Versions. It is deliberately **not** a
// string prefix test: "1.4" is a prefix of "1.40.0", and a prefix test would clear a vulnerable
// 1.4.2 while flagging an unaffected 1.40.0. It is also not semver, because the versions real
// libraries ship are not semver — 2.0, 1.11.0b1, 3.0.0-rc1, 2.2.4-lite all occur in the dataset's
// own bounds, and a strict semver parser rejects most of them.
//
// # The dataset and its provenance
//
// Retire.js's `jsrepository` corpus, as shipped inside Burp Suite 2026.7.1 at
// `resources/RetireJS/retirejs_repository.json`:
//
//	source:    Burp Suite 2026.7.1, resources/RetireJS/retirejs_repository.json
//	vendored:  internal/scanner/data/retirejs_repository.json
//	size:      514,644 bytes
//	sha256:    5fdf3cc5707264de891f3844becea5fbc17377e8a684aecf8d2fca7936afb6da
//	extracted: 2026-07-28
//	licence:   Apache-2.0 (retire.js, https://github.com/RetireJS/retire.js)
//
// Copied byte-for-byte from crates/scanner/data/retirejs_repository.json (same sha256, verified
// after the copy) so this Go tree stands alone rather than reaching across into the Rust crate.
// Never reformat it: the sha256 in this comment is the only thing that proves which snapshot the
// engine is actually evaluating.
//
// Embedded with go:embed rather than read from disk at runtime — the same decision, for the same
// reason, as the Rust module's include_str!: a scanner that guesses at an install path has a new
// failure mode ("it found nothing because the file was somewhere else"), which is precisely the kind
// of silent non-result this package refuses. An operator who wants a fresher snapshot passes it to
// LoadJsVulnDb, and that file's identity, size and entry counts are then reported instead of the
// vendored one's.
//
// **Currency is reported, not implied.** DatasetSummary carries the source and every count, so "no
// vulnerable libraries" is always qualified by which corpus said so and how much of it this engine
// could actually evaluate.
//
// # What is deliberately not implemented, and counted
//
// Retire.js has five extractor kinds. This port uses four (`uri`, `filename`, `filecontent`,
// `hashes`) and refuses `func`, which evaluates JavaScript in the page (`window.jQuery.fn.jquery`).
// That needs a JS engine, which this package does not have and should not grow. The refusal is
// **counted** in DatasetSummary rather than quietly skipped, because it is the difference between
// "we checked every way retire.js knows how" and "we checked four of five". `filecontentreplace` is
// a sed-style rewrite rather than a match, and is counted the same way.
//
// # The three verdicts, and why "clean" is the rarest
//
// A response either identifies a library at a comparable version (then it is vulnerable or it is
// not), or it identifies one whose version cannot be compared. That last case is verdictUndetermined
// and it is *reported*: an unknown version is not evidence of safety. Guessing "probably vulnerable"
// invents a finding; guessing "probably fine" hides one. Both are refusals to answer, and only one
// of them is honest about it.
//
// # Named divergences from the Rust module
//
//  1. **`hashes` is implemented here; Rust refuses it.** Whole-file SHA-1 to version is genuinely
//     cheap in Go, so the vendored corpus's 18 hash entries (4 components) are loaded and counted as
//     implemented — DatasetSummary.HashEntries — rather than counted as a refusal. A hash match is
//     the one signal that earns Certain confidence, the tier the Rust module documents as reserved
//     for exactly this and does not fill. Because a whole-file hash identifies the exact file, a
//     hash hit *supersedes* filename/content detections for that same component: a banner guess
//     about a file whose bytes are already known adds nothing but a duplicate finding.
//  2. **Go's regexp is RE2, and its bounded repeats stop at 1000.** Nine corpus `filecontent`
//     patterns do not compile verbatim here where Rust compiles seven of them. Two are genuinely
//     unsupported by both engines (jQuery's minified banner uses a backreference, lodash's uses a
//     lookbehind) and are counted in UnusablePatterns exactly as Rust counts them. The other seven
//     fail only on RE2's repeat ceiling (`{0,1800}`, `{1,5000}`, `{0,8000}`, …). Those are
//     **narrowed** — the upper bound clamped to 1000 — and each is named in
//     DatasetSummary.NarrowedPatterns. Narrowing an upper bound can only ever match *fewer* strings
//     than the corpus pattern, so it cannot invent a finding; dropping the pattern outright would be
//     the larger false negative. See narrowBoundedRepeats.
//  3. **A required-literal prefilter replaces Rust's RegexSet.** Go's standard library has no
//     RegexSet, and running all 206 `filecontent` patterns over one 540 KB bundle measured at 2.7
//     seconds — the corpus is full of patterns with no literal prefix for the engine to memchr on
//     (`/*\nYUI (§§version§§)`, `[^a-z.]jquery:[ ]?"…"`), each costing ~150 ms on its own. So each
//     pattern carries a literal every match of it must contain, derived from its own syntax tree
//     (see requiredLiteral), and the pattern runs only when a substring search finds that literal.
//     Same matches — the derivation only ever accepts a literal that is genuinely required, and a
//     pattern with no such literal always runs — at 76 ms for the same bundle and 0.8 ms for a 5 KB
//     script. 205 of the corpus's 206 content patterns get a prefilter; the one that does not is
//     counted in DatasetSummary.ContentPatternsWithoutPrefilter.
//  4. **The corpus's `critical` severity is kept as "critical".** Rust folds it onto High because its
//     Severity type has four levels and growing a fifth would change a type every check shares.
//     Finding.Severity here is already a string with a "critical" level, so folding would discard
//     information for nothing.
//  5. **The vendored corpus is parsed once per process, not once per call.** VendoredJsVulnDb caches
//     behind a sync.Once: the parsed database is immutable, and re-parsing 514 KB per scanner is
//     pure waste. Rust's JsVulnDb::vendored re-parses on each call.
//  6. **A component whose JSON shape is not the corpus's is named, not skipped.** Rust walks an
//     untyped serde_json::Value and silently ignores, say, a non-string entry in a pattern list. Go
//     decodes into typed structs, so such a component fails to decode as a whole; it is recorded in
//     DatasetSummary.UnusableComponents rather than dropped. Empty for the vendored corpus.
package scanner

import (
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The vendored corpus, compiled in. See the file docs for provenance.
//
//go:embed data/retirejs_repository.json
var vendoredRetireJS string

// vendoredRetireJSName is the name of the vendored corpus as it appears in every report.
const vendoredRetireJSName = "retirejs_repository.json (Burp Suite 2026.7.1, extracted 2026-07-28)"

// jsIssue is the issue name, an exact match for Burp's catalogued issue (catalog_data.go, type
// index 5243008) so EnrichFinding attaches Burp's own remediation instead of invented advice.
const jsIssue = "Vulnerable JavaScript dependency"

// jsUndeterminedIssue is the issue name for a library whose version could not be compared.
// Deliberately *not* a catalogued name: Burp has no definition for this, and inventing one that
// looks catalogued would put authoritative-sounding prose behind a non-conclusion.
const jsUndeterminedIssue = "JavaScript library version not comparable"

// strictVersionPattern is what retire.js substitutes for `§§version§§`: a version must start with a
// digit. Copied from retire.js's own versionPattern so a match here means the same thing it means
// upstream.
const strictVersionPattern = `[0-9][0-9.a-z_\-]+`

// looseVersionPattern is the same slot, widened to "whatever token is in that position". Used only
// after the strict pattern has already failed, and only on a URL, and its matches can only ever
// produce verdictUndetermined — never a vulnerability claim. This is what turns `jquery-latest.js`
// from a silent miss into a reported non-conclusion: something jQuery-shaped was served and this
// engine cannot say which version it was.
//
// No `.`, unlike the strict pattern: a dotted loose match is greedy across the rest of the filename,
// so `jquery-latest.min.js` would report its version as "latest.min". The point of this pattern is
// to name the token that should have been a version, and naming it wrongly in the report defeats
// that.
const looseVersionPattern = `[0-9A-Za-z][0-9A-Za-z_+\-]*`

// versionPlaceholder is the corpus's own `§§version§§` marker.
const versionPlaceholder = "§§version§§"

// Version is a version as libraries actually spell it: dotted numeric components plus an optional
// non-numeric tail.
//
// parts is the numeric prefix, tail everything after it with one leading separator stripped — so
// 3.0.0-rc1 is ([3,0,0], "rc1") and 1.11.0b1 is ([1,11,0], "b1").
type Version struct {
	parts []uint32
	tail  string
}

// ParseVersion parses, or refuses. ok == false means "this is not a version I can compare", which
// callers must propagate as verdictUndetermined rather than treating as either verdict.
//
// Refuses anything whose first dotted component has no leading digit — `latest`, `x`, the empty
// string. A numeric component wider than uint32 is refused for the same reason: an overflow that
// silently wrapped would compare wrongly, which is worse than not comparing.
func ParseVersion(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, false
	}
	var parts []uint32
	rest := s
	// Assigned on every path out of the loop.
	var tail string
	for {
		digits := leadingDigits(rest)
		if digits == 0 {
			tail = rest
			break
		}
		n, err := strconv.ParseUint(rest[:digits], 10, 32)
		if err != nil {
			return Version{}, false
		}
		parts = append(parts, uint32(n))
		rest = rest[digits:]
		if next, ok := strings.CutPrefix(rest, "."); ok {
			rest = next
			continue
		}
		tail = rest
		break
	}
	if len(parts) == 0 {
		return Version{}, false
	}
	return Version{
		parts: parts,
		tail:  strings.TrimRight(strings.TrimLeft(tail, "-_+"), "."),
	}, true
}

func leadingDigits(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

// Parts returns the numeric components, shortest-zero-padded on comparison. Exposed for tests.
func (v Version) Parts() []uint32 { return v.parts }

// Compare orders two versions element-wise on the numeric parts with the shorter side zero-padded,
// so 2.0 == 2.0.0. Then: an empty tail sorts **after** a non-empty one, so 3.0.0-rc1 < 3.0.0 — a
// release candidate is not the release, and a `below: 3.0.0` range must catch it.
//
// This is the only notion of "same version" in the package. Comparing the structs field-by-field
// (Go's == on the tail plus a slice walk) would make 2.0 and 2.0.0 unequal while Compare calls them
// equal, and two notions of "same version" inside one type is exactly the kind of near-miss that
// produces a range check that agrees with itself and disagrees with reality.
func (v Version) Compare(o Version) int {
	n := len(v.parts)
	if len(o.parts) > n {
		n = len(o.parts)
	}
	for i := 0; i < n; i++ {
		var a, b uint32
		if i < len(v.parts) {
			a = v.parts[i]
		}
		if i < len(o.parts) {
			b = o.parts[i]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.tail == "" && o.tail == "":
		return 0
	case v.tail == "" && o.tail != "":
		return 1
	case v.tail != "" && o.tail == "":
		return -1
	default:
		return strings.Compare(v.tail, o.tail)
	}
}

// String renders the version the way a report should show it.
func (v Version) String() string {
	joined := make([]string, len(v.parts))
	for i, p := range v.parts {
		joined[i] = strconv.FormatUint(uint64(p), 10)
	}
	out := strings.Join(joined, ".")
	if v.tail != "" {
		out += "-" + v.tail
	}
	return out
}

// versionEdge is one end of a version range.
type versionEdge struct {
	at        Version
	inclusive bool
}

// VersionRange is an affected-version range: retire.js's atOrAbove/above/below/atOrBelow
// predicates.
//
// A range with no bounds at all would match every version, so it is refused at load time rather
// than loaded and allowed to flag everything.
type VersionRange struct {
	lower *versionEdge
	upper *versionEdge
	// text is the predicate as the corpus spelled it, for the finding detail.
	text string
}

// Contains reports whether v falls inside the affected range.
func (r VersionRange) Contains(v Version) bool {
	if r.lower != nil {
		c := v.Compare(r.lower.at)
		if r.lower.inclusive {
			if c < 0 {
				return false
			}
		} else if c <= 0 {
			return false
		}
	}
	if r.upper != nil {
		c := v.Compare(r.upper.at)
		if r.upper.inclusive {
			if c > 0 {
				return false
			}
		} else if c >= 0 {
			return false
		}
	}
	return true
}

// Text returns the predicate as the corpus spelled it.
func (r VersionRange) Text() string { return r.text }

// Vuln is one known vulnerability in one component.
type Vuln struct {
	Range VersionRange
	// Severity is the corpus's severity word, canonicalised onto Finding.Severity's vocabulary.
	Severity    string
	Summary     string
	Identifiers []string
}

// urlPattern is a `uri`/`filename` pattern in both its strict and loose forms. See
// looseVersionPattern.
type urlPattern struct {
	strict *regexp.Regexp
	loose  *regexp.Regexp
}

// jsComponent is one library the corpus knows about.
type jsComponent struct {
	name string
	url  []urlPattern
	// hashes maps a lower-case hex SHA-1 of a whole file to the version that file is.
	hashes map[string]string
	vulns  []Vuln
	// droppedVulns counts vulnerability entries this engine refused to load, so "no range matched"
	// can say whether it evaluated the whole component or only part of it.
	droppedVulns int
}

// DatasetState is whether the corpus is usable at all.
//
// The zero value is DatasetUnavailable, mirroring the Rust enum's Default: the alternative — an
// empty component list that finds nothing — is indistinguishable from a clean scan. A caller must
// be able to tell "checked 76 libraries" from "never had a corpus to check against".
type DatasetState int

const (
	// DatasetUnavailable means no corpus was loaded; DatasetSummary.UnavailableReason says why.
	DatasetUnavailable DatasetState = iota
	// DatasetLoaded means a corpus parsed and its counts are real.
	DatasetLoaded
)

// IsAvailable reports whether a corpus was actually loaded.
func (s DatasetState) IsAvailable() bool { return s == DatasetLoaded }

func (s DatasetState) String() string {
	if s == DatasetLoaded {
		return "loaded"
	}
	return "unavailable"
}

// MarshalJSON renders the state as the word a report shows, not as an integer a reader has to map
// back by hand.
func (s DatasetState) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// DatasetSummary is what loading the corpus produced. Every number here appears in the coverage
// report, because a negative result is only as good as the corpus and the fraction of it this
// engine can evaluate.
type DatasetSummary struct {
	// Source is where the corpus came from — the vendored name or the operator's path.
	Source     string `json:"source"`
	Components int    `json:"components"`
	// Vulnerabilities counts entries loaded with an evaluable range.
	Vulnerabilities int `json:"vulnerabilities"`
	URLPatterns     int `json:"url_patterns"`
	ContentPatterns int `json:"content_patterns"`
	// ContentPatternsWithoutPrefilter counts content patterns for which no required literal could be
	// derived, so they run against every JavaScript body rather than only the ones that could match.
	// A cost figure, not a coverage one — those patterns are never skipped.
	ContentPatternsWithoutPrefilter int `json:"content_patterns_without_prefilter"`
	// HashEntries counts whole-file SHA-1 → version mappings loaded. Implemented here where the
	// Rust module refuses them; see divergence 1 in the file docs.
	HashEntries int `json:"hash_entries"`
	// UnsupportedFuncExtractors counts `func` extractors skipped: they need a JavaScript engine.
	UnsupportedFuncExtractors int `json:"unsupported_func_extractors"`
	// UnsupportedReplaceExtractors counts `filecontentreplace` extractors skipped: a sed-style
	// rewrite, not a match.
	UnsupportedReplaceExtractors int `json:"unsupported_replace_extractors"`
	// NarrowedPatterns names every corpus regex whose bounded repeat RE2 would not accept and which
	// was clamped to compile. Each entry can now match less than the corpus pattern does.
	NarrowedPatterns []string `json:"narrowed_patterns"`
	// UnusablePatterns names corpus regexes this engine rejected outright, with the reason.
	UnusablePatterns []string `json:"unusable_patterns"`
	// UnusableRanges names vulnerability entries dropped because their range was not evaluable.
	UnusableRanges []string `json:"unusable_ranges"`
	// UnusableComponents names components whose JSON did not have the corpus's shape.
	UnusableComponents []string     `json:"unusable_components"`
	State              DatasetState `json:"state"`
	// UnavailableReason is non-empty exactly when State is DatasetUnavailable.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

func unavailableSummary(source, why string) DatasetSummary {
	return DatasetSummary{Source: source, State: DatasetUnavailable, UnavailableReason: why}
}

// Summary is one line an operator can act on. Names the source and the refusals, never just the
// totals.
func (d DatasetSummary) Summary() string {
	if !d.State.IsAvailable() {
		return fmt.Sprintf("js vulnerability dataset UNAVAILABLE (%s): %s", d.Source, d.UnavailableReason)
	}
	return fmt.Sprintf(
		"%d components, %d vulnerabilities, %d url + %d content patterns + %d file hashes from %s; "+
			"skipped %d func / %d replace extractors, %d narrowed patterns, %d unusable patterns, "+
			"%d unusable ranges, %d unusable components",
		d.Components,
		d.Vulnerabilities,
		d.URLPatterns,
		d.ContentPatterns,
		d.HashEntries,
		d.Source,
		d.UnsupportedFuncExtractors,
		d.UnsupportedReplaceExtractors,
		len(d.NarrowedPatterns),
		len(d.UnusablePatterns),
		len(d.UnusableRanges),
		len(d.UnusableComponents),
	)
}

// contentPattern is one `filecontent` regex plus the literal every match of it must contain.
//
// literal is the prefilter: a substring search for it is one to three orders of magnitude cheaper
// than running the pattern, and a body that does not contain it cannot match. Empty when no literal
// could be derived — those patterns always run, so a failed derivation costs speed and never
// coverage.
type contentPattern struct {
	re      *regexp.Regexp
	literal string
}

// JsVulnDb is the parsed corpus.
type JsVulnDb struct {
	components []jsComponent
	// content holds every `filecontent` regex, flat, in component order.
	content []contentPattern
	// contentOwner is parallel to content: which component each flat pattern belongs to.
	contentOwner []int
	summary      DatasetSummary
}

var (
	vendoredJsOnce sync.Once
	vendoredJsDb   *JsVulnDb
)

// VendoredJsVulnDb returns the corpus compiled into the binary. Always available.
//
// Parsed once per process and shared: the result is immutable after parse, and every caller wants
// the same 514 KB of JSON turned into the same tables.
func VendoredJsVulnDb() *JsVulnDb {
	vendoredJsOnce.Do(func() {
		vendoredJsDb = parseJsVulnDb(vendoredRetireJS, vendoredRetireJSName)
	})
	return vendoredJsDb
}

// LoadJsVulnDb reads a refreshed corpus from disk, in the same jsrepository.json shape.
//
// A missing or unreadable file yields a DatasetUnavailable database, not an error the caller can
// drop on the floor: the check must still appear in the coverage report, saying it had nothing to
// check against.
func LoadJsVulnDb(path string) *JsVulnDb {
	src, err := os.ReadFile(path)
	if err != nil {
		return emptyJsVulnDb(unavailableSummary(path, err.Error()))
	}
	return parseJsVulnDb(string(src), path)
}

// UnavailableJsVulnDb is an explicitly unavailable database, for a caller that has decided not to
// load one.
func UnavailableJsVulnDb(why string) *JsVulnDb {
	return emptyJsVulnDb(unavailableSummary("<none>", why))
}

func emptyJsVulnDb(summary DatasetSummary) *JsVulnDb {
	return &JsVulnDb{summary: summary}
}

// Summary returns what loading this corpus produced.
func (db *JsVulnDb) Summary() DatasetSummary { return db.summary }

// retireComponent is one component as the corpus spells it.
type retireComponent struct {
	Extractors retireExtractors `json:"extractors"`
	Vulns      []retireVuln     `json:"vulnerabilities"`
}

type retireExtractors struct {
	URI                []string          `json:"uri"`
	Filename           []string          `json:"filename"`
	FileContent        []string          `json:"filecontent"`
	FileContentReplace []string          `json:"filecontentreplace"`
	Func               []string          `json:"func"`
	Hashes             map[string]string `json:"hashes"`
}

type retireVuln struct {
	AtOrAbove   *string                    `json:"atOrAbove"`
	Above       *string                    `json:"above"`
	Below       *string                    `json:"below"`
	AtOrBelow   *string                    `json:"atOrBelow"`
	Severity    string                     `json:"severity"`
	Identifiers map[string]json.RawMessage `json:"identifiers"`
}

// parseJsVulnDb turns one jsrepository.json into tables, recording everything it could not use.
//
// Components are visited in sorted name order so two runs over the same corpus produce findings in
// the same order — Go's map iteration is deliberately randomised, and a scanner whose report order
// changes between runs is a scanner whose diffs cannot be read.
func parseJsVulnDb(src, source string) *JsVulnDb {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(src), &root); err != nil {
		if !json.Valid([]byte(src)) {
			return emptyJsVulnDb(unavailableSummary(source,
				fmt.Sprintf("not parsable as jsrepository JSON: %v", err)))
		}
		return emptyJsVulnDb(unavailableSummary(source,
			"top level is not a JSON object of component names"))
	}

	summary := DatasetSummary{Source: source, State: DatasetLoaded}
	names := make([]string, 0, len(root))
	for n := range root {
		names = append(names, n)
	}
	sort.Strings(names)

	db := &JsVulnDb{}
	for _, name := range names {
		var comp retireComponent
		if err := json.Unmarshal(root[name], &comp); err != nil {
			summary.UnusableComponents = append(summary.UnusableComponents,
				fmt.Sprintf("%s: %v", name, err))
			continue
		}
		ci := len(db.components)

		var urls []urlPattern
		for _, kind := range []struct {
			label string
			pats  []string
		}{{"uri", comp.Extractors.URI}, {"filename", comp.Extractors.Filename}} {
			for _, raw := range kind.pats {
				strict, notes, err := compileCorpusPattern(substituteVersion(raw, strictVersionPattern))
				if err != nil {
					summary.UnusablePatterns = append(summary.UnusablePatterns,
						fmt.Sprintf("%s %s: %v", name, kind.label, err))
					continue
				}
				loose, looseNotes, err := compileCorpusPattern(substituteVersion(raw, looseVersionPattern))
				if err != nil {
					summary.UnusablePatterns = append(summary.UnusablePatterns,
						fmt.Sprintf("%s %s (loose form): %v", name, kind.label, err))
					continue
				}
				summary.NarrowedPatterns = appendNarrowed(summary.NarrowedPatterns, name, kind.label, notes)
				summary.NarrowedPatterns = appendNarrowed(summary.NarrowedPatterns, name, kind.label+" (loose form)", looseNotes)
				urls = append(urls, urlPattern{strict: strict, loose: loose})
			}
		}

		ownContent := 0
		for _, raw := range comp.Extractors.FileContent {
			re, notes, err := compileCorpusPattern(substituteVersion(raw, strictVersionPattern))
			if err != nil {
				summary.UnusablePatterns = append(summary.UnusablePatterns,
					fmt.Sprintf("%s filecontent: %v", name, err))
				continue
			}
			summary.NarrowedPatterns = appendNarrowed(summary.NarrowedPatterns, name, "filecontent", notes)
			ownContent++
			lit := requiredLiteral(re.String())
			if lit == "" {
				summary.ContentPatternsWithoutPrefilter++
			}
			db.content = append(db.content, contentPattern{re: re, literal: lit})
			db.contentOwner = append(db.contentOwner, ci)
		}

		summary.UnsupportedFuncExtractors += len(comp.Extractors.Func)
		summary.UnsupportedReplaceExtractors += len(comp.Extractors.FileContentReplace)

		var hashes map[string]string
		for h, v := range comp.Extractors.Hashes {
			if hashes == nil {
				hashes = make(map[string]string, len(comp.Extractors.Hashes))
			}
			hashes[strings.ToLower(h)] = v
		}
		summary.HashEntries += len(hashes)

		var vulns []Vuln
		dropped := 0
		for _, v := range comp.Vulns {
			r, ok := rangeOf(v)
			if !ok {
				dropped++
				summary.UnusableRanges = append(summary.UnusableRanges,
					fmt.Sprintf("%s: %s", name, rangeText(v)))
				continue
			}
			vulns = append(vulns, Vuln{
				Range:       r,
				Severity:    severityOf(v),
				Summary:     identifierString(v, "summary"),
				Identifiers: identifiersOf(v),
			})
		}

		summary.URLPatterns += len(urls)
		summary.ContentPatterns += ownContent
		summary.Vulnerabilities += len(vulns)
		db.components = append(db.components, jsComponent{
			name:         name,
			url:          urls,
			hashes:       hashes,
			vulns:        vulns,
			droppedVulns: dropped,
		})
	}
	summary.Components = len(db.components)
	db.summary = summary
	return db
}

func appendNarrowed(dst []string, component, kind string, notes []string) []string {
	for _, n := range notes {
		dst = append(dst, fmt.Sprintf("%s %s: %s", component, kind, n))
	}
	return dst
}

// signal is which evidence identified a library.
type signal int

const (
	// signalURL is a `uri`/`filename` pattern matching the request path. A claim about how the file
	// is named.
	signalURL signal = iota
	// signalContent is a `filecontent` version marker matching inside the body. A claim about the
	// file itself.
	signalContent
	// signalHash is a whole-file SHA-1 matching a corpus hash. A claim about the exact bytes.
	signalHash
)

// confidence is the ladder from the phase design: naming is tentative, an in-content marker is
// firm, and a whole-file hash is certain — the tier the Rust module reserves for a content-hash
// match and does not fill, because it does not implement hashes.
func (s signal) confidence() string {
	switch s {
	case signalHash:
		return "certain"
	case signalContent:
		return "firm"
	default:
		return "tentative"
	}
}

func (s signal) label() string {
	switch s {
	case signalHash:
		return "whole-file SHA-1"
	case signalContent:
		return "in-content version marker"
	default:
		return "URL"
	}
}

// detection is one library identified in one asset.
type detection struct {
	componentIx int
	component   string
	rawVersion  string
	version     Version
	comparable  bool
	signal      signal
}

func newDetection(ix int, c jsComponent, raw string, sig signal) detection {
	v, ok := ParseVersion(raw)
	return detection{
		componentIx: ix,
		component:   c.name,
		rawVersion:  raw,
		version:     v,
		comparable:  ok,
		signal:      sig,
	}
}

// pushDetection adds a detection unless the same (library, version) is already there, keeping the
// stronger signal when it is.
//
// A linear scan: one asset yields a handful of detections, so a hash map would cost more to build
// than the scan costs to run.
func pushDetection(out []detection, d detection) []detection {
	for i := range out {
		if out[i].componentIx == d.componentIx && out[i].rawVersion == d.rawVersion {
			if d.signal > out[i].signal {
				out[i].signal = d.signal
			}
			return out
		}
	}
	return append(out, d)
}

// verdict is the three possible answers. There is no fourth, and verdictNotVulnerable is the only
// one that justifies saying nothing.
type verdict int

const (
	verdictVulnerable verdict = iota
	verdictNotVulnerable
	verdictUndetermined
)

// detect identifies libraries in one asset: url is the request path, body the response body.
//
// One (library, version) appears once. The corpus has several `filecontent` patterns per library
// that overlap by design — jQuery has eleven, and a real jQuery banner matches two of them — so
// without collapsing them the same library at the same version would be reported twice and counted
// twice. The coverage counters here would be wrong, and they are the numbers a report leans on.
//
// The hash pass runs first and takes precedence: a whole-file SHA-1 names the exact file, so a
// filename or banner guess about the same component adds nothing but a duplicate finding.
func (db *JsVulnDb) detect(url string, body []byte) []detection {
	var out []detection
	identifiedByHash := make(map[int]bool)
	if len(body) > 0 {
		sum := sha1.Sum(body)
		digest := hex.EncodeToString(sum[:])
		for ci, c := range db.components {
			if v, ok := c.hashes[digest]; ok {
				identifiedByHash[ci] = true
				out = pushDetection(out, newDetection(ci, c, v, signalHash))
			}
		}
	}

	filename := url
	if i := strings.LastIndex(url, "/"); i >= 0 {
		filename = url[i+1:]
	}
	for ci, c := range db.components {
		if identifiedByHash[ci] {
			continue
		}
		raw, hit := "", false
		for _, p := range c.url {
			if v, ok := captureVersion(p.strict, url); ok {
				raw, hit = v, true
				break
			}
			if v, ok := captureVersion(p.strict, filename); ok {
				raw, hit = v, true
				break
			}
		}
		if !hit {
			for _, p := range c.url {
				if v, ok := captureVersion(p.loose, url); ok {
					raw, hit = v, true
					break
				}
				if v, ok := captureVersion(p.loose, filename); ok {
					raw, hit = v, true
					break
				}
			}
		}
		if hit {
			out = pushDetection(out, newDetection(ci, c, raw, signalURL))
		}
	}

	// The `filecontent` patterns, in component order, each gated on its required literal. Only valid
	// UTF-8 is scanned, matching the Rust module — the corpus patterns are text patterns and a regex
	// run over arbitrary bytes would report matches inside what is really a binary blob.
	//
	// present memoises the substring searches, because the corpus reuses a literal across several
	// patterns of the same library (jQuery has eleven content patterns) and searching a 540 KB body
	// once per pattern for the same string is the cost this prefilter exists to remove.
	if utf8.Valid(body) {
		text := string(body)
		present := make(map[string]bool)
		for i, p := range db.content {
			ci := db.contentOwner[i]
			if identifiedByHash[ci] {
				continue
			}
			if p.literal != "" {
				hit, known := present[p.literal]
				if !known {
					hit = strings.Contains(text, p.literal)
					present[p.literal] = hit
				}
				if !hit {
					continue
				}
			}
			if v, ok := captureVersion(p.re, text); ok {
				out = pushDetection(out, newDetection(ci, db.components[ci], v, signalContent))
			}
		}
	}
	return out
}

// requiredLiteral returns a literal string that every match of pattern must contain, or "" when none
// can be derived.
//
// Soundness is the whole point, so the walk only accepts a literal from a position that is
// *unavoidable*: the sole child of a capture, the body of a `+` or a `{n,}` with n ≥ 1, or any member
// of a concatenation (every member must match for the concatenation to match). Anything optional
// (`?`, `*`, `{0,n}`), any alternation (only one branch has to match), and any case-insensitive
// literal (a substring search would not find the other casing) yield "" — which makes the pattern run
// unconditionally. Erring that way costs time; erring the other way would make the check blind to a
// library while its pattern count still claimed otherwise.
//
// Derived from the pattern source as compiled, so a narrowed pattern's literal describes the narrowed
// pattern rather than the corpus's original.
func requiredLiteral(pattern string) string {
	ast, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return ""
	}
	lit := requiredLiteralOf(ast)
	if len(lit) < minPrefilterLiteral {
		return ""
	}
	return lit
}

// minPrefilterLiteral is the shortest literal worth searching for. `.` or `v` occurs in essentially
// every JavaScript file, so gating on one buys a whole extra pass over the body and skips nothing;
// below this length the pattern is cheaper to just run.
const minPrefilterLiteral = 3

func requiredLiteralOf(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return ""
		}
		return string(re.Rune)
	case syntax.OpCapture:
		return requiredLiteralOf(re.Sub[0])
	case syntax.OpPlus:
		return requiredLiteralOf(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiteralOf(re.Sub[0])
		}
		return ""
	case syntax.OpConcat:
		best := ""
		for _, sub := range re.Sub {
			// The longest required literal is the most selective prefilter, and every member of a
			// concatenation is required, so taking the longest is sound.
			if lit := requiredLiteralOf(sub); len(lit) > len(best) {
				best = lit
			}
		}
		return best
	}
	return ""
}

// judge decides one detection against the component's known vulnerabilities.
func (db *JsVulnDb) judge(d detection) (verdict, []Vuln, string) {
	c := db.components[d.componentIx]
	if !d.comparable {
		return verdictUndetermined, nil, fmt.Sprintf("version string %q is not comparable", d.rawVersion)
	}
	var hits []Vuln
	for _, v := range c.vulns {
		if v.Range.Contains(d.version) {
			hits = append(hits, v)
		}
	}
	if len(hits) > 0 {
		return verdictVulnerable, hits, ""
	}
	if c.droppedVulns > 0 {
		return verdictUndetermined, nil, fmt.Sprintf(
			"%d of %d known vulnerabilities for %s have ranges this engine cannot evaluate, so %s is not cleared",
			c.droppedVulns, c.droppedVulns+len(c.vulns), c.name, d.version)
	}
	return verdictNotVulnerable, nil, ""
}

// JsCoverage is what SCAN-01 actually looked at. Dataset first, because every other number here is
// worthless without knowing which corpus produced it.
type JsCoverage struct {
	Dataset DatasetSummary `json:"dataset"`
	// Responses counts responses handed to the check.
	Responses uint64 `json:"responses"`
	// NotJavaScript counts responses that did not look like a JavaScript asset, so were not
	// examined.
	NotJavaScript uint64 `json:"not_javascript"`
	// AssetsSeen counts JavaScript assets examined.
	AssetsSeen uint64 `json:"assets_seen"`
	// AssetsIdentified counts assets where a library *and* a comparable version were identified.
	AssetsIdentified uint64 `json:"assets_identified"`
	// AssetsUnidentified counts assets where no corpus pattern matched at all. **Not** clean: a
	// concatenated bundle with jQuery inlined usually matches nothing, and "0 vulnerable libraries"
	// must be distinguishable from "we could not identify any of the assets we saw".
	AssetsUnidentified uint64 `json:"assets_unidentified"`
	// DetectionsUndetermined counts detections whose version could not be compared, or whose
	// component has ranges this engine cannot evaluate. Reported as undetermined, never as clean.
	DetectionsUndetermined uint64 `json:"detections_undetermined"`
	// DetectionsVulnerable counts detections that landed inside a known-vulnerable range.
	DetectionsVulnerable uint64 `json:"detections_vulnerable"`
	// DetectionsCleared counts detections compared against the whole of their component's range set
	// with no hit — the only evidence-backed "not vulnerable" this check can produce.
	DetectionsCleared uint64 `json:"detections_cleared"`
	// DetectionsByFileHash counts detections identified by whole-file SHA-1, the only signal here
	// that earns certain confidence.
	DetectionsByFileHash uint64 `json:"detections_by_file_hash"`
	// SkippedDatasetUnavailable counts responses not examined at all because the corpus was
	// unavailable.
	SkippedDatasetUnavailable uint64 `json:"skipped_dataset_unavailable"`
}

// Inconclusive reports whether this check produced no evidence either way, for whatever reason. A
// report that shows zero findings must consult this before calling the result clean.
func (c JsCoverage) Inconclusive() bool {
	return !c.Dataset.State.IsAvailable() ||
		c.DetectionsUndetermined > 0 ||
		c.AssetsUnidentified > 0
}

// Summary is one line naming the corpus and every give-up.
func (c JsCoverage) Summary() string {
	return fmt.Sprintf(
		"%d responses, %d js assets: %d identified, %d unidentified; %d vulnerable, %d cleared, "+
			"%d undetermined detections (%d by file hash); %d skipped for an unavailable dataset. %s",
		c.Responses, c.AssetsSeen, c.AssetsIdentified, c.AssetsUnidentified,
		c.DetectionsVulnerable, c.DetectionsCleared, c.DetectionsUndetermined,
		c.DetectionsByFileHash, c.SkippedDatasetUnavailable, c.Dataset.Summary(),
	)
}

// JsLibraryCheck is SCAN-01 as a passive check: dataset plus the running record of what it looked
// at.
//
// Counters are atomics rather than a lock because each is independent and this runs from several
// off-hot-path scan tasks at once — the same reasoning as CoverageTracker's skip counters.
type JsLibraryCheck struct {
	db                 *JsVulnDb
	responses          atomic.Uint64
	notJS              atomic.Uint64
	assets             atomic.Uint64
	identified         atomic.Uint64
	unidentified       atomic.Uint64
	undetermined       atomic.Uint64
	vulnerable         atomic.Uint64
	cleared            atomic.Uint64
	byHash             atomic.Uint64
	datasetUnavailable atomic.Uint64
}

// JsLibraryCheckName is the check's name, as coverage and logs spell it.
const JsLibraryCheckName = "Vulnerable JavaScript dependency (SCAN-01)"

// NewJsLibraryCheck wraps one corpus in a check.
func NewJsLibraryCheck(db *JsVulnDb) *JsLibraryCheck {
	if db == nil {
		db = UnavailableJsVulnDb("no dataset supplied")
	}
	return &JsLibraryCheck{db: db}
}

// VendoredJsLibraryCheck is the vendored corpus, which is what a caller wants unless an operator
// supplied a fresher one.
func VendoredJsLibraryCheck() *JsLibraryCheck { return NewJsLibraryCheck(VendoredJsVulnDb()) }

// Coverage returns a point-in-time snapshot of what this check looked at.
func (c *JsLibraryCheck) Coverage() JsCoverage {
	return JsCoverage{
		Dataset:                   c.db.summary,
		Responses:                 c.responses.Load(),
		NotJavaScript:             c.notJS.Load(),
		AssetsSeen:                c.assets.Load(),
		AssetsIdentified:          c.identified.Load(),
		AssetsUnidentified:        c.unidentified.Load(),
		DetectionsUndetermined:    c.undetermined.Load(),
		DetectionsVulnerable:      c.vulnerable.Load(),
		DetectionsCleared:         c.cleared.Load(),
		DetectionsByFileHash:      c.byHash.Load(),
		SkippedDatasetUnavailable: c.datasetUnavailable.Load(),
	}
}

// Scan examines one response. path is the request path the response answered, which is where a
// `filename`/`uri` extractor looks.
func (c *JsLibraryCheck) Scan(path, contentType string, body []byte) []*Finding {
	c.responses.Add(1)
	if !c.db.summary.State.IsAvailable() {
		c.datasetUnavailable.Add(1)
		return nil
	}
	if !looksLikeJavaScript(path, contentType) {
		c.notJS.Add(1)
		return nil
	}
	c.assets.Add(1)

	detections := c.db.detect(path, body)
	if len(detections) == 0 {
		c.unidentified.Add(1)
		return nil
	}

	var out []*Finding
	anyComparable := false
	for _, d := range detections {
		if d.signal == signalHash {
			c.byHash.Add(1)
		}
		v, hits, why := c.db.judge(d)
		switch v {
		case verdictVulnerable:
			anyComparable = true
			c.vulnerable.Add(1)
			out = append(out, vulnerableJsFinding(d, hits, c.db.summary))
		case verdictNotVulnerable:
			anyComparable = true
			c.cleared.Add(1)
		case verdictUndetermined:
			c.undetermined.Add(1)
			out = append(out, undeterminedJsFinding(d, why, c.db.summary))
		}
	}
	if anyComparable {
		c.identified.Add(1)
	}
	return out
}

// vulnerableJsFinding builds a vulnerability finding. Severity comes from the corpus entry,
// confidence from the signal that identified the library — never promoted past what the evidence
// supports.
func vulnerableJsFinding(d detection, hits []Vuln, ds DatasetSummary) *Finding {
	worst := 0
	for _, h := range hits {
		if r := severityRank(h.Severity); r > worst {
			worst = r
		}
	}
	word := "vulnerabilities"
	if len(hits) == 1 {
		word = "vulnerability"
	}
	var detail strings.Builder
	fmt.Fprintf(&detail, "%s %s matched %d known %s (%s signal). Corpus: %s.",
		d.component, d.version, len(hits), word, d.signal.label(), ds.Source)
	for _, h := range hits {
		fmt.Fprintf(&detail, "\n  %s [%s]", h.Range.Text(), h.Severity)
		if h.Summary != "" {
			fmt.Fprintf(&detail, " %s", h.Summary)
		}
		if len(h.Identifiers) > 0 {
			fmt.Fprintf(&detail, " (%s)", strings.Join(h.Identifiers, ", "))
		}
	}
	return &Finding{
		Name:        jsIssue,
		Severity:    rankSeverity(worst),
		Confidence:  d.signal.confidence(),
		Description: detail.String(),
		Evidence:    d.component + "@" + d.version.String(),
		// Solution is left empty on purpose: EnrichFinding fills it from Burp's catalogued
		// definition for this exact issue name, which is real remediation text rather than something
		// written here.
		Timestamp: time.Now(),
	}
}

// undeterminedJsFinding reports a non-conclusion as one. Info/tentative because that is exactly what
// it is worth: evidence that something was served which this engine could not evaluate.
func undeterminedJsFinding(d detection, why string, ds DatasetSummary) *Finding {
	return &Finding{
		Name:       jsUndeterminedIssue,
		Severity:   "info",
		Confidence: "tentative",
		Description: fmt.Sprintf(
			"%s was identified but not assessed: %s. This is not a clean result — the library may or "+
				"may not be vulnerable. Corpus: %s.", d.component, why, ds.Source),
		Evidence: d.component + "@" + d.rawVersion,
		// This issue name is deliberately not in Burp's catalogue, so there is no catalogued
		// remediation to enrich from and this sentence is the honest instruction instead.
		Solution: "Determine the exact library version served at this path and re-check it against " +
			"the advisory data by hand.",
		Timestamp: time.Now(),
	}
}

// looksLikeJavaScript reports whether this response is worth looking at as a JavaScript asset.
//
// Path suffix or Content-Type, either alone. Servers get Content-Type wrong on static assets often
// enough that requiring both would silently skip real scripts, and requiring only the type would
// skip the `.js` files served as `text/plain`.
func looksLikeJavaScript(path, contentType string) bool {
	stem := path
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		stem = path[:i]
	}
	lower := strings.ToLower(stem)
	if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") {
		return true
	}
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// captureVersion runs one pattern and returns its version capture group.
//
// Group 1 by convention: every corpus pattern wraps `§§version§§` in its own parentheses. A pattern
// that matched but captured nothing is treated as no match — a "match" with no version is not
// something this check can do anything with.
func captureVersion(re *regexp.Regexp, hay string) (string, bool) {
	m := re.FindStringSubmatch(hay)
	if len(m) < 2 || m[1] == "" {
		return "", false
	}
	return m[1], true
}

func substituteVersion(pattern, version string) string {
	return strings.ReplaceAll(pattern, versionPlaceholder, version)
}

// maxRE2Repeat is the largest bounded-repeat count Go's regexp/syntax accepts. Nine of the corpus's
// `filecontent` patterns use a larger one.
const maxRE2Repeat = 1000

// compileCorpusPattern compiles one corpus regex, narrowing an over-large bounded repeat rather
// than dropping the pattern.
//
// The returned notes name every repeat that was clamped, so DatasetSummary can say which patterns
// now match less than the corpus says they should. A pattern that still will not compile — a
// backreference or a lookbehind, neither of which RE2 has — is returned as an error and counted,
// never silently dropped.
func compileCorpusPattern(pattern string) (*regexp.Regexp, []string, error) {
	re, err := regexp.Compile(pattern)
	if err == nil {
		return re, nil, nil
	}
	narrowed, notes := narrowBoundedRepeats(pattern)
	if len(notes) == 0 {
		return nil, nil, err
	}
	re, narrowErr := regexp.Compile(narrowed)
	if narrowErr != nil {
		// The narrowed form is no better; report the original refusal, which is the one an operator
		// can look up.
		return nil, nil, err
	}
	return re, notes, nil
}

// narrowBoundedRepeats clamps every `{m,n}` whose n exceeds RE2's ceiling down to `{m,1000}`.
//
// Only the upper bound of a two-sided repeat is touched, and only downwards. That direction is the
// whole point: a smaller upper bound matches a strict subset of what the corpus pattern matches, so
// the worst it can do is miss a library (a false negative, the same thing dropping the pattern
// would do, only smaller). Clamping a fixed `{n}` would go the other way — `X{5000}` narrowed to
// `X{1000}` starts matching shorter runs the corpus pattern rejects — so a fixed repeat is left
// alone and the pattern is refused instead. A lower bound above the ceiling cannot be narrowed
// either, since `{1500,1000}` is not a repeat at all.
//
// The walk tracks escapes and character classes so a literal `{` inside `[...]` or after a
// backslash is never mistaken for a repeat.
func narrowBoundedRepeats(pattern string) (string, []string) {
	var out strings.Builder
	var notes []string
	inClass := false
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch {
		case ch == '\\' && i+1 < len(pattern):
			out.WriteByte(ch)
			out.WriteByte(pattern[i+1])
			i++
			continue
		case ch == '[':
			inClass = true
		case ch == ']':
			inClass = false
		case ch == '{' && !inClass:
			lo, hi, end, ok := parseRepeat(pattern, i)
			if ok && hi > maxRE2Repeat && lo <= maxRE2Repeat {
				fmt.Fprintf(&out, "{%d,%d}", lo, maxRE2Repeat)
				notes = append(notes, fmt.Sprintf("{%d,%d} narrowed to {%d,%d}", lo, hi, lo, maxRE2Repeat))
				i = end - 1
				continue
			}
		}
		out.WriteByte(ch)
	}
	if len(notes) == 0 {
		return pattern, nil
	}
	return out.String(), notes
}

// parseRepeat reads a `{m,n}` starting at pattern[at]. ok is false for `{m}`, `{m,}`, or anything
// that is not a repeat at all — those are the forms narrowBoundedRepeats must not touch.
func parseRepeat(pattern string, at int) (lo, hi, end int, ok bool) {
	brace := strings.IndexByte(pattern[at:], '}')
	if brace < 0 {
		return 0, 0, 0, false
	}
	end = at + brace + 1
	body := pattern[at+1 : at+brace]
	comma := strings.IndexByte(body, ',')
	if comma < 0 {
		return 0, 0, 0, false
	}
	loStr, hiStr := body[:comma], body[comma+1:]
	if loStr == "" || hiStr == "" {
		return 0, 0, 0, false
	}
	lo, err := strconv.Atoi(loStr)
	if err != nil {
		return 0, 0, 0, false
	}
	hi, err = strconv.Atoi(hiStr)
	if err != nil {
		return 0, 0, 0, false
	}
	return lo, hi, end, true
}

// rangeOf builds a range from one corpus vulnerability entry, or refuses it.
//
// Refuses an entry with no evaluable bound at all: a bound-free range matches every version, so
// loading one would flag every sighting of the library as vulnerable. A bound that does not parse
// is a refusal for the same reason it is elsewhere in this file — the comparison would be a guess.
func rangeOf(v retireVuln) (VersionRange, bool) {
	var lower, upper *versionEdge
	var parts []string
	for _, b := range []struct {
		key       string
		val       *string
		inclusive bool
	}{{"atOrAbove", v.AtOrAbove, true}, {"above", v.Above, false}} {
		if b.val == nil {
			continue
		}
		at, ok := ParseVersion(*b.val)
		if !ok {
			return VersionRange{}, false
		}
		parts = append(parts, b.key+" "+*b.val)
		lower = &versionEdge{at: at, inclusive: b.inclusive}
	}
	for _, b := range []struct {
		key       string
		val       *string
		inclusive bool
	}{{"atOrBelow", v.AtOrBelow, true}, {"below", v.Below, false}} {
		if b.val == nil {
			continue
		}
		at, ok := ParseVersion(*b.val)
		if !ok {
			return VersionRange{}, false
		}
		parts = append(parts, b.key+" "+*b.val)
		upper = &versionEdge{at: at, inclusive: b.inclusive}
	}
	if lower == nil && upper == nil {
		return VersionRange{}, false
	}
	return VersionRange{lower: lower, upper: upper, text: strings.Join(parts, ", ")}, true
}

func rangeText(v retireVuln) string {
	var parts []string
	for _, b := range []struct {
		key string
		val *string
	}{{"atOrAbove", v.AtOrAbove}, {"above", v.Above}, {"atOrBelow", v.AtOrBelow}, {"below", v.Below}} {
		if b.val != nil {
			parts = append(parts, b.key+" "+*b.val)
		}
	}
	return strings.Join(parts, ", ")
}

// identifierString reads one identifier field that the corpus spells as a bare string.
func identifierString(v retireVuln, key string) string {
	raw, ok := v.Identifiers[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// identifiersOf collects the advisory ids a report should name, in the corpus's own key order.
//
// The corpus spells some of these as a string and some as an array of strings, so each is decoded
// both ways rather than assumed.
func identifiersOf(v retireVuln) []string {
	var out []string
	for _, key := range []string{"CVE", "githubID", "bug", "issue", "retid", "osvdb"} {
		raw, ok := v.Identifiers[key]
		if !ok {
			continue
		}
		var list []string
		if err := json.Unmarshal(raw, &list); err == nil {
			out = append(out, list...)
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// severityOf canonicalises the corpus's severity words onto Finding.Severity's vocabulary.
//
// `critical` is kept rather than folded onto high: Finding.Severity already has that level, so
// folding would discard what the corpus said. An unrecognised word becomes medium — the corpus
// called it a vulnerability, so dropping to info would understate it.
func severityOf(v retireVuln) string {
	switch v.Severity {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func rankSeverity(r int) string {
	switch r {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "info"
	}
}

// jsAssetOf pulls the path, content type and body a Scan needs out of one stored exchange.
//
// Returns ok == false when the exchange has no stored response: there is no asset to look at, which
// the caller must count rather than treat as a clean scan.
func jsAssetOf(store *core.TrafficStore, exchange *core.Exchange) (path, contentType string, body []byte, ok bool) {
	if exchange == nil || exchange.Response == nil {
		return "", "", nil, false
	}
	msg, err := store.Get(*exchange.Response)
	if err != nil {
		return "", "", nil, false
	}
	return exchange.Path, string(msg.Header("Content-Type")), readableBody(msg), true
}
