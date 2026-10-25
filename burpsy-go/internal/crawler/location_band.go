// A bounded tolerance band on location identity (burpsy-react-ui-9x67).
//
// # The problem this file exists for
//
// The location fingerprint is an exact hash of four components, and fingerprint.go's header
// documents the deliberate consequence: the outgoing link targets are kept RAW, so a page whose
// links rotate — a cache-buster, a nonce, a trace id in the query — is a brand-new location on
// every visit. The crawl re-walks it, and the frontier fills with near-identical pages.
//
// Burp does not have that problem. Its identity comparison is a tolerance, not a hash-equality
// test: `burp.Zmqs.NORMAL` ships `total_unmatched_action_descriptor_tolerance = 2` and
// `unmatched_anchor_tolerance = 2` (deobf_merged/burp/Zmqs.java:243), bound to the
// `crawler.crawl_optimization.total_unmatched_feature_tolerance` and
// `maximum_unmatched_anchor_tolerance` keys at Zeuc.java:17-18 and read through Zgjj.java:145-147.
// Burp's MORE_COMPLETE and MOST_COMPLETE strategies set both to 0, so the value is a per-strategy
// setting rather than a constant of the algorithm — but 2 is what Burp ships by default, and it is
// the closest analogue to the question this band answers: how much of a page already known may be
// missing and still be that page.
//
// # What the band tolerates, and what it must never tolerate
//
// One axis only: **query VALUES in a link target.** Two link targets are the same link for this
// purpose when they agree on scheme, host, port, path and the sorted set of query parameter NAMES,
// and differ only in what those parameters carry. A page whose link targets reduce to the same
// keys as a known location's, with at most `locationToleranceBand` of them carrying different
// values, is folded into that location.
//
// Everything else is refused, and those refusals are the load-bearing part:
//
//   - **A different path is never tolerated.** `/users/1/edit` and `/users/2/edit` are different
//     links, so `/users/1` and `/users/2` stay two locations. This is the false merge
//     discover.go calls the single worst failure this package can have: templating link targets
//     would make a crawl of a fifty-thousand-row table fetch one row and report a completed
//     crawl. The band is a tolerance on values, and a path segment is not a value.
//   - **A different shape is never tolerated.** The skeleton and the text bucket must match
//     exactly, which is what the shape digest keys on. A page that differs structurally is a
//     different page, and the band never sees it — it is in a different bucket and the comparison
//     is never made.
//
// # What a too-wide band costs
//
// The residual false merge the band introduces is narrow and named: two genuinely different
// locations differing in no way except the values their links carry. `/report?range=1` and
// `/report?range=2` are the shape. A band of 2 folds such a pair; a band with no upper bound folds
// any page whose whole link set is value-perturbed, which on a report or a paginated listing is
// one page of many presented as one. That is the same class of residual the log2 text-length
// bucket already carries and the fingerprint header already names ("two pages with no outgoing
// links, the same structure and similarly-sized text merge"). The band extends an
// already-documented coarseness by one bounded axis; it does not introduce a new direction of
// error. The bound is what keeps it a tolerance rather than a merge.
//
// # What the band cannot reach, stated plainly
//
// A session id in the PATH — `/(S(abc123))/Default.aspx`, the classic ASP.NET form the package
// docs name as a false-split case — is a different path and so is not folded. Templating path
// segments here would be the false merge above, for the same reason and with the same
// consequence. The band covers query values; that limit is the price of not merging detail pages,
// and it is the honest one to pay.
//
// # The memory argument
//
// Comparing a candidate against every known location is O(L) per response. This file does not do
// that: a fold requires the shape digest — skeleton, form signatures, text bucket — to be
// identical, so only locations sharing it can match, and the shape index on the Crawler makes that
// a bucket lookup. The cost is one extra map plus one fingerprint string per distinct shape, and
// one sorted raw-target slice and one sorted relaxed-key slice per location: bounded by
// Limits.MaxLocations locations and Limits.MaxLinksPerPage links each, the same two bounds that
// already cap the crawl. The band buys a bounded amount of memory for a bounded number of
// duplicate fetches, and both bounds are the crawl's own.
package crawler

import (
	"math/bits"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// locationToleranceBand is how many of a candidate page's link targets may carry different query
// values from the known location it is compared against, when every one of its link targets is the
// same link by path and parameter names.
//
// 2 is Burp's shipped default for the same question: `Zmqs.NORMAL` sets both
// `totalUnmatchedActionDescriptorTolerance` and `unmatchedAnchorTolerance` to 2
// (deobf_merged/burp/Zmqs.java:243). Burp's two more complete strategies set both to 0, so this is
// a strategy setting rather than an algorithmic constant — 2 is the value that ships, and naming
// it here makes the choice a decision on the record rather than an accident.
// A band of 0 disables the tolerance entirely, which is the pre-9x67 behaviour. A band that
// scaled with the number of links on the page would fold a whole link set at once, which is the
// false merge this file refuses; see the header.
const locationToleranceBand = 2

// shapeSeparator separates a shape digest's components in its preimage. Two newlines followed by
// a hash mark cannot appear in a path or a query parameter name, so no document can produce the
// same preimage by moving a component boundary across it.
const shapeSeparator = "\n##"

// locationEntry is what the crawl remembers about one location: where it was first seen, and the
// two link-target lists the band compares against.
//
// The two lists answer different questions and both are needed. `keys` is the relaxed view — the
// same links by path and parameter names — and decides whether two pages link to the same things
// at all. `targets` is the raw view, and is what makes "differs only in values" a checkable
// statement rather than an assertion: a candidate target absent from this list is a value that
// moved, and there may be at most `locationToleranceBand` of them.
//
// Both are sorted, so the comparisons are binary searches and the band allocates nothing on the
// crawl's hot path. Storing them at all is the band's price: the exact fingerprint map held 16
// bytes of hash per location, and these hold one string per link the page carried.
type locationEntry struct {
	// at is the URL the location was first seen at, and is what a folded fetch is told it
	// duplicated. Never rewritten: the first sighting is the one an operator reads.
	at string
	// targets are the page's link targets, raw and sorted. Nil for a non-HTML location, which has
	// no link set and is never a band candidate.
	targets []string
	// keys are the same links reduced to what the band may ignore, sorted.
	keys []string
}

// newLocationEntry builds the record for a newly admitted location. targets must already be
// sorted — parsePage sorts them once and hands the same slice to the fingerprint and to here.
func newLocationEntry(at string, targets []string) locationEntry {
	return locationEntry{at: at, targets: targets, keys: relaxedLinkKeys(targets)}
}

// relaxedLinkKeys reduces a page's sorted link targets to what the tolerance band is allowed to
// ignore: the query VALUES. The returned slice is sorted, because relaxedLinkKey preserves the
// relative order of its inputs (the path comes first and the parameter names follow in sorted
// order), so sorting the keys is consistent with the order the targets arrived in.
func relaxedLinkKeys(sorted []string) []string {
	if len(sorted) == 0 {
		return nil
	}
	keys := make([]string, len(sorted))
	for i, raw := range sorted {
		keys[i] = relaxedLinkKey(raw)
	}
	sort.Strings(keys)
	return keys
}

// relaxedLinkKey reduces one resolved link target to scheme://host/path?names.
//
// An unparseable target reduces to itself, and a query that would not parse is kept whole. Both
// reduce to something the band cannot loosen further: an unparseable URL is not evidence of
// anything, and dropping a mangled query would make two different mangled queries compare equal.
func relaxedLinkKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	b.WriteString(u.Host)
	// u.Path already carries its leading slash when it has one, so this is appended unconditionally
	// rather than adding another. An empty path is written as the bare host, which is what makes
	// `http://h` and `http://h/` one key — the same equivalence requestFingerprint makes.
	b.WriteString(u.EscapedPath())
	if u.Path == "" && u.RawQuery != "" {
		b.WriteByte('/')
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil && len(values) == 0 {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
		return b.String()
	}
	if len(values) == 0 {
		return b.String()
	}
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	b.WriteByte('?')
	for i, n := range names {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(n)
	}
	return b.String()
}

// withinTolerance reports whether candidate's links are known's links with at most band values
// moved. Both slices must be sorted and are NOT modified.
//
// Two conditions, both required, and the first is what stops a too-wide band.
//
// The RELAXED KEY SETS must be equal — same links, same multiset, by path and parameter names.
// This is the refusal discover.go's header calls the single worst failure this package can have: a
// page that links somewhere genuinely different must never be folded into one that does not, or a
// crawl of a fifty-thousand-row table would fetch one row and report a completed crawl. A page
// that gained or lost a link is a new location, not a rotated one — the direction of travel that
// loses coverage is the one this refuses, and "identical link sets" is the narrowest statement
// that still admits a value rotation.
//
// Then at most band of the candidate's raw targets may be absent from known, because each such
// absence is a value that moved. The reading is deliberately one-sided: a candidate target that
// IS present in known is not evidence that nothing moved, because a repeated link
// (`<a href="/x">` twice) collapses to one entry in the target list and there is no second raw
// target to move. The key-set equality above is what carries the "same links" half of the claim;
// this count carries the "a few values moved" half.
func withinTolerance(candidateTargets, candidateKeys []string, known locationEntry, band int) bool {
	if len(candidateTargets) != len(known.targets) || len(candidateKeys) != len(known.keys) {
		return false
	}
	for i := range candidateKeys {
		if candidateKeys[i] != known.keys[i] {
			return false
		}
	}
	changed := 0
	for _, target := range candidateTargets {
		if !containsSorted(known.targets, target) {
			changed++
			if changed > band {
				return false
			}
		}
	}
	return true
}

// containsSorted is sort.SearchStrings with the result already computed, spelled out so the
// allocation-free property is visible at the call site.
func containsSorted(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}

// foldWithinTolerance looks for a known location the candidate can be folded into, and returns
// where that location was first seen.
//
// The shape digest is the bucket key and it is exact: a candidate whose skeleton, form signatures
// or text-length bucket differs cannot be in this bucket at all. That is what makes the index a
// correctness tool and not only a speed one — the band is never asked whether a structurally
// different page is close enough, because the question is never put.
//
// The candidates are tried in admission order and the FIRST match wins, so a fold names the
// earliest location the page could be, which is the one whose first sighting an operator reads.
func (c *Crawler) foldWithinTolerance(page pageStructure) (string, bool) {
	return foldWithinToleranceIn(page, c.locationShapes, c.locations, c.toleranceBand())
}

// foldWithinToleranceIn is foldWithinTolerance against an explicit location set, so the global
// count and the per-phase walk decision can each ask the question against their own maps.
func foldWithinToleranceIn(page pageStructure, shapes map[string][]string, locations map[string]locationEntry, band int) (string, bool) {
	// A shape is only ever set by a document that parsed, so an empty one here means the parse
	// produced no structure at all and there is nothing to compare. Refused before the loop rather
	// than inside it: the empty string is not a bucket key anything is indexed under.
	if page.shape == "" {
		return "", false
	}
	keys := relaxedLinkKeys(page.linkTargets)
	for _, fingerprint := range shapes[page.shape] {
		entry, known := locations[fingerprint]
		if known && withinTolerance(page.linkTargets, keys, entry, band) {
			return entry.at, true
		}
	}
	return "", false
}

// recordStructuredLocation admits one HTML response as a location, or folds it into one already
// known. It reports false when the response was not admitted as a new location, in which case the
// caller must not traverse its links — the links here are the links there.
//
// Exact-first and band-second, deliberately. An exact match costs one map lookup and is the common
// case on a static site; the band is the expensive path and must never be able to change the answer
// for a response that already matched exactly.
//
// A fold is a duplicate for every counter that counts duplicates — it was recognised as a page
// already known, and its links were not walked again — and it has its own skip reason and its own
// report field, because "the same contents" and "the same page within a tolerance" are different
// facts and an operator tuning the crawl needs to tell them apart.
func (c *Crawler) recordStructuredLocation(page pageStructure, at string, fetch *Fetch, rep *Report) bool {
	if page.fingerprint == "" {
		return true
	}
	if first, seen := c.locations[page.fingerprint]; seen {
		rep.DuplicateLocations++
		fetch.DuplicateOf = first.at
		c.skips.record(SkipRecord{
			Reason: SkipDuplicateLocation, URL: at,
			Detail: "the same contents were already seen at " + first.at,
		})
		return false
	}
	if first, folded := c.foldWithinTolerance(page); folded {
		rep.DuplicateLocations++
		rep.LocationFolds++
		fetch.DuplicateOf = first
		c.skips.record(SkipRecord{
			Reason: SkipLocationFolded, URL: at,
			Detail: "the same page with at most " + strconv.Itoa(c.toleranceBand()) +
				" link value(s) moved was already seen at " + first,
		})
		return false
	}
	c.locations[page.fingerprint] = newLocationEntry(at, page.linkTargets)
	c.locationShapes[page.shape] = append(c.locationShapes[page.shape], page.fingerprint)
	return true
}

// recordPhaseWalk decides whether this response's links are walked, against the crawl phase's own
// location set (burpsy-react-ui-crediso). It answers the question recordStructuredLocation answers
// globally — "have the links of this page already been walked" — for the phase alone: a credential
// phase re-crawls the application behind its own session, and a page an earlier phase saw (under a
// different session, or none) is NOT a reason to skip the walk here, because the walk is how the
// phase discovers what the application shows this credential. The location COUNT stays global:
// recordStructuredLocation runs first, and identical content is counted and annotated as one
// location no matter how many phases fetched it. What changes per phase is only the traversal.
// This structure records nothing and touches no counter — the duplicate and fold skips the global
// recording already wrote are the whole accounting.
func (c *Crawler) recordPhaseWalk(page pageStructure, at string) bool {
	if page.fingerprint == "" {
		return true
	}
	if _, seen := c.phaseLocations[page.fingerprint]; seen {
		return false
	}
	if _, folded := foldWithinToleranceIn(page, c.phaseLocationShapes, c.phaseLocations, c.toleranceBand()); folded {
		return false
	}
	c.phaseLocations[page.fingerprint] = newLocationEntry(at, page.linkTargets)
	c.phaseLocationShapes[page.shape] = append(c.phaseLocationShapes[page.shape], page.fingerprint)
	return true
}

// recordLocation folds one exact fingerprint into the location map. It reports false when the
// fingerprint had already been seen, in which case the fetch is annotated with where it was first
// seen and the duplicate is counted.
//
// This is the non-HTML path, and only the non-HTML path. Those responses are fingerprinted over
// their bytes (rawBodyFingerprint) and carry no link set, so there is nothing for the band to
// compare and it is not offered the chance to guess: a JSON endpoint whose body embeds a timestamp
// is a new location every time, which fingerprint.go names as the accepted cost of the exact hash
// rather than a gap this file closes.
func (c *Crawler) recordLocation(fingerprint, at string, fetch *Fetch, rep *Report) bool {
	if fingerprint == "" {
		return true
	}
	if first, seen := c.locations[fingerprint]; seen {
		rep.DuplicateLocations++
		fetch.DuplicateOf = first.at
		c.skips.record(SkipRecord{
			Reason: SkipDuplicateLocation, URL: at,
			Detail: "the same contents were already seen at " + first.at,
		})
		return false
	}
	c.locations[fingerprint] = newLocationEntry(at, nil)
	return true
}

// shapeDigest is the digest that buckets locations for the tolerance band: everything the
// location fingerprint hashes except the link targets. Two pages can only be folded together if
// they agree on all of it, so the band never compares a candidate against a structurally
// different page.
//
// A shape is never indexed, and so is never a band candidate, when the response was a non-HTML
// body: the empty string is the refusal, and it is why parsePage can leave the field zero on a
// document that failed to parse without that document being folded into anything.
func shapeDigest(skeleton string, textLen int) string {
	var b strings.Builder
	b.WriteString(skeleton)
	b.WriteString(shapeSeparator)
	b.WriteString(strconv.Itoa(bits.Len(uint(textLen))))
	return hashSkeleton(b.String())
}

// toleranceBand is the band in force: the crawl strategy's (8bp2), or Burp's normal default.
func (c *Crawler) toleranceBand() int {
	if c.limits.LocationToleranceBand != nil {
		return *c.limits.LocationToleranceBand
	}
	return locationToleranceBand
}
