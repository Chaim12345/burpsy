package scanner

// Page comparison for the boolean SQL-injection technique on dynamic pages (burpsy-react-ui-v0ei.4).
//
// # Why exact equality was not enough
//
// The boolean technique asks one question: does the always-true condition leave the page as the
// baseline had it, while the always-false one changes it? ResponseFingerprint answers "as the
// baseline had it" by exact (whitespace-normalised) equality, which is right for a static page and
// wrong for nearly every real one. A page that prints the time it was rendered, a fresh CSRF token
// or the search term it was given differs from its own baseline on every request, so the true half
// never matched and the technique reported "both halves changed" — no evidence — on exactly the
// pages applications actually serve. sqlmap's answer, which this follows, has three parts:
//
//  1. Dynamic content is learned, not guessed. The baseline is fetched a second time and the two
//     copies are diffed; every region that differs between two requests that asked the same thing
//     is dynamic. Each region is remembered by the tokens around it (its anchors), and is cut out
//     of every later page wherever the same anchors enclose a region of similar size. Nothing is
//     masked by a fixed pattern ("anything that looks like a date"), so a count or a row that the
//     condition changes is never mistaken for noise unless the endpoint changed it unprompted.
//  2. The reflected payload is removed. A page that echoes the term it was searched for carries
//     the probe's own text, which differs between the true and false halves by construction. The
//     payload is subtracted from the HTML-unescaped body (and its percent-encoded spellings) before
//     comparison, so an echo can never be the difference.
//  3. Pages are compared by similarity, with the tolerance the endpoint itself showed. When the two
//     baselines are identical once dynamic regions are removed, "the same page" means identical:
//     nothing is lost against the exact comparison on a static page, where one removed row is a
//     real difference. When they still differ (a region the anchors could not pin down), "the same
//     page" means a token-level similarity ratio no further from the baseline than the baseline was
//     from itself, plus a small fixed tolerance. A page whose two baselines are less than
//     booleanMinStability alike is too unstable to judge, and the technique says so (undecided)
//     instead of guessing.
//
// The repeat and second-pair rules that turn one differential into evidence live with the probe
// (sqlBooleanProbe); this file only answers "same page or not".

import (
	"html"
	"net/url"
	"strings"
	"unicode"
)

const (
	// booleanDiffTolerance is how much further from the baseline than the baseline's own noise a
	// page may be and still count as the same page, in similarity-ratio units (ratio mode only).
	booleanDiffTolerance = 0.02
	// booleanMinStability is the least two baseline fetches must agree (after dynamic regions are
	// removed) for the page to be judged at all.
	booleanMinStability = 0.90
	// dynamicAnchorTokens is how many tokens either side of a dynamic region identify it.
	dynamicAnchorTokens = 4
	// lcsCellBudget bounds the dynamic-programming table of one comparison; beyond it the ratio
	// falls back to the multiset overlap (an upper bound, like difflib's quick_ratio).
	lcsCellBudget = 4_000_000
)

// pageTokens splits a body into the units compared: runs of letters and digits, and every other
// non-space character on its own. Whitespace is dropped, so re-indentation is not a difference.
func pageTokens(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		word := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
		if word {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
		if !unicode.IsSpace(r) {
			out = append(out, string(r))
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// tokenHunk is one region where two token sequences differ: a[i1:i2] stands where b[j1:j2] does.
type tokenHunk struct{ i1, i2, j1, j2 int }

// tokenAlignment returns the length of a longest common subsequence of a and b and the regions
// where they differ. A common prefix and suffix are matched first, and only the middle is aligned
// by dynamic programming; a middle too large for the budget is reported as one region and its
// common length estimated from the multiset overlap.
func tokenAlignment(a, b []string) (common int, hunks []tokenHunk) {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	common = pre + suf
	if len(ma) == 0 && len(mb) == 0 {
		return common, nil
	}
	if len(ma) == 0 || len(mb) == 0 || len(ma)*len(mb) > lcsCellBudget {
		return common + multisetOverlap(ma, mb), []tokenHunk{{pre, pre + len(ma), pre, pre + len(mb)}}
	}
	// lcs[i][j] is the LCS length of ma[i:] and mb[j:].
	n, m := len(ma), len(mb)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case ma[i] == mb[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	common += int(lcs[0][0])
	i, j := 0, 0
	open := false
	var h tokenHunk
	flush := func() {
		if open {
			h.i2, h.j2 = pre+i, pre+j
			hunks = append(hunks, h)
			open = false
		}
	}
	for i < n || j < m {
		if i < n && j < m && ma[i] == mb[j] {
			flush()
			i++
			j++
			continue
		}
		if !open {
			h = tokenHunk{i1: pre + i, j1: pre + j}
			open = true
		}
		if j >= m || (i < n && lcs[i+1][j] >= lcs[i][j+1]) {
			i++
		} else {
			j++
		}
	}
	flush()
	return common, hunks
}

func multisetOverlap(a, b []string) int {
	counts := make(map[string]int, len(a))
	for _, t := range a {
		counts[t]++
	}
	n := 0
	for _, t := range b {
		if counts[t] > 0 {
			counts[t]--
			n++
		}
	}
	return n
}

// tokenRatio is difflib's ratio over tokens: twice the common length over the total length.
func tokenRatio(a, b []string) float64 {
	if len(a)+len(b) == 0 {
		return 1
	}
	common, _ := tokenAlignment(a, b)
	return 2 * float64(common) / float64(len(a)+len(b))
}

func tokensEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dynamicRegion is a region that changed between two baseline fetches, remembered by the tokens
// that enclose it and the largest size it was seen at.
type dynamicRegion struct {
	before, after []string
	maxLen        int
}

// dynamicPlaceholder stands in for a removed region, so the anchors on either side stay apart.
const dynamicPlaceholder = "\x00dynamic\x00"

// learnDynamicRegions diffs two baseline fetches and returns the regions that differ, anchored.
//
// It follows sqlmap's findDynamicContent: the two pages are aligned, matching runs shorter than two
// anchors' worth of tokens are discarded as coincidence (two timestamps share digits), and every
// gap between the surviving runs is one dynamic region, anchored by the last tokens of the run
// before it and the first tokens of the run after it. A region with no anchor on either side (the
// whole page changed) cannot be located again and is not returned; such a page fails the stability
// check instead.
func learnDynamicRegions(a, b []string) []dynamicRegion {
	_, hunks := tokenAlignment(a, b)
	if len(hunks) == 0 {
		return nil
	}
	// The matching runs, in both pages' coordinates: before the first hunk, between hunks, after
	// the last.
	type run struct{ a1, a2, b1, b2 int }
	var runs []run
	pa, pb := 0, 0
	for _, h := range hunks {
		runs = append(runs, run{pa, h.i1, pb, h.j1})
		pa, pb = h.i2, h.j2
	}
	runs = append(runs, run{pa, len(a), pb, len(b)})
	minRun := 2 * dynamicAnchorTokens
	var kept []run
	for k, r := range runs {
		// The page's own first and last runs are kept at any length: they are its edges.
		if r.a2-r.a1 >= minRun || (k == 0 && r.a2 > r.a1) || (k == len(runs)-1 && r.a2 > r.a1) {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	// Gaps between kept runs, plus the page's edges when no run anchors them.
	type span struct{ a1, a2, b1, b2 int }
	var spans []span
	add := func(sp span) {
		if sp.a1 == sp.a2 && sp.b1 == sp.b2 {
			return
		}
		// Widen the region over the volatile tokens around it that both pages happened to share
		// (the minutes of two timestamps taken in the same minute), so its anchors are the words
		// around the value rather than the parts of the value that have not changed YET.
		for sp.a1 > 0 && sp.b1 > 0 && a[sp.a1-1] == b[sp.b1-1] && volatileToken(a[sp.a1-1]) {
			sp.a1--
			sp.b1--
		}
		for sp.a2 < len(a) && sp.b2 < len(b) && a[sp.a2] == b[sp.b2] && volatileToken(a[sp.a2]) {
			sp.a2++
			sp.b2++
		}
		// Regions closer than an anchor's length are one region: the second's leading anchor
		// would otherwise lie inside the first, and disappear with it.
		if n := len(spans); n > 0 && sp.a1-spans[n-1].a2 < dynamicAnchorTokens {
			spans[n-1].a2, spans[n-1].b2 = sp.a2, sp.b2
			return
		}
		spans = append(spans, sp)
	}
	add(span{0, kept[0].a1, 0, kept[0].b1})
	for k := 1; k < len(kept); k++ {
		add(span{kept[k-1].a2, kept[k].a1, kept[k-1].b2, kept[k].b1})
	}
	last := kept[len(kept)-1]
	add(span{last.a2, len(a), last.b2, len(b)})

	var out []dynamicRegion
	for _, sp := range spans {
		r := dynamicRegion{
			before: append([]string(nil), a[max(0, sp.a1-dynamicAnchorTokens):sp.a1]...),
			after:  append([]string(nil), a[sp.a2:min(len(a), sp.a2+dynamicAnchorTokens)]...),
			maxLen: max(sp.a2-sp.a1, sp.b2-sp.b1),
		}
		if len(r.before) == 0 && len(r.after) == 0 {
			continue
		}
		out = append(out, r)
	}
	return out
}

// volatileToken is a token that belongs to a changing value rather than to the text around it: one
// carrying a digit, or the punctuation that joins the parts of a date, a time or a number.
func volatileToken(t string) bool {
	switch t {
	case "-", ":", ".", "/", "+":
		return true
	}
	for _, r := range t {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasPrefixAt(toks []string, at int, want []string) bool {
	if at < 0 || at+len(want) > len(toks) {
		return false
	}
	for k, w := range want {
		if toks[at+k] != w {
			return false
		}
	}
	return true
}

// removeDynamicRegions cuts every learned region out of toks: wherever a region's leading anchor is
// followed, within a span no larger than twice the region's observed size (plus slack), by its
// trailing anchor, the tokens between become one placeholder. The size bound is what keeps an
// anchor that recurs on the page (`value = "`) from swallowing the content the condition changes.
func removeDynamicRegions(toks []string, regions []dynamicRegion) []string {
	for _, r := range regions {
		limit := 2*r.maxLen + 4
		var out []string
		i := 0
		for i < len(toks) {
			if !hasPrefixAt(toks, i, r.before) {
				out = append(out, toks[i])
				i++
				continue
			}
			from := i + len(r.before)
			end := -1
			switch {
			case len(r.after) == 0:
				// A region that ran to the end of the page.
				if len(toks)-from <= limit {
					end = len(toks)
				}
			default:
				for k := from; k <= len(toks)-len(r.after) && k-from <= limit; k++ {
					if hasPrefixAt(toks, k, r.after) {
						end = k
						break
					}
				}
			}
			if end < 0 || len(r.before) == 0 && from != 0 {
				out = append(out, toks[i])
				i++
				continue
			}
			out = append(out, toks[i:from]...)
			out = append(out, dynamicPlaceholder)
			i = end
			if len(r.before) == 0 {
				// A region that ran from the start of the page is removed once.
				out = append(out, toks[i:]...)
				i = len(toks)
			}
		}
		toks = out
	}
	return toks
}

// stripReflection removes a probe's own text from a body: the body is HTML-unescaped, then every
// occurrence of the payload as sent, percent-encoded and form-encoded is deleted. An empty payload
// (a baseline re-fetch) only unescapes, so every page is compared in the same form.
func stripReflection(body, payload string) string {
	body = html.UnescapeString(body)
	if payload == "" {
		return body
	}
	for _, form := range []string{payload, url.QueryEscape(payload), url.PathEscape(payload)} {
		body = strings.ReplaceAll(body, form, "")
	}
	return body
}

// booleanPage is one response as the boolean comparison sees it.
type booleanPage struct {
	status int
	toks   []string
}

// booleanComparator judges "same page as the baseline" for one insertion point.
type booleanComparator struct {
	regions []dynamicRegion
	base    booleanPage
	// exact is true when the two baselines are identical once dynamic regions are removed; the
	// comparison is then exact. Otherwise it is by ratio, within noise + booleanDiffTolerance.
	exact bool
	noise float64
	// stability is the similarity of the two baselines after dynamic regions were removed.
	stability float64
}

// newBooleanComparator learns the page's dynamic regions from two baseline fetches of the same
// request and measures how alike they still are.
func newBooleanComparator(status1 int, body1 string, status2 int, body2 string) *booleanComparator {
	a := pageTokens(stripReflection(body1, ""))
	b := pageTokens(stripReflection(body2, ""))
	c := &booleanComparator{regions: learnDynamicRegions(a, b)}
	c.base = booleanPage{status: status1, toks: removeDynamicRegions(a, c.regions)}
	other := removeDynamicRegions(b, c.regions)
	c.exact = tokensEqual(c.base.toks, other)
	c.stability = tokenRatio(c.base.toks, other)
	if status1 != status2 {
		c.stability = 0
	}
	c.noise = 1 - c.stability
	return c
}

// stable reports whether the baseline is steady enough to judge a condition against.
func (c *booleanComparator) stable() bool { return c.stability >= booleanMinStability }

// page normalises a probe's response: the reflected payload and the learned dynamic regions removed.
func (c *booleanComparator) page(status int, body, payload string) booleanPage {
	return booleanPage{status: status, toks: removeDynamicRegions(pageTokens(stripReflection(body, payload)), c.regions)}
}

// similarity is the token ratio of two normalised pages; a different status is no similarity.
func similarity(x, y booleanPage) float64 {
	if x.status != y.status {
		return 0
	}
	return tokenRatio(x.toks, y.toks)
}

// alike reports whether two normalised pages are the same page under this endpoint's tolerance.
func (c *booleanComparator) alike(x, y booleanPage) bool {
	if x.status != y.status {
		return false
	}
	if c.exact {
		return tokensEqual(x.toks, y.toks)
	}
	return 1-tokenRatio(x.toks, y.toks) <= c.noise+booleanDiffTolerance
}

// sameAsBase reports whether a normalised page is the baseline page.
func (c *booleanComparator) sameAsBase(x booleanPage) bool { return c.alike(c.base, x) }
