package tools

import (
	"bytes"

	"github.com/burpsy-go/burpsy/internal/core"
)

// This file ports crates/tools/src/comparer.rs: a diff between two messages at
// word or byte granularity, with a budget that bounds the work on large bodies.
// The Rust code is authoritative; every function here is a line-for-line port.
//
// # The cost problem, and why the trim is the whole trick
//
// The job this tool actually gets is "two 200 KB responses that differ in one
// character" — a reflected-payload check, a blind-injection oracle, a session
// token that changed. A textbook dynamic-programming diff is O(n*m): on 200 KB
// that is 4x10^10 cell updates, which is not a slow tool, it is a hung one.
//
// Myers' algorithm is O((n+m)*D) where D is the size of the edit script, so its
// cost is driven by *how different* the inputs are rather than how big they are.
// Stripping the common prefix and suffix first — one linear scan each — reduces
// the headline case to a handful of tokens before the real algorithm sees
// anything at all.
//
// # The bail-out, stated honestly
//
// Two genuinely unrelated 200 KB bodies have a large D, and O((n+m)*D) is then
// no better than quadratic. So D is capped by a budget scaled to the input size,
// and exceeding it produces a coarse "this whole region was replaced" diff with
// [DiffResult.Truncated] set. That is a real answer — the bodies share nothing
// worth aligning — delivered in bounded time instead of a hang. A capped diff
// must SAY it was capped, never look complete.
//
// # No bytes are copied
//
// Every op carries [core.Span]s into the two original buffers, never their
// contents. Diffing two 200 KB bodies allocates an op list proportional to the
// number of *changes*, in keeping with the rest of the codebase: hold offsets,
// not payloads.

// Granularity controls what counts as one unit of change.
type Granularity uint8

const (
	// GranularityByte treats every byte as a token. The finest view, and the one
	// that localises a single-character edit.
	GranularityByte Granularity = iota
	// GranularityWord treats a token as a maximal run of non-whitespace or a
	// maximal run of whitespace. Reads the way a human compares two responses,
	// and cuts the token count by roughly 6x on text.
	GranularityWord
)

// OpKind identifies the kind of one aligned region.
type OpKind uint8

const (
	OpEqual OpKind = iota
	// OpDelete is a region present in a, absent from b.
	OpDelete
	// OpInsert is a region absent from a, present in b.
	OpInsert
)

// Op is one aligned region. Spans index into the buffers given to Diff.
type Op struct {
	Kind OpKind
	A    core.Span
	B    core.Span
}

// DiffResult is the outcome of a diff.
type DiffResult struct {
	Granularity    Granularity
	Ops            []Op
	EqualTokens    int
	DeletedTokens  int
	InsertedTokens int
	// Truncated reports that the edit script exceeded the budget; the differing
	// region is reported as one wholesale replacement rather than aligned. The
	// diff is still correct, just coarse.
	Truncated bool
}

// IsIdentical reports whether the two inputs are byte-for-byte (or token-for-
// token) the same.
func (d *DiffResult) IsIdentical() bool {
	return d.DeletedTokens == 0 && d.InsertedTokens == 0
}

// Changes returns the total number of tokens that differ — the number to show
// as "N changes".
func (d *DiffResult) Changes() int {
	return d.DeletedTokens + d.InsertedTokens
}

// Diff diffs two buffers with a budget derived from their size.
func Diff(a, b []byte, granularity Granularity) *DiffResult {
	ta := newTokens(a, granularity)
	tb := newTokens(b, granularity)
	budget := budgetFor(ta.len() + tb.len())
	return run(ta, tb, granularity, budget)
}

// DiffWithBudget diffs with an explicit cap on the edit-script size. Useful to
// assert that a change really is small: a one-byte difference in a megabyte
// still resolves with maxD = 4.
func DiffWithBudget(a, b []byte, granularity Granularity, maxD int) *DiffResult {
	ta := newTokens(a, granularity)
	tb := newTokens(b, granularity)
	return run(ta, tb, granularity, maxD)
}

// budgetFor derives the cap on the edit-script size from the input token count.
// Work is O((n+m)*D), so the cap has to shrink as the inputs grow or the
// bail-out costs more than the diff. ~2x10^7 token comparisons is a few tens of
// milliseconds; the floor keeps small inputs aligning properly and the ceiling
// bounds the O(D^2) trace to about 16 MB.
func budgetFor(totalTokens int) int {
	b := 20_000_000 / (totalTokens + 1)
	if b < 64 {
		return 64
	}
	if b > 2048 {
		return 2048
	}
	return b
}

func run(ta, tb *tokens, granularity Granularity, maxD int) *DiffResult {
	na, nb := ta.len(), tb.len()

	// Linear prefix/suffix trim. This is what makes the headline case cheap.
	lo := 0
	for lo < na && lo < nb && ta.eq(lo, tb, lo) {
		lo++
	}
	tail := 0
	for tail < na-lo && tail < nb-lo && ta.eq(na-1-tail, tb, nb-1-tail) {
		tail++
	}
	midA, midB := na-tail-lo, nb-tail-lo

	var ops []Op
	equal, deleted, inserted := 0, 0, 0

	if lo > 0 {
		ops = append(ops, Op{Kind: OpEqual, A: ta.spanRange(0, lo), B: tb.spanRange(0, lo)})
		equal += lo
	}

	edits, ok := myers(midA, midB, func(x, y int) bool { return ta.eq(lo+x, tb, lo+y) }, maxD)
	truncated := !ok
	if ok {
		i := 0
		for i < len(edits) {
			j := i
			for j < len(edits) && edits[j].kind == edits[i].kind {
				j++
			}
			n := j - i
			switch edits[i].kind {
			case editEqual:
				ops = append(ops, Op{Kind: OpEqual, A: ta.spanRange(lo+edits[i].ax, n), B: tb.spanRange(lo+edits[i].bx, n)})
				equal += n
			case editDelete:
				ops = append(ops, Op{Kind: OpDelete, A: ta.spanRange(lo+edits[i].ax, n)})
				deleted += n
			case editInsert:
				ops = append(ops, Op{Kind: OpInsert, B: tb.spanRange(lo+edits[i].bx, n)})
				inserted += n
			}
			i = j
		}
	} else {
		if midA > 0 {
			ops = append(ops, Op{Kind: OpDelete, A: ta.spanRange(lo, midA)})
			deleted += midA
		}
		if midB > 0 {
			ops = append(ops, Op{Kind: OpInsert, B: tb.spanRange(lo, midB)})
			inserted += midB
		}
	}

	if tail > 0 {
		ops = append(ops, Op{Kind: OpEqual, A: ta.spanRange(na-tail, tail), B: tb.spanRange(nb-tail, tail)})
		equal += tail
	}

	return &DiffResult{
		Granularity:    granularity,
		Ops:            ops,
		EqualTokens:    equal,
		DeletedTokens:  deleted,
		InsertedTokens: inserted,
		Truncated:      truncated,
	}
}

// ---- tokens ------------------------------------------------------------------------------------

// tokens is a buffer viewed as a token sequence. Byte granularity stores no
// span table: token i *is* byte i, and materialising 200 000 spans to say so
// would cost more than the diff.
type tokens struct {
	buf         []byte
	spans       []core.Span // nil for byte granularity
	hashes      []uint64
	hashIsExact bool // true when a hash match implies a byte match
}

func newTokens(buf []byte, g Granularity) *tokens {
	switch g {
	case GranularityByte:
		hashes := make([]uint64, len(buf))
		for i, b := range buf {
			hashes[i] = uint64(b)
		}
		return &tokens{buf: buf, hashes: hashes, hashIsExact: true}
	default: // GranularityWord
		spans := wordSpans(buf)
		hashes := make([]uint64, len(spans))
		for i, s := range spans {
			hashes[i] = fnv1a(buf[s.Offset:s.End()])
		}
		return &tokens{buf: buf, spans: spans, hashes: hashes}
	}
}

func (t *tokens) len() int {
	if t.spans == nil {
		return len(t.buf)
	}
	return len(t.spans)
}

func (t *tokens) span(i int) core.Span {
	if t.spans == nil {
		return core.Span{Offset: i, Len: 1}
	}
	return t.spans[i]
}

// range returns one span covering count consecutive tokens from start.
func (t *tokens) spanRange(start, count int) core.Span {
	if count == 0 {
		return core.Span{Offset: t.span(min(start, t.len())).Offset, Len: 0}
	}
	first := t.span(start)
	last := t.span(start + count - 1)
	return core.Span{Offset: first.Offset, Len: last.End() - first.Offset}
}

func (t *tokens) eq(i int, other *tokens, j int) bool {
	if t.hashes[i] != other.hashes[j] {
		return false
	}
	if t.hashIsExact && other.hashIsExact {
		return true
	}
	a := t.span(i)
	b := other.span(j)
	return bytes.Equal(t.buf[a.Offset:a.End()], other.buf[b.Offset:b.End()])
}

func wordSpans(buf []byte) []core.Span {
	var out []core.Span
	i := 0
	for i < len(buf) {
		ws := asciiWhitespace(buf[i])
		start := i
		for i < len(buf) && asciiWhitespace(buf[i]) == ws {
			i++
		}
		out = append(out, core.Span{Offset: start, Len: i - start})
	}
	return out
}

// asciiWhitespace reports whether b is ASCII whitespace, matching Rust's
// u8::is_ascii_whitespace (space, tab, LF, CR, FF). Deliberately narrower than
// unicode.IsSpace, which would also classify VT, NEL and NBSP as whitespace and
// diverge from the Rust tokenisation.
func asciiWhitespace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', 0x0c:
		return true
	}
	return false
}

func fnv1a(b []byte) uint64 {
	h := uint64(0xcbf29ce484222325)
	for _, x := range b {
		h ^= uint64(x)
		h *= 0x100000001b3
	}
	return h
}

// ---- Myers ------------------------------------------------------------------------------------

type editKind uint8

const (
	editEqual editKind = iota
	editDelete
	editInsert
)

// edit is one step of the edit script. ax is an index into a for equal/delete
// steps; bx is an index into b for equal/insert steps.
type edit struct {
	kind   editKind
	ax, bx int
}

// myers runs greedy forward Myers with a per-round trace, capped at maxD. ok is
// false when the cap was hit. The trace keeps only the diagonals each round can
// actually read back — 2d+3 entries for round d — so its memory is O(D^2)
// rather than O(D*(n+m)). At the 2048 ceiling that is ~16 MB; storing the full
// diagonal array each round would be ~13 GB on a 200 KB input.
func myers(n, m int, eq func(i, j int) bool, maxD int) ([]edit, bool) {
	if maxD > n+m {
		maxD = n + m
	}
	off := maxD + 1
	v := make([]int32, 2*maxD+3)
	var trace [][]int32
	nI, mI := int32(n), int32(m)

	for d := 0; d <= maxD; d++ {
		row := make([]int32, 2*d+3)
		copy(row, v[off-d-1:off+d+2])
		trace = append(trace, row)
		for k := -d; k <= d; k += 2 {
			idx := k + off
			// Extend the furthest-reaching path on diagonal k: down (insert) or
			// right (delete).
			var x int32
			if k == -d || (k != d && v[idx-1] < v[idx+1]) {
				x = v[idx+1]
			} else {
				x = v[idx-1] + 1
			}
			y := x - int32(k)
			for x < nI && y < mI && eq(int(x), int(y)) {
				x++
				y++
			}
			v[idx] = x
			if x >= nI && y >= mI {
				return backtrack(trace, n, m), true
			}
		}
	}
	return nil, false
}

func backtrack(trace [][]int32, n, m int) []edit {
	var edits []edit
	x, y := int32(n), int32(m)
	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		di := int32(d)
		k := x - y
		at := func(kk int32) int32 { return v[kk+di+1] }
		var prevK int32
		if k == -di || (k != di && at(k-1) < at(k+1)) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := at(prevK)
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			edits = append(edits, edit{kind: editEqual, ax: int(x) - 1, bx: int(y) - 1})
			x--
			y--
		}
		if d > 0 {
			if x == prevX {
				edits = append(edits, edit{kind: editInsert, bx: int(prevY)})
			} else {
				edits = append(edits, edit{kind: editDelete, ax: int(prevX)})
			}
		}
		x = prevX
		y = prevY
	}
	for i, j := 0, len(edits)-1; i < j; i, j = i+1, j-1 {
		edits[i], edits[j] = edits[j], edits[i]
	}
	return edits
}
