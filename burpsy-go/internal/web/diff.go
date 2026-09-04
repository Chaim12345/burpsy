package web

// The Comparer's diff.
//
// # What was here before, and why it had to go
//
// compareOps used to walk a[i] against b[i] positionally: equal while the bytes matched, "replace"
// while they did not, then a trailing insert or delete for whatever was longer. That is not a diff.
// It has no alignment, so a single edit that changes length desynchronises every byte after it.
// Measured on the old implementation:
//
//	a = "the quick brown fox jumps over the lazy dog"   (43 bytes)
//	b = the same with one character inserted at offset 4
//	→ equal a_len=4, replace a_len=39, insert a_len=0
//
// 39 of 43 bytes reported as changed for a one-character insertion. The Comparer is a primary tool —
// comparing two responses is how an operator decides whether an input changed behaviour — so this
// did not merely look bad, it buried real differences in noise. The page disclosed that it compared
// *bytes* rather than words, which is a statement about granularity and said nothing about
// alignment, so the output read as trustworthy.
//
// # What it does now
//
// Three stages, cheapest first, because real inputs are two versions of the same message and almost
// all of their bytes are a shared prefix and suffix:
//
//  1. Trim the common prefix and the common suffix. On a typical pair of HTTP responses this leaves
//     a few hundred bytes in the middle, and it is O(n) with no allocation.
//  2. Myers' diff over what remains. O(ND) in time where D is the edit distance, which is small
//     exactly when the two inputs are related — the case that matters.
//  3. If D would exceed diffMaxEditDistance, stop and say so via diffResult.Truncated.
//
// # The bound, and why it is reported rather than hidden
//
// Myers is O(ND). For two unrelated blobs D approaches n+m, so a megabyte against a megabyte is
// quadratic and would hang the request. Rather than let that happen, the search is bounded, and when
// the bound is hit the result falls back to a single replace covering the whole differing middle —
// which is the honest answer ("these differ throughout, I did not align them") and is reported as
// `truncated` so the console can say so.
//
// Silently falling back would have recreated the original defect for large inputs while looking
// fixed for small ones, which is the worst of the options.

// diffMaxEditDistance bounds Myers' search, and the number comes from memory rather than taste.
//
// The trace retains one furthest-reaching array per generation so the edit script can be walked
// back, which is O(D²) ints: at 1024 that is about 1024 × 2051 × 8 bytes ≈ 17 MB worst case, and
// the search work is O(D²) ≈ 10⁶ steps. Both stay inside a request.
//
// The first draft used 4096 and sized the per-generation array by n+m rather than by D — 800 000
// ints per generation for a 200 KB pair, times 4096 generations, which is tens of gigabytes. The
// large-input test caught it by taking 311 seconds instead of failing an assertion. Hence both the
// smaller bound and the array sizing below: the array only ever needs to span the diagonals a
// distance-d search can reach, which is [-d, d].
//
// Inputs related enough for a comparison to be meaningful have an edit distance far below this;
// hitting it is itself evidence the two messages have little in common, which is what Truncated
// then says out loud.
const diffMaxEditDistance = 1024

// diffResult is a diff plus whether it is complete.
type diffResult struct {
	Ops []compareOp
	// Truncated reports that the edit-distance bound was hit and the differing middle is presented
	// as one replace rather than aligned. Surfaced to the operator: an unaligned diff labelled as
	// aligned is the defect this file exists to remove.
	Truncated bool
}

// diffBytes aligns a and b and returns equal/replace/insert/delete ops with offsets into each.
func diffBytes(a, b []byte) diffResult {
	// Stage 1: shared prefix and suffix.
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix &&
		a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}

	midA := a[prefix : len(a)-suffix]
	midB := b[prefix : len(b)-suffix]

	var ops []compareOp
	emit := func(op compareOp) {
		// Merge with the previous op when they are the same kind and adjacent, so a run of
		// single-byte edits renders as one hunk rather than hundreds. Myers naturally produces
		// per-element steps; the console draws hunks.
		if n := len(ops); n > 0 && ops[n-1].Kind == op.Kind {
			last := &ops[n-1]
			if last.AOffset+last.ALen == op.AOffset && last.BOffset+last.BLen == op.BOffset {
				last.ALen += op.ALen
				last.BLen += op.BLen
				return
			}
		}
		ops = append(ops, op)
	}

	if prefix > 0 {
		emit(compareOp{Kind: "equal", AOffset: 0, ALen: prefix, BOffset: 0, BLen: prefix})
	}

	truncated := false
	switch {
	case len(midA) == 0 && len(midB) == 0:
		// Identical once the ends are trimmed.
	case len(midA) == 0:
		emit(compareOp{Kind: "insert", AOffset: prefix, ALen: 0, BOffset: prefix, BLen: len(midB)})
	case len(midB) == 0:
		emit(compareOp{Kind: "delete", AOffset: prefix, ALen: len(midA), BOffset: prefix, BLen: 0})
	default:
		script, ok := myers(midA, midB, diffMaxEditDistance)
		if !ok {
			truncated = true
			emit(compareOp{
				Kind: "replace", AOffset: prefix, ALen: len(midA),
				BOffset: prefix, BLen: len(midB),
			})
			break
		}
		// Walk the edit script, translating positions back into offsets in the untrimmed inputs.
		ai, bi := prefix, prefix
		for _, step := range script {
			switch step {
			case diffEqual:
				emit(compareOp{Kind: "equal", AOffset: ai, ALen: 1, BOffset: bi, BLen: 1})
				ai++
				bi++
			case diffDelete:
				emit(compareOp{Kind: "delete", AOffset: ai, ALen: 1, BOffset: bi, BLen: 0})
				ai++
			case diffInsert:
				emit(compareOp{Kind: "insert", AOffset: ai, ALen: 0, BOffset: bi, BLen: 1})
				bi++
			}
		}
	}

	if suffix > 0 {
		emit(compareOp{
			Kind: "equal", AOffset: len(a) - suffix, ALen: suffix,
			BOffset: len(b) - suffix, BLen: suffix,
		})
	}

	// A delete immediately followed by an insert is a replacement, and the console draws replacements
	// side by side. Folding them keeps the rendering aligned and the hunk count meaningful.
	ops = foldReplacements(ops)

	if len(ops) == 0 {
		// Both inputs empty. One equal op of zero length keeps the "identical" check — which looks
		// for exactly one equal op — true rather than special-casing it at the call site.
		ops = []compareOp{{Kind: "equal"}}
	}
	return diffResult{Ops: ops, Truncated: truncated}
}

// foldReplacements turns adjacent delete+insert (in either order) into one replace.
func foldReplacements(ops []compareOp) []compareOp {
	out := make([]compareOp, 0, len(ops))
	for i := 0; i < len(ops); i++ {
		cur := ops[i]
		if i+1 < len(ops) {
			next := ops[i+1]
			if (cur.Kind == "delete" && next.Kind == "insert") ||
				(cur.Kind == "insert" && next.Kind == "delete") {
				del, ins := cur, next
				if cur.Kind == "insert" {
					del, ins = next, cur
				}
				out = append(out, compareOp{
					Kind:    "replace",
					AOffset: del.AOffset, ALen: del.ALen,
					BOffset: ins.BOffset, BLen: ins.BLen,
				})
				i++
				continue
			}
		}
		out = append(out, cur)
	}
	return out
}

// diffStep is one element of an edit script.
type diffStep uint8

const (
	diffEqual diffStep = iota
	diffDelete
	diffInsert
)

// myers computes a shortest edit script between a and b, or ok=false when the edit distance exceeds
// maxD.
//
// This is Myers' 1986 algorithm in its standard forward form: for each edit distance d, track the
// furthest-reaching path on each diagonal k, and keep every generation of that array (the "trace")
// so the script can be walked back once the end is reached.
//
// The trace is the memory cost — O(D²) ints — which is the other reason maxD exists.
func myers(a, b []byte, maxD int) ([]diffStep, bool) {
	n, m := len(a), len(b)
	if total := n + m; maxD > total {
		maxD = total
	}

	// v is indexed by diagonal k, which a distance-d search reaches only within [-d, d]. So the
	// array spans [-maxD, maxD], NOT [-(n+m), n+m] — sizing it by n+m is what made the first draft
	// allocate gigabytes. +3 and an offset of maxD+1 give headroom for the k±1 reads at the edges.
	offset := maxD + 1
	v := make([]int, 2*maxD+3)
	trace := make([][]int, 0, maxD+1)

	for d := 0; d <= maxD; d++ {
		// Snapshot before this generation overwrites it, so backtracking can replay the decisions.
		snapshot := make([]int, len(v))
		copy(snapshot, v)
		trace = append(trace, snapshot)

		for k := -d; k <= d; k += 2 {
			var x int
			// Choose the neighbour that reached further: down (insert) or right (delete).
			switch {
			case k == -d:
				x = v[k+1+offset]
			case k == d:
				x = v[k-1+offset] + 1
			case v[k-1+offset] < v[k+1+offset]:
				x = v[k+1+offset]
			default:
				x = v[k-1+offset] + 1
			}
			y := x - k
			// Follow the diagonal as far as the bytes match — the "snake".
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[k+offset] = x
			if x >= n && y >= m {
				return backtrack(a, b, trace, offset), true
			}
		}
	}
	return nil, false
}

// backtrack walks the trace from the end back to the origin, producing the edit script forwards.
func backtrack(a, b []byte, trace [][]int, offset int) []diffStep {
	var reversed []diffStep
	x, y := len(a), len(b)

	for d := len(trace) - 1; d >= 0 && (x > 0 || y > 0); d-- {
		v := trace[d]
		k := x - y

		// Which neighbour this position came from — the same choice myers made on the way out.
		var prevK int
		switch {
		case k == -d:
			prevK = k + 1
		case k == d:
			prevK = k - 1
		case v[k-1+offset] < v[k+1+offset]:
			prevK = k + 1
		default:
			prevK = k - 1
		}

		prevX := v[prevK+offset]
		prevY := prevX - prevK

		// Un-follow the snake: every step along the diagonal was an equality.
		for x > prevX && y > prevY {
			reversed = append(reversed, diffEqual)
			x--
			y--
		}
		if d == 0 {
			break
		}
		if x == prevX {
			reversed = append(reversed, diffInsert)
			y = prevY
		} else {
			reversed = append(reversed, diffDelete)
			x = prevX
		}
	}

	// Reverse in place.
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed
}
