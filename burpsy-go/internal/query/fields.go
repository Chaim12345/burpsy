package query

// Which fields a parsed query actually compares on.
//
// # Why this exists, and why it is not a weakening of Parse's guarantee
//
// Parse's contract is that every *Expr has already been type-checked, so Match cannot fail. That
// contract says nothing about *when* the fields a query names will have values. The package docs'
// "absent fields are absent, not zero" rule handles the runtime side: a comparison on a field the
// row does not carry yet is false, never true and never an error.
//
// A consumer that evaluates a query *before the response exists* needs more than that. The
// crawler's frontier gate (DSL-03) decides whether to fetch a URL, and at that moment `status`,
// `mime` and `body` have no value at all — not an absent one, an unobtainable one. Evaluating
// `mime = "text/html"` there and getting false back is indistinguishable from a page that really
// is not HTML, and `not mime = "text/html"` comes back *true* for every URL in the frontier. Both
// readings are wrong, and both are silent. That is the same defect DSL-04 exists to prevent, one
// layer up: a query that cannot be answered must say so rather than answer wrongly.
//
// Fields lets such a consumer refuse *precisely* the queries it cannot honestly evaluate, and
// accept the rest — instead of the two bad alternatives, silently matching false or refusing every
// query outright.
//
// This is read-only introspection. It inspects an Expr, constructs none, and offers no path to an
// Expr that skipped parseCmp's type check, so the invariant that makes Match infallible is
// untouched.

// Fields reports the fields this query compares on, in the grammar's own field order (host,
// method, mime, status, body) and without duplicates. A nil *Expr — "no filter" — names none.
func (e *Expr) Fields() []string {
	var seen [5]bool
	e.collectFields(&seen)
	// Built from the declared field order rather than discovery order, so the result is stable
	// across two queries that name the same fields in different places.
	order := [5]field{fieldHost, fieldMethod, fieldMime, fieldStatus, fieldBody}
	out := make([]string, 0, len(order))
	for _, f := range order {
		if seen[int(f)] {
			out = append(out, f.String())
		}
	}
	return out
}

// collectFields walks the tree. kindNot and the two boolean kinds recurse; only kindCmp names a
// field. A right child is nil for kindNot, which is why each branch is tested rather than the walk
// assuming two children.
func (e *Expr) collectFields(seen *[5]bool) {
	if e == nil {
		return
	}
	if e.kind == kindCmp {
		seen[int(e.field)] = true
		return
	}
	e.left.collectFields(seen)
	e.right.collectFields(seen)
}
