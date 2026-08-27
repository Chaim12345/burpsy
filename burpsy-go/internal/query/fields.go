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
// method, path, mime, status, body) and without duplicates. A nil *Expr — "no filter" — names none.
// fieldOrder is the declared field order, so Fields() is stable across two queries that name the
// same fields in different places.
//
// # Why this is a package-level var with a test behind it
//
// It used to be an array literal inside Fields, and the enum's comment claimed that adding a field
// without extending it would be "a compile error rather than a silent out-of-range panic". That was
// wrong: `[fieldCount]field{...}` with too few values is perfectly legal Go, and the missing slots
// are filled with the zero value — which is fieldHost. So adding `length` and `duration` to the
// grammar did not fail to compile; it made Fields() report `host,status,host,host`, emitting a field
// the query never named, twice. Exactly the silent-wrong-answer this package exists to eliminate,
// produced by the guard meant to prevent it.
//
// TestFieldOrderCoversEveryField is the guard that actually holds, because a length check and a
// duplicate check are things Go will not do for you here.
var fieldOrder = [fieldCount]field{
	fieldHost, fieldMethod, fieldPath, fieldMime, fieldStatus, fieldBody, fieldLength, fieldDuration,
	fieldHeader, fieldExtension, fieldParams, fieldHighlight, fieldComment,
}

func (e *Expr) Fields() []string {
	var seen [fieldCount]bool
	e.collectFields(&seen)
	out := make([]string, 0, len(fieldOrder))
	for _, f := range fieldOrder {
		if seen[int(f)] {
			out = append(out, f.String())
		}
	}
	return out
}

// collectFields walks the tree. kindNot and the two boolean kinds recurse; only kindCmp names a
// field. A right child is nil for kindNot, which is why each branch is tested rather than the walk
// assuming two children.
func (e *Expr) collectFields(seen *[fieldCount]bool) {
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
