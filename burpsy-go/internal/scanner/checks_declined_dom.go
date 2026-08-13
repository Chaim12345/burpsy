// checks_declined_dom.go used to name the DOM-based and stored catalog issues this port could
// not evaluate honestly, so they were counted as explicit declines rather than falling through
// as silent misses.
//
// Both blockers it described are gone:
//
//   - The browser/DOM execution engine now exists as `internal/domexec`, which renders the page
//     in real Chromium and observes tainted values arriving at instrumented sinks. The DOM rows
//     live in checks_dom.go and checks_dom_extra.go.
//   - The stored/second-order path now exists as `StoredLedger` plus `PlantStoredCanaries`,
//     which correlates a value planted in one exchange with its appearance in a later one. The
//     stored rows live in checks_stored.go.
//
// The list is therefore empty and `DOMAndStoredXSSDescriptors` returns nothing. Both are kept
// rather than deleted because they are the registration point a future decline needs: a row
// that cannot be evaluated honestly must have somewhere to be counted, and re-adding that
// plumbing under deadline pressure is how silent misses get shipped.
package scanner

// domAndStoredXSSDeclines is empty: every row it used to hold now has an evaluator. Adding an
// entry here is the correct move for a future issue whose capability is genuinely missing.
var domAndStoredXSSDeclines = []struct {
	name   string
	scope  DispatchScope
	reason string
}{}

// DOMAndStoredXSSDescriptors returns one declinedDescriptor per entry in
// domAndStoredXSSDeclines. Gated by extendedCoverageEnabled (see
// check_registry_declined.go): these issues have no existing ScanConfig
// toggle of their own, and inventing individual ones for checks that cannot
// run would misrepresent them as independently configurable.
func DOMAndStoredXSSDescriptors() []CheckDescriptor {
	out := make([]CheckDescriptor, 0, len(domAndStoredXSSDeclines))
	for _, d := range domAndStoredXSSDeclines {
		out = append(out, declinedDescriptor(d.name, d.scope, extendedCoverageEnabled, d.reason))
	}
	return out
}
