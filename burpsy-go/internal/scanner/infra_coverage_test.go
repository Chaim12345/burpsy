package scanner

import (
	"strings"
	"testing"
)

// TestInfraPrimitiveMappingResolvesAgainstTheShippedCatalog fails if any issue name in
// InfraPrimitives is not a real catalog issue. A typo here would silently exempt a row
// from the stale-reason guard below, so the mapping has to be anchored to catalog_data.go
// rather than trusted as prose.
func TestInfraPrimitiveMappingResolvesAgainstTheShippedCatalog(t *testing.T) {
	for _, p := range InfraPrimitives {
		if p.Name == "" || p.File == "" {
			t.Errorf("primitive %+v is missing a Name or File", p)
		}
		if len(p.UnblockedIssues) == 0 && len(p.WiredIssues) == 0 {
			t.Errorf("primitive %q claims no issues at all; a primitive that answers nothing should not be listed", p.Name)
		}
		for _, name := range append(append([]string{}, p.UnblockedIssues...), p.WiredIssues...) {
			if _, ok := ByName(name); !ok {
				t.Errorf("primitive %q names %q, which is not in the shipped catalog", p.Name, name)
			}
		}
	}
}

// TestInfraPrimitiveMappingClaimsNoIssueTwice keeps the accounting unambiguous: two
// primitives both claiming to answer one row would make the counts depend on which is
// consulted. A row must also never appear in both lists of one primitive — it is either
// still declined or it is wired, never both.
func TestInfraPrimitiveMappingClaimsNoIssueTwice(t *testing.T) {
	owner := make(map[string]string)
	for _, p := range InfraPrimitives {
		for _, name := range append(append([]string{}, p.UnblockedIssues...), p.WiredIssues...) {
			if prev, dup := owner[name]; dup {
				t.Errorf("issue %q is claimed by both %q and %q; exactly one primitive should own each row", name, prev, p.Name)
			}
			owner[name] = p.Name
		}
	}
}

// TestEveryIssueAnInfraPrimitiveUnblocksIsStillDeclined guards the distinction the two
// lists exist for: an UnblockedIssue has the machinery but no evaluator, so it MUST still
// be declined. A row that has been wired belongs in WiredIssues, where the test below
// checks the opposite property.
func TestEveryIssueAnInfraPrimitiveUnblocksIsStillDeclined(t *testing.T) {
	byName := make(map[string]CheckDescriptor)
	for _, d := range NativeCheckRegistry() {
		byName[d.Name] = d
	}
	for _, p := range InfraPrimitives {
		for _, name := range p.UnblockedIssues {
			d, ok := byName[name]
			if !ok {
				t.Errorf("primitive %q names %q, which has no registry row at all", p.Name, name)
				continue
			}
			if d.Implementation != ImplementationDeclined {
				t.Errorf("%q is %q but is listed as merely unblocked; move it to WiredIssues (primitive %q)",
					name, d.Implementation, p.Name)
			}
		}
	}
}

// TestEveryWiredIssueIsActuallyRunnable is the counterpart: a row claimed as wired must
// have a real evaluator. Listing a row as wired while it is still declined would be the
// dishonest direction — claiming detection this scanner does not perform.
func TestEveryWiredIssueIsActuallyRunnable(t *testing.T) {
	byName := make(map[string]CheckDescriptor)
	for _, d := range NativeCheckRegistry() {
		byName[d.Name] = d
	}
	for _, p := range InfraPrimitives {
		for _, name := range p.WiredIssues {
			d, ok := byName[name]
			if !ok {
				t.Errorf("primitive %q names %q, which has no registry row at all", p.Name, name)
				continue
			}
			if !d.Runnable() {
				t.Errorf("%q is listed as wired by %q but is not runnable (implementation %q, decline reason %q)",
					name, p.Name, d.Implementation, d.DeclineReason)
			}
		}
	}
}

// TestNoDeclineReasonCitesAnAvailablePrimitive is the honest-counting gate.
//
// Once a primitive exists, a decline reason asserting the capability is absent is simply
// false, and a false reason is worse than a missing check: an operator reading "burpsy has
// no native CSP evaluator" concludes the gap is architectural when it is now merely
// unwired. This test fails until such a reason is rewritten to say what is actually true —
// the machinery exists, no evaluator is wired to it yet.
//
// It deliberately scans the whole registry rather than only DeclinedCatalogDescriptors,
// because declined rows also live in the original native slice (SSRF, XXE), in
// CacheCheckDescriptors (smuggling, desync) and in DOMAndStoredXSSDescriptors.
func TestNoDeclineReasonCitesAnAvailablePrimitive(t *testing.T) {
	for _, d := range NativeCheckRegistry() {
		if d.Implementation != ImplementationDeclined {
			continue
		}
		for _, p := range InfraPrimitives {
			for _, phrase := range p.StaleReasonPhrases {
				if strings.Contains(d.DeclineReason, phrase) {
					t.Errorf("issue %q still declines with %q, but primitive %q (%s) now provides that capability; rewrite the reason to state the machinery exists and no evaluator is wired to it",
						d.Name, phrase, p.Name, p.File)
				}
			}
		}
	}
}

// TestInfraUnblockedIssueCountIsReportedNotInferred pins the number the docs quote, so a
// mapping edit that changes it has to change the doc too.
func TestInfraUnblockedIssueCountIsReportedNotInferred(t *testing.T) {
	const want = 0
	if got := InfraUnblockedIssueCount(); got != want {
		t.Fatalf("InfraUnblockedIssueCount() = %d, want %d; update docs/SCANNER-INFRA.md's totals table in the same commit as the mapping", got, want)
	}
}

// TestInfraWiredIssueCountIsReportedNotInferred pins the only number here that means
// coverage: rows whose machinery is now actually reached by an evaluator.
func TestInfraWiredIssueCountIsReportedNotInferred(t *testing.T) {
	const want = 139
	if got := InfraWiredIssueCount(); got != want {
		t.Fatalf("InfraWiredIssueCount() = %d, want %d; update docs/SCANNER-INFRA.md's totals table in the same commit as the mapping", got, want)
	}
}
