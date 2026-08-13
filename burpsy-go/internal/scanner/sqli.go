package scanner

// What is left of the original SQL-injection port, and why so little.
//
// This file used to hold a probe table (`sqlInjectionProbes`), an evidence bitmask
// (`SQLiEvidence` + four constants) and a decision table (`analyzeSQLiEvidence`) modelled on Java's
// Zh6 evaluator. Its only consumer was `ActiveScanner.checkSQLi`, which built each probe by
// appending a parameter literally named `test` to the request — so it fired only against
// applications whose vulnerable parameter happened to be called that, and when one was, appending a
// second copy still tested nothing because net/http's Query().Get returns the first value.
//
// That check is gone. `checks_core_injection.go` owns the row now and drives it through
// `ProbeHarness` over enumerated insertion points, classifying with the shared
// `ClassifyErrorEvidence` / `SQLErrorSignatures` machinery that every other injection family uses.
// Keeping a second, unused evidence model beside it was worse than dead weight: `internal/vulnapp`
// had grown branches matching this table's literal payload strings, so the vulnerable target was
// shaped around code nothing executed.
//
// Two things here are still live and stay:
//
//   - `sqlInjectionIssue`, the catalog row name, used by checks_core_injection.go.
//   - `responsesDiffer`, the package's one response-differencing helper, used by
//     checks_reflection3.go (backup files, User-Agent and Referer dependence) and
//     infra_authdiff.go (access-control comparison). It is deliberately the only such helper;
//     a second differencing layer is what the port's constraints forbid.

import "strings"

// sqlInjectionIssue is the catalog row name. Package-level so the descriptor and the finding
// cannot disagree about it.
const sqlInjectionIssue = "SQL injection"

// responsesDiffer reports whether two response bodies differ materially.
//
// Unchanged from the original port, deliberately. Java warns that difference checks are heuristic;
// requiring a difference that survives trimming avoids flagging transport formatting noise, and
// nothing more clever is attempted because four live callers (backup-file discovery, User-Agent and
// Referer dependence, access-control comparison) are calibrated against exactly this behaviour.
func responsesDiffer(left, right string) bool {
	if left == right {
		return false
	}
	return strings.TrimSpace(left) != strings.TrimSpace(right)
}
