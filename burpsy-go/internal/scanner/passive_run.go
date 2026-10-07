package scanner

// The live passive audit (burpsy-react-ui-v7fo): the passive check families — the rows
// that READ the captured exchange and send nothing — runnable over one exchange outside an
// audit session, so a capture surface (the live sweep) can run them as traffic lands.
//
// # What this is, and what it deliberately is not
//
// The posture and analysis families are already passive by construction: their gates
// (passivePostureEnabled, passiveAnalysisEnabled) are ScanConfig switches, and their
// checks read the exchange and return findings without ever reaching for the sender. What
// did not exist was a way to run exactly that subset over one exchange without
// dispatching the whole audit plan. RunPassiveChecks is that: it filters the enabled set
// to the two passive families — by FUNCTION IDENTITY against the families' gate
// functions, not by name list, so a descriptor added under one of those gates tomorrow is
// passive here automatically and nothing else ever is — builds one CheckContext, and runs
// each row. No ledger, no meter, no breakers: those exist to bound probe-sending, and a
// passive row sends nothing to bound.
//
// # What the caller owes
//
// The findings are RETURNED, not stored: the sweep adds them to the finding store under
// its own accounting (counted separately from active findings), and a later AuditSession
// over the same exchange merges into the same stored findings by finding identity —
// confirmed, not duplicated.
import (
	"context"
	"reflect"

	"github.com/burpsy-go/burpsy/internal/core"
)

// passiveGateFns are the enabled-gate functions the two passive families hang from.
// Function identity, not names: the set cannot drift as descriptors are added.
var passiveGateFns = map[uintptr]bool{
	funcPtr(passivePostureEnabled):  true,
	funcPtr(passiveAnalysisEnabled): true,
}

// funcPtr gives a comparable identity for a gate function.
func funcPtr(f func(*ScanConfig) bool) uintptr {
	return reflect.ValueOf(f).Pointer()
}

// RunPassiveChecks runs the enabled passive check families over one captured exchange and
// returns the findings they produced. Nil-safe on scanner and exchange; an exchange with
// no response yields nothing (the passive rows read the response).
//
// # cfg is the run configuration, and it narrows exactly as it narrows an audit
//
// The check set is enabledChecksUnder(cfg) — the same selection the audit dispatch reads — and
// not the scanner's bare family switches. Before burpsy-react-ui-saq3.3.2 this walked
// enabledChecks(), so a configuration that set scan_type_passive false, or deselected a passive
// issue type through selected_issues, stopped that type in every audit session and left it
// raising findings on every captured exchange the live sweep admitted: the sweep's ACTIVE half
// honoured the run's selection and its passive half, one loop earlier, did not. There is one
// selection implementation (issue_selection.go's filterBySelection, reached through
// enabledChecksUnder) and this is now one more caller of it, not a second copy.
//
// The run configuration also rides the context, as it does for a dispatched check, so a passive
// row that reads it (enumeration options, say) reads the run's and not the server default.
//
// The context is threaded so a future passive row that does bounded work (a body scan
// under a budget) can be cancelled like everything else.
func (s *ActiveScanner) RunPassiveChecks(ctx context.Context, ex *core.Exchange, cfg AuditConfig) []*Finding {
	if s == nil || ex == nil || ex.Response == nil {
		return nil
	}
	ctx = withRunConfig(ctx, cfg)
	var out []*Finding
	for _, c := range s.enabledChecksUnder(cfg) {
		if c.run == nil || c.enabled == nil {
			continue
		}
		// Not one of the two passive families. The family switches themselves were already applied
		// by enabledChecksUnder, along with scan_type_passive and the per-issue selection.
		if !passiveGateFns[funcPtr(c.enabled)] {
			continue
		}
		findings, err := c.run(s, ctx, ex)
		if err != nil {
			continue // a passive row's refusal is the audit's Skipped, not a finding; the sweep counts rows it got
		}
		for _, f := range findings {
			if f != nil {
				out = append(out, f)
			}
		}
	}
	return out
}
