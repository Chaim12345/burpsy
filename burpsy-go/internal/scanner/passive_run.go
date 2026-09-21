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
// The context is threaded so a future passive row that does bounded work (a body scan
// under a budget) can be cancelled like everything else.
func (s *ActiveScanner) RunPassiveChecks(ctx context.Context, ex *core.Exchange) []*Finding {
	if s == nil || ex == nil || ex.Response == nil {
		return nil
	}
	snap := s.ConfigSnapshot()
	var out []*Finding
	for _, c := range s.enabledChecks() {
		if c.run == nil || c.enabled == nil {
			continue
		}
		if !passiveGateFns[funcPtr(c.enabled)] {
			continue // not one of the two passive families
		}
		if !c.enabled(&snap) {
			continue // the family is switched off
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
