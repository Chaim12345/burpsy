package scanner

// The per-row corpus enable/disable (burpsy-react-ui-kdqj, criterion 1).
//
// The route and the leaf are the other half; these prove the half that can silently not exist: that
// a check switched off is a check the AUDIT ENGINE does not dispatch. ActiveCheckCount() is that
// claim in one number — it is len(enabledChecks()), the set a run uses — so an assertion on it fails
// the moment the engine stops consulting the disabled set. An assertion on the flag alone would pass
// while the switch changed nothing, which is the decorative-control defect this repository refuses
// to ship.

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

func TestA_disabled_corpus_check_is_not_in_the_engine_dispatch_set(t *testing.T) {
	store := core.NewTrafficStore()
	// Two checks with DISTINCT names: corpusCheck's helper names every check "t", and a name-keyed
	// disabled set over two same-named checks would disable both — a fixture artefact that would make
	// the assertion below pass for the wrong reason.
	parse := func(name, given string) *bcheck.Check {
		t.Helper()
		c, err := bcheck.Parse("metadata:\n  language: v2-beta\n  name: \"" + name + "\"\n" +
			"given " + given + " then\n  if {response.status_code} is \"200\" then\n" +
			"    report issue:\n      severity: low\n      confidence: certain\n  end if\n")
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return c
	}
	one := parse("first-check", "host")
	two := parse("second-check", "path")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1}).
		WithCorpusChecks([]*bcheck.Check{one, two})

	before := scan.ActiveCheckCount()
	if before != 2 {
		t.Fatalf("dispatch set = %d, want the 2 corpus checks with every built-in switch off", before)
	}

	scan.DisableCheck(two.Name)

	if got := scan.ActiveCheckCount(); got != before-1 {
		t.Errorf("dispatch set = %d after disabling one check, want %d: the audit engine is not "+
			"consulting the disabled set, so the leaf's switch would change nothing", got, before-1)
	}
	if !scan.CheckDisabled(two.Name) {
		t.Error("the check is not marked disabled after DisableCheck")
	}

	scan.EnableCheck(two.Name)
	if got := scan.ActiveCheckCount(); got != before {
		t.Errorf("dispatch set = %d after re-enabling, want %d", got, before)
	}

	// The disabled set is keyed by name and survives a corpus being replaced: a check switched off
	// before WithCorpusChecks runs is switched off when the corpus arrives.
	scan.DisableCheck(one.Name)
	scan.WithCorpusChecks([]*bcheck.Check{one, two})
	if got := scan.ActiveCheckCount(); got != 1 {
		t.Errorf("dispatch set = %d after a corpus reload, want 1: a name disabled before the corpus "+
			"loaded must still be disabled, or a reload silently re-enables checks the operator "+
			"switched off", got)
	}
}
