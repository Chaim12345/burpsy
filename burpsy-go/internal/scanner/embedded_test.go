package scanner

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// CORPUS-01: passive scanning runs PortSwigger's published corpus by default.
// The embedded snapshot must match the /tmp/BChecks oracle the conformance
// suite counts against -- a corpus update that changes the parse or
// classification counts is a change in what the proxy runs, and honest
// counting means that change is pinned here rather than shipped silently.
func TestEmbeddedCorpusParsesCleanly(t *testing.T) {
	store := core.NewTrafficStore()
	ps, err := LoadEmbedded(store, core.NewScope(), zap.NewNop())
	if err != nil {
		t.Fatalf("embedded corpus failed to load: %v", err)
	}
	r := ps.Report()
	if r.Files != 264 {
		t.Errorf("embedded corpus holds %d bcheck files, want 264 (the published PortSwigger set)", r.Files)
	}
	if len(r.Errors) != 0 {
		t.Errorf("%d embedded bchecks failed to parse, first: %s: %s", len(r.Errors), r.Errors[0].File, r.Errors[0].Err)
	}
	if r.Passive != 105 {
		t.Errorf("%d embedded bchecks classify as passive, want 105 (the count e2e-scan.sh asserts for the same corpus)", r.Passive)
	}
	if got := ps.Loaded(); got != 105 {
		t.Errorf("Loaded() = %d, want 105 passive checks run on every captured response", got)
	}
}
