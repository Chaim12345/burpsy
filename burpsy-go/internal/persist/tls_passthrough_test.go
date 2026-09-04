package persist

import (
	"reflect"
	"testing"
)

// The TLS passthrough list survives restarts through one settings value. Whole-list
// save, whole-list load: the web endpoint mirrors the live list after every mutation,
// so there is no incremental API to drift out of order.

func TestSavedTlsPassthroughPatternsRoundTripInOrder(t *testing.T) {
	p := newTestStore(t)

	p.SaveTlsPassthrough([]string{"*.bank.test", "safe.test"})
	got, err := p.LoadTlsPassthrough()
	if err != nil {
		t.Fatalf("LoadTlsPassthrough: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"*.bank.test", "safe.test"}) {
		t.Fatalf("restored = %v; the saved list must round-trip with its order intact", got)
	}

	// A later save replaces rather than appends: the mirror always writes what the
	// policy holds now, so a stale entry must not resurrect from an earlier save.
	p.SaveTlsPassthrough([]string{"only.now.test"})
	got, err = p.LoadTlsPassthrough()
	if err != nil {
		t.Fatalf("LoadTlsPassthrough after replace: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"only.now.test"}) {
		t.Fatalf("restored = %v; re-saving must replace the list, never grow it", got)
	}
}

func TestLoadTlsPassthroughOnAFreshDatabaseIsEmptyNotAnError(t *testing.T) {
	p := newTestStore(t)

	got, err := p.LoadTlsPassthrough()
	if err != nil {
		t.Fatalf("LoadTlsPassthrough on a fresh store: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("restored = %v; absence of a saved list is the empty state, not a failure", got)
	}
}
