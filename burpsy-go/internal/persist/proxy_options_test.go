package persist

import (
	"path/filepath"
	"reflect"
	"testing"

	"go.uber.org/zap"
)

// The proxy's response-modification switches survive restarts through one settings value.
//
// Before this landed, /api/proxy/options mutated the live option set and nothing else: every
// switch the operator turned on came back off after a restart, while the panel still rendered
// a perfectly working panel. A silent revert is worse than a refusal, because the operator has
// no way to learn the setting did not stick.

func TestSavedProxyOptionsRoundTrip(t *testing.T) {
	p := newTestStore(t)

	p.SaveProxyOptions(map[string]bool{
		"remove_all_javascript": true,
		"remove_object_tags":    false,
	})
	got, err := p.LoadProxyOptions()
	if err != nil {
		t.Fatalf("LoadProxyOptions: %v", err)
	}
	want := map[string]bool{
		"remove_all_javascript": true,
		"remove_object_tags":    false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %v, want %v", got, want)
	}
}

// A `false` must round-trip as a stored false, not vanish into absence. The restore path
// applies whatever it reads, so an option the operator deliberately turned *off* has to come
// back off — and if false were dropped on save, an option turned off would be
// indistinguishable from an option never touched. That is only invisible while every default
// is already off; it becomes a live-traffic bug the moment any default is on.
func TestSavedProxyOptionsKeepExplicitFalse(t *testing.T) {
	p := newTestStore(t)

	p.SaveProxyOptions(map[string]bool{"remove_all_javascript": false})
	got, err := p.LoadProxyOptions()
	if err != nil {
		t.Fatalf("LoadProxyOptions: %v", err)
	}
	on, present := got["remove_all_javascript"]
	if !present {
		t.Fatal("an explicitly-saved false was dropped; off and never-set must stay distinguishable")
	}
	if on {
		t.Fatal("a saved false read back as true")
	}
}

// The save is whole-document, so a key absent from a later save is gone rather than lingering.
// Same reasoning as SaveTlsPassthrough: the endpoint mirrors the confirmed live snapshot after
// every accepted edit, so the durable copy cannot drift from what the relay obeys.
func TestSavingProxyOptionsReplacesRatherThanMerges(t *testing.T) {
	p := newTestStore(t)

	p.SaveProxyOptions(map[string]bool{"remove_all_javascript": true, "remove_object_tags": true})
	p.SaveProxyOptions(map[string]bool{"remove_object_tags": true})

	got, err := p.LoadProxyOptions()
	if err != nil {
		t.Fatalf("LoadProxyOptions: %v", err)
	}
	if _, present := got["remove_all_javascript"]; present {
		t.Fatalf("a key dropped from the second save survived it: %v", got)
	}
	if !got["remove_object_tags"] {
		t.Fatalf("the surviving key lost its value: %v", got)
	}
}

// A fresh database is the empty state, not a failure: nil map, nil error. The caller then skips
// the apply entirely rather than writing a pile of explicit falses over NewOptions' defaults.
func TestLoadProxyOptionsOnAFreshDatabaseIsEmptyNotAnError(t *testing.T) {
	p := newTestStore(t)

	got, err := p.LoadProxyOptions()
	if err != nil {
		t.Fatalf("LoadProxyOptions on a fresh store: %v", err)
	}
	if got != nil {
		t.Fatalf("a fresh store yielded %v, want nil", got)
	}
}

// Unknown keys survive the load rather than being filtered here.
//
// This is the deliberate division of labour, and the test exists to stop a future change from
// "tidying" it: persist does not own the option vocabulary, so it cannot say which key it
// failed to recognise. The restore path in cmd/burpsy owns that, and logs the key by name. If
// this layer dropped them silently, a retired or renamed option would become a switch that
// disappeared from the operator's config with no diagnostic anywhere.
func TestLoadProxyOptionsPreservesUnrecognisedKeysForTheCallerToReport(t *testing.T) {
	p := newTestStore(t)

	p.SaveProxyOptions(map[string]bool{"retired_option_from_an_older_build": true})
	got, err := p.LoadProxyOptions()
	if err != nil {
		t.Fatalf("LoadProxyOptions: %v", err)
	}
	if !got["retired_option_from_an_older_build"] {
		t.Fatalf("an unrecognised key was filtered at the persistence layer: %v", got)
	}
}

// The defect itself, closed end to end: a switch set before a restart is still set after it.
//
// Every other test here exercises one Store. This one opens a second Store against the same
// file, which is what a restart actually is — and it is the only assertion that would have
// failed before this change, because the old endpoint mutated live state and wrote nothing.
// The others would all have passed against a saver that existed but was never called.
func TestProxyOptionsSurviveAReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")

	first, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first.SaveProxyOptions(map[string]bool{
		"remove_all_javascript": true,
		"remove_object_tags":    false,
	})
	first.Close()

	second, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	got, err := second.LoadProxyOptions()
	if err != nil {
		t.Fatalf("LoadProxyOptions after reopen: %v", err)
	}
	if !got["remove_all_javascript"] {
		t.Fatal("a switch turned on before the restart came back off — this is the defect, unfixed")
	}
	if got["remove_object_tags"] {
		t.Fatal("a switch left off came back on")
	}
}
