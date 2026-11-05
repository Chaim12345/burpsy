package proxy

import "testing"

// The passthrough panel refreshes on real movement of the host list: an add (a duplicate
// included - the panel shows the list as written), a removal that found its pattern, and the
// auto-add after a failed negotiation, which moves the list with no API call at all. A
// removal that matches nothing and a negotiation note that adds nothing stay silent.
func TestTlsPolicyAnnouncesRealMovementAndStaysSilentOtherwise(t *testing.T) {
	p := NewTlsPolicy()
	calls := 0
	p.OnChange(func() { calls++ })

	p.AddPassthrough("bank.test")
	if calls != 1 {
		t.Fatalf("an added host announced %d times, want 1", calls)
	}
	p.AddPassthrough("bank.test")
	if calls != 2 {
		t.Fatalf("a duplicate add announced %d times, want 2 - the panel lists it twice", calls)
	}
	if p.RemovePassthrough("never-added.test") {
		t.Fatal("removing an absent pattern reported true")
	}
	if calls != 2 {
		t.Fatalf("a no-op removal announced %d times, want still 2", calls)
	}
	if !p.RemovePassthrough("bank.test") {
		t.Fatal("removing a present pattern reported false")
	}
	if calls != 3 {
		t.Fatalf("a real removal announced %d times, want 3", calls)
	}

	// Auto-add on failure: the host lands with no API call, and announces the same way.
	p.SetAutoAddOnFailure(true)
	if !p.NoteFailedNegotiation("pinned.test") {
		t.Fatal("the first failed negotiation did not add the host")
	}
	if calls != 4 {
		t.Fatalf("the auto-add announced %d times, want 4", calls)
	}
	if p.NoteFailedNegotiation("pinned.test") {
		t.Fatal("the host was already present but reported added")
	}
	if calls != 4 {
		t.Fatalf("an already-present host announced %d times, want still 4", calls)
	}

	p2 := NewTlsPolicy()
	calls2 := 0
	p2.OnChange(func() { calls2++ })
	if p2.NoteFailedNegotiation("pinned.test") {
		t.Fatal("auto-add off still reported an add")
	}
	if calls2 != 0 {
		t.Fatalf("auto-add off announced %d times, want 0", calls2)
	}
}
