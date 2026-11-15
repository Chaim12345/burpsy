package proxy

import (
	"testing"
)

func boolp(b bool) *bool { return &b }

// listenerSpecEqual is meaning-equality, not pointer-equality: the tri-state fields are equal
// when both are nil (inherit) or point at the same VALUE, and nil versus an explicit false is a
// real difference, because inherit is not force-off.
func TestListenerSpecEqualityIsSemantic(t *testing.T) {
	base := ListenerSpec{Bind: "127.0.0.1:8080", RedirectPort: 443, ForceTLS: true, Invisible: boolp(true), HTTP2: boolp(false)}
	if !listenerSpecEqual(base, base) {
		t.Fatal("a spec is not equal to itself")
	}
	// Separately decoded, separately allocated - the same settings.
	twin := ListenerSpec{Bind: "127.0.0.1:8080", RedirectPort: 443, ForceTLS: true, Invisible: boolp(true), HTTP2: boolp(false)}
	if !listenerSpecEqual(base, twin) {
		t.Fatal("separately decoded copies of the same settings are not equal")
	}
	noInherit := base
	noInherit.Invisible = nil
	if listenerSpecEqual(base, noInherit) {
		t.Fatal("forced true read as equal to inherit (nil)")
	}
	forceOff := base
	forceOff.Invisible = boolp(false)
	if listenerSpecEqual(noInherit, forceOff) {
		t.Fatal("inherit (nil) read as equal to forced off - inherit is not force-off")
	}
	h2 := base
	h2.HTTP2 = nil
	if listenerSpecEqual(base, h2) {
		t.Fatal("HTTP2 forced off read as equal to inherit (nil)")
	}
	moved := base
	moved.RedirectPort = 444
	if listenerSpecEqual(base, moved) {
		t.Fatal("a changed redirect port read as equal")
	}
}

// The listener table announces real movement only: an add, a remove, and an update that
// changes the spec. An update that restates the current spec - same bind, same ticks,
// separately decoded - announces nothing.
func TestListenersAnnounceRealMovementAndStaySilentOtherwise(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)
	calls := 0
	srv.OnListenersChange(func() { calls++ })

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0", RedirectPort: 8081, Invisible: boolp(true)})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if calls != 1 {
		t.Fatalf("an added listener announced %d times, want 1", calls)
	}

	// Restating the same spec (freshly allocated *bool, same values) stays silent.
	if _, err := srv.UpdateListener(added.ID, ListenerSpec{Bind: added.Bind, RedirectPort: 8081, Invisible: boolp(true)}); err != nil {
		t.Fatalf("identical UpdateListener: %v", err)
	}
	if calls != 1 {
		t.Fatalf("an identical update announced %d times, want still 1", calls)
	}
	// Typing the resolved address keeps the socket, but rewrites the Bind cell from ":0" to
	// the real port - a rendered change, so it announces.
	if _, err := srv.UpdateListener(added.ID, ListenerSpec{Bind: added.BoundAddr, RedirectPort: 8081, Invisible: boolp(true)}); err != nil {
		t.Fatalf("resolved-bind UpdateListener: %v", err)
	}
	if calls != 2 {
		t.Fatalf("a Bind-cell-moving update announced %d times, want 2", calls)
	}

	// inherit -> forced off is real movement.
	if _, err := srv.UpdateListener(added.ID, ListenerSpec{Bind: added.BoundAddr, RedirectPort: 8081, Invisible: boolp(false)}); err != nil {
		t.Fatalf("tri-state-changing UpdateListener: %v", err)
	}
	if calls != 3 {
		t.Fatalf("a tri-state change announced %d times, want 3", calls)
	}

	if err := srv.RemoveListener(added.ID); err != nil {
		t.Fatalf("RemoveListener: %v", err)
	}
	if calls != 4 {
		t.Fatalf("a removed listener announced %d times, want 4", calls)
	}
	if err := srv.RemoveListener(added.ID); err == nil {
		t.Fatal("removing a missing listener reported success")
	}
	if calls != 4 {
		t.Fatalf("a failed removal announced %d times, want still 4", calls)
	}
}
