package session

// Pins the Session page's live-update contract (see onchange.go): every mutation the page
// renders announces exactly once, and the no-movement shapes stay silent — an unchanged rule
// PUT, an offset-0 or edge-clamped move, a removal of nothing, and a repeated Set-Cookie whose
// stored fields (absolute expiry included) are identical.

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

type changeCounter struct{ n int }

func (c *changeCounter) hook() func() { return func() { c.n++ } }

// plainRule builds a minimal valid rule: no macro steps, so its action list must not run a
// macro - a single enabled set-header action keeps ValidateRule satisfied without a network.
func plainRule(name string) *SessionRule {
	rule := NewSessionRule(name, []string{"example.com"}, nil)
	rule.Actions = []*Action{{Kind: ActionSetHeader, Enabled: true, Name: "x-test", Value: "1"}}
	return rule
}

func newHookedCoordinator() (*Coordinator, *changeCounter) {
	c := NewCoordinator(zap.NewNop())
	cc := &changeCounter{}
	c.OnChange(cc.hook())
	return c, cc
}

func TestRuleMovementAnnouncesAndNoOpsStaySilent(t *testing.T) {
	c, cc := newHookedCoordinator()

	id, err := c.AddRule(plainRule("one"))
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if cc.n != 1 {
		t.Fatalf("AddRule announced %d times, want 1", cc.n)
	}

	// An unchanged PUT is not movement.
	cur := c.Rule(id)
	if err := c.UpdateRule(id, plainRule("one")); err != nil {
		t.Fatalf("UpdateRule identical: %v", err)
	}
	if cc.n != 1 {
		t.Errorf("identical UpdateRule announced; count = %d, want 1", cc.n)
	}
	_ = cur

	// A changed PUT is.
	edit := plainRule("one")
	edit.ScopeHosts = []string{"example.com", "www.example.com"}
	if err := c.UpdateRule(id, edit); err != nil {
		t.Fatalf("UpdateRule changed: %v", err)
	}
	if cc.n != 2 {
		t.Errorf("changed UpdateRule did not announce; count = %d, want 2", cc.n)
	}

	// Offset-0 and edge-clamped moves are silent; a real move announces.
	if _, err := c.MoveRule(id, 0); err != nil {
		t.Fatalf("MoveRule 0: %v", err)
	}
	if _, err := c.MoveRule(id, -1); err == nil {
		t.Fatalf("MoveRule past the top should fail, it is the no-op shape")
	}
	if cc.n != 2 {
		t.Errorf("no-op moves announced; count = %d, want 2", cc.n)
	}

	id2, err := c.AddRule(plainRule("two"))
	if err != nil {
		t.Fatalf("AddRule two: %v", err)
	}
	if cc.n != 3 {
		t.Fatalf("second AddRule did not announce; count = %d, want 3", cc.n)
	}
	if _, err := c.MoveRule(id2, -1); err != nil {
		t.Fatalf("MoveRule real: %v", err)
	}
	if cc.n != 4 {
		t.Errorf("real MoveRule did not announce; count = %d, want 4", cc.n)
	}

	// Removing what is not there is silent; removing a held rule announces.
	c.RemoveRule(RuleID(9999))
	if cc.n != 4 {
		t.Errorf("absent RemoveRule announced; count = %d, want 4", cc.n)
	}
	c.RemoveRule(id2)
	if cc.n != 5 {
		t.Errorf("RemoveRule did not announce; count = %d, want 5", cc.n)
	}
}

func TestCookieJarMovementAnnouncesAndRepeatsStaySilent(t *testing.T) {
	c, cc := newHookedCoordinator()

	c.SetCookie("example.com", 443, true, "sid", "synthetic-a")
	if cc.n != 1 {
		t.Fatalf("SetCookie announced %d times, want 1", cc.n)
	}
	// Same name, same value: nothing changed.
	c.SetCookie("example.com", 443, true, "sid", "synthetic-a")
	if cc.n != 1 {
		t.Errorf("identical SetCookie announced; count = %d, want 1", cc.n)
	}
	// New value: movement.
	c.SetCookie("example.com", 443, true, "sid", "synthetic-b")
	if cc.n != 2 {
		t.Errorf("changed SetCookie did not announce; count = %d, want 2", cc.n)
	}

	// Absorbing the identical Set-Cookie from traffic is silent.
	c.AbsorbCookie("example.com", 443, true, "sid=synthetic-b; Path=/")
	if cc.n != 2 {
		t.Errorf("identical absorb announced; count = %d, want 2", cc.n)
	}
	// Gaining an expiry is movement, and a rolling Max-Age that slides a still-valid expiry
	// announces too: the page renders the expiry verbatim, so a silent slide would leave the
	// rendered Expires cell stale.
	c.AbsorbCookie("example.com", 443, true, "sid=synthetic-b; Path=/; Max-Age=3600")
	if cc.n != 3 {
		t.Fatalf("gaining an expiry is movement; count = %d, want 3", cc.n)
	}
	c.AbsorbCookie("example.com", 443, true, "sid=synthetic-b; Path=/; Max-Age=3600")
	if cc.n != 4 {
		t.Errorf("rolling Max-Age refresh (a rendered expiry change) did not announce; count = %d, want 4", cc.n)
	}
	// A withdrawal (Max-Age=0) is movement.
	c.AbsorbCookie("example.com", 443, true, "sid=synthetic-b; Path=/; Max-Age=0")
	if cc.n != 5 {
		t.Errorf("cookie withdrawal did not announce; count = %d, want 5", cc.n)
	}
	// The same absolute expiry re-sent stores nothing new: silent.
	c.AbsorbCookie("example.com", 443, true, "sid=fixed; Path=/; Expires=Thu, 01 Jan 2032 00:00:00 GMT")
	if cc.n != 6 {
		t.Fatalf("a new cookie with an absolute expiry did not announce; count = %d, want 6", cc.n)
	}
	c.AbsorbCookie("example.com", 443, true, "sid=fixed; Path=/; Expires=Thu, 01 Jan 2032 00:00:00 GMT")
	if cc.n != 6 {
		t.Errorf("identical absolute-expiry resubmission announced; count = %d, want 6", cc.n)
	}

	// Removals: absent is silent, held announces, clearing an empty jar is silent.
	if c.RemoveCookie("example.com", 443, true, "never-there") {
		t.Fatalf("RemoveCookie of an absent cookie reported true")
	}
	if cc.n != 6 {
		t.Errorf("absent RemoveCookie announced; count = %d, want 6", cc.n)
	}
	if !c.RemoveCookie("example.com", 443, true, "sid") {
		t.Fatalf("RemoveCookie of a held cookie reported false")
	}
	if cc.n != 7 {
		t.Errorf("RemoveCookie did not announce; count = %d, want 7", cc.n)
	}
	if !c.ClearJar("example.com", 443, true) {
		t.Fatalf("ClearJar of an existing authority reported false")
	}
	if cc.n != 7 {
		t.Errorf("clearing an already-empty jar announced; count = %d, want 7", cc.n)
	}
}

func TestAbsorbRequestCookieAnnouncesOnlyOnContentChange(t *testing.T) {
	c, cc := newHookedCoordinator()
	c.jarMgr.AbsorbRequestCookie("example.com", 443, true, "/", "tok", "synthetic-1")
	if cc.n != 1 {
		t.Fatalf("first request-cookie absorb announced %d times, want 1", cc.n)
	}
	c.jarMgr.AbsorbRequestCookie("example.com", 443, true, "/", "tok", "synthetic-1")
	if cc.n != 1 {
		t.Errorf("identical request-cookie absorb announced; count = %d, want 1", cc.n)
	}
	c.jarMgr.AbsorbRequestCookie("example.com", 443, true, "/", "tok", "synthetic-2")
	if cc.n != 2 {
		t.Errorf("changed request-cookie absorb did not announce; count = %d, want 2", cc.n)
	}
}

func TestTracerFlipAndEntriesAnnounce(t *testing.T) {
	c, cc := newHookedCoordinator()

	// Re-affirming the off default is silent; flipping on announces; re-affirming is silent again.
	c.SetTracerEnabled(false)
	if cc.n != 0 {
		t.Fatalf("re-affirming tracer off announced; count = %d, want 0", cc.n)
	}
	c.SetTracerEnabled(true)
	if cc.n != 1 {
		t.Fatalf("tracer flip announced %d times, want 1", cc.n)
	}
	c.SetTracerEnabled(true)
	if cc.n != 1 {
		t.Errorf("re-affirming tracer on announced; count = %d, want 1", cc.n)
	}

	// A recorded entry announces while the tracer is on.
	rule := plainRule("trace-me")
	c.recordTrace("proxy", MacroStep{URL: "https://example.com/"}, RuleID(1), rule, RecoveryOutcome{})
	if cc.n != 2 {
		t.Errorf("trace entry did not announce; count = %d, want 2", cc.n)
	}
	if got := len(c.TracerEntries()); got != 1 {
		t.Fatalf("tracer holds %d entries, want 1", got)
	}

	// Off again: one more announcement, and nothing records while off.
	c.SetTracerEnabled(false)
	if cc.n != 3 {
		t.Errorf("tracer off flip did not announce; count = %d, want 3", cc.n)
	}
	c.recordTrace("proxy", MacroStep{URL: "https://example.com/"}, RuleID(1), rule, RecoveryOutcome{})
	if cc.n != 3 {
		t.Errorf("record while off announced; count = %d, want 3", cc.n)
	}
}

// The comparison itself: any stored difference announces, expiry slides included, because the
// page renders the expiry verbatim; only a truly identical stored cookie stays silent.
func TestJarCookieDifferenceTracksRenderedState(t *testing.T) {
	future := time.Now().Add(time.Hour)
	base := jarCookie{Value: "v", Path: "/", Domain: "example.com", Expires: future}
	for _, tc := range []struct {
		name string
		new  jarCookie
		want bool
	}{
		{"identical", base, false},
		{"value differs", jarCookie{Value: "w", Path: "/", Domain: "example.com", Expires: future}, true},
		{"path differs", jarCookie{Value: "v", Path: "/x", Domain: "example.com", Expires: future}, true},
		{"domain differs", jarCookie{Value: "v", Path: "/", Domain: "other.test", Expires: future}, true},
		{"secure flag differs", jarCookie{Value: "v", Path: "/", Domain: "example.com", Expires: future, Secure: true}, true},
		{"httponly flag differs", jarCookie{Value: "v", Path: "/", Domain: "example.com", Expires: future, HTTPOnly: true}, true},
		{"expiry slides forward (rendered change)", jarCookie{Value: "v", Path: "/", Domain: "example.com", Expires: future.Add(time.Hour)}, true},
		{"expiry gained", jarCookie{Value: "v", Path: "/", Domain: "example.com", Expires: future}, true},
		{"both session (zero expiry)", jarCookie{Value: "v", Path: "/", Domain: "example.com"}, false},
	} {
		old := base
		if tc.name == "both session (zero expiry)" {
			old = jarCookie{Value: "v", Path: "/", Domain: "example.com"}
		}
		if tc.name == "expiry gained" {
			old = jarCookie{Value: "v", Path: "/", Domain: "example.com"}
		}
		if got := jarCookieMeaningfullyDifferent(old, tc.new); got != tc.want {
			t.Errorf("%s: jarCookieMeaningfullyDifferent = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Regression for the unlock-before-notify contract. The six rule-mutation methods once fired
// the hook through `defer c.noteChange()` after `defer c.mu.Unlock()`; defers are LIFO, so the
// hook ran while c.mu was still held. That was invisible while the only hook was the hub's
// non-blocking notify, but any hook that reads coordinator state deadlocks on it. This
// installs exactly such a hook; each mutation runs on its own goroutine so a regression fails
// the test instead of hanging the suite.
func TestHookFiresAfterCoordinatorLockReleased(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	c.OnChange(func() {
		// Reads that take c.mu (RLock) and the jar lock: if any mutation fires this while
		// holding its lock, the goroutine below never returns.
		c.AllRules()
		c.Cookies()
	})
	run := func(name string, op func()) {
		done := make(chan struct{})
		go func() { defer close(done); op() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not return: the hook fired while the coordinator lock was held", name)
		}
	}

	var id, id2 RuleID
	run("AddRule", func() { id, _ = c.AddRule(plainRule("lock-a")) })
	run("RestoreRule", func() {
		rule := plainRule("lock-b")
		rule.ID = RuleID(9999)
		_ = c.RestoreRule(rule)
		id2 = rule.ID
	})
	run("UpdateRule", func() { _ = c.UpdateRule(id, plainRule("lock-a-renamed")) })
	run("AddExtraction", func() {
		_ = c.AddExtraction(id, &Extraction{Name: "tok", From: "body", Pattern: "token=([a-z]+)"})
	})
	run("MoveRule", func() { _, _ = c.MoveRule(id2, -1) })
	run("RemoveRule", func() { c.RemoveRule(id2) })
}
