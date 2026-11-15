package core

// Tests for scope-change notification (burpsy-react-ui-e05t).
//
// # What is worth proving here, beyond "the handler was called"
//
// Three properties, and the second is the one that decided the design:
//
//  1. A handler IS told about every mutation that can change an authorisation answer — including the
//     ones that change the answer while leaving the rule COUNT identical, which is precisely what a
//     naive "did the list change" filter drops.
//
//  2. A handler may call back into the scope. A subscriber re-reading the scope to see what changed
//     is the obvious thing to do, and every mutator in scope.go used to hold a write lock with
//     `defer s.mu.Unlock()` at the point the notification would fire. A handler calling Contains()
//     there is a deadlock, so this is asserted with a real re-entrant call rather than described.
//
//  3. A panicking handler does not take the scope with it. The handler here is an extension: code this
//     repository does not control, in this process, and the operator's edit has ALREADY been applied
//     by the time it runs.

import (
	"sync"
	"testing"
)

// recorded collects the changes one handler saw.
type recorded struct {
	mu      sync.Mutex
	changes []ScopeChange
}

func (r *recorded) add(c ScopeChange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, c)
}

func (r *recorded) seen() []ScopeChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ScopeChange, len(r.changes))
	copy(out, r.changes)
	return out
}

func (r *recorded) count() int { return len(r.seen()) }

// The three count-changing mutators each notify, with the right operation name and counts.
func TestEveryCountChangingMutationNotifies(t *testing.T) {
	scope := NewScope()
	rec := &recorded{}
	unregister := scope.OnChange(rec.add)
	defer unregister()

	scope.AddInclude("a.test")
	scope.AddExclude("a.test/private")
	scope.Remove(ScopeInclude, "a.test")

	seen := rec.seen()
	if len(seen) != 3 {
		t.Fatalf("recorded %d changes, want 3 (add, exclude-add, remove): %+v", len(seen), seen)
	}
	if seen[0].Operation != "add" || seen[0].Before != 0 || seen[0].After != 1 {
		t.Errorf("the first change is %+v, want an add taking 0 rules to 1", seen[0])
	}
	if seen[1].Operation != "add" || seen[1].Before != 1 || seen[1].After != 2 {
		t.Errorf("the second change is %+v, want an add taking 1 to 2", seen[1])
	}
	if seen[2].Operation != "remove" || seen[2].Before != 2 || seen[2].After != 1 {
		t.Errorf("the third change is %+v, want a remove taking 2 to 1", seen[2])
	}
	for i, c := range seen {
		if !c.Changed() {
			t.Errorf("change %d reports Changed() = false but was delivered: %+v", i, c)
		}
	}
}

// The load-bearing case: a toggle changes what the scope AUTHORISES while leaving the rule count
// identical. A subscriber filtering on "did the count change" — the obvious implementation — never
// hears about it, and keeps serving a stale answer after the operator turned a rule off.
func TestAToggleNotifiesEvenThoughTheRuleCountDoesNotChange(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")
	// A genuinely PATH-SCOPED exclude. AddExclude is NOT the way to build one: it takes a HOST
	// pattern and does not parse a path out of it — verified by reading the rule back, which comes
	// back as pattern="a.test/admin" with a nil prefix and therefore matches a HOST, not a path.
	prefix := "/admin"
	scope.Add(NewScopeRuleWithPath(ScopeExclude, "a.test", prefix))

	rec := &recorded{}
	defer scope.OnChange(rec.add)()

	if scope.Contains("a.test", 80, "/admin/x", false) {
		t.Fatal("fixture assumption broken: the path-scoped exclude should already be hiding /admin")
	}

	// The identity is EXACT — kind, pattern, path prefix, port — because RemoveScoped's doc comment
	// says why: deleting or toggling the wrong scope rule silently changes the authorised surface.
	// Turn the EXCLUDE off. The rule count stays at 2; the answer changes.
	if scope.SetRuleEnabled(ScopeExclude, "a.test", &prefix, nil, nil, false) != ScopeMatchDone {
		t.Fatal("SetRuleEnabled did not find the rule it was given")
	}
	if scope.Contains("a.test", 80, "/admin/x", false) != true {
		t.Error("after disabling the exclude, /admin is still hidden")
	}

	seen := rec.seen()
	if len(seen) != 1 {
		t.Fatalf("a toggle delivered %d changes, want 1 — this is the case a count-diff filter drops", len(seen))
	}
	if seen[0].Operation != "enable" {
		t.Errorf("operation = %q, want %q", seen[0].Operation, "enable")
	}
	if seen[0].Before != seen[0].After {
		t.Errorf("the toggle reported different counts (%d -> %d); it is in place precisely because "+
			"they are equal", seen[0].Before, seen[0].After)
	}
	// Which is why Changed() is false here and the notification is still delivered: Changed() answers
	// "is my cached count still valid", and the handler that needs this one is not asking that.
	if seen[0].Changed() {
		t.Error("Changed() is true for a toggle, so the two signals have stopped meaning different things")
	}
}

// An in-place edit is the other count-preserving mutation.
func TestAnEditNotifiesEvenThoughTheRuleCountDoesNotChange(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")

	rec := &recorded{}
	defer scope.OnChange(rec.add)()

	replacement := NewScopeRule(ScopeInclude, "b.test")
	if !scope.ReplaceScoped(ScopeInclude, "a.test", nil, nil, nil, replacement) {
		t.Fatal("ReplaceScoped did not find the rule it was given")
	}
	seen := rec.seen()
	if len(seen) != 1 || seen[0].Operation != "replace" {
		t.Errorf("an edit delivered %+v, want one change named \"replace\"", seen)
	}
}

// A mutation that finds nothing is NOT a change, and must not wake a subscriber.
func TestAMutationThatChangesNothingDoesNotNotify(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")
	rec := &recorded{}
	defer scope.OnChange(rec.add)()

	// A remove of something that is not there, an edit of something that is not there, and a toggle
	// of something that is not there. All three are refused by their mutators and none of them is a
	// decision about what the scope authorises.
	if scope.Remove(ScopeInclude, "nope.test") {
		t.Error("Remove claimed to remove a rule that is not there")
	}
	if scope.ReplaceScoped(ScopeInclude, "nope.test", nil, nil, nil, NewScopeRule(ScopeInclude, "x")) {
		t.Error("ReplaceScoped claimed to replace a rule that is not there")
	}
	if scope.SetRuleEnabled(ScopeInclude, "nope.test", nil, nil, nil, false) == ScopeMatchDone {
		t.Error("SetRuleEnabled claimed to toggle a rule that is not there")
	}
	if got := rec.count(); got != 0 {
		t.Errorf("a handler was woken %d times by mutations that changed nothing", got)
	}
}

// A Clear is told about even when the scope was already empty: it is an operator decision a
// subscriber may act on (a frontier dropping everything it had queued), and "the operator cleared it"
// is a fact even when there was nothing to clear.
func TestAClearIsToldAboutEvenOnAnEmptyScope(t *testing.T) {
	scope := NewScope()
	rec := &recorded{}
	defer scope.OnChange(rec.add)()

	scope.Clear()
	if got := rec.count(); got != 1 {
		t.Fatalf("an empty Clear delivered %d changes, want 1", got)
	}
	if rec.seen()[0].Operation != "clear" {
		t.Errorf("operation = %q, want \"clear\"", rec.seen()[0].Operation)
	}
}

// THE DEADLOCK TEST. A handler re-reads the scope, which is what a real subscriber does to decide
// what to invalidate. Every mutator here holds a write lock with defer-unlock at the point the
// notification fires, so a handler calling Contains() inside that window deadlocks.
//
// Run with the test binary's own timeout as the backstop: a deadlock here is a hang, not a failure,
// and a test that hangs is how this gets discovered rather than in production.
func TestAHandlerMayReadTheScopeItWasToldAbout(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")

	var insideContains bool
	var insideRules int
	var mu sync.Mutex

	done := make(chan struct{})
	scope.OnChange(func(ScopeChange) {
		// Both of these take s.mu, so both would deadlock if the notification fired under the write
		// lock. Called from inside the handler deliberately.
		insideContains = scope.Contains("a.test", 80, "/x", false)
		insideRules = len(scope.Rules())
		close(done)
	})

	scope.AddInclude("b.test")
	<-done

	mu.Lock()
	defer mu.Unlock()
	if !insideContains {
		t.Error("Contains() from inside the handler said the pre-existing include no longer matches; " +
			"the handler must see the scope AS IT IS AFTER the change")
	}
	if insideRules != 2 {
		t.Errorf("Rules() from inside the handler reported %d rules, want 2: a handler woken by a "+
			"change must see the change applied, or it invalidates against the old state", insideRules)
	}
}

// A subscriber is third-party code in this process. A panic in one must not un-apply an edit the
// operator already made, nor take the request path down with it.
func TestAPanickingHandlerDoesNotTakeTheScopeWithIt(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")

	var after []ScopeChange
	scope.OnChange(func(ScopeChange) { panic("the extension is broken") })
	defer scope.OnChange(func(c ScopeChange) { after = append(after, c) })()

	scope.AddInclude("b.test")

	// The edit stands.
	if !scope.Contains("b.test", 80, "/x", false) {
		t.Error("a panicking handler un-applied the operator's edit")
	}
	// And a later change still reaches the remaining handlers.
	if len(after) != 1 {
		t.Errorf("a later change delivered %d notifications, want 1: one broken subscriber must not "+
			"stop the others", len(after))
	}
	// And the scope still answers requests at all.
	if !scope.Contains("a.test", 80, "/x", false) {
		t.Error("the scope stopped answering after a handler panicked")
	}
}

// Unregistering stops the notifications, and only for that registration.
func TestUnregisteringStopsTheNotifications(t *testing.T) {
	scope := NewScope()
	rec := &recorded{}
	unregister := scope.OnChange(rec.add)

	scope.AddInclude("a.test")
	if rec.count() != 1 {
		t.Fatalf("recorded %d before unregistering, want 1", rec.count())
	}
	unregister()
	scope.AddInclude("b.test")
	if rec.count() != 1 {
		t.Errorf("recorded %d after unregistering, want 1 — a removed handler is still being called",
			rec.count())
	}
}

// Two registrations of the SAME function are two subscriptions, and removing one leaves the other.
func TestTwoRegistrationsOfOneHandlerAreIndependent(t *testing.T) {
	scope := NewScope()
	rec := &recorded{}
	removeFirst := scope.OnChange(rec.add)
	defer scope.OnChange(rec.add)()

	scope.AddInclude("a.test")
	if rec.count() != 2 {
		t.Fatalf("one change reached %d handlers, want 2", rec.count())
	}
	removeFirst()
	scope.AddInclude("b.test")
	if rec.count() != 3 {
		t.Errorf("after removing one of two identical registrations, a change reached %d handlers "+
			"total (want 3): removing one took both, or neither", rec.count())
	}
}

// Calling the unregister twice is a no-op, not a panic and not a silent removal of someone else's.
func TestUnregisteringTwiceIsSafe(t *testing.T) {
	scope := NewScope()
	rec2 := &recorded{}
	unregister := scope.OnChange(rec2.add)
	scope.OnChange(rec2.add) // the second registration stays live; its remover is discarded, not called

	unregister()
	unregister() // must not panic, and must not touch the second registration
	scope.AddInclude("a.test")
	if rec2.count() != 1 {
		t.Errorf("after two unregister calls on the first registration, one change reached %d handlers, "+
			"want 1: the second call either removed the second registration or panicked silently", rec2.count())
	}
}

// The nil cases are the obvious ways to misuse the API and neither may panic.
func TestTheNilCasesAreRefusedRatherThanPanicking(t *testing.T) {
	var nilScope *Scope
	if unregister := nilScope.OnChange(func(ScopeChange) {}); unregister == nil {
		t.Error("OnChange on a nil Scope returned a nil unregister function; calling it would panic")
	} else {
		unregister() // must not panic
	}
	scope := NewScope()
	unregister := scope.OnChange(nil)
	unregister()               // must not panic
	scope.AddInclude("a.test") // and must not have registered anything that will be called
}

// The same re-entrancy property on the TOGGLE path specifically, and separately because the two fire
// sites are separate code: a handler that re-reads the scope from a toggle notification must not
// deadlock either. A test that only exercises Add leaves the toggle's own fire site unproven, and
// moving the notification inside that one critical section is a change a green suite would accept.
func TestAHandlerMayReadTheScopeFromAToggleNotification(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")

	insideRules := -1
	done := make(chan struct{})
	scope.OnChange(func(ScopeChange) {
		// Rules() takes the read lock. If the toggle fired while holding the write lock, this is a
		// deadlock — a hang, not a failure, which is why this test runs under the package timeout.
		insideRules = len(scope.Rules())
		close(done)
	})

	prefix := "/admin"
	scope.Add(NewScopeRuleWithPath(ScopeExclude, "a.test", prefix))
	if scope.SetRuleEnabled(ScopeExclude, "a.test", &prefix, nil, nil, false) != ScopeMatchDone {
		t.Fatal("SetRuleEnabled did not find the rule it was given")
	}
	<-done

	if insideRules != 2 {
		t.Errorf("Rules() from inside a toggle handler reported %d rules, want 2", insideRules)
	}
}

// The Changed() filter is what keeps a subscriber from being woken by an EDIT that changed nothing —
// a rule toggled to the value it already holds, which is a real call an operator's UI can make and
// which must not read as a decision. Without this test the filter could be deleted and every other
// test would still pass, which is the mutation that matters most here: a handler woken by a no-op
// toggle re-reads its cache for a change that did not happen.
func TestAToggleToTheValueAlreadySetIsNotToldAsAChange(t *testing.T) {
	scope := NewScope()
	scope.AddInclude("a.test")
	prefix := "/admin"
	scope.Add(NewScopeRuleWithPath(ScopeExclude, "a.test", prefix))

	// The exclude is enabled by construction.
	rec := &recorded{}
	defer scope.OnChange(rec.add)()

	if scope.SetRuleEnabled(ScopeExclude, "a.test", &prefix, nil, nil, true) != ScopeMatchDone {
		t.Fatal("SetRuleEnabled did not find the rule it was given")
	}
	if got := rec.count(); got != 0 {
		t.Errorf("setting a rule to the value it already holds delivered %d changes, want 0 — a "+
			"subscriber woken by a no-op re-reads its cache for a decision nobody made", got)
	}
}

// The drop switch and the custom drop scope announce like every other mutation - the Scope
// page renders both - and identical re-sets stay silent, the toggle discipline.
func TestDropSwitchAndDropScopeNotifyOnRealChangeOnly(t *testing.T) {
	scope := NewScope()
	rec := &recorded{}
	defer scope.OnChange(rec.add)()

	scope.SetDropOutOfScope(true)
	scope.SetDropOutOfScope(true) // re-affirming the value it holds changes no answer: silent
	scope.SetDropOutOfScope(false)
	if rec.count() != 2 {
		t.Fatalf("drop switch flips recorded %d changes, want 2 (on, off; the re-affirm is silent)", rec.count())
	}
	for i, c := range rec.seen() {
		if c.Operation != "drop_switch" {
			t.Errorf("change %d operation = %q, want drop_switch", i, c.Operation)
		}
	}

	custom := NewScope()
	custom.AddInclude("drop.test")
	scope.SetDropScope(custom, true)
	if rec.count() != 3 {
		t.Fatalf("installing a custom drop scope recorded %d changes, want 3", rec.count())
	}
	if got := rec.seen()[2].Operation; got != "drop_scope" {
		t.Errorf("change 2 operation = %q, want drop_scope", got)
	}
	// An identical reinstall (same rules, same mode, fresh object) changes no answer: silent.
	clone := NewScope()
	clone.AddInclude("drop.test")
	scope.SetDropScope(clone, true)
	if rec.count() != 3 {
		t.Errorf("identical drop-scope reinstall announced; count = %d, want 3", rec.count())
	}
	// Clearing it is a change.
	scope.SetDropScope(nil, false)
	if rec.count() != 4 {
		t.Errorf("clearing the custom drop scope did not announce; count = %d, want 4", rec.count())
	}
}
