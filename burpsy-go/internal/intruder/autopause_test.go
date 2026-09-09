package intruder

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// Burp's auto-pause (burpsy-react-ui-8f2): pause the attack when a chosen expression appears
// in — or goes missing from — a response. The mechanism already existed (Control); what was
// missing is the trigger.

// runningSender answers every request with the same canned response and records the count.
func intPtrHelper(n int) *int { return &n }

// autoPauseBase builds a 6-send sniper attack over one insertion point, the same way
// engine_test's fixtures do.
func autoPauseBase(t *testing.T) (*Attack, []InsertionPoint) {
	t.Helper()
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"p1", "p2", "p3", "p4", "p5", "p6"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{6}, 100)
	// A control is required for pause to mean anything: nil is the uncontrolled attack that
	// runs to completion, so the auto-pause would fire Pause() into the void. Concurrency 1
	// makes the hold observable: the pause can only stop NEW enumerations, and an attack
	// running 16-wide has already enumerated everything before the first response lands.
	a := NewAttack(base, sel, payloads, plan).WithControl(NewControl())
	a.Limits = Unthrottled(1)
	return a, sel
}

// The appears mode: an attack pauses itself when the lockout-style expression shows up, and
// the report says the predicate did it.
func TestAutoPauseHaltsWhenTheExpressionAppears(t *testing.T) {
	a, _ := autoPauseBase(t)
	ap, err := NewAutoPause([]string{"ACCOUNT LOCKED"}, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	a.WithAutoPause(ap)

	var mu sync.Mutex
	sent := 0
	startedCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return sent
	}
	body := func(n int) string {
		if n == 3 {
			return "ACCOUNT LOCKED: too many attempts"
		}
		return "welcome"
	}
	// The sender closes over the counter to decide the body.
	send := func(raw []byte) (Sent, error) {
		mu.Lock()
		sent++
		n := sent
		mu.Unlock()
		b := body(n)
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n" + b), Status: intPtrHelper(200)}, nil
	}

	// The pause fired at send 3. What proves the hold is that no NEW send starts while
	// paused: watch the sender's own counter, not Control.Progress — in-flight sends at the
	// moment of a pause settle afterwards BY DESIGN (they are requests the target already
	// received), so a settled-count comparison races. The started-count cannot: the driver's
	// gate blocks before the next Fill.
	go func() {
		for {
			if a.Control.Status() == StatusPaused {
				started := startedCount()
				time.Sleep(80 * time.Millisecond) // several gate ticks' worth
				if now := startedCount(); now != started {
					t.Errorf("the attack started sends %d -> %d while paused; the hold did not hold", started, now)
				}
				a.Control.Resume()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	r := Run(a, send, nil)
	if r.AutoPaused == 0 {
		t.Fatal("the report does not record that the auto-pause fired; the operator cannot tell who pressed the button")
	}
	if r.Sent < 3 {
		t.Errorf("the attack stopped before the lockout appeared (%d sent)", r.Sent)
	}
}

// The missing mode: pause when NO expression matches — the "success indicator disappeared"
// direction.
func TestAutoPauseHaltsWhenTheExpressionGoesMissing(t *testing.T) {
	a, _ := autoPauseBase(t)
	ap, err := NewAutoPause([]string{"session token"}, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	a.WithAutoPause(ap)

	var mu sync.Mutex
	sent := 0
	send := func(raw []byte) (Sent, error) {
		mu.Lock()
		sent++
		n := sent
		mu.Unlock()
		b := "normal page with session token"
		if n == 4 {
			b = "logged out — please sign in again"
		}
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n" + b), Status: intPtrHelper(200)}, nil
	}

	go func() {
		for {
			if a.Control.Status() == StatusPaused {
				a.Control.Resume()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	r := Run(a, send, nil)
	if r.AutoPaused == 0 {
		t.Fatal("the missing-mode predicate never fired")
	}
}

// Case sensitivity: the flag on the simple-string path folds case; disabling it must refuse
// the differently-cased hit.
func TestAutoPauseCaseSensitivityFlipsTheSimpleStringPath(t *testing.T) {
	build := func(caseSensitive bool) *Attack {
		a, _ := autoPauseBase(t)
		ap, err := NewAutoPause([]string{"locked"}, true, false, caseSensitive)
		if err != nil {
			t.Fatal(err)
		}
		return a.WithAutoPause(ap)
	}
	insensitive := build(false)
	sensitive := build(true)

	body := []byte("HTTP/1.1 200 OK\r\n\r\nACCOUNT LOCKED banner")
	if !insensitive.AutoPause.triggered(body) {
		t.Error("case-insensitive matching should fire on ACCOUNT LOCKED for pattern 'locked'")
	}
	if sensitive.AutoPause.triggered(body) {
		t.Error("case-sensitive matching fired on ACCOUNT LOCKED for pattern 'locked'; the flag is decorative")
	}
}

// A regex entry is compiled as-is: its own case flags rule.
func TestAutoPauseRegexEntriesCompileAsGiven(t *testing.T) {
	ap, err := NewAutoPause([]string{"(?i)quota.*exceeded"}, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !ap.triggered([]byte("HTTP/1.1 403\r\n\r\nYour QUOTA has been EXCEEDED")) {
		t.Error("the inline (?i) regex did not match; regex entries must be compiled as given")
	}
}

// An expression that does not compile is refused: an auto-pause that silently never fires is
// a control that lies by omission.
func TestAutoPauseRefusesAnUncompilableExpression(t *testing.T) {
	if _, err := NewAutoPause([]string{"([bad"}, false, false, false); err == nil {
		t.Fatal("an uncompilable regex was accepted; the attack would run uncontrolled while the panel says it is armed")
	}
}

// Unconfigured (nil) is never triggered — every existing attack behaves as before.
func TestAutoPauseNilIsNeverTriggered(t *testing.T) {
	var ap *AutoPause
	if ap.triggered([]byte("anything")) {
		t.Error("a nil auto-pause triggered")
	}
	empty, err := NewAutoPause(nil, true, false, false)
	if err != nil || empty != nil {
		t.Fatalf("an empty list should configure nothing, got %v, %v", empty, err)
	}
}
