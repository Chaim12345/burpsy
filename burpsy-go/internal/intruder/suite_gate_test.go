package intruder

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The dashboard's "Pause all tasks" has to reach the attack driver (burpsy-react-ui-cijs).
//
// dash.Registry.GateCheck had exactly one caller in the whole tree — the sequencer's capture loop —
// so pressing the button flipped the banner, the button and /api/dashboard's `paused` while a
// running attack carried on sending at the same rate. Intruder has its own Control pause, which
// worked; the suite-wide one did not reach it, and an operator who pressed "pause everything"
// should not have to go and find this attack's own button as well.
func TestTheSuiteGateHoldsTheAttackDriver(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	payloads := numItems(40, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{40}, 1_000)

	var sent atomic.Int64
	var seen [][]byte
	var mu sync.Mutex

	// The gate holds until released, so "did the driver stop" is answerable without sleeping on a
	// guess: the count is read while the gate is held and again after it is released.
	held := make(chan struct{})
	var gateCalls atomic.Int64

	a := NewAttack(base, pts[:1], []PayloadSet{payloads}, plan).WithLimits(Unthrottled(1))
	a.SuiteGate = func(context.Context) {
		if gateCalls.Add(1) == 3 {
			<-held // hold the driver from the third enumeration onwards
		}
	}

	done := make(chan *AttackReport, 1)
	go func() {
		done <- Run(a, func(raw []byte) (Sent, error) {
			sent.Add(1)
			mu.Lock()
			seen = append(seen, append([]byte(nil), raw...))
			mu.Unlock()
			return Sent{Raw: []byte("HTTP/1.1 200 OK\r\n\r\nok"), Duration: time.Millisecond, Status: ptr(200)}, nil
		}, nil)
	}()

	// Give the driver every chance to run past the gate if it is not actually holding. This is a
	// generous window on purpose: a gate that does not hold fails this loudly, and one that does
	// costs the suite this much once.
	deadline := time.After(2 * time.Second)
	var atHold int64
	for {
		if gateCalls.Load() >= 3 {
			time.Sleep(200 * time.Millisecond) // let anything unheld get ahead
			atHold = sent.Load()
			break
		}
		select {
		case <-deadline:
			t.Fatal("the gate was never reached; the driver is not calling SuiteGate at all")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	if atHold > 3 {
		t.Errorf("%d requests were sent while the suite gate was held; the driver did not stop", atHold)
	}

	close(held)
	report := <-done

	if report.Sent != 40 {
		t.Errorf("after the release the attack sent %d, want 40 — a pause must not lose work", report.Sent)
	}
	if final := sent.Load(); final <= atHold {
		t.Errorf("the attack sent %d before the release and %d after; releasing the gate did not resume it", atHold, final)
	}
}

// Nil is every caller that is not the web layer — the MCP surface, the CLI, every test above.
// They must keep their current behaviour exactly.
func TestAnAttackWithNoSuiteGateIsUnaffected(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	payloads := numItems(5, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{5}, 100)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, pts[:1], []PayloadSet{payloads}, plan).WithLimits(Unthrottled(2))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 5 {
		t.Fatalf("sent = %d, want 5", r.Sent)
	}
}
