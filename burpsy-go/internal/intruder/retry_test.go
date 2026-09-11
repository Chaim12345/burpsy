package intruder

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Burp's error handling (n39): "Number of retries on network failure" and "Pause before
// retry". Defaults recovered from the decompiled original — Zrur's
// requireNonNullElse(numretries, "3") and the "2000" paired with pausebeforeretry — with
// Zb33's validation bound ("Pause before retry must be between 0 and 600000").
//
// The origin fails the first two sends of the flaky payload with a network error and answers
// the third: Burp's own justification ("intermittent network failures are common when
// testing") in miniature. Without retries the attack reports a hole where the target simply
// hiccuped; with them the same attack reports the real answer and names the retries.
func Test_a_network_failure_is_retried_and_the_retry_is_counted(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
	atk := NewAttack(base, pts[:1], sets([]string{"flaky"}), plan).
		WithLimits(Unthrottled(1)).
		WithRetries(3, 0) // no pause in the test; the pause is its own test below

	var calls int32
	send := func(raw []byte) (Sent, error) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 || n == 2 {
			return Sent{}, errors.New("connection reset by peer")
		}
		status := 200
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\n\r\nanswered"), Status: &status}, nil
	}

	report := Run(atk, send, nil)

	if report.Failed != 0 {
		t.Fatalf("two transient failures then an answer is a completed attempt, not a failure: failed=%d errors=%v",
			report.Failed, report.Errors)
	}
	if report.Sent != 1 {
		t.Fatalf("one attempt (retries are not new attempts), got sent=%d", report.Sent)
	}
	if report.RetriesUsed != 2 {
		t.Fatalf("the report should name the 2 retry sends, got %d — an attack that stumbled its way to success reads differently from one that never stumbled", report.RetriesUsed)
	}
	if len(report.Attempts) != 1 || report.Attempts[0].Status == nil || *report.Attempts[0].Status != 200 {
		t.Fatalf("the attempt row should carry the eventual 200, got %+v", report.Attempts)
	}
}

// Exhausted retries stay a counted failure: retrying is hole-filling, not result-fabricating,
// so a target that never answers still reports the error — with the retry count showing the
// operator how much was already tried on their behalf.
func Test_a_failure_past_the_retry_count_stays_a_counted_failure(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
	atk := NewAttack(base, pts[:1], sets([]string{"dead"}), plan).
		WithLimits(Unthrottled(1)).
		WithRetries(2, 0)

	var calls int32
	send := func(raw []byte) (Sent, error) {
		atomic.AddInt32(&calls, 1)
		return Sent{}, errors.New("connection refused")
	}

	report := Run(atk, send, nil)

	if report.Failed != 1 {
		t.Fatalf("a target that never answers is one failed attempt, got failed=%d", report.Failed)
	}
	if got := atomic.LoadInt32(&calls); got != 3 { // 1 original + 2 retries
		t.Fatalf("2 retries should mean exactly 3 send calls, got %d", got)
	}
	if report.RetriesUsed != 2 {
		t.Fatalf("both retries should be counted, got %d", report.RetriesUsed)
	}
}

// The pause before retry waits (bounded by Burp's 0..600000ms validation) and notices a stop:
// a plain sleep would hold a stopped attack's goroutine for the whole pause.
func Test_the_pause_before_retry_is_waited_and_stoppable(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
	atk := NewAttack(base, pts[:1], sets([]string{"slow"}), plan).
		WithLimits(Unthrottled(1)).
		WithRetries(1, 120*time.Millisecond).
		WithControl(NewControl())

	// Stop the attack the moment its first send fails — the pause that follows must be cut
	// short by the stop, not slept in full.
	send := func(raw []byte) (Sent, error) {
		atk.Control.Stop("stopped from the test")
		return Sent{}, errors.New("connection reset")
	}

	started := time.Now()
	report := Run(atk, send, nil)
	elapsed := time.Since(started)

	if elapsed >= 120*time.Millisecond {
		t.Fatalf("a stopped attack must not sleep the full retry pause, took %v", elapsed)
	}
	if report.RetriesUsed != 0 {
		t.Fatalf("a stop during the pause wins over the retry, got %d retries", report.RetriesUsed)
	}
	if report.Status != StatusStopped {
		t.Fatalf("the report should say stopped, got %q", report.Status)
	}
}
