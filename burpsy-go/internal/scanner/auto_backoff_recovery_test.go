package scanner

// The auto-backoff flag (fkl8) tracks the LAST probe answer: a 429/503 sets it, and a
// probe answered normally clears it, so an item whose target recovers stops paying the
// per-step wait. Before succeeded cleared the flag, one rate-limited probe taxed every
// remaining step of the item - and a hot endpoint turned that tax into minutes.

import "testing"

func TestProbeMeterRecoveryClearsTheBackoffFlag(t *testing.T) {
	m := &probeMeter{}
	if m.limitedStatus.Load() != 0 {
		t.Fatal("a fresh meter already carried a rate-limit status")
	}
	m.rateLimited(429)
	if m.limitedStatus.Load() != 429 {
		t.Fatalf("rateLimited(429) left limitedStatus=%d", m.limitedStatus.Load())
	}
	m.succeeded()
	if m.limitedStatus.Load() != 0 {
		t.Fatalf("a normal answer did not clear the backoff flag: limitedStatus=%d", m.limitedStatus.Load())
	}
	m.rateLimited(503)
	m.rateLimited(429)
	if m.limitedStatus.Load() != 429 {
		t.Fatalf("the LAST limited status must win: got %d", m.limitedStatus.Load())
	}
	if got := m.rateLimitedCount.Load(); got != 3 {
		t.Fatalf("rateLimitedCount must keep counting every limited answer: got %d", got)
	}
}

func TestProbeMeterFailureKeepsTheBackoffFlag(t *testing.T) {
	m := &probeMeter{}
	m.rateLimited(429)
	m.failure()
	if m.limitedStatus.Load() != 429 {
		t.Fatal("a transport failure is not a recovery: it must not clear the backoff flag")
	}
}
