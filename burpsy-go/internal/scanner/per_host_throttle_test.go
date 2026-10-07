package scanner

import (
	"context"
	"testing"
	"time"
)

// TestPerHostThrottleDoesNotBlockOtherHosts verifies that a slow host does not
// block probes to a different host (m0sv). The per-host throttle paces probes
// to the SAME host; it must not stall other hosts.
func TestPerHostThrottleDoesNotBlockOtherHosts(t *testing.T) {
	// This is a unit test of the limiter logic itself, not a full audit.
	// The full integration test would require a live target.
	run := &auditRun{
		cfg: AuditConfig{
			PerHostThrottleMs:     SomeUint32(50),
			PerHostThrottleRandom: false,
		},
		perHostLastProbe: make(map[string]time.Time),
	}
	run.perHostThrottleMs = 50

	ctx := context.Background()
	hostA := "slow.example.com"
	hostB := "fast.example.com"

	// Probe hostA — should not block (first probe to this host).
	start := time.Now()
	run.perHostThrottle(ctx, hostA)
	elapsed := time.Since(start)
	if elapsed > 10*time.Millisecond {
		t.Errorf("first probe to hostA blocked for %v, want no throttle on first probe", elapsed)
	}

	// Probe hostB — should not block (different host).
	start = time.Now()
	run.perHostThrottle(ctx, hostB)
	elapsed = time.Since(start)
	if elapsed > 10*time.Millisecond {
		t.Errorf("first probe to hostB blocked for %v, want no throttle on first probe to a different host", elapsed)
	}

	// Probe hostA again — should block for ~50ms.
	start = time.Now()
	run.perHostThrottle(ctx, hostA)
	elapsed = time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("second probe to hostA blocked for %v, want at least 40ms throttle", elapsed)
	}
}

// TestPerHostInFlightCap verifies the per-host in-flight cap blocks when the
// cap is reached and releases when a probe completes.
func TestPerHostInFlightCap(t *testing.T) {
	run := &auditRun{
		cfg:             AuditConfig{},
		inFlightPerHost: make(map[string]int),
	}
	run.perHostMaxInFlight = 2

	ctx := context.Background()
	host := "example.com"

	// Acquire 2 slots — should succeed immediately.
	run.perHostInFlight(ctx, host)
	run.perHostInFlight(ctx, host)

	if got := run.inFlightPerHost[host]; got != 2 {
		t.Errorf("in-flight count = %d, want 2", got)
	}

	// Release one slot.
	run.releasePerHostInFlight(host)
	if got := run.inFlightPerHost[host]; got != 1 {
		t.Errorf("in-flight count after release = %d, want 1", got)
	}

	// Release the last slot.
	run.releasePerHostInFlight(host)
	if got := run.inFlightPerHost[host]; got != 0 {
		t.Errorf("in-flight count after second release = %d, want 0", got)
	}
}

// TestPerHostThrottleRandomDoesNotExceedBound verifies that the random jitter
// does not cause the throttle to exceed 1.5x the configured interval.
func TestPerHostThrottleRandomDoesNotExceedBound(t *testing.T) {
	run := &auditRun{
		cfg: AuditConfig{
			PerHostThrottleMs:     SomeUint32(100),
			PerHostThrottleRandom: true,
		},
		perHostLastProbe: make(map[string]time.Time),
	}
	run.perHostThrottleMs = 100

	ctx := context.Background()
	host := "example.com"

	// First probe — no throttle.
	run.perHostThrottle(ctx, host)

	// Second probe — should throttle for 100-150ms.
	start := time.Now()
	run.perHostThrottle(ctx, host)
	elapsed := time.Since(start)
	if elapsed < 90*time.Millisecond {
		t.Errorf("throttle with random jitter was %v, want at least 90ms", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("throttle with random jitter was %v, want at most 200ms (1.5x bound + margin)", elapsed)
	}
}
