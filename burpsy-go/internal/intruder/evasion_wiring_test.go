package intruder

// Tests for the WAF-evasion WIRING (burpsy-react-ui-tfqk).
//
// evasion_test.go proves the techniques work. It cannot prove they RUN: every test in it builds a
// UserAgentPool or a Jitter and calls it directly, so the whole file could sit in the package,
// green, while no attack ever applied a single technique — which is exactly the state it was in
// when this landed. These tests drive Run through the package's own captureAttack helper, so a
// regression that drops the wrap fails here instead of being invisible.

import (
	"strings"
	"testing"
	"time"
)

const evasionTemplate = "GET /?q=§x§ HTTP/1.1\r\nHost: target.test\r\nUser-Agent: burpsy-default\r\nAccept: */*\r\n\r\n"

// An attack configured with User-Agent rotation must actually send the rotated agent. This is the
// claim the whole feature rests on, and it holds only if Run wraps the SendFn it was given.
func TestAnAttackWithUserAgentRotationSendsTheRotatedAgent(t *testing.T) {
	pool, err := NewUserAgentPool([]string{"evasion-agent-1"})
	if err != nil {
		t.Fatalf("NewUserAgentPool: %v", err)
	}
	seen, _ := captureAttack(t, evasionTemplate, func(a *Attack) *Attack {
		ev := NewWAFEvasion(1)
		ev.UserAgents = pool
		a.Evasion = ev
		return a
	})

	if len(seen) == 0 {
		t.Fatal("the attack sent nothing; the fixture is not exercising the send path")
	}
	for i, raw := range seen {
		if !strings.Contains(string(raw), "evasion-agent-1") {
			t.Errorf("request %d did not carry the rotated User-Agent. Run is not applying the "+
				"evasion wrap, so a configured pool rotates through nothing:\n%s", i, raw)
		}
		if strings.Contains(string(raw), "burpsy-default") {
			t.Errorf("request %d still carries the template's original User-Agent beside the rotated "+
				"one; the rotation must replace it, not append:\n%s", i, raw)
		}
	}
}

// The inverse, and the one that keeps the feature honest: an attack that configured no evasion
// sends the template's own bytes unchanged. Without this the test above would pass even if evasion
// ran unconditionally — and an attack silently rewriting an operator's User-Agent when they asked
// for nothing is a worse defect than the feature being absent.
func TestAnAttackWithNoEvasionSendsTheTemplatesOwnUserAgent(t *testing.T) {
	seen, _ := captureAttack(t, evasionTemplate, nil)

	if len(seen) == 0 {
		t.Fatal("the attack sent nothing")
	}
	for i, raw := range seen {
		if !strings.Contains(string(raw), "burpsy-default") {
			t.Errorf("request %d lost the template's User-Agent with no evasion configured:\n%s", i, raw)
		}
	}
}

// Jitter composes with the rate limiter rather than replacing it: the wait happens INSIDE the
// wrapped send, so an attack configuring both pays both. Elapsed time is the only way to observe
// from outside that the jitter ran at all.
func TestAConfiguredJitterDelaysTheAttacksSends(t *testing.T) {
	j, err := NewJitter(20*time.Millisecond, 20*time.Millisecond, 3)
	if err != nil {
		t.Fatalf("NewJitter: %v", err)
	}
	start := time.Now()
	seen, _ := captureAttack(t, evasionTemplate, func(a *Attack) *Attack {
		ev := NewWAFEvasion(1)
		ev.Jitter = j
		a.Evasion = ev
		return a
	})
	elapsed := time.Since(start)

	if len(seen) == 0 {
		t.Fatal("the attack sent nothing")
	}
	// One fixed 20ms wait per send is the floor. Asserting the floor rather than a total, because
	// the engine's concurrency decides the wall-clock sum — the claim under test is "the jitter
	// ran", not "the engine is serial".
	if elapsed < 20*time.Millisecond {
		t.Errorf("the attack finished in %s with a 20ms-per-send jitter configured; the jitter is "+
			"not applied, which means Run is not wrapping the send", elapsed)
	}
}

// Header-order randomisation must reach the wire too, and it must not lose or duplicate a header
// while doing it — a shuffle that drops the Host is not evasion, it is a broken request.
func TestHeaderShuffleReachesTheWireWithoutLosingHeaders(t *testing.T) {
	seen, _ := captureAttack(t, evasionTemplate, func(a *Attack) *Attack {
		ev := NewWAFEvasion(42)
		ev.ShuffleHeaderOrder = true
		a.Evasion = ev
		return a
	})

	if len(seen) == 0 {
		t.Fatal("the attack sent nothing")
	}
	for i, raw := range seen {
		for _, required := range []string{"Host: target.test", "User-Agent: burpsy-default", "Accept: */*"} {
			if countHeaderLine(string(raw), required) != 1 {
				t.Errorf("request %d carries %q %d times after the header shuffle, want exactly 1; a "+
					"shuffle that drops or duplicates a header changes what the request MEANS:\n%s",
					i, required, countHeaderLine(string(raw), required), raw)
			}
		}
		if !strings.HasPrefix(string(raw), "GET /") {
			t.Errorf("request %d no longer starts with its request line; the shuffle moved a header "+
				"above it:\n%s", i, raw)
		}
	}
}

// A nil Evasion must not panic the attack — the nil-receiver path, exercised through the real
// entry point rather than by calling wrapOrIdentity directly.
func TestRunToleratesANilEvasion(t *testing.T) {
	_, rep := captureAttack(t, evasionTemplate, func(a *Attack) *Attack {
		a.Evasion = nil
		return a
	})
	if rep == nil {
		t.Fatal("Run returned no report for an attack with no evasion")
	}
}

// countHeaderLine counts exact header-line occurrences, so a dropped or duplicated header is
// visible rather than inferred from a substring match that a shuffled body could satisfy.
func countHeaderLine(raw, line string) int {
	n := 0
	for _, l := range strings.Split(raw, "\r\n") {
		if l == line {
			n++
		}
	}
	return n
}
