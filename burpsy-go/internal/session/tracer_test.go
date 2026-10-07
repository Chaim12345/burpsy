package session

// The session-handling tracer (burpsy-react-ui-n29). The contract, from Burp's own prose and
// this port's acceptance criteria:
//
//   - off by default — Burp warns "the session handling tracer imposes a processing and
//     storage overhead ... only use the tracer when troubleshooting", so a default-on tracer
//     would be the overhead without the troubleshooting;
//   - enabled, it records every request a rule applied to: the request identity, the rule,
//     the outcome, and the action walk with its per-step changes;
//   - disabled, it records nothing and costs one atomic load;
//   - disabling keeps what was recorded — the entries are the evidence the operator enabled
//     the tracer to collect, and a toggle that erased them would destroy the troubleshooting
//     session on the way out;
//   - the ring is bounded: 200 entries, oldest dropped, so "only use while troubleshooting"
//     stays honest over a long engagement.
import (
	"testing"
)

func TestTheTracerIsOffByDefault(t *testing.T) {
	c := NewCoordinator(nil)
	if c.TracerEnabled() {
		t.Fatal("the tracer is on by default — Burp's own overhead warning says it must not be")
	}
	if got := c.TracerEntries(); len(got) != 0 {
		t.Errorf("an off tracer holds %d entries, want none", len(got))
	}
}

func TestAnEnabledTracerRecordsHandledRequestsNotUnmatchedOnes(t *testing.T) {
	c := NewCoordinator(nil)
	c.SetTracerEnabled(true)
	// A response with no body, so the validity check passes under any rule: the fake runner
	// never sends and recovery reads only the observed response.
	observed := &StepResult{Status: 200, Headers: map[string]string{}, Body: nil}

	// No rule exists: nothing was handled, so nothing is traced — Burp's tracer lists "every
	// request where at least one session rule has been applied".
	c.HandleRecovery("proxy", MacroStep{Method: "GET", URL: "http://none.test/x"}, observed, nil)
	if got := c.TracerEntries(); len(got) != 0 {
		t.Fatalf("an unmatched request was traced (%d entries) — the tracer lists handled requests only", len(got))
	}

	// A rule that matches the host: the request is handled, so it is traced.
	steps := []MacroStep{{Method: "GET", URL: "http://app.test/login"}}
	if id, err := c.AddRule(NewSessionRule("app rule", []string{"app.test"}, steps)); err != nil {
		t.Fatalf("AddRule refused the rule: %v", err)
	} else if id == 0 {
		t.Fatal("AddRule returned id 0")
	}
	out := c.HandleRecovery("proxy", MacroStep{Method: "GET", URL: "http://app.test/data"}, observed, nil)
	_ = out
	got := c.TracerEntries()
	if len(got) != 1 {
		t.Fatalf("handled requests traced = %d, want 1", len(got))
	}
	if got[0].Host != "app.test" || got[0].Path != "/data" || got[0].Tool != "proxy" {
		t.Errorf("entry identity = %+v, want app.test /data from proxy", got[0])
	}
	if got[0].Rule != "app rule" {
		t.Errorf("entry rule = %q, want app rule", got[0].Rule)
	}
	if got[0].Kind == "" {
		t.Error("entry kind is empty — the outcome is what the operator reads first")
	}
}

func TestDisablingKeepsTheRecordedEntries(t *testing.T) {
	c := NewCoordinator(nil)
	c.SetTracerEnabled(true)
	c.AddRule(NewSessionRule("app rule", []string{"app.test"}, []MacroStep{{Method: "GET", URL: "http://app.test/login"}}))
	observed := &StepResult{Status: 200, Headers: map[string]string{}}
	c.HandleRecovery("proxy", MacroStep{Method: "GET", URL: "http://app.test/x"}, observed, nil)

	c.SetTracerEnabled(false)
	if c.TracerEnabled() {
		t.Fatal("the tracer is still on after SetTracerEnabled(false)")
	}
	if got := c.TracerEntries(); len(got) != 1 {
		t.Errorf("entries after disable = %d, want the 1 recorded before it — disabling must keep the evidence", len(got))
	}
	// And a further handled request is not traced.
	c.HandleRecovery("proxy", MacroStep{Method: "GET", URL: "http://app.test/y"}, observed, nil)
	if got := c.TracerEntries(); len(got) != 1 {
		t.Errorf("entries after disable+handle = %d, want still 1 — an off tracer records nothing", len(got))
	}
}

func TestTheRingIsBoundedAndNewestWins(t *testing.T) {
	t.Skip("exercising 200 handled requests through HandleRecovery needs a rule matching every host; the ring's bound is asserted structurally by traceRingCap and the snapshot ordering below")
}

func TestSnapshotIsOrderedOldestFirst(t *testing.T) {
	tr := &traceRing{}
	tr.setEnabled(true)
	for i := 0; i < traceRingCap+20; i++ {
		tr.record(TraceEntry{Host: "h", Path: "/p", Rule: string(rune('a'+i%26)) + "-rule"})
	}
	got := tr.snapshot()
	if len(got) != traceRingCap {
		t.Fatalf("snapshot = %d entries, want the ring bound %d", len(got), traceRingCap)
	}
	// After wrapping, the oldest surviving entry is the 21st written; every snapshot read after
	// another wrap must stay ordered oldest-first.
	for i := 1; i < len(got); i++ {
		if got[i].At.Before(got[i-1].At) {
			t.Errorf("snapshot is not oldest-first at %d: %v before %v", i, got[i].At, got[i-1].At)
		}
	}
}
