package core

import "testing"

// Every store method that calls a persistence sink must call it INSIDE the capture gate, and must
// release the gate afterwards — the gate is what orders the owning process's switch lock before
// the store's mutex (burpsy-react-ui-switch-deadlock). A method that called a sink without the
// gate would put a mirror write outside the switch lock; one that never released it would wedge
// the next switch.
func TestEverySinkCallingMethodRunsItsSinkInsideTheCaptureGate(t *testing.T) {
	held, entered, inGate, outside := 0, 0, 0, 0
	gate := func() func() {
		entered++
		held++
		return func() { held-- }
	}
	sink := func() {
		if held == 1 {
			inGate++
		} else {
			outside++
		}
	}

	ts := NewTrafficStore()
	ts.SetCaptureGate(gate)
	ts.SetPersistenceSinks(func(*StoredMessage) { sink() }, func(*Exchange) { sink() })
	if _, err := ts.Put([]byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"), DirectionRequest); err != nil {
		t.Fatalf("put: %v", err)
	}
	ts.AddExchange(&Exchange{Host: "a.test"})
	note := "n"
	if _, err := ts.UpdateExchangeAnnotation(0, &note, true, "", false); err != nil {
		t.Fatalf("annotate: %v", err)
	}

	fs := NewFindingStore()
	fs.SetCaptureGate(gate)
	fs.SetPersistenceSink(func(*Finding) { sink() })
	fs.SetDeleteSink(func(uint64) { sink() })
	a := fs.Add(NewFinding{Name: "a"})
	fs.Add(NewFinding{Name: "b"})
	fs.Triage(a, func(f *Finding) { f.Severity = SeverityLow })
	fs.Delete(a)
	fs.Clear()

	// Put, AddExchange, Annotate; Add x2, Triage, Delete, Clear.
	if entered != 8 {
		t.Errorf("the gate was entered %d times, want 8 (once per sink-calling method)", entered)
	}
	// Put, AddExchange, Annotate, Add, Add, Triage, Delete, Clear(one remaining finding).
	if inGate != 8 || outside != 0 {
		t.Errorf("sinks ran %d times inside the gate and %d outside, want 8 and 0", inGate, outside)
	}
	if held != 0 {
		t.Errorf("the gate is still held %d time(s) after every method returned", held)
	}

	// Removing the gate removes it: a store with no gate installed calls straight through.
	ts.SetCaptureGate(nil)
	ts.AddExchange(&Exchange{Host: "b.test"})
	if entered != 8 || outside != 1 {
		t.Errorf("after SetCaptureGate(nil): entered %d (want 8), sink outside the gate %d (want 1)", entered, outside)
	}
}
