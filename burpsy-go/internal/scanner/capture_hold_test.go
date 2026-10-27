package scanner

import (
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// One captured exchange is several writes — earlier stages, request, response, the exchange row —
// and a project switch must land before all of them or after all of them, never between
// (burpsy-react-ui-capture-split). The switch is serialised by the capture gate, so Record must take
// the gate exactly once and hold it across every write; per-write entries (the old shape: one per
// Put and one for AddExchange) leave a switch-sized gap between the messages and the row naming them.
func TestRecordHoldsTheCaptureGateOnceAcrossEveryWrite(t *testing.T) {
	store := core.NewTrafficStore()
	var entered, held atomic.Int64
	var writesOutsideHold atomic.Int64
	store.SetCaptureGate(func() func() {
		entered.Add(1)
		held.Add(1)
		return func() { held.Add(-1) }
	})
	store.SetPersistenceSinks(
		func(*core.StoredMessage) {
			if held.Load() != 1 {
				writesOutsideHold.Add(1)
			}
		},
		func(*core.Exchange) {
			if held.Load() != 1 {
				writesOutsideHold.Add(1)
			}
		},
	)
	_, err := Capture{Store: store}.Record(CapturedExchange{
		Host: "a.test", Port: 80, Method: "GET", Path: "/",
		Request:         []byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"),
		RequestOriginal: []byte("GET /orig HTTP/1.1\r\nHost: a.test\r\n\r\n"),
		Response:        []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := entered.Load(); got != 1 {
		t.Errorf("Record took the capture gate %d times, want once across all its writes", got)
	}
	if got := writesOutsideHold.Load(); got != 0 {
		t.Errorf("%d durable writes ran outside the single hold", got)
	}
	if held.Load() != 0 {
		t.Errorf("the gate is still held after Record returned")
	}
}
