package scanner

// What the exchange row says about the message it indexes.
//
// capture_test.go pins that Record refuses an incomplete capture. This file pins the other half: the
// row it does create describes the bytes it points at and nothing else. Both halves were live
// divergences between the proxy's hand-rolled capture sites and this producer — the plain-HTTP path
// stored the origin's response and then described it with the status and length of the rewritten one,
// so the row disagreed with its own message whenever a Match & Replace rule fired.
//
// The three status cases are internal/proxy's parseStatusCode tests, moved here when that second
// status-line parser was deleted. They are unchanged in intent: a well-formed status is read, bare LF
// line endings still yield one, and an unusable one is left absent rather than guessed.

import (
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// rowCapture is the producer wired to a bare store: no scanner and no finding store, so these tests
// observe the row and not the scanning.
func rowCapture() (Capture, *core.TrafficStore) {
	store := core.NewTrafficStore()
	return Capture{Store: store, Logger: zap.NewNop()}, store
}

func recordResponse(t *testing.T, response string) (*core.Exchange, *core.TrafficStore) {
	t.Helper()
	c, store := rowCapture()
	ex, err := c.Record(CapturedExchange{
		Host:     "h.test",
		Port:     80,
		Method:   "GET",
		Path:     "/one",
		Request:  []byte(testRequest),
		Response: []byte(response),
		Started:  time.Now(),
		Duration: 7 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Record(%q): %v", response, err)
	}
	return ex, store
}

// The moved case: a three-digit status off a well-formed response, and — the part the proxy's own
// parser could not promise — a length that matches the message actually in the store.
func TestTheRowDescribesTheResponseItIndexes(t *testing.T) {
	ex, store := recordResponse(t, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	if ex.Status == nil || *ex.Status != 404 {
		t.Fatalf("status = %v, want 404", ex.Status)
	}
	stored, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("stored response: %v", err)
	}
	if ex.ResponseLen != len(stored.Raw()) {
		t.Errorf("ResponseLen = %d but the stored response is %d bytes; the row is describing bytes that are not in the store",
			ex.ResponseLen, len(stored.Raw()))
	}
}

// The deleted parser accepted bare LF, so this pins that the store's parser does too: a
// non-conformant origin must not lose its status on the way through the seam.
func TestARowGetsAStatusFromBareLFLineEndings(t *testing.T) {
	ex, _ := recordResponse(t, "HTTP/1.1 200 OK\nServer: x\n\nbody")
	if ex.Status == nil || *ex.Status != 200 {
		t.Fatalf("status = %v, want 200", ex.Status)
	}
}

// An unusable status token leaves Status absent, which core.Exchange models as nil and every consumer
// already reads as absent — never a 0 that would render as a real status code. The bytes still arrived
// and are still kept: an unreadable first line is not an incomplete exchange.
func TestARowLeavesAnUnreadableStatusAbsentRatherThanGuessingIt(t *testing.T) {
	for _, response := range []string{
		"not a response\r\n\r\n",
		"HTTP/1.1 99 BAD\r\n\r\n",
		"HTTP/1.1 600 BAD\r\n\r\n",
	} {
		ex, _ := recordResponse(t, response)
		if ex.Status != nil {
			t.Errorf("Record(%q) status = %d, want absent", response, *ex.Status)
		}
		if ex.Response == nil {
			t.Errorf("Record(%q) indexed no response", response)
		}
	}
}

// Notes has to be on the row before AddExchange runs, because the store's observers — the durable
// mirror and the live site map — see the row from inside that call and never again. A note assigned to
// the returned exchange afterwards is a note neither of them ever records, which is why
// CapturedExchange carries the field instead of leaving callers to set it themselves.
func TestNotesReachTheStoreObserversWithTheRow(t *testing.T) {
	c, store := rowCapture()
	seen := make(chan *string, 1)
	store.ObserveExchanges(func(ex *core.Exchange) { seen <- ex.Notes })

	note := "[burpsy] this capture is not verbatim"
	if _, err := c.Record(CapturedExchange{
		Host:     "h.test",
		Port:     80,
		Method:   "GET",
		Path:     "/chat",
		Request:  []byte(testRequest),
		Response: []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"),
		Started:  time.Now(),
		Notes:    &note,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := <-seen
	if got == nil {
		t.Fatal("the observer saw a row with no note, so nothing downstream of AddExchange can know this capture was rewritten")
	}
	if *got != note {
		t.Errorf("note = %q, want %q", *got, note)
	}
}
