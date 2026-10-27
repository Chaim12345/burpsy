package web

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// gateCounter installs a capture gate on srv's traffic store that counts entries and reports
// whether every durable write ran while exactly one hold was open.
func gateCounter(t *testing.T, srv *Server) (entered *atomic.Int64, outside *atomic.Int64) {
	t.Helper()
	entered, outside = new(atomic.Int64), new(atomic.Int64)
	var held atomic.Int64
	srv.store.SetCaptureGate(func() func() {
		entered.Add(1)
		held.Add(1)
		return func() { held.Add(-1) }
	})
	check := func() {
		if held.Load() != 1 {
			outside.Add(1)
		}
	}
	srv.store.SetPersistenceSinks(func(*core.StoredMessage) { check() }, func(*core.Exchange) { check() })
	t.Cleanup(func() { srv.store.SetCaptureGate(nil); srv.store.SetPersistenceSinks(nil, nil) })
	return entered, outside
}

// A Repeater send is a request, a response and the row naming both; one gate hold covers all three
// so a project switch lands before or after the send, never inside it
// (burpsy-react-ui-capture-split-web).
func TestARepeaterRecordHoldsTheCaptureGateOnce(t *testing.T) {
	srv := newTestServer()
	entered, outside := gateCounter(t, srv)
	srv.recordRepeaterExchange(repeaterSendSpec{
		Host: "a.test", Port: 80, Raw: []byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"), AsWritten: "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n",
	}, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.ProtocolHTTP1, core.ExchangeDuration{}, time.Now())
	if entered.Load() != 1 || outside.Load() != 0 {
		t.Errorf("a Repeater record entered the capture gate %d times with %d writes outside one hold; want 1 and 0",
			entered.Load(), outside.Load())
	}
}

func TestAHARImportEntryHoldsTheCaptureGateOnce(t *testing.T) {
	srv := newTestServer()
	entered, outside := gateCounter(t, srv)
	var entries []harEntry
	if err := json.Unmarshal([]byte(`[{"startedDateTime":"2026-10-27T10:00:00Z","time":5,
		"request":{"method":"GET","url":"http://a.test/x","httpVersion":"HTTP/1.1","headers":[]},
		"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[],"content":{"text":"hi"}}}]`), &entries); err != nil {
		t.Fatal(err)
	}
	if res := srv.importHAREntries(entries); res.Imported != 1 {
		t.Fatalf("imported %d entries: %+v", res.Imported, res)
	}
	if entered.Load() != 1 || outside.Load() != 0 {
		t.Errorf("a HAR entry entered the capture gate %d times with %d writes outside one hold; want 1 and 0",
			entered.Load(), outside.Load())
	}
}
