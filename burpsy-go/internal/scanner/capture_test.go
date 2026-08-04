package scanner

import (
	"errors"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func newTestCapture() (Capture, *core.TrafficStore, *core.FindingStore) {
	store := core.NewTrafficStore()
	findings := core.NewFindingStore()
	return Capture{
		Store:    store,
		Scanner:  NewPassiveScanner(store, zap.NewNop()),
		Findings: findings,
		Logger:   zap.NewNop(),
	}, store, findings
}

const testResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n<html><body>hi</body></html>"
const testRequest = "GET /p HTTP/1.1\r\nHost: h\r\n\r\n"

// TestRecordIndexesRequestResponseAndScans is the happy path: both messages stored, the exchange
// indexed with a resolved status, and the passive check set actually run.
func TestRecordIndexesRequestResponseAndScans(t *testing.T) {
	cap, store, findings := newTestCapture()
	ex, err := cap.Record(CapturedExchange{
		Host: "h", Port: 80, Method: "GET", Path: "/p",
		Request: []byte(testRequest), Response: []byte(testResponse),
		Started: time.Now(), Duration: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if ex.Response == nil {
		t.Fatal("an indexed exchange must carry a stored response")
	}
	if ex.Status == nil || *ex.Status != 200 {
		t.Fatalf("status %v, want 200 read off the stored response's parsed shape", ex.Status)
	}
	msgs, exchanges := store.Count()
	if msgs != 2 || exchanges != 1 {
		t.Fatalf("expected 2 messages and 1 exchange, got %d and %d", msgs, exchanges)
	}
	// The response is readable back through the id the exchange carries — the property the crawler
	// relies on to extract links from exactly the bytes that were scanned.
	stored, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("stored response does not resolve: %v", err)
	}
	if string(stored.Header("Content-Type")) != "text/html" {
		t.Errorf("stored response headers did not survive: %q", stored.Header("Content-Type"))
	}
	if findings.Count() == 0 {
		t.Error("the passive check set did not run: this response is missing every security header")
	}
}

// TestRecordNeverIndexesAnExchangeWithoutAStoredResponse is the invariant that keeps the live-audit
// sweep alive.
//
// internal/web/liveaudit.go walks the exchange index from a monotonic high-water cursor and breaks on
// the first exchange whose Response is nil. A single such row therefore stops that sweep for the life
// of the process while its progress counter keeps looking healthy — so one failed crawl request would
// silently disable live audit. Record refuses to create the row at all, and this test is what stops
// that refusal from being softened back into a "more honest" half-exchange later.
func TestRecordNeverIndexesAnExchangeWithoutAStoredResponse(t *testing.T) {
	cases := []struct {
		name     string
		request  string
		response string
		wantErr  error
	}{
		{"no response bytes at all", testRequest, "", ErrNoResponse},
		// "garbage" has no three-token start line, which is what core.Parse rejects — chosen over a
		// vaguer non-HTML string because the store is deliberately lenient about everything else, and a
		// test that depended on that leniency would be testing the wrong layer.
		{"a response the store cannot parse", testRequest, "garbage", nil},
		{"a request the store cannot parse", "", testResponse, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap, store, findings := newTestCapture()
			ex, err := cap.Record(CapturedExchange{
				Host: "h", Port: 80, Method: "GET", Path: "/p",
				Request: []byte(tc.request), Response: []byte(tc.response),
			})
			if err == nil {
				t.Fatalf("Record must refuse this rather than indexing a half-exchange; it returned %+v", ex)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not wrap %v", err, tc.wantErr)
			}
			if ex != nil {
				t.Errorf("a refused capture must return no exchange, got %+v", ex)
			}
			// Nothing was indexed, so no cursor-walking consumer can trip over it.
			if _, exchanges := store.Count(); exchanges != 0 {
				t.Errorf("%d exchanges indexed; a refused capture must index none", exchanges)
			}
			for _, indexed := range store.Exchanges() {
				if indexed.Response == nil {
					t.Fatalf("exchange %d has a nil Response, which wedges the live-audit sweep", indexed.ID)
				}
			}
			if findings.Count() != 0 {
				t.Error("nothing should have been scanned: there was no complete exchange to scan")
			}
		})
	}
}

// TestEveryIndexedExchangeHasAResponse states the invariant as a property over a mixed batch, which is
// the form a consumer actually depends on: whatever the caller throws at Record, the index never grows
// a row that a nil-Response check would stop at.
func TestEveryIndexedExchangeHasAResponse(t *testing.T) {
	cap, store, _ := newTestCapture()
	inputs := []CapturedExchange{
		{Host: "h", Method: "GET", Path: "/1", Request: []byte(testRequest), Response: []byte(testResponse)},
		{Host: "h", Method: "GET", Path: "/2", Request: []byte(testRequest), Response: nil},
		{Host: "h", Method: "GET", Path: "/3", Request: []byte(testRequest), Response: []byte("garbage")}, // no 3-token start line
		{Host: "h", Method: "GET", Path: "/4", Request: []byte(testRequest), Response: []byte(testResponse)},
	}
	accepted := 0
	for _, in := range inputs {
		if _, err := cap.Record(in); err == nil {
			accepted++
		}
	}
	if accepted != 2 {
		t.Fatalf("expected the two well-formed exchanges to be accepted, got %d", accepted)
	}
	exchanges := store.Exchanges()
	if len(exchanges) != accepted {
		t.Fatalf("%d exchanges indexed for %d accepted captures", len(exchanges), accepted)
	}
	for _, ex := range exchanges {
		if ex.Response == nil {
			t.Fatalf("exchange %d has a nil Response", ex.ID)
		}
		if ex.ResponseLen == 0 {
			t.Errorf("exchange %d records a zero response length", ex.ID)
		}
	}
}

// TestScanExchangeToleratesAMissingScannerOrFindingStore pins the nil-tolerance the proxy relied on
// before this pipeline was extracted: a proxy configured without a scanner still captures traffic.
func TestScanExchangeToleratesAMissingScannerOrFindingStore(t *testing.T) {
	store := core.NewTrafficStore()
	for _, c := range []Capture{
		{Store: store},
		{Store: store, Scanner: NewPassiveScanner(store, zap.NewNop())},
		{Store: store, Findings: core.NewFindingStore()},
	} {
		ex, err := c.Record(CapturedExchange{
			Host: "h", Method: "GET", Path: "/p",
			Request: []byte(testRequest), Response: []byte(testResponse),
		})
		if err != nil {
			t.Fatalf("capture without a full scanner wiring must still store traffic: %v", err)
		}
		if ex.Response == nil {
			t.Error("the exchange must still be complete")
		}
	}
}
