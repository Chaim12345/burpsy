package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// A restored row keeps its request. The pointer conversion of Exchange.Request (wtov) lost the
// load-side assignment, so after a restart every exchange came back with no request: search found
// nothing in any request captured before it, and the console showed request-less rows.
func TestARestoredExchangeKeepsItsRequest(t *testing.T) {
	s := newTestStore(t)
	s.SaveExchange(&core.Exchange{
		ID: 7, Request: core.MsgPtr(core.MsgId(1527)), Response: core.MsgPtr(core.MsgId(1528)),
		Host: "restore.test", Port: 80, Method: "GET", Path: "/metrics",
	})
	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	if loaded[0].Request == nil {
		t.Fatal("the restored exchange has no request: the request column was read and dropped")
	}
	if *loaded[0].Request != 1527 {
		t.Errorf("Request = %d, want 1527", *loaded[0].Request)
	}
	if loaded[0].Response == nil || *loaded[0].Response != 1528 {
		t.Errorf("Response = %v, want 1528", loaded[0].Response)
	}
}
