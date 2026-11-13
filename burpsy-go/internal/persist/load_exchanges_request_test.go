package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// TestLoadExchangesRelinksRequest pins issue #371: a persisted request_msg must come back
// as ex.Request after a reload, so a restored project's history rows name their request.
func TestLoadExchangesRelinksRequest(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	// Mirror appends the way the running process does, so LoadMessages/LoadExchanges have rows.
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)

	reqID, err := store.Put([]byte("GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n."), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: "a.test", Port: 80, Method: "GET", Path: "/x",
	})

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	if loaded[0].Request == nil {
		t.Fatal("restored exchange has nil Request — the request_msg column was not relinked (issue #371)")
	}
	if *loaded[0].Request != reqID {
		t.Errorf("restored Request = %d, want %d", *loaded[0].Request, reqID)
	}

	// Full restore: message 0 IS in the restored set (reqID == 0 here), so the wtov rule
	// reads the persisted column as naming it and the byRequest index resolves it.
	messages, err := p.LoadMessages(store.SegmentLog())
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) == 0 {
		t.Fatal("LoadMessages returned no messages — the sink did not mirror Put")
	}
	store2 := core.NewTrafficStore()
	store2.Restore(messages, loaded)
	if _, err := store2.ExchangeByRequest(reqID); err != nil {
		t.Errorf("after Restore, ExchangeByRequest(%d) failed: %v", reqID, err)
	}
}
