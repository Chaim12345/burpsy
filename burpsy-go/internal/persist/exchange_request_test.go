package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The request column must survive a restart as the id it names: TrafficStore.Restore indexes
// byRequest only for exchanges whose Request is set, and findings plus every report format
// resolve their host, path and method through ExchangeByRequest. A load that left Request nil
// turned every restart into attribution loss with no error anywhere.
func TestExchangeRequestIdSurvivesARestart(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)

	reqID, err := store.Put([]byte("GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("Put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("Put response: %v", err)
	}
	store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID, Host: "a.test", Port: 80,
		Method: "GET", Path: "/a", ResponseLen: 20,
	})

	restored := core.NewTrafficStore()
	if err := p.Restore(restored, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	ex, err := restored.ExchangeByRequest(reqID)
	if err != nil {
		t.Fatalf("ExchangeByRequest(%d) after restart: %v", reqID, err)
	}
	if ex.Host != "a.test" || ex.Method != "GET" || ex.Path != "/a" {
		t.Fatalf("resolved exchange = %+v, want a.test GET /a", ex)
	}
	if ex.Request == nil || *ex.Request != reqID {
		t.Fatalf("restored Request = %v, want %d", ex.Request, reqID)
	}
}

// The 0 ambiguity stays resolved the way Restore documents it: a persisted request_msg of 0
// with no messages restored at all can only have meant "no request", so the row restores with
// a nil Request and is not indexed (the byRequest[0] collision AddExchange avoids).
func TestARestartKeepsTheMessageZeroAmbiguityRule(t *testing.T) {
	p := newTestStore(t)
	p.SaveExchange(&core.Exchange{Host: "tunnel.test", Port: 443, Method: "CONNECT", Path: "tunnel.test:443"})

	msgs, err := p.LoadMessages(nil)
	if err != nil {
		t.Fatalf("LoadMessages: %v", err)
	}
	exs, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	restored := core.NewTrafficStore()
	restored.Restore(msgs, exs)

	ex, err := restored.GetExchange(0)
	if err != nil {
		t.Fatalf("GetExchange(0): %v", err)
	}
	if ex.Request != nil {
		t.Fatalf("restored Request = %v, want nil (no messages exist for the column to name)", *ex.Request)
	}
	if _, err := restored.ExchangeByRequest(0); err == nil {
		t.Fatal("ExchangeByRequest(0) resolved a row with no request; the index must not carry it")
	}
}
