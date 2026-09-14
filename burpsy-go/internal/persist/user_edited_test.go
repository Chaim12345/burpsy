package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The operator's own edit must survive a restart (burpsy-react-ui-sd0d).
//
// Worth its own test because losing it is silent in the direction that matters: the exchange, its
// bytes, its stages and every other column come back perfectly, and the row simply stops claiming the
// operator touched it — a badge that quietly disappears rather than an error. The reverse is the worse
// failure and is asserted in the same test: a row nobody edited that comes back claiming an operator
// edit puts a false annotation on ordinary traffic, which is the defect this column replaced.
//
// Both directions in one test on purpose. They are one bit, and a round trip that hard-coded either
// answer would pass a test that only checked one of them.
func TestTheOperatorEditedFlagSurvivesSaveLoadRoundTrip(t *testing.T) {
	p := newTestStore(t)
	// Through the live store's sink rather than by calling SaveExchange directly, so the ids the rows
	// are saved under are the ones the running proxy would have given them — an exchange written with
	// a hand-picked id would be a different call from this one.
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	req, resp := putPair(t, store)

	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "edited.test", Port: 443, TLS: true, Method: "POST", Path: "/login",
		UserEdited: true,
	})
	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "untouched.test", Port: 443, TLS: true, Method: "GET", Path: "/",
	})

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d exchanges, want 2", len(loaded))
	}
	if !loaded[0].UserEdited {
		t.Errorf("the exchange the operator edited loaded with UserEdited false; history would drop the badge across a restart")
	}
	if loaded[1].UserEdited {
		t.Errorf("an exchange nobody edited loaded as edited by the operator; every reloaded row would carry a false badge")
	}
}
