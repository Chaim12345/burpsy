package persist

import (
	"database/sql"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-7py5: exchanges gained request_params so the History "Parameterized requests"
// filter can mean what Burp's does. The load side has a job the other exchange columns do not, and
// this is where it is pinned.

// putExchangeRequest stores one request message and returns its id. The traffic store is separate
// from the persistence store — the row under test is what SaveExchange wrote, and the message it
// points at is what a restore would read back.
func putExchangeRequest(t *testing.T, raw string) core.MsgId {
	t.Helper()
	id, err := core.NewTrafficStore().Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return id
}

// A count survives a save/load round trip, which is the whole point of the column.
func TestTheRequestParameterCountSurvivesARoundTrip(t *testing.T) {
	s := newTestStore(t)
	reqID := putExchangeRequest(t, "POST /login?next=/home HTTP/1.1\r\nHost: a.test\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=x")
	s.SaveExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Host: "a.test", Port: 443, TLS: true,
		Method: "POST", Path: "/login?next=/home", RequestParams: 3,
	})

	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	if loaded[0].RequestParams != 3 {
		t.Errorf("RequestParams = %d after a round trip, want 3", loaded[0].RequestParams)
	}
}

// The case the other exchange columns do NOT share, and the reason this column is NULLable.
//
// A row written before the column existed was certainly NOT examined for parameters. Reading it as
// zero would keep it out of the "Parameterized requests" filter and report a clean answer about a
// request nobody looked at — the same overclaim as an unreadable body counting zero. It must read
// back as the unknown sentinel instead.
func TestALegacyRowReadsBackAsNotComputedRatherThanZeroParameters(t *testing.T) {
	s := newTestStore(t)
	reqID := putExchangeRequest(t, "GET /x?a=1 HTTP/1.1\r\nHost: a.test\r\n\r\n")
	s.SaveExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Host: "a.test", Port: 80, Method: "GET", Path: "/x?a=1",
	})
	// Write the row as an older build would have: no request_params at all.
	if _, err := s.db.Exec(`UPDATE exchanges SET request_params = NULL`); err != nil {
		t.Fatalf("blank the column: %v", err)
	}

	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	if loaded[0].RequestParams != requestParamsUnknown {
		t.Errorf("RequestParams = %d for a row that predates the column, want %d (not computed). "+
			"Zero would be a claim about that request that no build ever made",
			loaded[0].RequestParams, requestParamsUnknown)
	}
}

// A genuine zero is a real answer and must survive as one. This is the other half of the previous
// test: if NULL and 0 both read as "no parameters", the column carries no information at all — and
// the filter could not tell a request it examined from one it never looked at.
func TestAGenuineZeroIsNotTheUnknownSentinel(t *testing.T) {
	s := newTestStore(t)
	reqID := putExchangeRequest(t, "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n")
	s.SaveExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Host: "a.test", Port: 80, Method: "GET", Path: "/x", RequestParams: 0,
	})
	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if loaded[0].RequestParams != 0 {
		t.Errorf("RequestParams = %d, want 0 — a request with no query string and no body CERTAINLY "+
			"has no parameters, and that is a real answer", loaded[0].RequestParams)
	}
}

// The two helpers must not disagree about what the sentinel means, which is why they live beside
// each other rather than one being inlined at a call site.
func TestTheUnknownSentinelIsWrittenAsNullAndReadAsTheSentinel(t *testing.T) {
	// A negative in-memory count is written as NULL, never as a number: a reader must not have to
	// interpret a negative to mean "unknown".
	if v := requestParamValue(-5); v != nil {
		t.Errorf("a negative count wrote %v, want NULL", v)
	}
	// And a real count is written as itself.
	if v := requestParamValue(0); v != 0 {
		t.Errorf("a genuine zero wrote %v, want 0", v)
	}
	var null int64
	if got := requestParamValueFromScan(sql.NullInt64{}); got != requestParamsUnknown {
		t.Errorf("a NULL column read as %d, want %d", got, requestParamsUnknown)
	}
	if got := requestParamValueFromScan(sql.NullInt64{Int64: 7, Valid: true}); got != 7 {
		t.Errorf("a stored 7 read as %d, want 7", got)
	}
	_ = null
}
