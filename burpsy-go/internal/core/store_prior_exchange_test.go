package core

// PriorExchange resolves the second request a stored (second-order) check compares against: the
// most recent earlier capture of the same endpoint — same origin (scheme+host+port) and same
// path, where the path carries the query string so "/a" and "/a?x=1" are different endpoints.
//
// The property is pinned rather than left to reading: the lookup is the half of gap 3 the audit
// engine threads into CheckContext.StoredExchange, and a regression that returned the wrong
// candidate — or one added *after* the given exchange — would silently misdirect a stored check.

import (
	"testing"
)

// seedExchange indexes one exchange over a request/response pair, returning its id (its position).
func seedExchange(t *testing.T, store *TrafficStore, id ExchangeID, host string, port uint16, tls bool, path string) ExchangeID {
	t.Helper()
	reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\n"), DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     host,
		Port:     port,
		TLS:      tls,
		Method:   "GET",
		Path:     path,
	}
	store.AddExchange(ex)
	return ex.ID
}

func TestPriorExchangeReturnsTheMostRecentEarlierSameEndpointCapture(t *testing.T) {
	store := NewTrafficStore()

	// Two earlier captures of /login on one host, then the exchange under audit.
	first := seedExchange(t, store, 0, "app.test", 443, true, "/login")
	second := seedExchange(t, store, 0, "app.test", 443, true, "/login")
	underAudit := seedExchange(t, store, 0, "app.test", 443, true, "/login")

	got, ok := store.PriorExchange("app.test", 443, true, "/login", underAudit)
	if !ok {
		t.Fatal("expected a prior exchange, found none")
	}
	// The second capture is the most recent one added before underAudit, not the first.
	if got.ID != second {
		t.Errorf("prior id = %d, want %d (the most recent earlier capture)", got.ID, second)
	}
	_ = first
}

func TestPriorExchangeReturnsFalseWhenNoEarlierEndpointCaptureExists(t *testing.T) {
	store := NewTrafficStore()

	// The only capture of /login is the one we audit — there is nothing before it.
	underAudit := seedExchange(t, store, 0, "app.test", 443, true, "/login")

	if _, ok := store.PriorExchange("app.test", 443, true, "/login", underAudit); ok {
		t.Error("expected no prior exchange for the first capture of its endpoint")
	}
}

func TestPriorExchangeIgnoresCandidatesAddedAfterTheGivenExchange(t *testing.T) {
	store := NewTrafficStore()

	underAudit := seedExchange(t, store, 0, "app.test", 443, true, "/login")
	// A later capture of the same endpoint must not be returned: "before" is positional, and a
	// stored check threads a payload forward, never reads a request it cannot have caused.
	later := seedExchange(t, store, 0, "app.test", 443, true, "/login")

	if got, ok := store.PriorExchange("app.test", 443, true, "/login", underAudit); ok {
		t.Errorf("returned id %d (later=%d): candidates added after the given exchange must be ignored", got.ID, later)
	}
}

func TestPriorExchangeMatchesOriginAndPathNotJustHost(t *testing.T) {
	store := NewTrafficStore()

	// Different endpoints that share the host: a second-order check only threads same-endpoint
	// traffic, so only /login below counts, and /other or the plaintext origin must not.
	other := seedExchange(t, store, 0, "app.test", 443, true, "/other")
	plain := seedExchange(t, store, 0, "app.test", 80, false, "/login")
	first := seedExchange(t, store, 0, "app.test", 443, true, "/login")
	withQuery := seedExchange(t, store, 0, "app.test", 443, true, "/login?next=/home")
	underAudit := seedExchange(t, store, 0, "app.test", 443, true, "/login")

	got, ok := store.PriorExchange("app.test", 443, true, "/login", underAudit)
	if !ok {
		t.Fatal("expected a prior same-endpoint exchange, found none")
	}
	if got.ID != first {
		t.Errorf("prior id = %d, want %d; /other=%d, plaintext /login=%d, and /login?next= must not match",
			got.ID, first, other, plain)
	}
	_ = withQuery
}

func TestPriorExchangeIsAReadOverIndexedExchangesAndCopiesNoBytes(t *testing.T) {
	store := NewTrafficStore()

	// Many candidates of the same endpoint; the lookup must return the highest-indexed earlier one
	// without mutating the store or requiring any message bytes.
	var ids []ExchangeID
	for i := 0; i < 5; i++ {
		ids = append(ids, seedExchange(t, store, 0, "h.test", 80, false, "/p"))
	}
	underAudit := seedExchange(t, store, 0, "h.test", 80, false, "/p")

	got, ok := store.PriorExchange("h.test", 80, false, "/p", underAudit)
	if !ok {
		t.Fatal("expected a prior exchange")
	}
	want := ids[len(ids)-1]
	if got.ID != want {
		t.Errorf("prior id = %d, want %d (the latest of %d candidates)", got.ID, want, len(ids))
	}
	// The returned pointer is the store's own Exchange row, not a copy: no duplicate storage.
	if got != store.exchanges[want] {
		t.Error("PriorExchange did not return the indexed exchange row")
	}
}
