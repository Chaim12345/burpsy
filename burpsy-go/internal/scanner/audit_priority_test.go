package scanner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The audit queue's priority order (burpsy-react-ui-ftk2), through AuditSession, whose start order is
// what a time-bounded run actually spends its budget on.

func priorityExchange(t *testing.T, store *core.TrafficStore, method, path, extraHeaders, body string) core.ExchangeID {
	t.Helper()
	raw := method + " " + path + " HTTP/1.1\r\nHost: app.test\r\n" + extraHeaders + "\r\n" + body
	reqID, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "app.test", Port: 80, Method: method, Path: path}
	store.AddExchange(ex)
	return ex.ID
}

func startOrder(out *SessionOutcome) []core.ExchangeID {
	ids := make([]core.ExchangeID, 0, len(out.StartOrder))
	for _, p := range out.StartOrder {
		ids = append(ids, p.ExchangeID)
	}
	return ids
}

func Test_the_audit_queue_starts_the_most_exposing_items_first(t *testing.T) {
	store := core.NewTrafficStore()
	static := priorityExchange(t, store, "GET", "/about", "", "")
	search := priorityExchange(t, store, "GET", "/search?q=1&page=2", "", "")
	searchAgain := priorityExchange(t, store, "GET", "/search?q=7&page=9", "", "")
	login := priorityExchange(t, store, "POST", "/login", "Content-Type: application/json\r\nCookie: sid=1\r\n",
		`{"user":"a","pass":"b"}`)
	submitted := []core.ExchangeID{static, search, searchAgain, login}

	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{MaxConcurrency: 1})
	out, _ := s.AuditSession(context.Background(), submitted, DefaultAuditConfig())

	got := startOrder(out)
	// login: two new body points plus its cookie, and full interest (POST, JSON, authenticated).
	// search: two new query points. Its repeat adds nothing new: the same parameters on the same
	// endpoint are the same attack surface, so it falls behind items that have not been covered.
	if len(got) != 4 || got[0] != login || got[1] != search {
		t.Fatalf("start order %v, want login (%d) then search (%d) first", got, login, search)
	}
	pos := map[core.ExchangeID]int{}
	for i, id := range got {
		pos[id] = i
	}
	if pos[searchAgain] < pos[search] {
		t.Errorf("a capture of an already-covered endpoint started before the first: %v", got)
	}
	first := out.StartOrder[0]
	if first.Interest != 1 || first.Exposure != 1 || first.NewPoints < 2 {
		t.Errorf("login's score row %+v, want interest 1, exposure 1, at least 2 new points", first)
	}
	for _, p := range out.StartOrder {
		if p.ExchangeID == searchAgain && p.NewPoints != 0 {
			t.Errorf("the repeated search reported %d new point(s), want 0", p.NewPoints)
		}
	}
	// Outcomes still come back in the order requested.
	for i, item := range out.Items {
		if item.ExchangeID != submitted[i] {
			t.Fatalf("outcome %d is %d, want %d: the outcome order must stay the request order", i, item.ExchangeID, submitted[i])
		}
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"start_order":[{"exchange_id":`) {
		t.Errorf("start_order not on the wire: %s", raw)
	}
}

// Equal scores keep the requested order, so a batch of identical captures runs as it always did.
func Test_ties_keep_the_requested_order(t *testing.T) {
	store := core.NewTrafficStore()
	a := priorityExchange(t, store, "GET", "/a", "", "")
	b := priorityExchange(t, store, "GET", "/b", "", "")
	c := priorityExchange(t, store, "GET", "/c", "", "")
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{MaxConcurrency: 1})
	order, _ := s.priorityOrder([]core.ExchangeID{c, a, b}, DefaultAuditConfig())
	if order[0] != 0 || order[1] != 1 || order[2] != 2 {
		t.Errorf("tied items reordered: %v", order)
	}
}

// An item whose capture cannot be read goes last, unscored, and is still audited (refused with its
// reason), never dropped.
func Test_an_unreadable_item_goes_last_and_is_still_counted(t *testing.T) {
	store := core.NewTrafficStore()
	real := priorityExchange(t, store, "GET", "/search?q=1", "", "")
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{MaxConcurrency: 1})
	out, _ := s.AuditSession(context.Background(), []core.ExchangeID{9999, real}, DefaultAuditConfig())
	got := startOrder(out)
	if len(got) != 2 || got[0] != real || got[1] != 9999 || !out.StartOrder[1].Unreadable {
		t.Errorf("start order %+v, want the readable item first and the unreadable one last, marked", out.StartOrder)
	}
	if len(out.Items) != 2 {
		t.Errorf("the unreadable item was dropped from the outcome: %d item(s)", len(out.Items))
	}
}

// With exposure equal, interest decides: a state-changing, structured, authenticated request starts
// before a plain GET, wherever it was submitted.
func Test_interest_breaks_an_exposure_tie(t *testing.T) {
	store := core.NewTrafficStore()
	// Two points each: a Content-Type header and one parameter. Only the POST's is structured.
	get := priorityExchange(t, store, "GET", "/a?x=1", "Content-Type: text/plain\r\n", "")
	post := priorityExchange(t, store, "POST", "/b", "Content-Type: application/x-www-form-urlencoded\r\n", "y=1")
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{MaxConcurrency: 1})
	_, scores := s.priorityOrder([]core.ExchangeID{get, post}, DefaultAuditConfig())
	if scores[0].ExchangeID != post || scores[0].NewPoints != scores[1].NewPoints {
		t.Errorf("scores %+v: want the POST first on interest alone, with equal new points", scores)
	}
	if want := 2.0 / 3; scores[0].Interest < want-1e-9 || scores[0].Interest > want+1e-9 || scores[1].Interest != 0 {
		t.Errorf("interest %v / %v, want 2/3 (method, content type) and 0", scores[0].Interest, scores[1].Interest)
	}
}
