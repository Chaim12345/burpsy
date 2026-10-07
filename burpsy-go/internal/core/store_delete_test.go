package core

// Delete and Clear are tombstones, not splices (burpsy-react-ui-r6li).
//
// Exchange ids are positional — Restore's contract and every other tool's currency. A deletion that
// spliced the slice would renumber every later row mid-engagement: the organizer item naming
// exchange 4 would silently name a different request, and a saved audit reference would point
// somewhere else. So the row stays and a flag decides visibility, and the properties pinned here are
// the ones that hold only if that is really how it works: ids keep resolving, a new exchange lands
// at the next positional slot, and a deleted row is invisible to every read path, not just the
// listing.

import (
	"strings"
	"testing"
)

func putExchange(t *testing.T, store *TrafficStore, path string) ExchangeID {
	t.Helper()
	id, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: h\r\n\r\n"), DirectionRequest)
	if err != nil {
		t.Fatalf("Put %s: %v", path, err)
	}
	store.AddExchange(&Exchange{Request: MsgPtr(id), Host: "h", Port: 80, Method: "GET", Path: path})
	ex, err := store.GetExchange(ExchangeID(int(id)))
	if err != nil {
		t.Fatalf("exchange %d: %v", id, err)
	}
	return ex.ID
}

func TestDeleteExchangesHidesTheTickedRowsWithoutRenumberingTheRest(t *testing.T) {
	store := NewTrafficStore()
	first := putExchange(t, store, "/first")
	second := putExchange(t, store, "/second")
	third := putExchange(t, store, "/third")

	removed := store.DeleteExchanges([]ExchangeID{first, third, 99})
	if removed != 2 {
		t.Fatalf("DeleteExchanges reported %d removed, want 2: an out-of-range id is skipped, not counted", removed)
	}

	// The listing drops the deleted rows but keeps the live one reachable by its own id — the
	// organizer item and the audit reference that named it still resolve to the same request.
	if got := len(store.Exchanges()); got != 1 {
		t.Fatalf("Exchanges lists %d rows after deleting 2 of 3, want 1", got)
	}
	live, err := store.GetExchange(second)
	if err != nil {
		t.Fatalf("the untouched exchange no longer resolves: %v", err)
	}
	msg, err := store.Get(MsgOrZero(live.Request))
	if err != nil {
		t.Fatalf("the untouched exchange's request message does not resolve: %v", err)
	}
	if !strings.Contains(string(msg.Raw()), "/second") {
		t.Errorf("id %d resolves to different bytes after a sibling deletion — ids were renumbered", second)
	}

	// The deleted ids answer "not found", through the direct lookup and through the message-id
	// index the detail pane reads.
	if _, err := store.GetExchange(first); err == nil {
		t.Errorf("a deleted exchange resolved through GetExchange")
	}
	if _, err := store.ExchangeByRequest(MsgId(first)); err == nil {
		t.Errorf("a deleted exchange resolved through ExchangeByRequest")
	}

	// Deleted slots stay spent: the next capture takes the next positional id, not the freed one.
	fourth := putExchange(t, store, "/fourth")
	if fourth != third+1 {
		t.Fatalf("new exchange took id %d, want %d — a deleted slot was reused", fourth, third+1)
	}
}

func TestDeleteIsIdempotentAndTheCountIsHonest(t *testing.T) {
	store := NewTrafficStore()
	a := putExchange(t, store, "/a")
	b := putExchange(t, store, "/b")

	if n := store.DeleteExchanges([]ExchangeID{a}); n != 1 {
		t.Fatalf("first delete removed %d, want 1", n)
	}
	if n := store.DeleteExchanges([]ExchangeID{a}); n != 0 {
		t.Fatalf("re-deleting a removed row reported %d, want 0 — the API answer would double-count", n)
	}
	if _, exchanges := store.Count(); exchanges != 1 {
		t.Fatalf("Count says %d exchanges after one delete, want 1", exchanges)
	}
	if n := store.ClearExchanges(); n != 1 {
		t.Fatalf("Clear removed %d, want the one live row", n)
	}
	if n := store.ClearExchanges(); n != 0 {
		t.Fatalf("a second Clear removed %d, want 0", n)
	}
	if _, exchanges := store.Count(); exchanges != 0 {
		t.Fatalf("Count says %d exchanges after Clear, want 0", exchanges)
	}

	// Clear answers Clear: a new exchange still takes the next positional id, because the ids of
	// the cleared rows are still the currency every other store names them by.
	after := putExchange(t, store, "/after-clear")
	if after != b+1 {
		t.Fatalf("exchange after Clear took id %d, want %d", after, b+1)
	}
}

func TestAnAnnotationCannotResurrectADeletedExchange(t *testing.T) {
	store := NewTrafficStore()
	id := putExchange(t, store, "/annotated")
	store.DeleteExchanges([]ExchangeID{id})

	if _, err := store.UpdateExchangeAnnotation(id, nil, false, "red", true); err == nil {
		t.Fatal("a highlight PATCH on a deleted exchange succeeded — the operator was shown a row they had deleted")
	}
}
