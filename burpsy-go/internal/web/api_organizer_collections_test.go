package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/organizer"
)

// The collections surface is the "no grouping" fix (dcr): create / rename / note / duplicate /
// delete / move / copy, mirroring Burp's organizer collections menu. These tests drive the wire
// routes and pin the refusals that keep the model honest — a duplicate name, a delete that must
// not silently destroy saved work, a move to a collection that does not exist.

func collectionJSON(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	rec := get(t, s, "/api/tools/organizer")
	var body struct {
		Collections []map[string]any `json:"collections"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode organizer list: %v", err)
	}
	return body.Collections
}

// deleteReq issues DELETE; the shared helpers cover GET and POST-with-body only.
func deleteReq(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestACollectionCanBeCreatedRenamedNotedAndShownInTheList(t *testing.T) {
	s := organizerTestServer(t)

	rec := postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "Auth bypasses"})
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d, body %q", rec.Code, rec.Body.String())
	}
	var created organizer.Collection
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.ID == 0 || created.Name != "Auth bypasses" {
		t.Fatalf("created = %+v", created)
	}

	if rec := putJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(created.ID)), map[string]any{"name": "Authn issues", "note": "everything from the login crawl"}); rec.Code != http.StatusOK {
		t.Fatalf("rename+note = %d, body %q", rec.Code, rec.Body.String())
	}
	cols := collectionJSON(t, s)
	if len(cols) != 1 || cols[0]["name"] != "Authn issues" || cols[0]["note"] != "everything from the login crawl" {
		t.Fatalf("collections after rename = %+v", cols)
	}
}

func TestASecondCollectionWithTheSameNameIsRefused(t *testing.T) {
	s := organizerTestServer(t)
	postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "triage"})
	rec := postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "triage"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate name = %d, want 400: two identically named groups make Move to… ambiguous", rec.Code)
	}
}

func TestDeletingACollectionDefaultsToUnlinkingItsItemsToTheInbox(t *testing.T) {
	s := organizerTestServer(t)
	item := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, ""))
	rec := postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "temp"})
	var c organizer.Collection
	json.Unmarshal(rec.Body.Bytes(), &c)
	putJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(c.ID))+"/items", map[string]any{"item_ids": []int{item.ID}})

	// items=inbox is also the default when the query is absent: the operator's saved work must
	// not vanish because a query parameter did.
	rec = deleteReq(t, s, "/api/tools/organizer/collections/"+itoa(uint64(c.ID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d, body %q", rec.Code, rec.Body.String())
	}
	var out struct {
		Unlinked int `json:"unlinked"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Unlinked != 1 {
		t.Fatalf("unlinked = %d, want 1", out.Unlinked)
	}
	items := s.organizer.List()
	if len(items) != 1 || items[0].Collection != 0 {
		t.Fatalf("items after delete = %+v; unlinking must return them to the inbox, not drop them", items)
	}
}

func TestDeletingACollectionWithItemsDeleteDestroysTheItemsAndReportsIt(t *testing.T) {
	s := organizerTestServer(t)
	item := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, ""))
	rec := postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "doomed"})
	var c organizer.Collection
	json.Unmarshal(rec.Body.Bytes(), &c)
	putJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(c.ID))+"/items", map[string]any{"item_ids": []int{item.ID}})

	if rec := deleteReq(t, s, "/api/tools/organizer/collections/"+itoa(uint64(c.ID))+"?items=delete"); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	if len(s.organizer.List()) != 0 {
		t.Fatalf("items survived items=delete; the explicit destructive choice must take them with the group")
	}
}

func TestMovingItemsBetweenCollectionsAndTheInboxRoundTrips(t *testing.T) {
	s := organizerTestServer(t)
	first := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, ""))
	second := s.organizer.Add(captureExchange(t, s, "app.test", "/b", 200, ""))
	postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "one"})
	postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "two"})
	cols := collectionJSON(t, s)
	one := int(cols[0]["id"].(float64))
	two := int(cols[1]["id"].(float64))

	if rec := putJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(one))+"/items", map[string]any{"item_ids": []int{first.ID, second.ID}}); rec.Code != http.StatusOK {
		t.Fatalf("move into one = %d, body %q", rec.Code, rec.Body.String())
	}
	if s.organizer.List()[0].Collection != one || s.organizer.List()[1].Collection != one {
		t.Fatalf("items not in collection one: %+v", s.organizer.List())
	}

	// Copy, not move: the source keeps its item and a fresh one appears in the target.
	if rec := putJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(two))+"/items", map[string]any{"item_ids": []int{first.ID}, "copy": true}); rec.Code != http.StatusOK {
		t.Fatalf("copy into two = %d", rec.Code)
	}
	if len(s.organizer.List()) != 3 {
		t.Fatalf("after copy there are %d items, want 3 — a copy must duplicate, not relocate", len(s.organizer.List()))
	}
	if s.organizer.List()[0].Collection != one {
		t.Fatalf("the copied-from item left collection one; copy must leave the original in place")
	}

	// Inbox move uses the literal "inbox" because 0 is not a collection the UI can name.
	if rec := putJSON(t, s, "/api/tools/organizer/collections/inbox", map[string]any{"item_ids": []int{first.ID, second.ID}}); rec.Code != http.StatusOK {
		t.Fatalf("move to inbox = %d", rec.Code)
	}
	for _, it := range s.organizer.List() {
		if it.ID == first.ID || it.ID == second.ID {
			if it.Collection != 0 {
				t.Fatalf("item %d still in collection %d after the inbox move", it.ID, it.Collection)
			}
		}
	}
}

func TestDuplicatingACollectionCopiesItsItemsUnderFreshIDsAndANonCollidingName(t *testing.T) {
	s := organizerTestServer(t)
	item := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, ""))
	s.organizer.Update(item.ID, "interesting", "check the cookie", "")
	rec := postJSON(t, s, "/api/tools/organizer/collections", map[string]any{"name": "original"})
	var c organizer.Collection
	json.Unmarshal(rec.Body.Bytes(), &c)
	putJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(c.ID))+"/items", map[string]any{"item_ids": []int{item.ID}})

	if rec := postJSON(t, s, "/api/tools/organizer/collections/"+itoa(uint64(c.ID))+"/duplicate", nil); rec.Code != http.StatusOK {
		t.Fatalf("duplicate = %d, body %q", rec.Code, rec.Body.String())
	}
	cols := collectionJSON(t, s)
	if len(cols) != 2 {
		t.Fatalf("%d collections after duplicate, want 2", len(cols))
	}
	if cols[1]["name"] != "original (copy)" {
		t.Fatalf("copy name = %v, want 'original (copy)'", cols[1]["name"])
	}
	all := s.organizer.List()
	if len(all) != 2 {
		t.Fatalf("%d items after duplicate, want 2 — a copy duplicates the items", len(all))
	}
	if all[1].ID == all[0].ID {
		t.Fatalf("the duplicated item reuses id %d; a copy is a new item, not a second pointer", all[0].ID)
	}
	if all[1].Title != "interesting" || all[1].Note != "check the cookie" {
		t.Fatalf("duplicated item lost its annotations: %+v", all[1])
	}
}

func TestCollectionRoutesAnswer404ForUnknownCollectionsAnd405ForWrongVerbs(t *testing.T) {
	s := organizerTestServer(t)
	if rec := putJSON(t, s, "/api/tools/organizer/collections/4242", map[string]any{"name": "x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("rename unknown = %d, want 404", rec.Code)
	}
	if rec := putJSON(t, s, "/api/tools/organizer/collections/4242/items", map[string]any{"item_ids": []int{1}}); rec.Code != http.StatusNotFound {
		t.Fatalf("move into unknown = %d, want 404", rec.Code)
	}
	if rec := deleteReq(t, s, "/api/tools/organizer/collections/4242"); rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown = %d, want 404", rec.Code)
	}
	if rec := get(t, s, "/api/tools/organizer/collections/1"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET one collection = %d, want 405", rec.Code)
	}
}
