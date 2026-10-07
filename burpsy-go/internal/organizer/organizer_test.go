package organizer

import "testing"

func TestStore_AddListUpdateRemoveRoundTrip(t *testing.T) {
	s := New()
	first := s.Add(10)
	if first.ID != 1 || first.Exchange != 10 || first.Highlight != "none" {
		t.Fatalf("first = %+v, want id 1/exchange 10/highlight none", first)
	}
	second := s.Add(20)
	if second.ID != 2 {
		t.Fatalf("second id = %d, want 2", second.ID)
	}
	if items := s.List(); len(items) != 2 {
		t.Fatalf("len = %d, want 2", len(items))
	}
	if !s.Update(2, "Important", "review later", "yellow") {
		t.Fatalf("Update(2) reported not found")
	}
	items := s.List()
	if items[1].Title != "Important" || items[1].Note != "review later" || items[1].Highlight != "yellow" {
		t.Fatalf("updated item = %+v", items[1])
	}
	if !s.Remove(1) {
		t.Fatalf("Remove(1) reported not found")
	}
	if items = s.List(); len(items) != 1 || items[0].ID != 2 {
		t.Fatalf("after remove = %+v, want only id 2", items)
	}
}

func TestStore_UpdateKeepsHighlightWhenEmpty(t *testing.T) {
	s := New()
	s.Add(1)
	if !s.Update(1, "t", "n", "") {
		t.Fatalf("Update returned not found")
	}
	if s.List()[0].Highlight != "none" {
		t.Fatalf("highlight overwritten by empty value: %+v", s.List()[0])
	}
}

func TestStore_UnknownIdReported(t *testing.T) {
	s := New()
	if s.Update(99, "t", "n", "") {
		t.Fatalf("Update(99) on empty store reported success")
	}
	if s.Remove(99) {
		t.Fatalf("Remove(99) on empty store reported success")
	}
}

func TestStore_NewItemStartsAtStatusNewAndSetStatusChangesOnlyThatItem(t *testing.T) {
	s := New()
	first := s.Add(1)
	if first.Status != StatusNew {
		t.Fatalf("fresh item status = %q, want %q: untriaged must exist as a state", first.Status, StatusNew)
	}
	s.Add(2)
	if !s.SetStatus(first.ID, StatusDone) {
		t.Fatalf("SetStatus reported not found")
	}
	items := s.List()
	if items[0].Status != StatusDone {
		t.Fatalf("first item status = %q, want done", items[0].Status)
	}
	if items[1].Status != StatusNew {
		t.Fatalf("second item status = %q; a status set on one item must not leak to another", items[1].Status)
	}
	if s.SetStatus(99, StatusDone) {
		t.Fatalf("SetStatus on an unknown id reported success")
	}
}

func TestStore_ValidStatusAcceptsOnlyTheFive(t *testing.T) {
	for _, valid := range []Status{StatusNew, StatusInProgress, StatusPostponed, StatusDone, StatusIgnored} {
		if !ValidStatus(valid) {
			t.Fatalf("ValidStatus(%q) = false; a defined status must be valid", valid)
		}
	}
	if ValidStatus(Status("finished")) || ValidStatus(Status("")) || ValidStatus(Status("NEW")) {
		t.Fatalf("an invented, empty or wrong-cased value passed as a status; the wire contract is the five lowercase values")
	}
}

func TestStore_CollectionsRoundTripWithMembershipAndTheInboxIsZero(t *testing.T) {
	s := New()
	item := s.Add(10)
	c, ok := s.NewCollection("auth")
	if !ok || c.ID == 0 {
		t.Fatalf("NewCollection = %+v ok=%v", c, ok)
	}
	if _, ok := s.NewCollection("auth"); ok {
		t.Fatalf("a duplicate collection name was accepted; Move to… would become ambiguous")
	}
	if got := s.MoveToCollection([]int{item.ID}, c.ID); got != 1 {
		t.Fatalf("MoveToCollection moved %d items, want 1", got)
	}
	if s.List()[0].Collection != c.ID {
		t.Fatalf("item collection = %d, want %d", s.List()[0].Collection, c.ID)
	}
	if s.ItemsIn(c.ID) != 1 || s.ItemsIn(0) != 0 {
		t.Fatalf("ItemsIn = (%d, %d), want (1, 0)", s.ItemsIn(c.ID), s.ItemsIn(0))
	}
	// Unlink back to the inbox, Burp's Move to… with the inbox as destination.
	if got := s.MoveToCollection([]int{item.ID}, 0); got != 1 {
		t.Fatalf("unlink moved %d, want 1", got)
	}
	if s.List()[0].Collection != 0 {
		t.Fatalf("after unlink the item is in collection %d, want 0 (the inbox)", s.List()[0].Collection)
	}
	if got := s.MoveToCollection([]int{item.ID}, 999); got != -1 {
		t.Fatalf("moving into an unknown collection returned %d, want -1 so the caller can answer 404", got)
	}
}

func TestStore_DeleteCollectionUnlinksByDefaultAndDeletesItemsOnlyWhenTold(t *testing.T) {
	s := New()
	keep := s.Add(1)
	lose := s.Add(2)
	c, _ := s.NewCollection("temp")
	s.MoveToCollection([]int{keep.ID, lose.ID}, c.ID)

	unlinked, ok := s.DeleteCollection(c.ID, false)
	if !ok || unlinked != 2 {
		t.Fatalf("DeleteCollection = (%d, %v), want (2, true)", unlinked, ok)
	}
	if len(s.List()) != 2 || s.List()[0].Collection != 0 || s.List()[1].Collection != 0 {
		t.Fatalf("items after unlink = %+v; the default must return them to the inbox, never drop them", s.List())
	}
	if len(s.Collections()) != 0 {
		t.Fatalf("the collection survived its own delete")
	}

	c2, _ := s.NewCollection("doomed")
	s.MoveToCollection([]int{keep.ID}, c2.ID)
	if _, ok := s.DeleteCollection(c2.ID, true); !ok {
		t.Fatalf("DeleteCollection(with items) reported not found")
	}
	if len(s.List()) != 1 || s.List()[0].ID != lose.ID {
		t.Fatalf("items after destructive delete = %+v; only the collection's own items go with it", s.List())
	}
	if _, ok := s.DeleteCollection(999, false); ok {
		t.Fatalf("deleting an unknown collection reported success")
	}
}

func TestStore_RenameCollectionRefusesUnknownAndTakenNames(t *testing.T) {
	s := New()
	a, _ := s.NewCollection("a")
	s.NewCollection("b")
	if !s.RenameCollection(a.ID, "c") {
		t.Fatalf("rename to a free name reported failure")
	}
	if s.RenameCollection(a.ID, "b") {
		t.Fatalf("renaming onto a taken name succeeded; the two groups would be indistinguishable")
	}
	if s.RenameCollection(999, "z") {
		t.Fatalf("renaming an unknown collection succeeded")
	}
	if !s.SetCollectionNote(a.ID, "about") || s.Collections()[0].Note != "about" {
		t.Fatalf("SetCollectionNote did not stick")
	}
	if s.SetCollectionNote(999, "x") {
		t.Fatalf("noting an unknown collection succeeded")
	}
}

func TestStore_RestoreKeepsCollectionIDsAndResumesBothCounters(t *testing.T) {
	s := New()
	item := s.Add(5)
	c, _ := s.NewCollection("kept")
	s.MoveToCollection([]int{item.ID}, c.ID)
	snapshot := s.List()
	cols := s.Collections()

	fresh := New()
	fresh.Restore(snapshot, cols)
	if got := fresh.List()[0]; got.ID != item.ID || got.Collection != c.ID {
		t.Fatalf("restored item = %+v; ids and membership must survive the round trip", got)
	}
	added := fresh.Add(6)
	if added.ID <= item.ID {
		t.Fatalf("Add after restore minted id %d, at or below the restored %d", added.ID, item.ID)
	}
	next, _ := fresh.NewCollection("after")
	if next.ID <= c.ID {
		t.Fatalf("NewCollection after restore minted id %d, at or below the restored %d", next.ID, c.ID)
	}
}
