package organizer

import (
	"strings"
	"testing"
)

func seededStore(t *testing.T) (*Store, Collection, Collection, Item) {
	t.Helper()
	o := New()
	a, _ := o.NewCollection("alpha")
	b, _ := o.NewCollection("beta")
	it := o.Add(4242)
	o.Update(it.ID, "title", "note", "red")
	it = o.List()[0]
	return o, a, b, it
}

func TestMoveItemIfUnchanged(t *testing.T) {
	o, a, b, it := seededStore(t)
	if err := o.MoveItemIfUnchanged(it, a); err != nil {
		t.Fatal(err)
	}
	got := o.List()[0]
	if got.Collection != a.ID || got.Title != it.Title || got.Status != it.Status || got.ID != it.ID {
		t.Fatalf("move changed more than membership: %+v", got)
	}
	// Destination drift: rename between review and install is refused under one lock.
	if err := o.MoveItemIfUnchanged(o.List()[0], Collection{ID: b.ID, Name: "renamed"}); err == nil || !strings.Contains(err.Error(), "renamed since review") {
		t.Fatal("renamed destination accepted")
	}
	// Destination deletion is refused under the same lock.
	if err := o.MoveItemIfUnchanged(o.List()[0], Collection{ID: 999, Name: "ghost"}); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal("missing destination accepted")
	}
	// A changed item is refused; nothing applied.
	changed := o.List()[0]
	changed.Title = "other"
	if err := o.MoveItemIfUnchanged(changed, b); err == nil || !strings.Contains(err.Error(), "changed since review") {
		t.Fatal("stale item accepted")
	}
	// A no-op move is refused.
	cur := o.List()[0]
	if err := o.MoveItemIfUnchanged(cur, a); err == nil || !strings.Contains(err.Error(), "already in that collection") {
		t.Fatal("no-op move accepted")
	}
	// Inbox (collection 0) needs no destination snapshot and moves back.
	if err := o.MoveItemIfUnchanged(o.List()[0], Collection{}); err != nil {
		t.Fatal(err)
	}
	if o.List()[0].Collection != 0 {
		t.Fatal("move to inbox not applied")
	}
	// A removed item is refused.
	removed := o.List()[0]
	o.Remove(removed.ID)
	if err := o.MoveItemIfUnchanged(removed, b); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal("removed item accepted")
	}
}

func TestCopyItemIfUnchanged(t *testing.T) {
	o, a, b, it := seededStore(t)
	if err := o.MoveItemIfUnchanged(it, a); err != nil {
		t.Fatal(err)
	}
	before := o.List()
	dup, err := o.CopyItemIfUnchanged(before[0], b)
	if err != nil {
		t.Fatal(err)
	}
	if dup.ID <= before[0].ID || dup.Collection != b.ID {
		t.Fatalf("copy id/collection wrong: %+v", dup)
	}
	if dup.Exchange != before[0].Exchange || dup.Title != before[0].Title || dup.Note != before[0].Note || dup.Highlight != before[0].Highlight || dup.Status != before[0].Status {
		t.Fatalf("copy fields not from reviewed item: %+v", dup)
	}
	after := o.List()
	if len(after) != 2 || after[0] != before[0] {
		t.Fatal("copy changed the source")
	}
	// Ids stay monotonic across repeated copies.
	dup2, err := o.CopyItemIfUnchanged(o.List()[0], b)
	if err != nil || dup2.ID <= dup.ID {
		t.Fatalf("copy ids not monotonic: %d then %d (%v)", dup.ID, dup2.ID, err)
	}
	// Copying into the same collection is the duplicate: allowed.
	if _, err := o.CopyItemIfUnchanged(o.List()[0], a); err != nil {
		t.Fatal("same-collection copy refused")
	}
	// Destination rename/deletion drift and a changed source are refused.
	if _, err := o.CopyItemIfUnchanged(o.List()[0], Collection{ID: b.ID, Name: "renamed"}); err == nil || !strings.Contains(err.Error(), "renamed since review") {
		t.Fatal("renamed destination accepted")
	}
	if _, err := o.CopyItemIfUnchanged(o.List()[0], Collection{ID: 999, Name: "ghost"}); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal("missing destination accepted")
	}
	changed := o.List()[0]
	changed.Note = "other"
	if _, err := o.CopyItemIfUnchanged(changed, b); err == nil || !strings.Contains(err.Error(), "changed since review") {
		t.Fatal("stale source accepted")
	}
	if len(o.List()) != 4 {
		t.Fatal("a refused copy still appended")
	}
}

func TestDeleteItemIfUnchanged(t *testing.T) {
	o, a, _, it := seededStore(t)
	if err := o.MoveItemIfUnchanged(it, a); err != nil {
		t.Fatal(err)
	}
	other := o.Add(7777)
	collections := o.Collections()
	if err := o.DeleteItemIfUnchanged(o.List()[0]); err != nil {
		t.Fatal(err)
	}
	got := o.List()
	if len(got) != 1 || got[0] != other {
		t.Fatal("delete removed more than the saved item")
	}
	if len(o.Collections()) != len(collections) {
		t.Fatal("delete changed collections")
	}
	// A changed item and a removed item are both refused.
	changed := o.List()[0]
	changed.Title = "other"
	if err := o.DeleteItemIfUnchanged(changed); err == nil || !strings.Contains(err.Error(), "changed since review") {
		t.Fatal("stale item accepted")
	}
	if err := o.DeleteItemIfUnchanged(Item{ID: 999}); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal("missing item accepted")
	}
	if len(o.List()) != 1 {
		t.Fatal("a refused delete still removed")
	}
}
