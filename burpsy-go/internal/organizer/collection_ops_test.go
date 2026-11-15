package organizer

import (
	"strings"
	"testing"
)

func TestDuplicateCollectionIfUnchanged(t *testing.T) {
	o := New()
	c, _ := o.NewCollection("src")
	o.SetCollectionNote(c.ID, "why")
	c.Note = "why"
	it := o.Add(7)
	o.Update(it.ID, "t", "n", "red")
	o.MoveToCollection([]int{it.ID}, c.ID)
	members := o.Members(c.ID)
	dup, err := o.DuplicateCollectionIfUnchanged(c, members, "src (copy)")
	if err != nil || dup.Note != "why" || o.ItemsIn(dup.ID) != 1 || o.ItemsIn(c.ID) != 1 {
		t.Fatalf("duplicate: %v %+v", err, dup)
	}
	copied := o.Members(dup.ID)[0]
	if copied.ID == it.ID || copied.Title != "t" || copied.Highlight != "red" || copied.Exchange != 7 {
		t.Fatalf("copy fields: %+v", copied)
	}
	// Membership drift refuses.
	o.Add(8)
	o.MoveToCollection([]int{3}, c.ID)
	if _, err := o.DuplicateCollectionIfUnchanged(c, members, "other"); err == nil || !strings.Contains(err.Error(), "items changed") {
		t.Fatalf("drift accepted: %v", err)
	}
	if _, err := o.DuplicateCollectionIfUnchanged(c, o.Members(c.ID), "src (copy)"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("name clash accepted: %v", err)
	}
}

func TestDeleteCollectionIfUnchanged(t *testing.T) {
	o := New()
	c, _ := o.NewCollection("a")
	it := o.Add(1)
	o.MoveToCollection([]int{it.ID}, c.ID)
	members := o.Members(c.ID)
	o.Update(it.ID, "edited", "", "")
	if _, err := o.DeleteCollectionIfUnchanged(c, members, true); err == nil {
		t.Fatal("stale member accepted")
	}
	n, err := o.DeleteCollectionIfUnchanged(c, o.Members(c.ID), false)
	if err != nil || n != 1 || len(o.Collections()) != 0 || o.List()[0].Collection != 0 {
		t.Fatalf("keep-items delete: %v %d %+v", err, n, o.List())
	}
	d, _ := o.NewCollection("b")
	o.MoveToCollection([]int{it.ID}, d.ID)
	if n, err := o.DeleteCollectionIfUnchanged(d, o.Members(d.ID), true); err != nil || n != 1 || len(o.List()) != 0 {
		t.Fatalf("with-items delete: %v %d", err, n)
	}
	if _, err := o.DeleteCollectionIfUnchanged(d, nil, false); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("missing collection accepted: %v", err)
	}
}
