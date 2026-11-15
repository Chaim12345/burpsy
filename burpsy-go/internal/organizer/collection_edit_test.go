package organizer

import "testing"

func TestCollectionAtomicEdit(t *testing.T) {
	o := New()
	c, _ := o.NewCollection("old")
	o.NewCollection("taken")
	for _, tc := range []struct{ name, note string }{{"Inbox", ""}, {"taken", ""}, {" ", ""}} {
		if o.EditCollectionIfUnchanged(c, tc.name, tc.note) == nil {
			t.Fatal("invalid atomic edit accepted")
		}
		if o.Collections()[0] != c {
			t.Fatal("partial write")
		}
	}
	if err := o.EditCollectionIfUnchanged(c, " new ", "note"); err != nil {
		t.Fatal(err)
	}
	if o.EditCollectionIfUnchanged(c, "overwrite", "") == nil {
		t.Fatal("stale atomic edit accepted")
	}
	got := o.Collections()[0]
	if got.Name != "new" || got.Note != "note" {
		t.Fatal("atomic fields missing")
	}
}
