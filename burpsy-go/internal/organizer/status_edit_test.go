package organizer

import "testing"

func TestSetStatusIfUnchanged(t *testing.T) {
	o := New()
	it := o.Add(7)
	if err := o.SetStatusIfUnchanged(it, "invalid"); err == nil {
		t.Fatal("invalid enum accepted")
	}
	if got := o.List()[0]; got != it {
		t.Fatal("invalid enum changed item")
	}
	changed := it
	changed.Note = "other"
	if err := o.SetStatusIfUnchanged(changed, StatusDone); err == nil {
		t.Fatal("full snapshot ignored")
	}
	if err := o.SetStatusIfUnchanged(it, StatusDone); err != nil {
		t.Fatal(err)
	}
	want := it
	want.Status = StatusDone
	if o.List()[0] != want {
		t.Fatal("non-status field mutated")
	}
	o.Remove(it.ID)
	if err := o.SetStatusIfUnchanged(want, StatusNew); err == nil {
		t.Fatal("missing accepted")
	}
}
