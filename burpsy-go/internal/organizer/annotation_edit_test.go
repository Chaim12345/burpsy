package organizer

import (
	"strings"
	"testing"
)

func TestSetAnnotationIfUnchanged(t *testing.T) {
	o := New()
	it := o.Add(7)
	if err := o.SetAnnotationIfUnchanged(it, "t", "n", "chartreuse"); err == nil || !strings.Contains(err.Error(), "must be none, red") {
		t.Fatal("invalid highlight accepted")
	}
	if err := o.SetAnnotationIfUnchanged(it, "t", "n", ""); err == nil || !strings.Contains(err.Error(), "must be none, red") {
		t.Fatal("blank highlight accepted")
	}
	if got := o.List()[0]; got != it {
		t.Fatal("invalid highlight changed item")
	}
	if err := o.SetAnnotationIfUnchanged(it, it.Title, it.Note, it.Highlight); err == nil || !strings.Contains(err.Error(), "unchanged") {
		t.Fatal("no-op accepted")
	}
	changed := it
	changed.Status = StatusDone
	if err := o.SetAnnotationIfUnchanged(changed, "t", "n", "red"); err == nil || !strings.Contains(err.Error(), "changed since review") {
		t.Fatal("full snapshot ignored")
	}
	if err := o.SetAnnotationIfUnchanged(it, "new title", "new note", "red"); err != nil {
		t.Fatal(err)
	}
	want := it
	want.Title, want.Note, want.Highlight = "new title", "new note", "red"
	if o.List()[0] != want {
		t.Fatal("non-annotation field mutated")
	}
	// Legacy over-cap values are preserved: an all-unchanged write refuses as a no-op
	// before any cap check, and an edit keeping an over-cap title is refused, not truncated.
	big := strings.Repeat("x", ItemTitleLimit+5)
	o.Update(it.ID, big, "n", "")
	legacy := o.List()[0]
	if err := o.SetAnnotationIfUnchanged(legacy, legacy.Title, legacy.Note, legacy.Highlight); err == nil || !strings.Contains(err.Error(), "unchanged") {
		t.Fatal("legacy no-op not refused as no-op")
	}
	if err := o.SetAnnotationIfUnchanged(legacy, legacy.Title, "changed note", legacy.Highlight); err == nil || !strings.Contains(err.Error(), "512 UTF-8 bytes") {
		t.Fatal("over-cap title kept")
	}
	if o.List()[0] != legacy {
		t.Fatal("over-cap legacy value mutated")
	}
	if err := o.SetAnnotationIfUnchanged(legacy, "within limits", "changed note", "none"); err != nil {
		t.Fatal(err)
	}
	current := o.List()[0]
	o.Remove(current.ID)
	if err := o.SetAnnotationIfUnchanged(current, "a", "b", "red"); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal("missing accepted")
	}
}
