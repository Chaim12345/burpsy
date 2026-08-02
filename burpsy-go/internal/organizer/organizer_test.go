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
