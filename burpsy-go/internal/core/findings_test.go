package core

import (
	"testing"
	"time"
)

func TestFindingStoreAddAssignsTimestamp(t *testing.T) {
	fs := NewFindingStore()
	before := uint64(time.Now().UnixMilli())
	id := fs.Add(NewFinding{Name: "test"})
	after := uint64(time.Now().UnixMilli())

	f, err := fs.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f.Timestamp == 0 {
		t.Error("timestamp is 0, want real Unix milliseconds")
	}
	if f.Timestamp < before || f.Timestamp > after {
		t.Errorf("timestamp %d outside [%d, %d]", f.Timestamp, before, after)
	}
}

func TestFindingStoreCRUD(t *testing.T) {
	fs := NewFindingStore()
	id1 := fs.Add(NewFinding{Name: "a", Severity: SeverityHigh})
	id2 := fs.Add(NewFinding{Name: "b", Severity: SeverityLow})

	if fs.Count() != 2 {
		t.Errorf("count = %d, want 2", fs.Count())
	}
	if id1 == id2 {
		t.Errorf("ids collide: %d", id1)
	}

	f, err := fs.Get(id1)
	if err != nil {
		t.Fatalf("Get(%d): %v", id1, err)
	}
	if f.Name != "a" || f.Severity != SeverityHigh {
		t.Errorf("finding = %+v, want name=a high", f)
	}

	if !fs.Delete(id1) {
		t.Error("Delete(id1) = false, want true")
	}
	if fs.Delete(id1) {
		t.Error("second Delete(id1) = true, want false")
	}
	if _, err := fs.Get(id1); err == nil {
		t.Error("Get after delete should error")
	}
	if fs.Count() != 1 {
		t.Errorf("count after delete = %d, want 1", fs.Count())
	}

	fs.Clear()
	if fs.Count() != 0 {
		t.Errorf("count after clear = %d, want 0", fs.Count())
	}
}
