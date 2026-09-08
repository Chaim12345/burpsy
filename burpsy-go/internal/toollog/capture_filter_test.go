package toollog

import (
	"testing"
)

func mustFilter(t *testing.T, f CaptureFilter) CaptureFilter {
	t.Helper()
	if err := f.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return f
}

func TestStatusBucketsKeepOnlyTheirClass(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	if err := l.SetFilter(mustFilter(t, CaptureFilter{Status: []int{2, 5}})); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/", 200, Bytes(10), 1, "", nil)
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/old", 301, Bytes(10), 1, "", nil)
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/boom", 500, Bytes(10), 1, "", nil)
	if n := l.Count(); n != 2 {
		t.Errorf("Count = %d, want 2xx and 5xx only", n)
	}
	if n := l.Filtered(); n != 1 {
		t.Errorf("Filtered = %d, want the refused 3xx counted beside Uncaptured", n)
	}
}

func TestBadRegexIsRefusedWithTheOldFilterIntact(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	if err := l.SetFilter(mustFilter(t, CaptureFilter{Search: SearchSpec{Term: "shop", Regex: false}})); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	if err := l.SetFilter(CaptureFilter{Search: SearchSpec{Term: "([unclosed", Regex: true}}); err == nil {
		t.Errorf("bad regex accepted")
	}
	// The refused save must not have replaced the working filter.
	l.Record(ToolRepeater, "shop.test", 80, false, "GET", "/", 200, Bytes(1), 1, "", nil)
	l.Record(ToolRepeater, "other.test", 80, false, "GET", "/", 200, Bytes(1), 1, "", nil)
	if n := l.Count(); n != 1 {
		t.Errorf("Count = %d, want the old term filter still in force", n)
	}
}

func TestSearchNegateAndCase(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	if err := l.SetFilter(mustFilter(t, CaptureFilter{
		Search: SearchSpec{Term: "ADMIN", Regex: false, CaseSensitive: false, Negate: true},
	})); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/admin/panel", 200, Bytes(1), 1, "", nil)
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/shop/cart", 200, Bytes(1), 1, "", nil)
	if n := l.Count(); n != 1 {
		t.Errorf("Count = %d, want only the non-admin row", n)
	}
}

func TestScopeOnlyWithoutScopeFiltersNothing(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	if err := l.SetFilter(CaptureFilter{ScopeOnly: true}); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/", 200, Bytes(1), 1, "", nil)
	if n := l.Count(); n != 1 {
		t.Errorf("Count = %d, want 1: nil scope must fail safe, not empty the log", n)
	}
}

type denyScope struct{}

func (denyScope) Contains(host string, port uint16, path string, isTLS bool) bool { return false }

func TestScopeOnlyWithScopeDropsOutOfScope(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	l.SetScope(denyScope{})
	if err := l.SetFilter(CaptureFilter{ScopeOnly: true}); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	l.Record(ToolRepeater, "a.test", 80, false, "GET", "/", 200, Bytes(1), 1, "", nil)
	if n := l.Count(); n != 0 {
		t.Errorf("Count = %d, want the denied row refused", n)
	}
	if n := l.Filtered(); n != 1 {
		t.Errorf("Filtered = %d, want 1", n)
	}
}

func TestSetCapacityRefusesNonPositiveAndTrims(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	if err := l.SetCapacity(0); err == nil {
		t.Errorf("capacity 0 accepted: a bound of nothing would read as unlimited nowhere")
	}
	for i := 0; i < 5; i++ {
		l.Record(ToolRepeater, "a.test", 80, false, "GET", "/", 200, Bytes(1), 1, "", nil)
	}
	if err := l.SetCapacity(2); err != nil {
		t.Fatalf("SetCapacity: %v", err)
	}
	if n := l.Count(); n != 2 {
		t.Errorf("Count = %d after trim to 2, want newest 2 kept", n)
	}
}

func TestSetCommentWritesWithoutTouchingTheNote(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	id := l.Record(ToolRepeater, "a.test", 80, false, "GET", "/", 200, Bytes(1), 1, "producer note", nil)
	if !l.SetComment(id, "look again") {
		t.Fatalf("SetComment refused a live id")
	}
	got := l.All()[0]
	if got.Comment != "look again" {
		t.Errorf("comment = %q, want the annotation", got.Comment)
	}
	if got.Note != "producer note" {
		t.Errorf("note = %q, want the producer note untouched", got.Note)
	}
	if l.SetComment(999, "nowhere") {
		t.Errorf("SetComment accepted an unknown id")
	}
}

func TestSetHighlightWritesReFiresTheSinkAndClears(t *testing.T) {
	l := New()
	l.WithCapacity(100)
	var sinkSaw *Entry
	l.SetPersistenceSink(func(e *Entry) { sinkSaw = e })
	id := l.Record(ToolRepeater, "a.test", 80, false, "GET", "/", 200, Bytes(1), 1, "producer note", nil)
	if !l.SetHighlight(id, "red") {
		t.Fatal("SetHighlight refused a live id")
	}
	got := l.All()[0]
	if got.Highlight != "red" || got.Note != "producer note" {
		t.Errorf("entry after SetHighlight = highlight %q note %q, want red with the producer note untouched", got.Highlight, got.Note)
	}
	if sinkSaw == nil || sinkSaw.Highlight != "red" {
		t.Errorf("persistence sink last saw %+v, want the re-fired entry carrying highlight red", sinkSaw)
	}
	if !l.SetHighlight(id, "") {
		t.Fatal("SetHighlight clear refused a live id")
	}
	if got := l.All()[0].Highlight; got != "" {
		t.Errorf("highlight after clear = %q, want empty", got)
	}
	if l.SetHighlight(999, "red") {
		t.Errorf("SetHighlight accepted an unknown id")
	}
}
