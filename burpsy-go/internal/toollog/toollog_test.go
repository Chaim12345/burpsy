package toollog

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Test_new_records_every_tool by default pins the capture axis's default:
// a fresh log must capture all eight tools, because the zero value of the
// bitmask would otherwise mean "record nothing" and a tool log that silently
// records nothing is exactly the class of lie this package refuses to tell.
func Test_new_captures_every_tool_by_default(t *testing.T) {
	l := New()
	for _, tool := range ToolAll {
		if !l.Capturing(tool) {
			t.Fatalf("fresh log does not capture %s by default", tool)
		}
	}
}

// Test_record_when_capture_off_is_uncaptured_not_entry pins both halves of the
// axis: a request for a tool whose capture is off is counted as uncaptured and
// never becomes an entry. A capture that silently dropped the request would
// read as an empty log; the counter is what makes the loss honest.
func Test_record_when_capture_off_counts_uncaptured_and_stores_nothing(t *testing.T) {
	l := New()
	l.SetCapturing(ToolIntruder, false)

	if id := l.Record(ToolIntruder, "h", 80, false, "GET", "/", 200, nil, 1, "", nil); id != 0 {
		t.Fatalf("capture-off Record returned id %d, want 0 (nothing stored)", id)
	}
	if got := l.Uncaptured(ToolIntruder); got != 1 {
		t.Fatalf("Uncaptured(ToolIntruder) = %d, want 1", got)
	}
	if l.Count() != 0 {
		t.Fatalf("Count() = %d after capture-off record, want 0", l.Count())
	}
	// The counter is per-tool: a different tool's capture is unaffected.
	if id := l.Record(ToolRepeater, "h", 80, false, "GET", "/", 200, nil, 1, "", nil); id != 1 {
		t.Fatalf("capture-on Record returned id %d, want 1", id)
	}
	if got := l.Uncaptured(ToolRepeater); got != 0 {
		t.Fatalf("Uncaptured(ToolRepeater) = %d, want 0", got)
	}
}

// Test_set_capturing_re_enables_pins the toggle back on: turning a tool's
// capture back on resumes storing its requests, and only those requests — the
// uncaptured counter does not retroactively admit earlier refusals.
func Test_set_capturing_back_on_restores_recording(t *testing.T) {
	l := New()
	l.SetCapturing(ToolScanner, false)
	l.Record(ToolScanner, "h", 80, false, "GET", "/", 200, nil, 1, "", nil)
	if l.Capturing(ToolScanner) || l.Uncaptured(ToolScanner) != 1 {
		t.Fatalf("after disable: capturing=%v uncaptured=%d, want false/1", l.Capturing(ToolScanner), l.Uncaptured(ToolScanner))
	}

	l.SetCapturing(ToolScanner, true)
	if !l.Capturing(ToolScanner) {
		t.Fatal("SetCapturing(scanner, true) did not re-enable capture")
	}
	if id := l.Record(ToolScanner, "h", 80, false, "GET", "/", 200, nil, 1, "", nil); id != 1 {
		t.Fatalf("re-enabled Record returned id %d, want 1", id)
	}
	if got := l.Uncaptured(ToolScanner); got != 1 {
		t.Fatalf("Uncaptured(ToolScanner) after re-enable = %d, want 1 (the earlier refusal survives)", got)
	}
}

// Test_uncaptured_counts_survive_clear but vanish on restore pins where the
// counter lives: clearing the buffer must not un-send traffic (so the count
// stays), while a persisted snapshot carries no such history (so Restore
// resets it). These are the same fact two ways.
func Test_clear_keeps_uncaptured_and_restore_resets_it(t *testing.T) {
	l := New()
	l.SetCapturing(ToolSession, false)
	l.Record(ToolSession, "h", 80, false, "GET", "/", 200, nil, 1, "", nil)
	l.Record(ToolSession, "h", 80, false, "GET", "/", 200, nil, 1, "", nil)

	l.Clear()
	if got := l.Uncaptured(ToolSession); got != 2 {
		t.Fatalf("Uncaptured(ToolSession) after Clear = %d, want 2 (clearing did not un-send)", got)
	}

	l.Restore([]*Entry{})
	if got := l.Uncaptured(ToolSession); got != 0 {
		t.Fatalf("Uncaptured(ToolSession) after Restore = %d, want 0 (snapshot carries no such history)", got)
	}
}

// Test_set_all_capturing_toggles_every_tool at once — the nuclear switch still
// has to be observable per-tool, and it must not corrupt the bitmask.
func Test_set_all_capturing_off_then_on_restores_every_tool(t *testing.T) {
	l := New()
	l.SetAllCapturing(false)
	for _, tool := range ToolAll {
		if l.Capturing(tool) {
			t.Fatalf("after SetAllCapturing(false) %s still captures", tool)
		}
		if id := l.Record(tool, "h", 80, false, "GET", "/", 200, nil, 1, "", nil); id != 0 {
			t.Fatalf("%s recorded id %d under all-off, want 0", tool, id)
		}
	}

	l.SetAllCapturing(true)
	for _, tool := range ToolAll {
		if !l.Capturing(tool) {
			t.Fatalf("after SetAllCapturing(true) %s does not capture", tool)
		}
	}
	// Every tool's refusal was counted.
	for _, tool := range ToolAll {
		if l.Uncaptured(tool) != 1 {
			t.Fatalf("Uncaptured(%s) = %d, want 1 from the all-off window", tool, l.Uncaptured(tool))
		}
	}
}

// Test_tool_from_name round-trips a wire name (as Tool.String produces) back to
// the ordinal, and refuses unknown names so a caller cannot silently mis-record
// under the wrong tool.
func Test_tool_from_name_round_trips(t *testing.T) {
	for _, tool := range ToolAll {
		if got, ok := ToolFromName(tool.String()); !ok || got != tool {
			t.Fatalf("ToolFromName(%q) = %v/%v, want %v/true", tool.String(), got, ok, tool)
		}
	}
	if _, ok := ToolFromName("bcheck"); ok {
		t.Fatal("ToolFromName(\"bcheck\") resolved, want false (no such tool)")
	}
}

// A row recorded with an exchange keeps the link, a row recorded without one
// has none, and the link is a copy: a caller reusing its pointer (a loop
// variable, a scratch field) must not be able to reach back into the log and
// change where a stored row points, for the same reason the response length is
// copied rather than aliased.
func Test_record_links_exchange_and_copies_it(t *testing.T) {
	l := New()

	id := core.ExchangeID(4)
	if got := l.Record(ToolRepeater, "h", 80, false, "GET", "/linked", 200, nil, 1, "", &id); got == 0 {
		t.Fatal("Record refused a capturing tool")
	}
	entries := l.All()
	if entries[0].Exchange == nil || *entries[0].Exchange != 4 {
		t.Fatalf("linked entry exchange = %v, want 4", entries[0].Exchange)
	}

	id = 99
	if *entries[0].Exchange == 99 {
		t.Fatal("entry aliases the caller's pointer; mutating it rewrote the logged link")
	}

	if got := l.Record(ToolScanner, "h", 80, false, "GET", "/bare", 200, nil, 1, "", nil); got == 0 {
		t.Fatal("Record refused a capturing tool")
	}
	if entries := l.All(); entries[1].Exchange != nil {
		t.Fatalf("unlinked entry exchange = %v, want nil", entries[1].Exchange)
	}
}

// The MIME capture filter refuses a row by the type that row actually carried.
//
// Burp's "Capture by MIME type" exists so a long engagement's log is not swamped by images and
// fonts. The filter is an EXCLUSION list, so an empty one captures everything — which is what the
// log did before this existed and what every caller that names no types still means.
//
// The distinction this pins is between the two kinds of "no type": a row recorded through Record,
// whose caller never measured one, must never be refused (nil), while a response that genuinely
// declared no usable Content-Type ("") is a measured fact that simply matches no pattern. Judging
// the first would silently drop rows from tools that have nothing to do with media types.
func TestTheMimeFilterRefusesARowByTheTypeItCarriedAndNeverJudgesAnUnmeasuredOne(t *testing.T) {
	l := New()
	if err := l.SetFilter(CaptureFilter{MIME: []string{"image/png"}}); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	png, html, none := "image/png", "text/html", ""

	if id := l.RecordMime(ToolProxy, "t.test", 80, false, "GET", "/logo.png", 200, nil, 0, "", nil, &png); id != 0 {
		t.Errorf("a row whose response was image/png was captured, so the exclusion did nothing and the log still fills with images")
	}
	if id := l.RecordMime(ToolProxy, "t.test", 80, false, "GET", "/index.html", 200, nil, 0, "", nil, &html); id == 0 {
		t.Errorf("a text/html row was refused by an image/png exclusion, so the filter is refusing types it was not asked to")
	}
	if id := l.RecordMime(ToolProxy, "t.test", 80, false, "GET", "/typeless", 200, nil, 0, "", nil, &none); id == 0 {
		t.Errorf("a response that declared no Content-Type was refused; \"\" matches no pattern and must be captured")
	}
	// Record's whole point: a caller with no media type to declare passes nil, and nil is never judged.
	if id := l.Record(ToolScanner, "t.test", 80, false, "GET", "/audit", 0, nil, 0, "audit", nil); id == 0 {
		t.Errorf("a row recorded without a measured media type was refused by a MIME exclusion; an unmeasured type is not a type, and judging it drops rows from tools that never had one")
	}
}
