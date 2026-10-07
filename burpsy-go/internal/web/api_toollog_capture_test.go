package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/toollog"
)

func jsonBody(t *testing.T, body any) *strings.Reader {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.NewReader(string(raw))
}

func httptestRec(t *testing.T, s *Server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

type toolLogCaptureView struct {
	FilteredTotal uint64 `json:"filtered_total"`
	Capacity      int    `json:"capacity"`
	ScopeAttached bool   `json:"scope_attached"`
	Filter        struct {
		Status    []int  `json:"status"`
		Term      string `json:"term"`
		Regex     bool   `json:"regex"`
		Case      bool   `json:"case_sensitive"`
		Negate    bool   `json:"negate"`
		ScopeOnly bool   `json:"scope_only"`
	} `json:"filter"`
}

// The capture filter round-trips through one endpoint and actually filters.
func TestToolLogCaptureFilterRoundTrip(t *testing.T) {
	s := newTestServer()
	// The filter is capture-time: set it before recording, the way the page does.
	body := map[string]any{
		"filter": map[string]any{"status": []int{2}},
	}
	if rec := postJSON(t, s, "/api/tools/log", body); rec.Code != http.StatusOK {
		t.Fatalf("POST filter: status = %d (%s)", rec.Code, rec.Body.String())
	}
	s.toolLog.Record(toollog.ToolRepeater, "shop.test", 80, false, "GET", "/cart", 200, toollog.Bytes(10), 1, "", nil)
	s.toolLog.Record(toollog.ToolRepeater, "shop.test", 80, false, "GET", "/old", 404, toollog.Bytes(10), 1, "", nil)
	rec := get(t, s, "/api/tools/log")
	var got toolLogCaptureView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	if len(got.Filter.Status) != 1 || got.Filter.Status[0] != 2 {
		t.Errorf("filter echo = %+v, want status [2]", got.Filter)
	}
	var total struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &total); err != nil {
		t.Fatalf("decode total: %v", err)
	}
	if total.Total != 1 {
		t.Errorf("total = %d, want only the 2xx row surviving capture", total.Total)
	}
}

// A bad regex is refused with the previous filter still in force.
func TestToolLogCaptureFilterRefusesBadRegex(t *testing.T) {
	s := newTestServer()
	bad := map[string]any{
		"filter": map[string]any{"term": "([unclosed", "regex": true},
	}
	if rec := postJSON(t, s, "/api/tools/log", bad); rec.Code != http.StatusBadRequest {
		t.Errorf("POST bad regex: status = %d, want 400", rec.Code)
	}
}

// Capacity round-trips, and non-positive is refused.
func TestToolLogCapacityRoundTrip(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/tools/log", map[string]any{"capacity": 50}); rec.Code != http.StatusOK {
		t.Fatalf("POST capacity: status = %d (%s)", rec.Code, rec.Body.String())
	}
	rec := get(t, s, "/api/tools/log")
	var got toolLogCaptureView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Capacity != 50 {
		t.Errorf("capacity = %d, want 50", got.Capacity)
	}
	if rec := postJSON(t, s, "/api/tools/log", map[string]any{"capacity": 0}); rec.Code != http.StatusBadRequest {
		t.Errorf("POST capacity 0: status = %d, want 400", rec.Code)
	}
}

// The filter echo is wire shape: status must be an array even on a fresh server where no
// capture filter was ever set — a nil slice marshals as null and clients reading
// filter.status.length crash on first paint.
func TestToolLogFilterEchoStatusIsArrayOnFreshServer(t *testing.T) {
	s := newTestServer()
	var body struct {
		Filter struct {
			Status []int `json:"status"`
		} `json:"filter"`
	}
	if err := json.Unmarshal(get(t, s, "/api/tools/log").Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Filter.Status == nil {
		t.Error("filter.status is null; wire shape promises an array")
	}
	if len(body.Filter.Status) != 0 {
		t.Errorf("filter.status = %v on a fresh server, want empty", body.Filter.Status)
	}
}

// A comment sticks to its entry and survives the projection; unknown ids 404.
func TestToolLogCommentRoundTrip(t *testing.T) {
	s := newTestServer()
	id := s.toolLog.Record(toollog.ToolRepeater, "a.test", 80, false, "GET", "/", 200, toollog.Bytes(1), 1, "", nil)
	req, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id), jsonBody(t, map[string]any{"comment": "look again"}))
	rec := httptestRec(t, s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH comment: status = %d (%s)", rec.Code, rec.Body.String())
	}
	rec = get(t, s, "/api/tools/log")
	var body struct {
		Entries []struct {
			Comment string `json:"comment"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Entries) != 1 || body.Entries[0].Comment != "look again" {
		t.Errorf("entries = %+v, want the comment on the row", body.Entries)
	}

	req, _ = http.NewRequest(http.MethodPatch, "/api/tools/log/99999", jsonBody(t, map[string]any{"comment": "x"}))
	if rec := httptestRec(t, s, req); rec.Code != http.StatusNotFound {
		t.Errorf("PATCH unknown id: status = %d, want 404", rec.Code)
	}
}

// The highlight sticks, round-trips through the wire, and an unknown colour is a 400 naming the
// vocabulary rather than a silently-coerced empty string.
func TestToolLogHighlightRoundTripAndValidation(t *testing.T) {
	s := newTestServer()
	id := s.toolLog.Record(toollog.ToolRepeater, "a.test", 80, false, "GET", "/", 200, toollog.Bytes(1), 1, "", nil)
	req, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id), jsonBody(t, map[string]any{"comment": "", "highlight": "yellow"}))
	if rec := httptestRec(t, s, req); rec.Code != http.StatusOK {
		t.Fatalf("PATCH highlight: status = %d (%s)", rec.Code, rec.Body.String())
	}
	rec := get(t, s, "/api/tools/log")
	var body struct {
		Entries []struct {
			Highlight string `json:"highlight"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Entries) != 1 || body.Entries[0].Highlight != "yellow" {
		t.Errorf("entries = %+v, want highlight yellow on the row", body.Entries)
	}

	req, _ = http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id), jsonBody(t, map[string]any{"highlight": "crimson"}))
	if rec := httptestRec(t, s, req); rec.Code != http.StatusBadRequest {
		t.Errorf("PATCH invalid highlight: status = %d, want 400", rec.Code)
	}
}

// burpsy-react-ui-iyb6: Comment and Highlight used to be plain strings, so an absent JSON key
// decoded to "" and was written unconditionally — a comment-only PATCH cleared whatever highlight
// the row already carried, and a highlight-only PATCH cleared any comment. This pins both
// directions, plus the two edge cases the pointer rewrite has to get right: an empty patch body
// still 404s on an unknown id and is a no-op success on a known one.
func TestToolLogPatchLeavesTheOmittedAxisAlone(t *testing.T) {
	s := newTestServer()
	id := s.toolLog.Record(toollog.ToolRepeater, "a.test", 80, false, "GET", "/", 200, toollog.Bytes(1), 1, "", nil)

	// Seed both axes, then patch comment alone: highlight must survive.
	seed, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id),
		jsonBody(t, map[string]any{"comment": "first", "highlight": "red"}))
	if rec := httptestRec(t, s, seed); rec.Code != http.StatusOK {
		t.Fatalf("seed PATCH: status = %d (%s)", rec.Code, rec.Body.String())
	}
	commentOnly, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id),
		jsonBody(t, map[string]any{"comment": "second"}))
	if rec := httptestRec(t, s, commentOnly); rec.Code != http.StatusOK {
		t.Fatalf("comment-only PATCH: status = %d (%s)", rec.Code, rec.Body.String())
	}

	entry := toolLogEntryByID(t, s, id)
	if entry.Comment != "second" {
		t.Errorf("comment = %q, want the new comment applied", entry.Comment)
	}
	if entry.Highlight != "red" {
		t.Errorf("highlight = %q, want the seeded highlight to survive a comment-only PATCH", entry.Highlight)
	}

	// Now patch highlight alone: comment must survive in the other direction.
	highlightOnly, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id),
		jsonBody(t, map[string]any{"highlight": "blue"}))
	if rec := httptestRec(t, s, highlightOnly); rec.Code != http.StatusOK {
		t.Fatalf("highlight-only PATCH: status = %d (%s)", rec.Code, rec.Body.String())
	}
	entry = toolLogEntryByID(t, s, id)
	if entry.Highlight != "blue" {
		t.Errorf("highlight = %q, want the new highlight applied", entry.Highlight)
	}
	if entry.Comment != "second" {
		t.Errorf("comment = %q, want the prior comment to survive a highlight-only PATCH", entry.Comment)
	}

	// An empty body on a known id changes nothing and still succeeds.
	empty, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/"+itoa(id), jsonBody(t, map[string]any{}))
	if rec := httptestRec(t, s, empty); rec.Code != http.StatusOK {
		t.Fatalf("empty PATCH on a known id: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	entry = toolLogEntryByID(t, s, id)
	if entry.Comment != "second" || entry.Highlight != "blue" {
		t.Errorf("entry = %+v, want an empty PATCH to change nothing", entry)
	}

	// An empty body on an unknown id still 404s: "nothing to change" must not read as "found".
	emptyMissing, _ := http.NewRequest(http.MethodPatch, "/api/tools/log/99999", jsonBody(t, map[string]any{}))
	if rec := httptestRec(t, s, emptyMissing); rec.Code != http.StatusNotFound {
		t.Errorf("empty PATCH on an unknown id: status = %d, want 404", rec.Code)
	}
}

// toolLogEntryByID fetches one row's comment/highlight off the wire, the same projection every
// consumer of /api/tools/log reads — asserting against the handler's own struct fields would prove
// nothing about what a caller actually receives.
func toolLogEntryByID(t *testing.T, s *Server, id uint64) struct {
	Comment   string `json:"comment"`
	Highlight string `json:"highlight"`
} {
	t.Helper()
	rec := get(t, s, "/api/tools/log")
	var body struct {
		Entries []struct {
			ID        uint64 `json:"id"`
			Comment   string `json:"comment"`
			Highlight string `json:"highlight"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, e := range body.Entries {
		if e.ID == id {
			return struct {
				Comment   string `json:"comment"`
				Highlight string `json:"highlight"`
			}{Comment: e.Comment, Highlight: e.Highlight}
		}
	}
	t.Fatalf("no entry with id %d in /api/tools/log", id)
	return struct {
		Comment   string `json:"comment"`
		Highlight string `json:"highlight"`
	}{}
}
