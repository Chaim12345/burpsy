package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/toollog"
)

func ui2LoggerSeedRow(t *testing.T, s *Server, path string) uint64 {
	t.Helper()
	exID := seedUI2Exchange(t, s, "GET "+path+" HTTP/1.1\r\nHost: lg.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nlogged")
	n := 6
	return s.toolLog.Record(toollog.ToolRepeater, "lg.test", 443, true, "GET", path, 200, &n, 3, "", &exID)
}

func ui2HX(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func ui2LoggerComment(s *Server, id uint64) (string, string) {
	for _, e := range s.toolLog.All() {
		if e.ID == id {
			return e.Comment, e.Highlight
		}
	}
	return "<missing>", ""
}

// The detail pane shows the row, its row actions and the linked exchange's bytes.
func TestUI2LoggerEntryDetail(t *testing.T) {
	s := newTestServer()
	id := ui2LoggerSeedRow(t, s, "/detail?x=1")
	rec := ui2HX(t, s, "/ui2/logger/entry/"+strconv.FormatUint(id, 10))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "<!doctype") {
		t.Fatalf("detail = %d, want a fragment: %.200s", rec.Code, body)
	}
	for _, want := range []string{"https://lg.test/detail?x=1", "curl -i -X GET &#39;https://lg.test/detail?x=1&#39;", "Save annotation", "logged", "/ui2/history?q=host"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail lacks %q", want)
		}
	}
	// Negative control: an id the log does not hold says so instead of rendering a row.
	if gone := ui2HX(t, s, "/ui2/logger/entry/999").Body.String(); !strings.Contains(gone, "no longer in the log") {
		t.Errorf("unknown id did not say it is gone: %.200s", gone)
	}
}

// The view filters narrow the table; the method/status/tool axes are applied server-side.
func TestUI2LoggerViewFilters(t *testing.T) {
	s := newTestServer()
	ui2LoggerSeedRow(t, s, "/keep")
	s.toolLog.Record(toollog.ToolScanner, "other.test", 80, false, "POST", "/drop", 0, nil, 1, "", nil) // no response
	body := ui2HX(t, s, "/ui2/logger?v_tool=repeater&v_status=2").Body.String()
	if !strings.Contains(body, "/keep") || strings.Contains(body, "/drop") {
		t.Fatalf("tool+status filter did not narrow the rows")
	}
	if body := ui2HX(t, s, "/ui2/logger?v_status=0").Body.String(); !strings.Contains(body, "/drop") || strings.Contains(body, "/keep") {
		t.Fatalf("no-response filter did not keep only the row without a status")
	}
}

// CSV export carries every filtered row in toolLogToCSV's columns, with formula cells defused.
func TestUI2LoggerExportCSV(t *testing.T) {
	s := newTestServer()
	id := ui2LoggerSeedRow(t, s, "/csv")
	s.toolLog.SetComment(id, `=HYPERLINK("x")`)
	rec := getUI2(t, s, "/ui2/logger/export")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, `"ID","Timestamp","Tool","Host","Port","Method","Path","Status","Length","Duration","Comment"`) {
		t.Errorf("export header changed: %.120s", body)
	}
	if !strings.Contains(body, `"'=HYPERLINK(""x"")"`) || strings.Contains(body, `"=HYPERLINK`) {
		t.Errorf("formula cell not guarded: %s", body)
	}
	if empty := getUI2(t, s, "/ui2/logger/export?v_tool=scanner").Body.String(); strings.Contains(empty, "/csv") {
		t.Errorf("export ignored the view filter")
	}
}

// Annotation applies directly (PATCH /api/tools/log/{id} is riskLocal); a bad highlight is refused.
func TestUI2LoggerAnnotate(t *testing.T) {
	s := newTestServer()
	id := ui2LoggerSeedRow(t, s, "/note")
	sid := strconv.FormatUint(id, 10)
	rec := ui2LoggerAction(t, s, "annotate", "id="+sid+"&comment=look+here&highlight=red")
	if c, h := ui2LoggerComment(s, id); c != "look here" || h != "red" {
		t.Fatalf("annotation not saved: %q %q (%d)", c, h, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "annotation saved") {
		t.Errorf("no outcome note")
	}
	rec = ui2LoggerAction(t, s, "annotate", "id="+sid+"&comment=changed&highlight=chartreuse")
	if c, _ := ui2LoggerComment(s, id); c != "look here" {
		t.Fatalf("refused annotation still changed the comment to %q", c)
	}
	if !strings.Contains(rec.Body.String(), "Not applied") {
		t.Errorf("refusal not rendered")
	}
}

// Clearing the log is a reviewed spend: the review clears nothing, the run without a token is
// refused, the run with the token clears.
func TestUI2LoggerClearReviewed(t *testing.T) {
	s := newTestServer()
	ui2LoggerSeedRow(t, s, "/clear")
	token, sheet := ui2LoggerReview(t, s, "clear-review", "")
	if len(s.toolLog.All()) != 1 || !strings.Contains(sheet, "DELETE /api/tools/log") {
		t.Fatalf("review mutated the log or did not name the call")
	}
	ui2LoggerAction(t, s, "clear-run", "")
	if len(s.toolLog.All()) != 1 {
		t.Fatalf("clear-run without a token cleared the log")
	}
	rec := ui2LoggerAction(t, s, "clear-run", "token="+token)
	if len(s.toolLog.All()) != 0 || !strings.Contains(rec.Body.String(), "tool log cleared") {
		t.Fatalf("reviewed clear did not clear: %.300s", rec.Body.String())
	}
}

// Add-to-scope derives the rule from the row on the server and spends a reviewed token.
func TestUI2LoggerScopeReviewed(t *testing.T) {
	s := newTestServer()
	id := strconv.FormatUint(ui2LoggerSeedRow(t, s, "/scope"), 10)
	token, sheet := ui2LoggerReview(t, s, "scope-review", "id="+id)
	if !strings.Contains(sheet, "lg.test") {
		t.Fatalf("review does not name the host")
	}
	ui2LoggerAction(t, s, "scope-run", "id="+id)
	if inc := scopeKinds(t, get(t, s, "/api/scope"))["include"]; len(inc) != 0 {
		t.Fatalf("scope-run without a token changed scope: %v", inc)
	}
	ui2LoggerAction(t, s, "scope-run", "id="+id+"&token="+token)
	if inc := scopeKinds(t, get(t, s, "/api/scope"))["include"]; len(inc) != 1 || inc[0] != "lg.test" {
		t.Fatalf("reviewed add-to-scope did not add lg.test: %v", inc)
	}
}

// The row limit rides the capture-settings review; a non-number is refused before minting.
func TestUI2LoggerCapacityReviewed(t *testing.T) {
	s := newTestServer()
	if rec := ui2LoggerAction(t, s, "filter-set", "capacity=abc"); strings.Contains(rec.Body.String(), `name="token"`) {
		t.Fatalf("an invalid row limit minted a review")
	}
	token, sheet := ui2LoggerReview(t, s, "filter-set", "capacity=7")
	if !strings.Contains(sheet, "&#34;capacity&#34;:7") || s.toolLog.Capacity() == 7 {
		t.Fatalf("review did not bind the capacity, or applied it early")
	}
	ui2LoggerAction(t, s, "filter-run", "token="+token+"&capacity=7")
	if s.toolLog.Capacity() != 7 {
		t.Fatalf("reviewed capacity not applied: %d", s.toolLog.Capacity())
	}
}
