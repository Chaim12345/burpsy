package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/toollog"
)

// The Logger infinite-scroll sentinel hx-gets /ui2/logger?offset=N and swaps the
// answer with beforeend into the tbody. The answer must be a rows-only fragment:
// returning the full page would paste the capture panel, filter block and table
// header into the middle of the list on every appended page.
func TestUI2LoggerAppendFragmentIsRowsOnly(t *testing.T) {
	s := newTestServer()
	for i := range 30 {
		s.toolLog.Record(toollog.ToolProxy, "h.test", 80, false, "GET", fmt.Sprintf("/log/%d", i), 404, toollog.Bytes(10), 1, "", nil)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui2/logger?limit=10&offset=10", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("append = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<!doctype") || strings.Contains(body, "<thead") || strings.Contains(body, `id="capture"`) {
		t.Errorf("append fragment carries the page chrome (doctype/thead/capture panel), want rows only")
	}
	if got := strings.Count(body, "<tr><td>"); got != 10 {
		t.Errorf("append carried %d entry rows, want 10", got)
	}
	if !strings.Contains(body, `class="sentinel-row"`) || !strings.Contains(body, `"offset": 20`) {
		t.Errorf("append must carry the next sentinel pointing at offset 20")
	}

	// Last page: offset=20 limit=10 -> 10 rows, no sentinel.
	req = httptest.NewRequest(http.MethodGet, "/ui2/logger?limit=10&offset=20", nil)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body = rec.Body.String()
	if got := strings.Count(body, "<tr><td>"); got != 10 {
		t.Errorf("last page carried %d entry rows, want 10", got)
	}
	if strings.Contains(body, "sentinel-row") {
		t.Errorf("last page must not carry a sentinel")
	}

	// offset=0 still renders the full page with its header and capture panel.
	rec = getUI2(t, s, "/ui2/logger?limit=10")
	body = rec.Body.String()
	if !strings.Contains(body, "<thead") {
		t.Errorf("full logger page lost its table header")
	}
}
