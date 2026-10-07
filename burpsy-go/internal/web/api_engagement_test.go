package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's site-map engagement searches (burpsy-react-ui-1s07): Find comments, Find scripts
// and Find references. These pin that each kind finds what it claims over real stored
// responses, that the reference search is anchored to the URL the operator typed rather than
// matching every attribute on the page, and that a page's own attributes are not confused
// between the kinds.

// engagementSeed records one exchange whose response is an HTML page carrying one comment,
// one external script, and two links — so each search has exactly one honest hit to find.
func engagementSeed(t *testing.T, s *Server) *core.Exchange {
	t.Helper()
	page := "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<html><body>" +
		"<!-- admin debug hint: remove before launch -->" +
		"<script src=\"/static/app.js\"></script>" +
		"<a href=\"https://shop.test/checkout\">checkout</a>" +
		"<a href=\"/help\">help</a>" +
		"</body></html>"
	reqID, err := s.store.Put([]byte("GET /page HTTP/1.1\r\nHost: shop.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte(page), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request:  core.MsgPtr(reqID),
		Response: &respID,
		Host:     "shop.test",
		Port:     80,
		Method:   "GET",
		Path:     "/page",
		Status:   &status,
	}
	s.store.AddExchange(ex)
	return ex
}

func engagementGet(t *testing.T, s *Server, path string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d (%s)", path, rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return body
}

func engagementRows(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, ok := body["rows"].([]any)
	if !ok {
		t.Fatalf("rows missing or wrong shape: %v", body)
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		row := r.(map[string]any)
		out = append(out, row["snippet"].(string))
	}
	return out
}

func TestFindCommentsReportsHTMLCommentsWithTheirText(t *testing.T) {
	s := newTestServer()
	engagementSeed(t, s)

	body := engagementGet(t, s, "/api/engagement/comments")
	rows := engagementRows(t, body)
	if len(rows) != 1 {
		t.Fatalf("comments rows = %v, want exactly one", rows)
	}
	if !strings.Contains(rows[0], "admin debug hint") {
		t.Errorf("comment row %q does not carry the comment's text", rows[0])
	}
}

func TestFindScriptsReportsScriptSourcesAndNotOtherAttributes(t *testing.T) {
	s := newTestServer()
	engagementSeed(t, s)

	rows := engagementRows(t, engagementGet(t, s, "/api/engagement/scripts"))
	if len(rows) != 1 {
		t.Fatalf("scripts rows = %v, want exactly the one script src", rows)
	}
	if !strings.Contains(rows[0], "/static/app.js") {
		t.Errorf("script row %q does not carry the src", rows[0])
	}
}

func TestFindReferencesMatchesOnlyTheURLTheOperatorNamed(t *testing.T) {
	s := newTestServer()
	engagementSeed(t, s)

	rows := engagementRows(t, engagementGet(t, s, "/api/engagement/references?q=https://shop.test/checkout"))
	if len(rows) != 1 {
		t.Fatalf("reference rows = %v, want exactly the checkout link", rows)
	}
	if !strings.Contains(rows[0], "/checkout") {
		t.Errorf("reference row %q does not carry the target", rows[0])
	}
}

func TestFindReferencesWithoutATargetIsRefusedNotEmptied(t *testing.T) {
	s := newTestServer()
	engagementSeed(t, s)

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/engagement/references", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("references without q = %d (%s), want 400 — an empty result would read as searched-and-clean",
			rec.Code, rec.Body.String())
	}
}

func TestEngagementUnknownKindIsANamedRefusal(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/engagement/tokens", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown kind = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "comments") {
		t.Errorf("refusal %q does not name the valid kinds", rec.Body.String())
	}
}
