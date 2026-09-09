package web

// DELETE /api/sitemap (burpsy-react-ui-10e): the suppression endpoint. These tests drive the HTTP
// surface, so what is pinned is what a caller sees: the refusals are named 400s rather than silent
// successes, a valid call removes the branch from the next GET, and the store the operator's other
// tools read is untouched — the recorded decision that makes suppression different from deletion.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sitemapDelete(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/sitemap", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestSitemapDeleteSuppressesABranchFromTheViewNotTheStore(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "h", "GET", "/api/data")
	addTraffic(t, s.store, "h", "GET", "/apiary")

	rec := sitemapDelete(t, s, `{"host":"h","port":80,"tls":false,"path":"/api","kind":"branch"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/sitemap: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	tree := sitemapTreeRaw(t, s)
	joined, _ := json.Marshal(tree)
	if strings.Contains(string(joined), "/api/data") {
		t.Fatalf("the suppressed branch is still in the tree: %s", joined)
	}
	if !strings.Contains(string(joined), "/apiary") {
		t.Fatalf("/apiary vanished with the /api branch — the wire layer's suppression lost the item/branch distinction: %s", joined)
	}
	// The recorded decision, checked from the outside: the capture rows survive a suppressed map.
	if _, exchanges := s.store.Count(); exchanges != 2 {
		t.Fatalf("store holds %d exchanges after a map suppression, want 2 — the view delete touched the capture", exchanges)
	}
}

func TestSitemapDeleteRefusesBodiesThatNameNothing(t *testing.T) {
	s := newTestServer()

	// No host: the call names nothing, so success would be a lie about what was removed.
	if rec := sitemapDelete(t, s, `{"path":"/api","kind":"branch"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a body with no host answered %d, want 400", rec.Code)
	}
	// A path without a verb: "delete /api" is not a sentence until item or branch is chosen, and
	// guessing one would act on a decision the caller never made.
	if rec := sitemapDelete(t, s, `{"host":"h","port":80,"tls":false,"path":"/api"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a path with no kind answered %d, want 400", rec.Code)
	}
	// Not JSON at all.
	if rec := sitemapDelete(t, s, `not-json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a non-JSON body answered %d, want 400", rec.Code)
	}
}
