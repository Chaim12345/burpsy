package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// fxxm batch 8: /api/intercept/, /api/intercept/rules/, /api/tools/organizer/ and
// /api/tools/organizer/collections/ moved to remainder keys. Every row below was captured on the
// pre-change tree (backlog-b9 1fbcc5e2) and must pass there too: status, redirect target, Allow and
// the first 200 bytes of the body are an observable contract, including the encoded-slash and
// nested shapes.
func TestSubtreeRemainderShapesBatch8KeepTheirOldAnswers(t *testing.T) {
	s := newTestServer()
	cases := []struct {
		method, path string
		code         int
		loc, allow   string
		body         string
	}{
		{"GET", "/api/intercept", 200, "", "", "{\"enabled\":false,\"wired\":true,\"pending\":0,\"held\":[],\"holds_every_request\":false,\"holds_every_response\":false,\"in_scope_only\":false,\"scope_attached\":true}\n"},
		{"GET", "/api/intercept/", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/a", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/a/b/c", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/1", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/1/forward", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/1/drop", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/1/x", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/%2F", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/1%2Fforward", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/intercept/rules", 307, "/api/intercept/rules/", "", "<a href=\"/api/intercept/rules/\">Temporary Redirect</a>.\n\n"},
		{"GET", "/api/intercept/rules/", 404, "", "", "Unknown direction\n"},
		{"GET", "/api/intercept/rules/a", 404, "", "", "Unknown direction\n"},
		{"GET", "/api/intercept/rules/a/b", 404, "", "", "Unknown direction\n"},
		{"GET", "/api/intercept/rules/requests", 200, "", "", "{\"wired\":true,\"active\":false,\"unconditional\":false,\"count\":0,\"rules\":[]}\n"},
		{"GET", "/api/intercept/rules/requests/", 200, "", "", "{\"wired\":true,\"active\":false,\"unconditional\":false,\"count\":0,\"rules\":[]}\n"},
		{"GET", "/api/intercept/rules/responses", 200, "", "", "{\"wired\":true,\"active\":false,\"unconditional\":false,\"count\":0,\"rules\":[]}\n"},
		{"GET", "/api/tools/organizer", 200, "", "", "{\"collections\":[],\"items\":[]}\n"},
		{"GET", "/api/tools/organizer/", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/a/b", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/1", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/1/", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/1/status", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/1/status/x", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/a%2Fb", 405, "", "POST, PUT, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections", 405, "", "POST", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections/", 405, "", "PUT, POST, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections/a/b/c", 405, "", "PUT, POST, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections/1", 405, "", "PUT, POST, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections/inbox/items", 405, "", "PUT, POST, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections/1/items", 405, "", "PUT, POST, DELETE", "Method not allowed\n"},
		{"GET", "/api/tools/organizer/collections/1/duplicate", 405, "", "PUT, POST, DELETE", "Method not allowed\n"},
		{"POST", "/api/intercept", 405, "", "GET", "Method not allowed\n"},
		{"POST", "/api/intercept/", 400, "", "", "Usage: /api/intercept/{id}/forward|drop\n"},
		{"POST", "/api/intercept/a", 400, "", "", "Usage: /api/intercept/{id}/forward|drop\n"},
		{"POST", "/api/intercept/a/b/c", 400, "", "", "Invalid held message id\n"},
		{"POST", "/api/intercept/1", 400, "", "", "Usage: /api/intercept/{id}/forward|drop\n"},
		{"POST", "/api/intercept/1/forward", 404, "", "", "no held message 1\n"},
		{"POST", "/api/intercept/1/drop", 404, "", "", "no held message 1\n"},
		{"POST", "/api/intercept/1/x", 404, "", "", "Unknown action\n"},
		{"POST", "/api/intercept/%2F", 400, "", "", "Usage: /api/intercept/{id}/forward|drop\n"},
		{"POST", "/api/intercept/1%2Fforward", 404, "", "", "no held message 1\n"},
		{"POST", "/api/intercept/rules", 307, "/api/intercept/rules/", "", ""},
		{"POST", "/api/intercept/rules/", 405, "", "GET, PUT", "Method not allowed\n"},
		{"POST", "/api/intercept/rules/a", 405, "", "GET, PUT", "Method not allowed\n"},
		{"POST", "/api/intercept/rules/a/b", 405, "", "GET, PUT", "Method not allowed\n"},
		{"POST", "/api/intercept/rules/requests", 405, "", "GET, PUT", "Method not allowed\n"},
		{"POST", "/api/intercept/rules/requests/", 405, "", "GET, PUT", "Method not allowed\n"},
		{"POST", "/api/intercept/rules/responses", 405, "", "GET, PUT", "Method not allowed\n"},
		{"POST", "/api/tools/organizer", 404, "", "", "No exchange 0 has been captured\n"},
		{"POST", "/api/tools/organizer/", 400, "", "", "Invalid item id\n"},
		{"POST", "/api/tools/organizer/a/b", 400, "", "", "Invalid item id\n"},
		{"POST", "/api/tools/organizer/1", 404, "", "", "Item not found\n"},
		{"POST", "/api/tools/organizer/1/", 404, "", "", "Item not found\n"},
		{"POST", "/api/tools/organizer/1/status", 405, "", "PUT", "Method not allowed\n"},
		{"POST", "/api/tools/organizer/1/status/x", 400, "", "", "Invalid item id\n"},
		{"POST", "/api/tools/organizer/a%2Fb", 400, "", "", "Invalid item id\n"},
		{"POST", "/api/tools/organizer/collections", 400, "", "", "A collection needs a name\n"},
		{"POST", "/api/tools/organizer/collections/", 400, "", "", "A collection needs a name\n"},
		{"POST", "/api/tools/organizer/collections/a/b/c", 400, "", "", "Invalid collection id\n"},
		{"POST", "/api/tools/organizer/collections/1", 405, "", "", "Method not allowed\n"},
		{"POST", "/api/tools/organizer/collections/inbox/items", 400, "", "", "Invalid collection id\n"},
		{"POST", "/api/tools/organizer/collections/1/items", 405, "", "", "Method not allowed\n"},
		{"POST", "/api/tools/organizer/collections/1/duplicate", 404, "", "", "Collection not found\n"},
		{"PUT", "/api/intercept", 405, "", "GET", "Method not allowed\n"},
		{"PUT", "/api/intercept/", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/a", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/a/b/c", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/1", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/1/forward", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/1/drop", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/1/x", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/%2F", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/1%2Fforward", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/intercept/rules", 307, "/api/intercept/rules/", "", ""},
		{"PUT", "/api/intercept/rules/", 404, "", "", "Unknown direction\n"},
		{"PUT", "/api/intercept/rules/a", 404, "", "", "Unknown direction\n"},
		{"PUT", "/api/intercept/rules/a/b", 404, "", "", "Unknown direction\n"},
		{"PUT", "/api/intercept/rules/requests", 200, "", "", "{\"wired\":true,\"active\":false,\"unconditional\":false,\"count\":0,\"rules\":[]}\n"},
		{"PUT", "/api/intercept/rules/requests/", 200, "", "", "{\"wired\":true,\"active\":false,\"unconditional\":false,\"count\":0,\"rules\":[]}\n"},
		{"PUT", "/api/intercept/rules/responses", 200, "", "", "{\"wired\":true,\"active\":false,\"unconditional\":false,\"count\":0,\"rules\":[]}\n"},
		{"PUT", "/api/tools/organizer", 405, "", "GET, POST", "Method not allowed\n"},
		{"PUT", "/api/tools/organizer/", 400, "", "", "Invalid item id\n"},
		{"PUT", "/api/tools/organizer/a/b", 400, "", "", "Invalid item id\n"},
		{"PUT", "/api/tools/organizer/1", 405, "", "", "Method not allowed\n"},
		{"PUT", "/api/tools/organizer/1/", 405, "", "", "Method not allowed\n"},
		{"PUT", "/api/tools/organizer/1/status", 400, "", "", "Unknown status \"\"; the valid statuses are new, in_progress, postponed, done, ignored\n"},
		{"PUT", "/api/tools/organizer/1/status/x", 400, "", "", "Invalid item id\n"},
		{"PUT", "/api/tools/organizer/a%2Fb", 400, "", "", "Invalid item id\n"},
		{"PUT", "/api/tools/organizer/collections", 405, "", "POST", "Method not allowed\n"},
		{"PUT", "/api/tools/organizer/collections/", 405, "", "", "Method not allowed\n"},
		{"PUT", "/api/tools/organizer/collections/a/b/c", 400, "", "", "Invalid collection id\n"},
		{"PUT", "/api/tools/organizer/collections/1", 200, "", "", ""},
		{"PUT", "/api/tools/organizer/collections/inbox/items", 400, "", "", "Invalid collection id\n"},
		{"PUT", "/api/tools/organizer/collections/1/items", 404, "", "", "Collection not found\n"},
		{"PUT", "/api/tools/organizer/collections/1/duplicate", 405, "", "", "Method not allowed\n"},
		{"DELETE", "/api/intercept", 405, "", "GET", "Method not allowed\n"},
		{"DELETE", "/api/intercept/", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/a", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/a/b/c", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/1", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/1/forward", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/1/drop", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/1/x", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/%2F", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/1%2Fforward", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/intercept/rules", 307, "/api/intercept/rules/", "", ""},
		{"DELETE", "/api/intercept/rules/", 405, "", "GET, PUT", "Method not allowed\n"},
		{"DELETE", "/api/intercept/rules/a", 405, "", "GET, PUT", "Method not allowed\n"},
		{"DELETE", "/api/intercept/rules/a/b", 405, "", "GET, PUT", "Method not allowed\n"},
		{"DELETE", "/api/intercept/rules/requests", 405, "", "GET, PUT", "Method not allowed\n"},
		{"DELETE", "/api/intercept/rules/requests/", 405, "", "GET, PUT", "Method not allowed\n"},
		{"DELETE", "/api/intercept/rules/responses", 405, "", "GET, PUT", "Method not allowed\n"},
		{"DELETE", "/api/tools/organizer", 405, "", "GET, POST", "Method not allowed\n"},
		{"DELETE", "/api/tools/organizer/", 400, "", "", "Invalid item id\n"},
		{"DELETE", "/api/tools/organizer/a/b", 400, "", "", "Invalid item id\n"},
		{"DELETE", "/api/tools/organizer/1", 404, "", "", "Item not found\n"},
		{"DELETE", "/api/tools/organizer/1/", 404, "", "", "Item not found\n"},
		{"DELETE", "/api/tools/organizer/1/status", 405, "", "PUT", "Method not allowed\n"},
		{"DELETE", "/api/tools/organizer/1/status/x", 400, "", "", "Invalid item id\n"},
		{"DELETE", "/api/tools/organizer/a%2Fb", 400, "", "", "Invalid item id\n"},
		{"DELETE", "/api/tools/organizer/collections", 405, "", "POST", "Method not allowed\n"},
		{"DELETE", "/api/tools/organizer/collections/", 405, "", "", "Method not allowed\n"},
		{"DELETE", "/api/tools/organizer/collections/a/b/c", 400, "", "", "Invalid collection id\n"},
		{"DELETE", "/api/tools/organizer/collections/1", 404, "", "", "Collection not found\n"},
		{"DELETE", "/api/tools/organizer/collections/inbox/items", 400, "", "", "Invalid collection id\n"},
		{"DELETE", "/api/tools/organizer/collections/1/items", 405, "", "", "Method not allowed\n"},
		{"DELETE", "/api/tools/organizer/collections/1/duplicate", 405, "", "", "Method not allowed\n"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		req.Host = "127.0.0.1:8081"
		s.mux.ServeHTTP(rec, req)
		b := rec.Body.String()
		if len(b) > 200 {
			b = b[:200]
		}
		if rec.Code != c.code || rec.Header().Get("Location") != c.loc || rec.Header().Get("Allow") != c.allow || b != c.body {
			t.Errorf("%s %s = %d loc=%q allow=%q body=%q; want %d loc=%q allow=%q body=%q", c.method, c.path, rec.Code, rec.Header().Get("Location"), rec.Header().Get("Allow"), b, c.code, c.loc, c.allow, c.body)
		}
	}
}

// The published OpenAPI document names the concrete shapes callers send, never a remainder
// wildcard: rekeying a route to "{rest...}" must not rewrite its published contract.
func TestOpenAPIPublishesNoRemainderSpelling(t *testing.T) {
	for path := range openAPIDocument()["paths"].(map[string]any) {
		if strings.Contains(path, "...}") {
			t.Errorf("published path %q carries a remainder wildcard", path)
		}
	}
}
