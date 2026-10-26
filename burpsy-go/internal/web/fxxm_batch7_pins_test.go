package web

import (
	"net/http/httptest"
	"testing"
)

// fxxm batch 7: /api/report/, /api/datasets/ and /api/sequencer/capture/ moved to {rest...}
// remainder keys. These pins were captured on the pre-change tree (backlog-b9 383c6f36) and must
// pass there too: status, Allow and body of the subtree shapes are an observable contract.
func TestSubtreeRemainderShapesKeepTheirOldAnswers(t *testing.T) {
	s := newTestServer()
	cases := []struct {
		method, path string
		code         int
		allow, body  string
	}{
		{"GET", "/api/report/a/b", 404, "", "404 page not found\n"},
		{"GET", "/api/report/nosuch", 404, "", "404 page not found\n"},
		{"POST", "/api/report/a/b", 405, "GET", "Method not allowed\n"},
		{"POST", "/api/report/nosuch", 405, "GET", "Method not allowed\n"},
		{"GET", "/api/datasets/a/b", 404, "", "no dataset named \"a\"; GET /api/datasets/ lists them\n"},
		{"POST", "/api/datasets/a/b", 405, "GET", "Method not allowed\n"},
		{"GET", "/api/sequencer/capture/a/b", 400, "", "Invalid capture id\n"},
		{"POST", "/api/sequencer/capture/a/b", 405, "", "Method not allowed\n"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.code || rec.Header().Get("Allow") != c.allow || rec.Body.String() != c.body {
			t.Errorf("%s %s = %d allow=%q body=%q; want %d allow=%q body=%q", c.method, c.path, rec.Code, rec.Header().Get("Allow"), rec.Body.String(), c.code, c.allow, c.body)
		}
	}
}
