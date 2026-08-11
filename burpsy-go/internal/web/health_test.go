package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpointsReportReady(t *testing.T) {
	s := newTestServer()

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", path, rec.Code)
		}
		if got := rec.Body.String(); got != "ok\n" {
			t.Fatalf("GET %s: body = %q, want %q", path, got, "ok\\n")
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("GET %s: content type = %q", path, got)
		}
	}
}

func TestHealthEndpointSupportsHeadAndRejectsWrites(t *testing.T) {
	s := newTestServer()

	headReq := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	headRec := httptest.NewRecorder()
	s.mux.ServeHTTP(headRec, headReq)
	if headRec.Code != http.StatusOK || headRec.Body.Len() != 0 {
		t.Fatalf("HEAD /healthz: status=%d body=%q, want 200 and empty body", headRec.Code, headRec.Body.String())
	}

	postReq := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	postRec := httptest.NewRecorder()
	s.mux.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz: status = %d, want 405", postRec.Code)
	}
	if got := postRec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("POST /healthz: Allow = %q, want %q", got, "GET, HEAD")
	}
}
