package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUIAssetsAreCompressedAndRevalidated(t *testing.T) {
	for _, path := range []string{"/", "/app.js", "/style.css", "/issues.worker.js"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		uiHandler(rec, req)
		res := rec.Result()
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("%s: status %d encoding %q", path, res.StatusCode, res.Header.Get("Content-Encoding"))
		}
		zr, err := gzip.NewReader(res.Body)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(zr)
		if len(body) == 0 {
			t.Fatalf("%s: empty body", path)
		}
		etag := res.Header.Get("ETag")
		if etag == "" {
			t.Fatalf("%s: no ETag", path)
		}
		req2 := httptest.NewRequest(http.MethodGet, path, nil)
		req2.Header.Set("If-None-Match", etag)
		rec2 := httptest.NewRecorder()
		uiHandler(rec2, req2)
		if rec2.Code != http.StatusNotModified {
			t.Fatalf("%s: revalidation got %d", path, rec2.Code)
		}
		// A client that does not accept gzip still gets the plain bytes.
		rec3 := httptest.NewRecorder()
		uiHandler(rec3, httptest.NewRequest(http.MethodGet, path, nil))
		if rec3.Header().Get("Content-Encoding") != "" || rec3.Body.Len() != len(body) {
			t.Fatalf("%s: plain response differs", path)
		}
	}
}
