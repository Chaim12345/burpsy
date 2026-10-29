package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestXUIPagesAndAssets(t *testing.T) {
	s := newTestServer()
	for path, want := range map[string]string{"/x": "xui-rows", "/x/prove": "xui-rows", "/x/datastar.js": "", "/x/xui.css": ""} {
		rec := get(t, s, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if want != "" && !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: missing %q", path, want)
		}
	}
}

func TestXUIDetailErrors(t *testing.T) {
	s := newTestServer()
	if c := get(t, s, "/x/detail?id=abc").Code; c != http.StatusBadRequest {
		t.Fatalf("bad id: %d", c)
	}
	if c := get(t, s, "/x/detail?id=999999").Code; c != http.StatusNotFound {
		t.Fatalf("missing id: %d", c)
	}
}

func TestXUIStreamSendsFirstFrameAndStops(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/x/map/stream", "/x/prove/stream"} {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, p, nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { s.mux.ServeHTTP(rec, req); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not stop after context cancel", p)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Fatalf("%s content-type %q", p, ct)
		}
		if !strings.Contains(rec.Body.String(), "datastar-patch-elements") {
			t.Fatalf("%s: no patch frame: %q", p, rec.Body.String())
		}
	}
}
