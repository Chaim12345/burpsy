package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// "Show response in browser" (burpsy-react-ui-js5y): the stored response replayed verbatim
// so the operator's own browser renders what the target produced. These pin the replay's
// honesty: status and headers come from the stored head, framing headers do not survive,
// the body is the stored one, and a missing response is a named refusal.

func inBrowserSeed(t *testing.T, s *Server, response string) core.ExchangeID {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET /page HTTP/1.1\r\nHost: shop.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte(response), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     "shop.test",
		Port:     80,
		Method:   "GET",
		Path:     "/page",
		Status:   &status,
	}
	s.store.AddExchange(ex)
	return ex.ID
}

func TestResponseInBrowserReplaysStatusHeadersAndBody(t *testing.T) {
	s := newTestServer()
	id := inBrowserSeed(t, s, "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nX-Custom: probe\r\n\r\n<h1>gone</h1>")

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/exchange/in-browser/"+strconv.FormatUint(uint64(id), 10), nil))
	if rec.Code != 404 {
		t.Errorf("replayed status = %d, want the stored 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want the stored text/html", ct)
	}
	if xc := rec.Header().Get("X-Custom"); xc != "probe" {
		t.Errorf("X-Custom = %q, want the stored value — headers are part of what the target sent", xc)
	}
	if body := rec.Body.String(); !strings.Contains(body, "<h1>gone</h1>") {
		t.Errorf("body = %q, want the stored page", body)
	}
}

func TestResponseInBrowserDropsFramingButStatesNoStore(t *testing.T) {
	s := newTestServer()
	id := inBrowserSeed(t, s, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\nhi")

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/exchange/in-browser/"+strconv.FormatUint(uint64(id), 10), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Framing headers describe the original socket conversation; this replay owns its own.
	if cl := rec.Header().Get("Content-Length"); cl != "" {
		t.Errorf("Content-Length %q must not be echoed from a stored head", cl)
	}
	if te := rec.Header().Get("Transfer-Encoding"); te != "" {
		t.Errorf("Transfer-Encoding %q must not be echoed — the stored framing is not this reply's framing", te)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store — stored evidence must not enter the browser's cache", cc)
	}
	if body := rec.Body.String(); body != "hi" {
		t.Errorf("body = %q, want the stored payload", body)
	}
}

func TestResponseInBrowserRefusesACompressedResponseRatherThanInventingALength(t *testing.T) {
	s := newTestServer()
	id := inBrowserSeed(t, s, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8braw-gzip-bytes")

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/exchange/in-browser/"+strconv.FormatUint(uint64(id), 10), nil))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415 — serving gzip under a recomputed length hands the browser bytes it was never told to decompress", rec.Code)
	}
}

func TestResponseInBrowserNamesAMissingResponse(t *testing.T) {
	s := newTestServer()
	reqID, err := s.store.Put([]byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	ex := &core.Exchange{Request: reqID, Host: "h", Port: 80, Method: "GET", Path: "/x", Status: &status}
	s.store.AddExchange(ex)

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/exchange/in-browser/"+strconv.FormatUint(uint64(ex.ID), 10), nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No response") {
		t.Errorf("refusal %q does not say there is no response", rec.Body.String())
	}
}
