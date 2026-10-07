package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func postHAR(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/history/import/har", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func decodeHARResult(t *testing.T, rec *httptest.ResponseRecorder) harImportResult {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d; body %s", rec.Code, rec.Body.String())
	}
	var out harImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode result %q: %v", rec.Body.String(), err)
	}
	return out
}

func storedRequest(t *testing.T, s *Server, ex *core.Exchange) []byte {
	t.Helper()
	msg, err := s.store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		t.Fatalf("request message not in store: %v", err)
	}
	return msg.Raw()
}

func storedResponse(t *testing.T, s *Server, ex *core.Exchange) []byte {
	t.Helper()
	msg, err := s.store.Get(core.MsgOrZero(ex.Response))
	if err != nil {
		t.Fatalf("response message not in store: %v", err)
	}
	return msg.Raw()
}

// The acceptance of burpsy-react-ui-eyi1: a HAR entry becomes a history row whose request and response
// are real, parseable HTTP messages — which is what makes it viewable and resendable in Repeater — with
// its routing facts and its timing carried across.
func TestHARImportCreatesAResendableHistoryRow(t *testing.T) {
	s := newTestServer()
	har := `{"log":{"version":"1.2","entries":[
		{"startedDateTime":"2026-10-05T12:00:00.000Z","time":123.5,
		 "request":{"method":"GET","url":"https://api.example.com:8443/users?id=7","httpVersion":"HTTP/2",
		  "headers":[{"name":":authority","value":"api.example.com"},{"name":"Accept","value":"application/json"}]},
		 "response":{"status":200,"statusText":"OK","httpVersion":"HTTP/2",
		  "headers":[{"name":"content-type","value":"application/json; charset=utf-8"},{"name":"content-length","value":"999"}],
		  "content":{"size":11,"mimeType":"application/json","text":"{\"ok\":true}"}}}
	]}}`

	res := decodeHARResult(t, postHAR(t, s, har))
	if res.Imported != 1 || res.Skipped != 0 {
		t.Fatalf("imported %d skipped %d, want 1/0 (errors: %v)", res.Imported, res.Skipped, res.Errors)
	}

	exchanges := s.store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("store holds %d exchanges, want 1", len(exchanges))
	}
	ex := exchanges[0]

	if ex.Host != "api.example.com" || ex.Port != 8443 || !ex.TLS {
		t.Errorf("routing = %s:%d tls=%v, want api.example.com:8443 tls=true", ex.Host, ex.Port, ex.TLS)
	}
	if ex.Method != "GET" || ex.Path != "/users?id=7" {
		t.Errorf("method/path = %q %q, want GET /users?id=7", ex.Method, ex.Path)
	}
	if ex.Status == nil || *ex.Status != 200 {
		t.Errorf("status = %v, want 200", ex.Status)
	}
	if ex.Source != core.SourceImport {
		t.Errorf("source = %q, want %q — an imported row must not claim the proxy captured it", ex.Source, core.SourceImport)
	}
	if ex.Duration.Millis() != 123 {
		t.Errorf("duration = %d ms, want 123 (the HAR entry time)", ex.Duration.Millis())
	}
	if ex.StartedMs == 0 {
		t.Error("startedDateTime was not carried; the row shows no capture time")
	}

	// The request parses as an HTTP request, with the h2 pseudo-header gone and a Host synthesised from
	// the URL authority — the shape Repeater needs to resend it.
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(storedRequest(t, s, ex))))
	if err != nil {
		t.Fatalf("stored request does not parse: %v", err)
	}
	if req.Method != "GET" || req.RequestURI != "/users?id=7" {
		t.Errorf("parsed request line = %s %s, want GET /users?id=7", req.Method, req.RequestURI)
	}
	if req.Host != "api.example.com:8443" {
		t.Errorf("Host = %q, want api.example.com:8443 (synthesised from the URL)", req.Host)
	}
	if got := bytes.ToLower(storedRequest(t, s, ex)); bytes.Contains(got, []byte(":authority")) {
		t.Error("the h2 :authority pseudo-header was rendered as a header line")
	}

	// The response parses, its body survives, and its Content-Length was recomputed to the real body
	// length rather than the stale 999 the HAR carried.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(storedResponse(t, s, ex))), nil)
	if err != nil {
		t.Fatalf("stored response does not parse: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("stored response body does not read (framing and body disagree): %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q, want %q", string(body), `{"ok":true}`)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d (recomputed, not the HAR's 999)", resp.ContentLength, len(body))
	}
}

// A binary response body is carried as base64 in HAR; import must decode it back to the bytes.
func TestHARImportDecodesBase64ResponseBodies(t *testing.T) {
	s := newTestServer()
	// "hello" base64 is "aGVsbG8=".
	har := `{"log":{"version":"1.2","entries":[
		{"request":{"method":"GET","url":"http://x.test/bin","headers":[]},
		 "response":{"status":200,"statusText":"OK","headers":[{"name":"content-type","value":"application/octet-stream"}],
		  "content":{"size":5,"mimeType":"application/octet-stream","encoding":"base64","text":"aGVsbG8="}}}
	]}}`

	if res := decodeHARResult(t, postHAR(t, s, har)); res.Imported != 1 {
		t.Fatalf("imported %d, want 1 (errors: %v)", res.Imported, res.Errors)
	}
	ex := s.store.Exchanges()[0]
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(storedResponse(t, s, ex))), nil)
	if err != nil {
		t.Fatalf("stored response does not parse: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("decoded body = %q, want %q", string(body), "hello")
	}
}

// A HAR request body is rendered with a recomputed Content-Length, so a POST with a body resends.
func TestHARImportRendersAPostBody(t *testing.T) {
	s := newTestServer()
	har := `{"log":{"version":"1.2","entries":[
		{"request":{"method":"POST","url":"http://x.test/submit",
		  "headers":[{"name":"Content-Type","value":"application/x-www-form-urlencoded"},{"name":"Content-Length","value":"0"}],
		  "postData":{"mimeType":"application/x-www-form-urlencoded","text":"a=1&b=2"}},
		 "response":{"status":204,"statusText":"No Content","headers":[],"content":{"size":0}}}
	]}}`

	if res := decodeHARResult(t, postHAR(t, s, har)); res.Imported != 1 {
		t.Fatalf("imported %d, want 1 (errors: %v)", res.Imported, res.Errors)
	}
	ex := s.store.Exchanges()[0]
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(storedRequest(t, s, ex))))
	if err != nil {
		t.Fatalf("stored request does not parse: %v", err)
	}
	if req.ContentLength != 7 {
		t.Errorf("Content-Length = %d, want 7 (recomputed from the body, not the HAR's stale 0)", req.ContentLength)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "a=1&b=2" {
		t.Errorf("body = %q, want a=1&b=2", string(body))
	}
}

// A HAR entry with no response (status 0 — an in-flight or failed request) is imported as a
// request-only row rather than a fabricated empty response.
func TestHARImportKeepsARequestOnlyEntry(t *testing.T) {
	s := newTestServer()
	har := `{"log":{"version":"1.2","entries":[
		{"request":{"method":"GET","url":"http://x.test/pending","headers":[]},
		 "response":{"status":0,"statusText":"","headers":[],"content":{"size":0}}}
	]}}`

	if res := decodeHARResult(t, postHAR(t, s, har)); res.Imported != 1 {
		t.Fatalf("imported %d, want 1 (errors: %v)", res.Imported, res.Errors)
	}
	ex := s.store.Exchanges()[0]
	if ex.Response != nil {
		t.Error("a status-0 entry was given a response; it should be a request-only row")
	}
	if ex.Status != nil {
		t.Errorf("a request-only row carries a status %v; it should have none", ex.Status)
	}
	if ex.Request == nil {
		t.Error("the request half was dropped")
	}
}

// A malformed entry is skipped and reported, and the entries around it still import — one bad row in a
// capture must not cost the rest.
func TestHARImportSkipsAMalformedEntryAndKeepsTheRest(t *testing.T) {
	s := newTestServer()
	har := `{"log":{"version":"1.2","entries":[
		{"request":{"method":"GET","url":"/relative/only","headers":[]},"response":{"status":200,"headers":[],"content":{"size":0}}},
		{"request":{"method":"GET","url":"http://good.test/ok","headers":[]},"response":{"status":200,"statusText":"OK","headers":[],"content":{"size":0}}}
	]}}`

	res := decodeHARResult(t, postHAR(t, s, har))
	if res.Imported != 1 || res.Skipped != 1 {
		t.Fatalf("imported %d skipped %d, want 1/1 (errors: %v)", res.Imported, res.Skipped, res.Errors)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "entry 0") {
		t.Errorf("errors = %v, want one naming entry 0", res.Errors)
	}
	if len(s.store.Exchanges()) != 1 {
		t.Fatalf("store holds %d exchanges, want 1 (only the good entry)", len(s.store.Exchanges()))
	}
	if s.store.Exchanges()[0].Host != "good.test" {
		t.Errorf("imported the wrong entry: host %q", s.store.Exchanges()[0].Host)
	}
}

// The route contract: POST a valid HAR succeeds, and the shapes that cannot be an import are refused
// with a 4xx rather than a panic or a silent empty success.
func TestHARImportRouteContract(t *testing.T) {
	s := newTestServer()

	if rec := get(t, s, "/api/history/import/har"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", rec.Code)
	}
	if rec := postHAR(t, s, "not json"); rec.Code != http.StatusBadRequest {
		t.Errorf("POST of non-JSON = %d, want 400", rec.Code)
	}
	if rec := postHAR(t, s, `{"log":{"version":"1.2","entries":[]}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST of an empty HAR = %d, want 400: an import of nothing is not an import", rec.Code)
	}
}
