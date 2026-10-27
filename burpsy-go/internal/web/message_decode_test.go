package web

// A compressed response is readable in history.
//
// The other half of the gzip/deflate gap: a gzipped response body rendered as raw text is a screenful
// of binary, and burpsy had no HTTP decompressor anywhere. The raw bytes stay exactly as captured —
// that invariant is the point of the whole capture layer — so the decode is served alongside them.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func storeResponse(t *testing.T, srv *Server, raw []byte) uint64 {
	t.Helper()
	id, err := srv.store.Put(raw, core.DirectionResponse)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return uint64(id)
}

func fetchMessage(t *testing.T, srv *Server, id uint64) MessageView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/message/%d", id), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("message status = %d (%s)", rec.Code, rec.Body.String())
	}
	var view MessageView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return view
}

func gzipHTML(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(buf.Len()) + "\r\n\r\n"
	return append([]byte(head), buf.Bytes()...)
}

func TestAGzippedResponseIsReadableInHistory(t *testing.T) {
	srv := newTestServer()
	const body = `<html><body><h1>secrets</h1></body></html>`
	raw := gzipHTML(t, body)
	msgID := storeResponse(t, srv, raw)
	view := fetchMessage(t, srv, msgID)

	if view.ContentEncoding != "gzip" {
		t.Errorf("content_encoding = %q, want gzip", view.ContentEncoding)
	}
	if view.Decoded == nil {
		t.Fatal("no decoded rendering: a gzipped body renders as binary and is unreadable")
	}
	if !strings.Contains(*view.Decoded, body) {
		t.Errorf("decoded = %q, want the plaintext body", *view.Decoded)
	}
	if !strings.HasPrefix(*view.Decoded, "HTTP/1.1 200 OK") {
		t.Errorf("decoded = %q, want the head kept so the pane reads as a response", *view.Decoded)
	}
	// The record must not have been rewritten. History disagreeing with a packet capture for a reason
	// the operator cannot see is the failure the capture layer is built to prevent.
	//
	// Asserted through Len and the store rather than through view.Text, and the reason is a separate
	// defect this test found: MessageView.Text is a JSON string, so any body that is not valid UTF-8
	// — which every gzip body is — comes back with each invalid byte replaced by U+FFFD. The stored
	// bytes are exact (checked below); the *wire projection of them* is lossy for binary, and has
	// been since MessageView existed. That is a reason the decoded rendering matters and not an
	// argument against it, but it is not something this change fixes, so the assertion says what it
	// can honestly check.
	if view.Len != len(raw) {
		t.Errorf("len = %d, want the captured %d bytes", view.Len, len(raw))
	}
	stored, err := srv.store.Get(core.MsgId(msgID))
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !bytes.Equal(stored.Raw(), raw) {
		t.Error("the stored message is no longer the exact captured bytes")
	}
	if view.DecodeError != "" {
		t.Errorf("decode_error = %q on a successful decode", view.DecodeError)
	}
}

func TestAPlaintextResponseCarriesNoDecodedRendering(t *testing.T) {
	srv := newTestServer()
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello")
	view := fetchMessage(t, srv, storeResponse(t, srv, raw))
	if view.Decoded != nil {
		t.Errorf("decoded = %q on a plaintext message", *view.Decoded)
	}
	if view.ContentEncoding != "" || view.DecodeError != "" {
		t.Errorf("view = %+v, want no encoding and no error", view)
	}
}

func TestAnUndecodableEncodingSaysSoRatherThanRenderingNothing(t *testing.T) {
	srv := newTestServer()
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n\r\n\x01\x02\x03")
	view := fetchMessage(t, srv, storeResponse(t, srv, raw))

	if view.ContentEncoding != "br" {
		t.Errorf("content_encoding = %q, want br", view.ContentEncoding)
	}
	if view.Decoded != nil {
		t.Error("a corrupt brotli body was reported as decoded")
	}
	// "burpsy cannot read this" and "there was nothing to read" must not merge into one blank pane.
	if !strings.Contains(view.DecodeError, "br") {
		t.Errorf("decode_error = %q, want the encoding named", view.DecodeError)
	}
}

func TestACorruptCompressedBodyReportsTheFailure(t *testing.T) {
	srv := newTestServer()
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nthis is not gzip")
	view := fetchMessage(t, srv, storeResponse(t, srv, raw))
	if view.Decoded != nil {
		t.Errorf("decoded = %q for a body that is not gzip", *view.Decoded)
	}
	if view.DecodeError == "" {
		t.Error("a failed decode reported no reason")
	}
}

func TestAChunkedGzippedResponseIsDecoded(t *testing.T) {
	srv := newTestServer()
	const body = `<html><body><h1>chunked and packed</h1></body></html>`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(body))
	zw.Close()
	packed := buf.Bytes()

	// Two chunks, so a decoder that only handled the single-chunk case fails here. The chunk sizes
	// frame the compressed bytes, so the framing must come off first.
	var framed bytes.Buffer
	half := len(packed) / 2
	for _, part := range [][]byte{packed[:half], packed[half:]} {
		framed.WriteString(strconv.FormatInt(int64(len(part)), 16) + "\r\n")
		framed.Write(part)
		framed.WriteString("\r\n")
	}
	framed.WriteString("0\r\n\r\n")
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"),
		framed.Bytes()...)

	view := fetchMessage(t, srv, storeResponse(t, srv, raw))
	if view.Decoded == nil {
		t.Fatalf("chunked gzip was not decoded (error: %q)", view.DecodeError)
	}
	if !strings.Contains(*view.Decoded, body) {
		t.Errorf("decoded = %q, want the plaintext body", *view.Decoded)
	}
}
