package web

// body_base64 on /api/message/{id} (burpsy-react-ui-n7n): the octets `text` cannot carry. JSON
// strings are UTF-8, so a body with a byte like 0x89 (PNG signatures start with it) arrives in the
// UI with that byte already replaced by U+FFFD — and a Render view built from the lossy text would
// show a different image than the server sent. The field carries the exact body, base64, and is
// populated only when the body is not valid UTF-8: for text bodies `text` already is the body, and
// encoding every body would triple the common response for no reader.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestMessageViewCarriesExactBytesForNonUTF8Bodies(t *testing.T) {
	s := newTestServer()
	body := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00}, []byte("tail")...)
	id, err := s.store.Put(append([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"), body...), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	rec := get(t, s, "/api/message/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/message: status = %d", rec.Code)
	}
	var view struct {
		Text    string `json:"text"`
		Body64  string `json:"body_base64"`
		Round64 string `json:"-"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(view.Body64)
	if err != nil {
		t.Fatalf("body_base64 is not base64: %v", err)
	}
	if string(raw) != string(body) {
		t.Fatalf("body_base64 decodes to %x, want the exact captured body %x — the bytes did not survive", raw, body)
	}
	// And the lossy path is exactly why the field exists: text has already lost the bytes.
	if view.Text == string(body) {
		t.Fatal("text carried the binary body intact; the test premise (and the field's reason to exist) is wrong")
	}
}

// burpsy-react-ui-r0go: body_base64 used to be captured before dechunking and decompression, so a
// chunked, gzipped image rendered as garbage — the render tab's <img> decoder was handed chunk-size
// digits and a gzip header instead of pixels. Both wrappings are ordinary on the real internet, so
// this pins both at once: the base64 must decode to the exact original image bytes.
func TestMessageViewBody64IsDechunkedAndDecompressed(t *testing.T) {
	s := newTestServer()
	img := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, bytes.Repeat([]byte{0xab, 0xcd, 0x00, 0xff}, 64)...)

	var packedBuf bytes.Buffer
	zw := gzip.NewWriter(&packedBuf)
	if _, err := zw.Write(img); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	packed := packedBuf.Bytes()

	// Two chunks, so a decoder that only handles a single chunk still fails here — same shape as
	// message_decode_test.go's chunked-gzip case, but through the Body64 path instead of Decoded.
	var framed bytes.Buffer
	half := len(packed) / 2
	for _, part := range [][]byte{packed[:half], packed[half:]} {
		framed.WriteString(strconv.FormatInt(int64(len(part)), 16) + "\r\n")
		framed.Write(part)
		framed.WriteString("\r\n")
	}
	framed.WriteString("0\r\n\r\n")
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Encoding: gzip\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n"), framed.Bytes()...)

	id, err := s.store.Put(raw, core.DirectionResponse)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rec := get(t, s, "/api/message/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/message: status = %d", rec.Code)
	}
	var view struct {
		Body64 string `json:"body_base64"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Body64 == "" {
		t.Fatal("body_base64 is empty for a chunked, gzipped image body")
	}
	got, err := base64.StdEncoding.DecodeString(view.Body64)
	if err != nil {
		t.Fatalf("body_base64 is not base64: %v", err)
	}
	if !bytes.Equal(got, img) {
		t.Fatalf("body_base64 decodes to %d bytes that do not match the original %d-byte image — "+
			"the render tab would be handed chunk framing and/or gzip framing instead of pixels", len(got), len(img))
	}
}

// The other half of the same bug: a chunked image with no Content-Encoding at all. The old code
// gated dechunking on a supported Content-Encoding being present, so a chunked-only body's Body64
// (there being no compression step to trigger the unwrap) stayed framed with chunk-size digits.
func TestMessageViewBody64IsDechunkedWithNoContentEncoding(t *testing.T) {
	s := newTestServer()
	img := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, bytes.Repeat([]byte{0x11, 0x22, 0x00, 0xff}, 64)...)

	var framed bytes.Buffer
	half := len(img) / 2
	for _, part := range [][]byte{img[:half], img[half:]} {
		framed.WriteString(strconv.FormatInt(int64(len(part)), 16) + "\r\n")
		framed.Write(part)
		framed.WriteString("\r\n")
	}
	framed.WriteString("0\r\n\r\n")
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\n\r\n"),
		framed.Bytes()...)

	id, err := s.store.Put(raw, core.DirectionResponse)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rec := get(t, s, "/api/message/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/message: status = %d", rec.Code)
	}
	var view struct {
		Body64          string `json:"body_base64"`
		ContentEncoding string `json:"content_encoding"`
		DecodeError     string `json:"decode_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.ContentEncoding != "" {
		t.Errorf("content_encoding = %q, want empty — there is no Content-Encoding on this response", view.ContentEncoding)
	}
	if view.DecodeError != "" {
		t.Errorf("decode_error = %q, want empty — nothing here is compressed, so there is nothing to fail decoding", view.DecodeError)
	}
	got, err := base64.StdEncoding.DecodeString(view.Body64)
	if err != nil {
		t.Fatalf("body_base64 is not base64: %v", err)
	}
	if !bytes.Equal(got, img) {
		t.Fatalf("body_base64 decodes to %d bytes that do not match the original %d-byte image — "+
			"chunk framing survived into the render tab", len(got), len(img))
	}
}

// Regression guard for the same fix: bad chunk framing on a body with no Content-Encoding must not
// start reporting a decode_error where none existed before. DecodeError's own doc says it names why a
// *compressed* message could not be decoded, and nothing here is compressed.
func TestMessageViewBadChunkFramingWithNoContentEncodingReportsNoDecodeError(t *testing.T) {
	s := newTestServer()
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot a valid chunk size\r\ndata")
	id, err := s.store.Put(raw, core.DirectionResponse)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rec := get(t, s, "/api/message/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/message: status = %d", rec.Code)
	}
	var view struct {
		DecodeError string `json:"decode_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.DecodeError != "" {
		t.Errorf("decode_error = %q on an uncompressed body with bad chunk framing; nothing here was ever compressed", view.DecodeError)
	}
}

func TestMessageViewOmitsBody64ForUTF8Bodies(t *testing.T) {
	s := newTestServer()
	id, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nplain text body"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rec := get(t, s, "/api/message/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/message: status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "body_base64") {
		t.Fatal("a plain-text body carries body_base64 — encoding every body triples the common response for no reader")
	}
}
