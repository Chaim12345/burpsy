package web

// body_base64 on /api/message/{id} (burpsy-react-ui-n7n): the octets `text` cannot carry. JSON
// strings are UTF-8, so a body with a byte like 0x89 (PNG signatures start with it) arrives in the
// UI with that byte already replaced by U+FFFD — and a Render view built from the lossy text would
// show a different image than the server sent. The field carries the exact body, base64, and is
// populated only when the body is not valid UTF-8: for text bodies `text` already is the body, and
// encoding every body would triple the common response for no reader.

import (
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
