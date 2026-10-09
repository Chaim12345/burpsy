package web

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-yahm: windowed reads of a stored message.

type windowReply struct {
	Len            int                        `json:"len"`
	Head           string                     `json:"head"`
	BodySource     string                     `json:"body_source"`
	TotalBodyBytes int                        `json:"total_body_bytes"`
	ByteOffset     int                        `json:"byte_offset"`
	WindowBytes    int                        `json:"window_bytes"`
	NextOffset     *int                       `json:"next_offset"`
	WindowBase64   string                     `json:"window_base64"`
	WindowText     string                     `json:"window_text"`
	WindowUTF8     bool                       `json:"window_utf8"`
	Anchor         *int                       `json:"anchor"`
	Matches        []struct{ Start, End int } `json:"matches"`
	MatchesCapped  bool                       `json:"matches_capped"`
}

func getWindow(t *testing.T, s *Server, id uint64, query string) (windowReply, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/message/%d?%s", id, query), nil))
	var out windowReply
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding the window: %v", err)
		}
	}
	return out, rec
}

// bigBody is n bytes that are not UTF-8 throughout (0x80-0xff runs), with CRLFs and a marker.
func bigBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	copy(b[n/2:], []byte("\r\n--NEEDLE--\r\n"))
	return b
}

func TestA3MiBBodyCanBeReadToItsLastByteInWindows(t *testing.T) {
	s := newTestServer()
	body := bigBody(3 << 20)
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "+fmt.Sprint(len(body))+"\r\n\r\n"), body...)
	id := putMessage(t, s, raw, core.DirectionResponse)

	var got bytes.Buffer
	offset, calls := 0, 0
	for {
		w, rec := getWindow(t, s, id, fmt.Sprintf("byte_offset=%d&max_bytes=65536", offset))
		if rec.Code != http.StatusOK {
			t.Fatalf("window at %d answered %d: %s", offset, rec.Code, rec.Body.String())
		}
		if !strings.HasPrefix(w.Head, "HTTP/1.1 200 OK") || w.TotalBodyBytes != len(body) || w.Len != len(raw) {
			t.Fatalf("window metadata wrong: head %q total %d len %d", w.Head, w.TotalBodyBytes, w.Len)
		}
		chunk, err := base64.StdEncoding.DecodeString(w.WindowBase64)
		if err != nil || len(chunk) != w.WindowBytes || w.ByteOffset != offset {
			t.Fatalf("window at %d: %v, %d bytes vs %d, offset %d", offset, err, len(chunk), w.WindowBytes, w.ByteOffset)
		}
		got.Write(chunk)
		calls++
		if w.NextOffset == nil {
			break
		}
		offset = *w.NextOffset
	}
	if !bytes.Equal(got.Bytes(), body) {
		t.Fatalf("the reassembled body (%d bytes) is not the stored body (%d bytes)", got.Len(), len(body))
	}
	if calls != 48 {
		t.Fatalf("%d windows for 3 MiB at 64 KiB; want 48", calls)
	}
	// The last window's next_offset is marshalled null, not omitted.
	_, rec := getWindow(t, s, id, fmt.Sprintf("byte_offset=%d&max_bytes=65536", len(body)-10))
	if !strings.Contains(rec.Body.String(), `"next_offset":null`) || !strings.Contains(rec.Body.String(), `"window_utf8":false`) {
		t.Fatalf("the final window does not say it is the end: %.300s", rec.Body.String())
	}
}

func TestAPatternAnchorsTheWindow(t *testing.T) {
	s := newTestServer()
	body := strings.Repeat("a", 5000) + "<title>Secret Page</title>" + strings.Repeat("b", 3000) + "<TITLE>again</TITLE>"
	id := putMessage(t, s, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+body), core.DirectionResponse)

	w, rec := getWindow(t, s, id, "pattern=%3Ctitle%3E&byte_offset=-5&max_bytes=40")
	if rec.Code != http.StatusOK || w.Anchor == nil || *w.Anchor != 5000 || w.ByteOffset != 4995 {
		t.Fatalf("anchor/offset wrong (%d): %s", rec.Code, rec.Body.String())
	}
	if w.WindowText != "aaaaa<title>Secret Page</title>"+strings.Repeat("b", 9) || !w.WindowUTF8 {
		t.Fatalf("window text %q", w.WindowText)
	}
	if len(w.Matches) != 1 || w.Matches[0].Start != 5000 {
		t.Fatalf("matches %+v (the second is upper-case)", w.Matches)
	}
	w, _ = getWindow(t, s, id, "pattern=%3Ctitle%3E&case_insensitive=true&max_bytes=10")
	if len(w.Matches) != 2 || w.Matches[1].Start != 5000+26+3000 {
		t.Fatalf("case-insensitive matches %+v", w.Matches)
	}
	// No match: an empty window, matches [] and anchor null — not an error and not the start of the body.
	_, rec = getWindow(t, s, id, "pattern=zzz")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"matches":[]`) || !strings.Contains(rec.Body.String(), `"anchor":null`) || !strings.Contains(rec.Body.String(), `"window_bytes":0`) {
		t.Fatalf("a pattern with no match answered %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPlainMessageReadIsUnchanged(t *testing.T) {
	s := newTestServer()
	id := putMessage(t, s, []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), core.DirectionRequest)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/message/%d", id), nil))
	var view map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view["text"] != "GET / HTTP/1.1\r\nHost: a\r\n\r\n" || view["window_base64"] != nil {
		t.Fatalf("the unwindowed read changed shape: %s", rec.Body.String())
	}
}

func TestADecodedWindowIsTheBodyMessageViewDecodes(t *testing.T) {
	s := newTestServer()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	plain := strings.Repeat("decoded body line\n", 400)
	zw.Write([]byte(plain))
	zw.Close()
	// Chunked AND gzipped, so both layers must come off.
	var chunked bytes.Buffer
	data := gz.Bytes()
	for len(data) > 0 {
		n := 700
		if n > len(data) {
			n = len(data)
		}
		fmt.Fprintf(&chunked, "%x\r\n", n)
		chunked.Write(data[:n])
		chunked.WriteString("\r\n")
		data = data[n:]
	}
	chunked.WriteString("0\r\n\r\n")
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"), chunked.Bytes()...)
	id := putMessage(t, s, raw, core.DirectionResponse)

	w, rec := getWindow(t, s, id, "decoded=true&max_bytes=65536")
	if rec.Code != http.StatusOK || w.BodySource != "decoded" || w.WindowText != plain || w.NextOffset != nil {
		t.Fatalf("decoded window answered %d: %.300s", rec.Code, rec.Body.String())
	}
	// Held to messageViewOf: the same unwrapping, the same bytes.
	mv := messageViewOf(id, len(raw), raw)
	if mv.Decoded == nil || !strings.HasSuffix(*mv.Decoded, w.WindowText) {
		t.Fatal("the decoded window disagrees with MessageView.Decoded")
	}
	// The wire window is the compressed, chunked bytes.
	w, _ = getWindow(t, s, id, "max_bytes=65536")
	if w.BodySource != "wire" || w.TotalBodyBytes != chunked.Len() {
		t.Fatalf("wire window: source %s, %d bytes", w.BodySource, w.TotalBodyBytes)
	}
}

func TestWindowRefusals(t *testing.T) {
	s := newTestServer()
	id := putMessage(t, s, []byte("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\nxxxx"), core.DirectionResponse)
	for _, q := range []string{"max_bytes=0", "max_bytes=65537", "byte_offset=-1", "byte_offset=x", "pattern=(", "decoded=true"} {
		if _, rec := getWindow(t, s, id, q); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d: %s", q, rec.Code, rec.Body.String())
		}
	}
}
