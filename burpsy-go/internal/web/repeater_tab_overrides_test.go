package web

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Repeater's per-tab overrides added by burpsy-react-ui-of0z: "Unpack compressed responses" and
// "Streaming response timeout". Driven through POST /api/repeater/send against real origins, and
// asserted on the marshalled JSON the panel reads.

type sendWire struct {
	Status                     int    `json:"status"`
	Response                   string `json:"response"`
	ResponseMsgID              uint64 `json:"response_msg_id"`
	ResponseUnpacked           string `json:"response_unpacked"`
	ResponseUnpackedBodyBase64 string `json:"response_unpacked_body_base64"`
	UnpackedFrom               string `json:"unpacked_from"`
	UnpackError                string `json:"unpack_error"`
}

func gzipOrigin(t *testing.T, plain string, encoding string) *httptest.Server {
	t.Helper()
	var packed bytes.Buffer
	zw := gzip.NewWriter(&packed)
	zw.Write([]byte(plain))
	zw.Close()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", encoding)
		w.Header().Set("Content-Length", fmt.Sprint(packed.Len()))
		w.Write(packed.Bytes())
	}))
}

func sendRepeater(t *testing.T, s *Server, authority string, options map[string]any) (int, sendWire, string) {
	t.Helper()
	body := map[string]any{"target": authority, "request": "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"}
	if options != nil {
		body["options"] = options
	}
	rec := postJSON(t, s, "/api/repeater/send", body)
	var out sendWire
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func TestUnpackCompressedResponsesIsOnByDefaultAndDisplayOnly(t *testing.T) {
	const plain = "hello, the decoded body"
	origin := gzipOrigin(t, plain, "gzip")
	defer origin.Close()
	s := newTestServer()
	authority := strings.TrimPrefix(origin.URL, "http://")

	code, out, raw := sendRepeater(t, s, authority, nil)
	if code != http.StatusOK {
		t.Fatalf("send = %d: %s", code, raw)
	}
	if out.UnpackedFrom != "gzip" || out.UnpackError != "" {
		t.Fatalf("unpacked_from/error = %q/%q, want gzip and no error — Burp unpacks by default", out.UnpackedFrom, out.UnpackError)
	}
	head, body, _ := strings.Cut(out.ResponseUnpacked, "\r\n\r\n")
	if body != plain || strings.Contains(strings.ToLower(head), "content-encoding") ||
		!strings.Contains(head, fmt.Sprintf("Content-Length: %d", len(plain))) {
		t.Fatalf("response_unpacked = %q, want the decoded body under a head that no longer claims gzip", out.ResponseUnpacked)
	}
	if !strings.Contains(out.Response, "Content-Encoding: gzip") || strings.Contains(out.Response, plain) {
		t.Fatal("`response` must stay the compressed bytes that arrived")
	}
	var stored struct {
		Text string `json:"text"`
	}
	json.Unmarshal(getJSON(t, s, fmt.Sprintf("/api/message/%d", out.ResponseMsgID)).Body.Bytes(), &stored)
	if !strings.Contains(stored.Text, "Content-Encoding: gzip") || strings.Contains(stored.Text, plain) {
		t.Fatalf("the stored response = %q; unpack is display only and the store keeps the bytes that arrived", stored.Text)
	}

	// The tab turns it off: the compressed bytes only, nothing unpacked.
	_, off, raw := sendRepeater(t, s, authority, map[string]any{"unpack_responses": false})
	if off.ResponseUnpacked != "" || off.UnpackedFrom != "" || strings.Contains(raw, "response_unpacked") {
		t.Fatalf("with unpack off the answer still carries an unpacked rendering: %s", raw)
	}
}

func TestUnpackNamesAnEncodingItCannotDecode(t *testing.T) {
	origin := gzipOrigin(t, "x", "br")
	defer origin.Close()
	s := newTestServer()
	_, out, raw := sendRepeater(t, s, strings.TrimPrefix(origin.URL, "http://"), nil)
	if out.UnpackedFrom != "br" || !strings.Contains(out.UnpackError, "no decoder") || out.ResponseUnpacked != "" {
		t.Fatalf("a brotli response = %s, want unpacked_from br with the reason it stayed packed", raw)
	}
}

// eventStreamOrigin answers with a chunked text/event-stream that sends one event and then holds the
// stream open — the shape that used to read as a hung target.
func eventStreamOrigin() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
}

func TestAStreamingResponseTimeoutReturnsWhatTheStreamSentByTheCutoff(t *testing.T) {
	origin := eventStreamOrigin()
	defer origin.Close()
	s := newTestServer()
	authority := strings.TrimPrefix(origin.URL, "http://")

	// Without the tab's streaming window the same send is an ordinary read: bounded here by a short
	// response timeout, it fails rather than returning the event.
	if code, _, raw := sendRepeater(t, s, authority, map[string]any{"response_timeout_ms": 400}); code == http.StatusOK {
		t.Fatalf("without a streaming window the open stream should not read as a complete response: %s", raw)
	}

	started := time.Now()
	code, out, raw := sendRepeater(t, s, authority, map[string]any{"streaming_timeout_ms": 400})
	elapsed := time.Since(started)
	if code != http.StatusOK || out.Status != 200 || !strings.Contains(out.Response, "data: one") {
		t.Fatalf("streaming send = %d: %s, want 200 carrying the event that arrived", code, raw)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the send took %v; the 400ms streaming window should have cut it off", elapsed)
	}
}

// An unframed read-until-close response held open — a long-poll — is cut off by the window too.
func TestAStreamingTimeoutCutsOffAHeldUnframedResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				c.Read(buf)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"partial\":"))
				time.Sleep(5 * time.Second)
				c.Close()
			}(conn)
		}
	}()
	s := newTestServer()
	started := time.Now()
	code, out, raw := sendRepeater(t, s, ln.Addr().String(), map[string]any{"streaming_timeout_ms": 300})
	if code != http.StatusOK || !strings.HasSuffix(out.Response, `{"partial":`) || time.Since(started) > 3*time.Second {
		t.Fatalf("held unframed response = %d after %v: %s", code, time.Since(started), raw)
	}
}

func TestAStreamingTimeoutOverH2ReturnsTheEventsThatArrived(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: over-h2\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	s := newTestServer()
	s.sender.WithTLSVerify(false)
	authority := strings.TrimPrefix(origin.URL, "https://")
	body := map[string]any{
		"target": origin.URL, "request": "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"options": map[string]any{"streaming_timeout_ms": 400, "protocol_preference": "http2"},
	}
	started := time.Now()
	rec := postJSON(t, s, "/api/repeater/send", body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data: over-h2") || time.Since(started) > 5*time.Second {
		t.Fatalf("h2 streaming send = %d after %v: %s", rec.Code, time.Since(started), rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `HTTP/2 200`) {
		t.Fatalf("the send did not ride h2: %s", rec.Body.String())
	}
}

func TestAStreamingTimeoutRefusesANegativeWindow(t *testing.T) {
	s := newTestServer()
	code, _, raw := sendRepeater(t, s, "127.0.0.1:1", map[string]any{"streaming_timeout_ms": -1})
	if code != http.StatusBadRequest || !strings.Contains(raw, "streaming_timeout_ms") {
		t.Fatalf("= %d %s", code, raw)
	}
}
