package sender

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSendRawPlainHTTP verifies SendRaw reads a complete keep-alive response
// without hanging on EOF.
func TestSendRawPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello from target"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	portU64, _ := strconv.ParseUint(portStr, 10, 16)

	raw := "GET /echo HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	resp, err := NewSender(DefaultSenderConfig()).SendRaw(context.Background(), host, uint16(portU64), false, []byte(raw))
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if !strings.Contains(string(resp), "200 OK") {
		t.Errorf("missing status line: %q", string(resp))
	}
	if !strings.Contains(string(resp), "hello from target") {
		t.Errorf("missing body: %q", string(resp))
	}
}

// TestSendRawChunked verifies chunked transfer-encoding responses are read to
// the terminating chunk.
func TestSendRawChunked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(200)
		fl.Flush()
		w.Write([]byte("chunk-one"))
		fl.Flush()
		w.Write([]byte("chunk-two"))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	portU64, _ := strconv.ParseUint(portStr, 10, 16)

	raw := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	resp, err := NewSender(DefaultSenderConfig()).SendRaw(context.Background(), host, uint16(portU64), false, []byte(raw))
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	body := string(resp)
	if !strings.Contains(body, "chunk-one") || !strings.Contains(body, "chunk-two") {
		t.Errorf("chunked body incomplete: %q", body)
	}
}

// TestSendRawTLS verifies TLS dialing with a self-signed cert and
// InsecureSkipVerify.
func TestSendRawTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure hello"))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	portU64, _ := strconv.ParseUint(portStr, 10, 16)

	cfg := DefaultSenderConfig()
	cfg.TLSVerify = false
	cfg.Timeout = 10 * time.Second

	raw := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	resp, err := NewSender(cfg).SendRaw(context.Background(), host, uint16(portU64), true, []byte(raw))
	if err != nil {
		t.Fatalf("SendRaw TLS: %v", err)
	}
	if !strings.Contains(string(resp), "secure hello") {
		t.Errorf("missing TLS body: %q", string(resp))
	}
}

// Sender.Send is the path the active scanner's probes take, so the no-follow guarantee is pinned here
// too and not only on the authorised wrapper: a probe that followed a 30x would attribute the
// redirect target's response to the URL the check asked about.
func TestSendReturnsARedirectRatherThanFollowingIt(t *testing.T) {
	followed := make(chan string, 1)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed <- r.URL.Path
		io.WriteString(w, "internal service")
	}))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", elsewhere.URL+"/internal")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	portU64, _ := strconv.ParseUint(portStr, 10, 16)

	resp, err := NewSender(DefaultSenderConfig()).Send(context.Background(), &Request{
		Method: "GET", Host: host, Port: uint16(portU64), Path: "/go",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if string(resp.Body) == "internal service" {
		t.Fatal("the body came from the redirect target: the transport followed the 30x")
	}
	select {
	case path := <-followed:
		t.Fatalf("the redirect target was dialled at %q", path)
	default:
	}
}

// TestSendFallsBackToRaw verifies Send (the http.Client path) still works.
func TestSendUsesHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "client-path-ok")
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	portU64, _ := strconv.ParseUint(portStr, 10, 16)

	s := NewSender(DefaultSenderConfig())
	resp, err := s.Send(context.Background(), &Request{
		Method: "GET",
		Host:   host,
		Port:   uint16(portU64),
		Path:   "/",
		TLS:    false,
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "client-path-ok" {
		t.Errorf("resp = %d %q", resp.StatusCode, string(resp.Body))
	}
}
