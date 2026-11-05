package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// A chunked response through the TLS-intercept leg must reach a strict HTTP/1.1 client readable,
// including when it is gzip-encoded, and the tunnel must stay framed for the next request.
//
// The field failure (SUMIT engagement, a build from 3e68af16): python requests through
// -intercept-tls got Cloudflare's and Express's chunked answers with the chunk framing gone and the
// Transfer-Encoding: chunked head kept, so the client read the gzip magic as a chunk size —
// ChunkedEncodingError: InvalidChunkLength(got length b'\x1f\x8b\x08...') — and an Express 404 page
// failed the same way on its "<!DOCTYPE". f5884f04 (609d) fixed it by re-framing the decoded payload,
// but its test drives only the plaintext leg; this pins the TLS leg the bug was seen on.
//
// The origin speaks h2 as well as HTTP/1.1, like Cloudflare. The client offers only http/1.1, as
// urllib3 does, and the proxy mirrors that offer upstream, so both legs are HTTP/1.1 — there is no
// h2-to-h1 transcoding on this path (an h2 client goes through relayH2, where net/http frames).
func TestAChunkedResponseThroughTheTLSInterceptStaysReadableByAStrictHTTP1Client(t *testing.T) {
	const json = `{"ok":true,"items":[1,2,3]}`
	// Express's own 404 page, newlines included: a client reading it as a chunk size fails at once.
	const page = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot GET /nope</pre>\n</body>\n</html>\n"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(json))
	_ = zw.Close()

	var originProto atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originProto.Store(int32(r.ProtoMajor))
		// Two writes with a flush between and no Content-Length: net/http frames this as chunked.
		write := func(status int, b []byte) {
			w.WriteHeader(status)
			_, _ = w.Write(b[:len(b)/2])
			w.(http.Flusher).Flush()
			_, _ = w.Write(b[len(b)/2:])
		}
		if r.URL.Path == "/api" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			write(http.StatusOK, gz.Bytes())
			return
		}
		w.Header().Set("Content-Type", "text/html")
		write(http.StatusNotFound, []byte(page))
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	origin := strings.TrimPrefix(target.URL, "https://")

	certDir := t.TempDir()
	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()
	caPEM, err := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, origin)
	if resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"}); err != nil || resp.StatusCode != http.StatusOK { //nolint:bodyclose // a CONNECT answer carries no body
		t.Fatalf("CONNECT through the proxy failed: %v", err)
	}
	host, _, _ := net.SplitHostPort(origin)
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with the intercepting proxy: %v", err)
	}
	br := bufio.NewReader(conn)

	// Both requests ride one tunnel: the second only parses if the first ended on its own framing.
	for _, tc := range []struct {
		path   string
		status int
		want   []byte
	}{
		{"/nope", http.StatusNotFound, []byte(page)},
		{"/api", http.StatusOK, gz.Bytes()},
	} {
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip\r\n\r\n", tc.path, origin)
		resp, err := http.ReadResponse(br, &http.Request{Method: "GET"}) //nolint:bodyclose // the answer is read, not kept
		if err != nil {
			t.Fatalf("%s: a strict client could not parse the response head — the tunnel lost its framing: %v", tc.path, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: the head says chunked but the body is not chunk-framed (the InvalidChunkLength failure): %v", tc.path, err)
		}
		if resp.StatusCode != tc.status || !bytes.Equal(body, tc.want) {
			t.Fatalf("%s: got %d %q, want %d %q", tc.path, resp.StatusCode, body, tc.status, tc.want)
		}
		if originProto.Load() != 1 {
			t.Fatalf("%s: the origin was reached over HTTP/%d; an http/1.1-only client must be carried over HTTP/1.1", tc.path, originProto.Load())
		}
	}
}
