package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// headScript is a tus server's offset check answered both ways stacks answer a HEAD — with the
// Content-Length a GET would have had (Express), and declared chunked — and no body after either
// head, as RFC 9112 §6.3 requires. /after is the ordinary request that follows on the connection.
var headScript = map[string]string{
	"HEAD /files/cl":      "HTTP/1.1 200 OK\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: 5\r\nContent-Length: 1234\r\n\r\n",
	"HEAD /files/chunked": "HTTP/1.1 200 OK\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
	"GET /after":          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nafter",
	"GET /both":           "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
}

// serveScripted answers every request on every connection ln accepts with script[method+" "+path],
// verbatim, keeping each connection alive — so an origin's next response is on the same socket as the
// one before, which is what a relay that over-reads a body would swallow.
func serveScripted(t *testing.T, ln net.Listener, script map[string]string) {
	t.Helper()
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					answer, ok := script[req.Method+" "+req.URL.Path]
					if !ok {
						answer = "HTTP/1.1 500 Unscripted\r\nContent-Length: 0\r\n\r\n"
					}
					if _, err := io.WriteString(c, answer); err != nil {
						return
					}
				}
			}(c)
		}
	}()
}

// startInterceptProxy runs a TLS-intercepting proxy with an in-memory store and returns its address,
// the CA pool a client trusts it with, the server and the store.
func startInterceptProxy(t *testing.T) (string, *x509.CertPool, *Server, *core.TrafficStore) {
	t.Helper()
	certDir := t.TempDir()
	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(c)
		}
	}()
	caPEM, err := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return ln.Addr().String(), pool, srv, store
}

// openInterceptTunnel CONNECTs through the proxy and completes TLS with its leaf, offering only
// http/1.1 the way urllib3 and most tus clients do.
func openInterceptTunnel(t *testing.T, proxyAddr, origin string, pool *x509.CertPool) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, origin)
	if resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"}); err != nil || resp.StatusCode != http.StatusOK { //nolint:bodyclose // a CONNECT answer carries no body
		t.Fatalf("CONNECT through the proxy failed: %v", err)
	}
	host, _, _ := net.SplitHostPort(origin)
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with the intercepting proxy: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

// The answer to a HEAD has no body, whatever Content-Length or Transfer-Encoding its head declares,
// and the relay must neither wait for one nor eat the next response looking for it. Before this the
// proxy's body read asked the status alone: a HEAD answered with a Content-Length hung until the
// origin closed (both legs), and one answered chunked was streamed as an open-ended body, so the
// client got its head but the intercepted tunnel then sat on a body that never came for the whole
// streaming window and the next request on it timed out. tus checks every upload's offset with a
// HEAD, so an upload through the proxy stalled at its first resume.
func TestTheAnswerToAHeadCarriesNoBodyWhateverItsHeadDeclares(t *testing.T) {
	head := func(t *testing.T, conn net.Conn, br *bufio.Reader, target, host, path string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "HEAD %s HTTP/1.1\r\nHost: %s\r\nTus-Resumable: 1.0.0\r\n\r\n", target, host)
		resp, err := http.ReadResponse(br, &http.Request{Method: "HEAD"}) //nolint:bodyclose // a HEAD answer carries no body
		if err != nil {
			t.Fatalf("HEAD %s: no answer — the relay is waiting for a body a HEAD answer never has: %v", path, err)
		}
		if resp.Header.Get("Upload-Offset") != "5" {
			t.Fatalf("HEAD %s: the answer lost its headers: %v", path, resp.Header)
		}
	}

	t.Run("TLS intercept keeps the tunnel framed for the next request", func(t *testing.T) {
		certDir := t.TempDir()
		cert, _ := generateSelfSigned(t, certDir)
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		serveScripted(t, ln, headScript)
		origin := ln.Addr().String()
		proxyAddr, pool, _, _ := startInterceptProxy(t)
		conn, br := openInterceptTunnel(t, proxyAddr, origin, pool)

		for _, path := range []string{"/files/cl", "/files/chunked"} {
			head(t, conn, br, path, origin, path)
			// The same tunnel, and behind it the same upstream connection: this parses only if neither
			// side read past the HEAD answer's head.
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "GET /after HTTP/1.1\r\nHost: %s\r\n\r\n", origin)
			resp, err := http.ReadResponse(br, &http.Request{Method: "GET"}) //nolint:bodyclose // closed by the loop below
			if err != nil {
				t.Fatalf("after HEAD %s, the next request on the tunnel got no answer: %v", path, err)
			}
			if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "after" {
				t.Fatalf("after HEAD %s, the next response was misframed: %q, %v", path, body, err)
			}
		}
	})

	t.Run("plain leg answers at once and records no open-ended stream", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serveScripted(t, ln, headScript)
		origin := ln.Addr().String()
		store := core.NewTrafficStore()
		_, proxyAddr := startPlainProxy(t, store, testScope())

		// The plain leg serves one request per client connection, so each HEAD gets its own.
		for _, path := range []string{"/files/cl", "/files/chunked"} {
			conn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				t.Fatal(err)
			}
			head(t, conn, bufio.NewReader(conn), "http://"+origin+path, origin, path)
			conn.Close()

			// A HEAD answer admitted as a stream was recorded only when the 30 s window closed, and
			// then as an open-ended response — a note that is false for a message with no body.
			ex := awaitExchangeFor(t, store, path, "plain")
			if ex.Notes != nil && strings.Contains(*ex.Notes, "open-ended") {
				t.Errorf("HEAD %s was recorded as a stream: %q", path, *ex.Notes)
			}
		}
	})
}

// A chunked answer that also declares a Content-Length is forwarded without it, in both positions of
// the strip switch. With strip on the Transfer-Encoding used to go and the Content-Length stay, so a
// client read that many bytes of the now close-delimited body ("hel" of "hello world") and parsed the
// rest as the next response. Transfer-Encoding wins (RFC 9112 §6.3), and a proxy must drop the
// Content-Length before forwarding (§6.1). The assertion reads the raw forwarded head, because Go's
// own parser quietly discards the conflicting field and would pass either way.
func TestAChunkedAnswerThatAlsoDeclaresAContentLengthIsForwardedWithoutIt(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	serveScripted(t, ln, headScript)
	origin := ln.Addr().String()
	proxyAddr, pool, srv, _ := startInterceptProxy(t)

	for _, strip := range []bool{true, false} {
		t.Run(fmt.Sprintf("strip=%v", strip), func(t *testing.T) {
			srv.config.Streaming().SetResponseHandling(true, strip, false)
			conn, br := openInterceptTunnel(t, proxyAddr, origin, pool)
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "GET /both HTTP/1.1\r\nHost: %s\r\n\r\n", origin)

			var head strings.Builder
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					t.Fatalf("reading the forwarded head: %v (so far %q)", err, head.String())
				}
				head.WriteString(line)
				if line == "\r\n" {
					break
				}
			}
			if strings.Contains(strings.ToLower(head.String()), "\ncontent-length:") {
				t.Errorf("the forwarded head still declares the origin's Content-Length beside its chunked framing:\n%s", head.String())
			}
			resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader(head.String()), br)), &http.Request{Method: "GET"}) //nolint:bodyclose // the answer is read, not kept
			if err != nil {
				t.Fatalf("parse the forwarded response: %v", err)
			}
			if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "hello world" {
				t.Errorf("the client read %q (%v), want the whole body %q", body, err, "hello world")
			}
		})
	}
}
