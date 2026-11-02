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
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

const reusedTunnelDenial = `{"error":"forbidden","detail":"this role may not update the job"}`

// startClosingOrigin is a TLS origin that answers every PUT with a 403 JSON body (reading the request
// body first, as Express does), and then — per mode — keeps the connection, says Connection: close
// and closes it, or closes it without saying so (an idle keep-alive timeout that fired before the
// client's next request). It counts the connections it accepted.
func startClosingOrigin(t *testing.T, mode string) (string, *atomic.Int32) {
	t.Helper()
	cert, _ := generateSelfSigned(t, t.TempDir())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for served := 0; ; served++ {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					if mode == "drop-second" && served == 1 {
						return // the request arrived; the origin closes without answering it
					}
					hdr := "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
					if mode == "close" {
						hdr += "Connection: close\r\n"
					}
					fmt.Fprintf(c, hdr+"\r\n%s", len(reusedTunnelDenial), reusedTunnelDenial)
					if mode == "close" || mode == "silent-close" {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), &conns
}

// A client keeps its intercepted tunnel open across requests (python requests.Session does), but
// the proxy's upstream connection behind it can end after any response: the origin says
// Connection: close, or closes an idle keep-alive connection without saying so. The proxy dialled
// the upstream once per tunnel and wrote the next request into the dead socket, read EOF, and closed
// the client's tunnel with no response — RemoteDisconnected on the client, nothing in the log. The
// next request on the tunnel must instead reach the origin over a fresh upstream connection.
func TestTheNextRequestOnATunnelSurvivesTheOriginClosingTheUpstream(t *testing.T) {
	for _, mode := range []string{"keep-alive", "close", "silent-close"} {
		t.Run(mode, func(t *testing.T) {
			origin, conns := startClosingOrigin(t, mode)

			conn, br := openReusedTunnel(t, origin)

			body := `{"status":"done","note":"` + strings.Repeat("x", 200) + `"}`
			for i := 1; i <= 3; i++ {
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(conn, "PUT /api/jobs/7 HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
					origin, len(body), body)
				resp, err := http.ReadResponse(br, &http.Request{Method: "PUT"})
				if err != nil {
					t.Fatalf("PUT #%d on the reused tunnel: no response — the proxy closed the client's tunnel when the upstream was gone: %v", i, err)
				}
				got, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != 403 || string(got) != reusedTunnelDenial {
					t.Fatalf("PUT #%d: %d %q (%v), want the origin's 403 JSON", i, resp.StatusCode, got, err)
				}
				// Simulate a client that does not honour Connection: close; one that does would open a
				// new tunnel, which already worked.
				time.Sleep(50 * time.Millisecond)
			}
			want := int32(1)
			if mode != "keep-alive" {
				want = 3
			}
			if n := conns.Load(); n != want {
				t.Errorf("the origin saw %d upstream connection(s), want %d", n, want)
			}
		})
	}
}

// openReusedTunnel starts a TLS-intercepting proxy and opens one keep-alive tunnel through it to origin,
// offering only http/1.1 as python requests does.
func openReusedTunnel(t *testing.T, origin string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	certDir := t.TempDir()
	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatal(err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).WithScope(testScope()).WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxyAddr := startProxy(t, srv)
	caPEM, err := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, origin)
	if resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"}); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	host, _, _ := net.SplitHostPort(origin)
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	t.Cleanup(func() { conn.Close() })
	return conn, br
}

// When the origin takes a request on a reused connection and closes without answering — a keep-alive
// close racing the request past the reuse check — the request cannot be safely re-sent, and the client
// must be told so with a 502 rather than having its tunnel closed under it.
func TestARequestTheOriginDropsIsAnswered502NotASilentClose(t *testing.T) {
	origin, _ := startClosingOrigin(t, "drop-second")
	conn, br := openReusedTunnel(t, origin)
	for i := 1; i <= 2; i++ {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "PUT /api/jobs/7 HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\n{}", origin)
		resp, err := http.ReadResponse(br, &http.Request{Method: "PUT"})
		if err != nil {
			t.Fatalf("PUT #%d: the client's tunnel was closed with no response: %v", i, err)
		}
		got, _ := io.ReadAll(resp.Body)
		if i == 1 && resp.StatusCode != 403 {
			t.Fatalf("PUT #1: %d %q, want the origin's 403", resp.StatusCode, got)
		}
		if i == 2 && (resp.StatusCode != 502 || !strings.Contains(string(got), "not re-sent")) {
			t.Fatalf("PUT #2: %d %q, want burpsy's 502 saying the dropped request was not re-sent", resp.StatusCode, got)
		}
	}
}
