package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// A close-delimited response ends when the connection does, and the connection used to close only
// after the record — passive scan, DOM pass, page observer — had returned. A slow record (here an
// observer held for 3 s; in the field a scan that hung on Juice Shop's /ftp/ listing) kept the client
// waiting for an answer it already had. The client must read its EOF while the record still runs.
func TestACloseDelimitedResponseEndsBeforeTheRecordFinishes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer string // the origin's whole reply; it closes after it
	}{
		{"frameless", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>frameless</body></html>"},
		{"short content-length", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 400\r\n\r\n<html><body>short</body></html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
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
							line, err := br.ReadString('\n')
							if err != nil || line == "\r\n" {
								break
							}
						}
						c.Write([]byte(tc.answer))
					}(c)
				}
			}()

			release := make(chan struct{})
			observed := make(chan struct{}, 1)
			t.Cleanup(func() { close(release) })
			store := core.NewTrafficStore()
			cfg := NewProxyConfig(store).
				WithScope(testScope()).
				WithLogger(zap.NewNop()).
				WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
				WithPageObserver(func(*core.Exchange, []byte) {
					observed <- struct{}{}
					select {
					case <-release:
					case <-time.After(3 * time.Second):
					}
				})
			srv := NewServer(cfg)
			pl, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pl.Close() })
			go func() {
				for {
					c, err := pl.Accept()
					if err != nil {
						return
					}
					go srv.handleConnection(c)
				}
			}()

			conn, err := net.Dial("tcp", pl.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET /page HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr().String())
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			start := time.Now()
			var got bytes.Buffer
			_, _ = got.ReadFrom(conn)
			took := time.Since(start)

			if !strings.Contains(got.String(), "<body>") {
				t.Fatalf("the client did not get the body: %q", got.String())
			}
			if took > 2*time.Second {
				t.Errorf("the client waited %v for the end of a close-delimited response: the record held it", took)
			}
			select {
			case <-observed:
			case <-time.After(5 * time.Second):
				t.Error("the exchange was never recorded")
			}
		})
	}
}
