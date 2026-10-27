package proxy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// ibhs: native fuzz for the proxy's own parsers. Crashers, if any, land in testdata
// via the go fuzzer; this file carries the seed corpus. Short local smoke runs; W5
// schedules the nightly-length runs.

// FuzzParseClientHelloALPN feeds arbitrary bytes to the ClientHello ALPN extraction
// tls_peek performs on every TLS-tunnel connect.
func FuzzParseClientHelloALPN(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x2f, 0x03, 0x03})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, record []byte) {
		protos, err := parseClientHelloALPN(record)
		if err != nil {
			if protos != nil {
				t.Fatalf("errored parse returned protocols: %v", protos)
			}
			return
		}
		for _, p := range protos {
			if p == "" {
				t.Fatalf("empty protocol name from %q", record)
			}
		}
	})
}

// FuzzAltSvcLearn feeds arbitrary Alt-Svc header values to the vln3 table. Property:
// whatever it learns, a lookup for the same origin returns either nothing or an
// endpoint of the origin's own host with a real port.
func FuzzAltSvcLearn(f *testing.F) {
	f.Add("example.com", uint16(443), `h3=":8443"`)
	f.Add("example.com", uint16(443), `h3=":8443"; ma=3600`)
	f.Add("example.com", uint16(443), `h2=":443", h3=":99999"`)
	f.Add("example.com", uint16(443), "clear")
	f.Add("example.com", uint16(443), `h3="other.example:8443"`)
	f.Add("example.com", uint16(443), "h3=':8443'")
	f.Add("example.com", uint16(443), "")
	f.Add("example.com", uint16(443), `h3=":0"`)
	f.Add("example.com", uint16(443), `h3=":-1"`)
	f.Fuzz(func(t *testing.T, host string, port uint16, header string) {
		table := newAltSvcTable()
		now := time.Now()
		table.learn(host, port, header, now)
		if endpoint, ok := table.h3Endpoint(host, port, now); ok {
			prefix := host + ":"
			if !strings.HasPrefix(endpoint, prefix) {
				t.Fatalf("learned an endpoint off the origin's host: %q from %q", endpoint, header)
			}
		}
		// "clear" always wins for its origin.
		table.learn(host, port, `h3=":8443"`, now)
		table.learn(host, port, "clear", now)
		if endpoint, ok := table.h3Endpoint(host, port, now); ok {
			t.Fatalf("clear left an endpoint: %q", endpoint)
		}
	})
}

// FuzzProxyDechunk covers the proxy's private dechunk copy (options.go) - the
// canonical httputil.Dechunk has its own fuzzer; this one guards the divergence.
func FuzzProxyDechunk(f *testing.F) {
	f.Add([]byte("4\r\nWiki\r\n0\r\n\r\n"))
	f.Add([]byte("1a;ext=1\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n"))
	f.Add([]byte("zz\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		out, ok := httputil.Dechunk(body)
		if ok && len(out) > len(body) {
			t.Fatalf("dechunk grew the body: %d bytes in, %d out", len(body), len(out))
		}
	})
}

// FuzzReadFullRequest feeds arbitrary request lines and head bytes to the head
// reader every plaintext request passes through.
func FuzzReadFullRequest(f *testing.F) {
	f.Add("GET / HTTP/1.1\r\n", "Host: x\r\n\r\n")
	f.Add("POST /a HTTP/1.1\r\n", "Content-Length: 5\r\n\r\nhello")
	f.Add("GET / HTTP/1.1\r\n", "Content-Length: 999999999\r\n\r\n")
	f.Add("\r\n", "\r\n")
	f.Add("G\x00T / HTTP/1.1\r\n", "H: v\r\n\r\n")
	f.Fuzz(func(t *testing.T, requestLine, rest string) {
		got := readFullRequest(requestLine, bufio.NewReader(strings.NewReader(rest)))
		if got == nil {
			// Refused only for a head past the cap; anything smaller must come back.
			if len(requestLine)+len(rest) <= maxRequestHeadBytes {
				t.Fatalf("a %d-byte request was refused as an oversized head", len(requestLine)+len(rest))
			}
			return
		}
		if !bytes.HasPrefix(got, []byte(requestLine)) {
			t.Fatalf("head reader dropped the request line: %q -> %q", requestLine, got)
		}
	})
}
