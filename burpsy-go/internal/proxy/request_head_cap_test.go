package proxy

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"time"
)

// A client that streams header lines without end used to grow readFullRequest's buffer until the
// process ran out of memory (burpsy-react-ui-proxy-no-timeouts). The head is now refused at
// maxRequestHeadBytes — and refused having read only about that much, not after reading it all.
func TestAnEndlessRequestHeadIsRefusedAtTheCap(t *testing.T) {
	var fed int64
	endless := io.Reader(readerFunc(func(p []byte) (int, error) {
		line := "X-Pad: " + strings.Repeat("a", 100) + "\r\n"
		n := copy(p, line)
		fed += int64(n)
		return n, nil
	}))
	got := readFullRequest("GET / HTTP/1.1\r\n", bufio.NewReader(endless))
	if got != nil {
		t.Fatalf("an endless head came back as %d bytes instead of being refused", len(got))
	}
	if fed > 2*maxRequestHeadBytes {
		t.Errorf("read %d bytes before refusing a head capped at %d", fed, maxRequestHeadBytes)
	}
	// One line with no newline at all is the same attack.
	noNewline := readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = 'a'
		}
		return len(p), nil
	})
	if got := readFullRequest("GET / HTTP/1.1\r\n", bufio.NewReader(noNewline)); got != nil {
		t.Fatalf("a newline-less header line came back as %d bytes", len(got))
	}
	// And an ordinary head under the cap is untouched.
	ok := readFullRequest("GET / HTTP/1.1\r\n", bufio.NewReader(strings.NewReader("Host: a\r\n\r\n")))
	if string(ok) != "GET / HTTP/1.1\r\nHost: a\r\n\r\n" {
		t.Errorf("a normal head = %q", ok)
	}
}

func TestTheUpstreamDialerIsBounded(t *testing.T) {
	if d := (&Server{}).upstreamDialer(); d.Timeout <= 0 || d.Timeout > time.Minute {
		t.Errorf("upstream dial timeout = %v; want a bound under a minute, not the OS connect timeout", d.Timeout)
	}
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }
