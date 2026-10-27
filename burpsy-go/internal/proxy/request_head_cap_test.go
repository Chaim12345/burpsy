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
	got, tooLarge := readFullRequestBounded("GET / HTTP/1.1\r\n", bufio.NewReader(endless))
	if !tooLarge || got != nil {
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
	if got, tooLarge := readFullRequestBounded("GET / HTTP/1.1\r\n", bufio.NewReader(noNewline)); !tooLarge {
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

// The request-side chunk decoder bounds its size lines and its trailer section the way the header
// block is bounded: an endless size line, or endless trailers after the last chunk, are refused
// rather than buffered (burpsy-react-ui-bodycap-note-lost).
func TestTheRequestChunkDecoderBoundsItsLines(t *testing.T) {
	endless := func(prefix string, line string) *bufio.Reader {
		sent := false
		return bufio.NewReader(readerFunc(func(p []byte) (int, error) {
			if !sent {
				sent = true
				return copy(p, prefix), nil
			}
			n := 0
			for n < len(p) {
				n += copy(p[n:], line)
			}
			return n, nil
		}))
	}
	done := make(chan bool, 2)
	go func() { _, ok := readChunkedBody(endless("", "f")); done <- ok }()
	go func() { _, ok := readChunkedBody(endless("1\r\na\r\n0\r\n", "X-T: v\r\n")); done <- ok }()
	for i := 0; i < 2; i++ {
		select {
		case ok := <-done:
			if ok {
				t.Error("an unbounded chunk stream was accepted as a complete body")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the chunk decoder kept reading an endless line")
		}
	}
	body, ok := readChunkedBody(bufio.NewReader(strings.NewReader("3\r\nabc\r\n0\r\nX-T: v\r\n\r\n")))
	if !ok || string(body) != "abc" {
		t.Errorf("a normal chunked body = %q, %v", body, ok)
	}
}
