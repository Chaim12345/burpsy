package httputil

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// withBodyCap lowers ReadResponseBody's cap for one test, so the cut can be exercised without
// pushing 64 MiB through every case.
func withBodyCap(t *testing.T, n int) {
	t.Helper()
	old := maxResponseBodyBytes
	maxResponseBodyBytes = n
	t.Cleanup(func() { maxResponseBodyBytes = old })
}

// TestABodyCutAtTheCapIsReportedNotSilent is burpsy-react-ui-h1-cap-silent: the HTTP/1 reader used
// to stop at the cap and return the prefix with a nil error, so a cut body was indistinguishable
// from a whole one — unlike the h2 and h3 legs, which note it. Every framing that can pass the cap
// now returns the prefix WITH a *BodyCapError; every framing that ends at or inside it does not.
func TestABodyCutAtTheCapIsReportedNotSilent(t *testing.T) {
	withBodyCap(t, 8)
	cases := []struct {
		name     string
		head     string
		wire     string
		wantBody string
		framing  string // "" means the body is whole: no error at all
	}{
		{"content-length over", "Content-Length: 12", "0123456789ab", "01234567", FramingContentLength},
		{"content-length exactly at", "Content-Length: 8", "01234567", "01234567", ""},
		{"content-length under", "Content-Length: 3", "012", "012", ""},
		{"chunked over mid-chunk", "Transfer-Encoding: chunked", "c\r\n0123456789ab\r\n0\r\n\r\n", "c\r\n01234567", FramingChunked},
		{"chunked over on a boundary", "Transfer-Encoding: chunked", "8\r\n01234567\r\n4\r\nabcd\r\n0\r\n\r\n", "8\r\n01234567\r\n", FramingChunked},
		{"chunked exactly at", "Transfer-Encoding: chunked", "8\r\n01234567\r\n0\r\n\r\n", "8\r\n01234567\r\n0\r\n\r\n", ""},
		{"chunked under", "Transfer-Encoding: chunked", "3\r\n012\r\n0\r\n\r\n", "3\r\n012\r\n0\r\n\r\n", ""},
		{"close-delimited reaching the cap", "X-None: 1", "0123456789ab", "01234567", FramingCloseDelimited},
		{"close-delimited under", "X-None: 1", "012", "012", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			head := []byte("HTTP/1.1 200 OK\r\n" + c.head + "\r\n\r\n")
			body, err := ReadResponseBody(bufio.NewReader(strings.NewReader(c.wire)), head)
			if string(body) != c.wantBody {
				t.Errorf("body = %q, want %q", body, c.wantBody)
			}
			var capErr *BodyCapError
			if c.framing == "" {
				if err != nil {
					t.Fatalf("a whole body came back with an error: %v", err)
				}
				return
			}
			if !errors.As(err, &capErr) {
				t.Fatalf("a body past the cap came back with err = %v; want *BodyCapError", err)
			}
			if capErr.Framing != c.framing || capErr.Cap != 8 || capErr.Received != 8 {
				t.Errorf("cap error = %+v; want framing %s, cap 8, received 8", capErr, c.framing)
			}
			if !strings.Contains(capErr.Note(), "8-byte cap") {
				t.Errorf("note does not name the cap: %q", capErr.Note())
			}
		})
	}
}

// TestTheCapNoteMatchesTheH2AndH3Wording: one operator-facing sentence for the same event on every
// protocol, so a reader of history learns one phrase.
func TestTheCapNoteMatchesTheH2AndH3Wording(t *testing.T) {
	e := &BodyCapError{Cap: MaxResponseBodyBytes, Framing: FramingChunked}
	if want := "the response body passed the 67108864-byte cap and was cut there"; e.Note() != want {
		t.Fatalf("Note = %q, want %q", e.Note(), want)
	}
}
