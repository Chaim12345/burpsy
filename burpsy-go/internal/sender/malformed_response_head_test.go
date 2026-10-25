package sender

// burpsy-react-ui-0vzb.24, end to end: a response carrying a CRLF-split header line comes back to
// the caller whole, injected bytes included — never as one "malformed MIME header" error with the
// evidence discarded. classifyFraming names the same framing the reader uses, because pipeline.go's
// own invariant is that the two can never disagree about what a head means.

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadResponseReturnsAHeadWithAMalformedHeaderLineWhole(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: session=x\r\ninjected: yes\r\n" +
		"colonless\r\n\r\nhello"
	resp, err := readResponse(bufio.NewReader(strings.NewReader(raw)), true, false, nil)
	if err != nil {
		t.Fatalf("the response must come back whole, not as an error: %v", err)
	}
	if string(resp) != raw {
		t.Fatalf("the raw response changed on the way back.\ngot:  %q\nwant: %q", resp, raw)
	}
	if !strings.Contains(string(resp), "injected: yes") || !strings.Contains(string(resp), "colonless") {
		t.Fatalf("the injected bytes are the evidence; they must be in the response: %q", resp)
	}
}

func TestClassifyFramingSeesPastAMalformedHeaderLine(t *testing.T) {
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\ninjected\r\n\r\n")
	if got := classifyFraming(head); got != framingContentLength {
		t.Fatalf("framing = %q, want %q — the reader frames this body by Content-Length now, and the name must agree", got, framingContentLength)
	}
	chunked := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\ninjected\r\n\r\n")
	if got := classifyFraming(chunked); got != framingChunked {
		t.Fatalf("framing = %q, want %q", got, framingChunked)
	}
}
