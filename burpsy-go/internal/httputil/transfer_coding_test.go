package httputil

import (
	"bufio"
	"strings"
	"testing"
)

// The final transfer coding decides the framing: "gzip, chunked" is chunk-framed, a non-chunked
// coding runs to the close of the connection even beside a Content-Length.
func TestFinalTransferCodingDecidesTheFraming(t *testing.T) {
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
	if !ResponseIsChunked([]byte(chunked)) || ResponseIsFrameless([]byte(chunked)) {
		t.Error(`"gzip, chunked" is not read as chunked`)
	}
	body, err := ReadResponseBody(bufio.NewReader(strings.NewReader("3\r\nabc\r\n0\r\n\r\nNEXT")), []byte(chunked))
	if err != nil || string(body) != "3\r\nabc\r\n0\r\n\r\n" {
		t.Errorf("chunked body = %q, %v: the read ran past the terminal chunk", body, err)
	}
	split := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
	if !ResponseIsChunked([]byte(split)) {
		t.Error("two Transfer-Encoding lines are not read as one list")
	}
	closeDelimited := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 2\r\n\r\n"
	if !ResponseIsFrameless([]byte(closeDelimited)) || ResponseIsChunked([]byte(closeDelimited)) {
		t.Error("a non-chunked transfer coding is not close-delimited")
	}
	body, err = ReadResponseBody(bufio.NewReader(strings.NewReader("abcdef")), []byte(closeDelimited))
	if err != nil || string(body) != "abcdef" {
		t.Errorf("close-delimited body = %q, %v: Content-Length was believed over the transfer coding", body, err)
	}
}
