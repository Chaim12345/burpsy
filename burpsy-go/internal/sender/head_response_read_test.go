package sender

import (
	"bufio"
	"strings"
	"testing"
)

// A HEAD answer ends at its head. Reading the Content-Length it describes blocked until the
// deadline and failed the send; here the bytes after the head belong to the next response.
func TestReadResponseToHEADStopsAtTheHead(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(head + "HTTP/1.1 204 No Content\r\n\r\n"))
	resp, _, err := readResponse(br, "HEAD", true, false, nil)
	if err != nil || string(resp) != head {
		t.Fatalf("HEAD read = %q, %v, want the head alone", resp, err)
	}
	if requestMethod([]byte("HEAD /x HTTP/1.1\r\n\r\n")) != "HEAD" {
		t.Error("requestMethod did not read the method")
	}
}
