package sender

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// A streaming response cut at maxStreamingBodyBytes was returned as if the stream had ended there.
// It now carries the same cap note and never-pool rule as a capped buffered body
// (burpsy-react-ui-bodycap-note-lost); a stream that ends under the cap carries none.
func TestAStreamingBodyCutAtTheCapSaysSo(t *testing.T) {
	long := io.LimitReader(endlessA{}, maxStreamingBodyBytes+1024)
	body, capped := drainStreamingBody(bufio.NewReader(long))
	if len(body) != maxStreamingBodyBytes {
		t.Fatalf("kept %d bytes, want the cap %d", len(body), maxStreamingBodyBytes)
	}
	if capped == nil || !strings.Contains(capped.Note(), "cap") {
		t.Fatalf("a stream cut at the cap carried no note: %v", capped)
	}
	short, capped := drainStreamingBody(bufio.NewReader(bytes.NewReader([]byte("data: 1\n\n"))))
	if capped != nil || string(short) != "data: 1\n\n" {
		t.Errorf("a stream that ended under the cap = %q, note %v", short, capped)
	}
}

type endlessA struct{}

func (endlessA) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}
