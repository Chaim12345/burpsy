package sender

// PR #363 review: httputil.ReadResponseBody wrapped ANY io.ReadFull error as a
// TruncatedBodyError, so a body read killed by the caller's deadline was salvaged as a
// complete response - bytes the origin never finished sending, recorded as if it had.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// PR #363 review: a body read killed by the caller's deadline is a FAILED send, not a
// salvageable truncation - the origin was still writing, so the partial is not "everything it
// sent". Salvaging it completed a response the origin never finished.
func TestABodyReadKilledByTheDeadlineFailsTheSend(t *testing.T) {
	srv := startTruncatingListingServer(t, 1*time.Second)
	host, port := mustHostPort(t, srv.addr)
	s := NewSender(DefaultSenderConfig())
	raw := []byte("GET /ftp/ HTTP/1.1\r\nHost: " + srv.addr + "\r\n\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _, err := s.SendRawOutcome(ctx, host, port, false, raw, ProtocolPreferenceHTTP1)
	if err == nil {
		t.Fatal("a body read killed by the deadline was salvaged as a complete response")
	}
	var truncated *httputil.TruncatedBodyError
	if errors.As(err, &truncated) {
		t.Fatalf("a timeout masqueraded as a clean truncation: %v", err)
	}
	// Let the server's keep-alive hold run out so its goroutine is done before the test is.
	time.Sleep(1200 * time.Millisecond)
}
