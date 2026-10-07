package httputil

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// A response that never ends is the whole reason this file exists. ReadResponseBody's unframed branch
// copies until EOF, and on an SSE stream or a long-poll EOF never comes, so the client is sent
// nothing (burpsy-react-ui-wet3). These tests pin the streaming form's contract: chunks arrive as
// they land, a stream that stops is not an error, and what arrived is still returned.

// streamHead builds a complete response head. extra is the header block WITHOUT its trailing blank
// line, which the helper adds. A head missing that terminator is unparseable, and an earlier
// version of this helper omitted it — so four tests below were silently exercising the parser's
// refusal rather than the streaming path, and passing for the wrong reason.
func streamHead(status, extra string) []byte {
	// The terminator is a BLANK line: CRLF CRLF. "status CRLF + headers CRLF" is only one CRLF and
	// parses as a head with no end, which is why an earlier version of this helper made four tests
	// pass for the wrong reason.
	return []byte("HTTP/1.1 " + status + "\r\n" + extra + "\r\n\r\n")
}

// chunkReader feeds a scripted stream and then blocks, so a read that would wait forever does. The
// deadline models what a proxy leg sets: the stream produces its bytes and then simply stops.
type chunkReader struct {
	data []byte
	off  int
	// stopWith is the error the reader reports once its data is exhausted. A deadline error models an
	// open-ended stream inside its window; io.EOF models a close-delimited one.
	stopWith error
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.off < len(r.data) {
		n := copy(p, r.data[r.off:])
		r.off += n
		return n, nil
	}
	if r.stopWith != nil {
		return 0, r.stopWith
	}
	return 0, io.EOF
}

var errWindowClosed = errors.New("read window closed")

func TestAnUnframedStreamDeliversEveryChunkBeforeItStops(t *testing.T) {
	// Three SSE frames, then the window closes with the stream still open — the exact shape that
	// hangs the buffered path.
	raw := "data: one\n\ndata: two\n\ndata: three\n\n"
	br := bufio.NewReader(&chunkReader{data: []byte(raw), stopWith: errWindowClosed})

	var chunks []string
	got, err := StreamResponse(br, streamHead("200 OK", "Content-Type: text/event-stream"), func(p []byte) {
		chunks = append(chunks, string(p))
	})
	if err != nil {
		t.Fatalf("StreamResponse: %v", err)
	}
	if string(got.Body) != raw {
		t.Errorf("body = %q, want the whole stream %q", got.Body, raw)
	}
	if got.Completed {
		t.Error("Completed is true: the peer never framed an end, so this response did not complete")
	}
	if !got.Truncated {
		t.Error("Truncated is false: the stream was cut off and the caller must be able to say so")
	}
	if len(chunks) == 0 {
		t.Fatal("onChunk was never called: the caller was sent nothing until the stream stopped, which is the defect")
	}
	// The chunks must add up to the body — the callback is a view of the same bytes, not a second
	// parse that could disagree with the returned result.
	if joined := strings.Join(chunks, ""); joined != raw {
		t.Errorf("chunks joined = %q, want %q", joined, raw)
	}
}

func TestAnUnframedStreamThatClosesIsCompleteNotTruncated(t *testing.T) {
	raw := "data: one\n\n"
	br := bufio.NewReader(strings.NewReader(raw))
	got, err := StreamResponse(br, streamHead("200 OK", ""), nil)
	if err != nil {
		t.Fatalf("StreamResponse: %v", err)
	}
	if !got.Completed || got.Truncated {
		t.Errorf("Completed=%v Truncated=%v, want true/false: an EOF on an unframed body is how it legitimately ends", got.Completed, got.Truncated)
	}
	if string(got.Body) != raw {
		t.Errorf("body = %q, want %q", got.Body, raw)
	}
}

func TestAChunkedStreamThatNeverTerminatesReturnsWhatArrived(t *testing.T) {
	// A chunked body with no terminal chunk: the stream is cut off, not malformed. The first chunk
	// must be delivered and returned, and the second frame's size line must not be mistaken for
	// payload.
	raw := "5\r\nhello\r\n6\r\n world\r\n"
	br := bufio.NewReader(&chunkReader{data: []byte(raw), stopWith: errWindowClosed})

	var delivered bytes.Buffer
	got, err := StreamResponse(br, streamHead("200 OK", "Transfer-Encoding: chunked"), func(p []byte) { delivered.Write(p) })
	if err != nil {
		t.Fatalf("StreamResponse: %v", err)
	}
	if delivered.String() != "hello world" {
		t.Errorf("delivered = %q, want the decoded payload %q — chunk framing must not reach the client", delivered.String(), "hello world")
	}
	if got.Completed {
		t.Error("Completed is true: there was no terminal chunk")
	}
	if !got.Truncated {
		t.Error("Truncated is false: the chunk stream stopped mid-body")
	}
}

func TestACompleteChunkedStreamIsCompleted(t *testing.T) {
	raw := "5\r\nhello\r\n0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	got, err := StreamResponse(br, streamHead("200 OK", "Transfer-Encoding: chunked"), nil)
	if err != nil {
		t.Fatalf("StreamResponse: %v", err)
	}
	if !got.Completed || got.Truncated {
		t.Errorf("Completed=%v Truncated=%v, want true/false", got.Completed, got.Truncated)
	}
	if string(got.Body) != "hello" {
		t.Errorf("body = %q, want the decoded payload %q", got.Body, "hello")
	}
}

func TestALengthDelimitedBodyIsReadWholeAndIsComplete(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("hello world"))
	got, err := StreamResponse(br, streamHead("200 OK", "Content-Length: 11"), nil)
	if err != nil {
		t.Fatalf("StreamResponse: %v", err)
	}
	if !got.Completed {
		t.Error("Completed is false: a satisfied Content-Length completes the body")
	}
	if string(got.Body) != "hello world" {
		t.Errorf("body = %q", got.Body)
	}
}

func TestALengthDelimitedBodyThatEndsShortIsAnErrorNotAPrefix(t *testing.T) {
	// The peer declared 11 and delivered 5. That is a protocol fault, and returning the prefix with
	// no error would present a truncated response as a complete one.
	br := bufio.NewReader(strings.NewReader("hello"))
	_, err := StreamResponse(br, streamHead("200 OK", "Content-Length: 11"), nil)
	if err == nil {
		t.Fatal("a short length-delimited body returned no error; the caller cannot tell a malformed response from a whole one")
	}
}

func TestABodilessStatusIsNotStreamed(t *testing.T) {
	// 204 and 304 never carry a body. Streaming one would read the NEXT response on a keep-alive
	// connection as though it were this one's body — the same class of bug as reading past a 101.
	for _, status := range []string{"204 No Content", "304 Not Modified", "101 Switching Protocols"} {
		br := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
		called := false
		got, err := StreamResponse(br, streamHead(status, ""), func([]byte) { called = true })
		if err != nil {
			t.Errorf("%s: %v", status, err)
			continue
		}
		if called || len(got.Body) != 0 {
			t.Errorf("%s streamed %d bytes; a status that never carries a body must leave the next response alone", status, len(got.Body))
		}
		if !got.Completed {
			t.Errorf("%s: Completed is false; a bodiless response is complete by definition", status)
		}
	}
}

func TestABadChunkSizeIsAnErrorNotAStream(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("nothex\r\ndata\r\n"))
	if _, err := StreamResponse(br, streamHead("200 OK", "Transfer-Encoding: chunked"), nil); err == nil {
		t.Error("an unparseable chunk size returned no error; a malformed frame is a fault, not a stream that stopped")
	}
}

func TestOnChunkReceivesACopyRatherThanAWindowIntoTheBuffer(t *testing.T) {
	// A callback that kept the slice would be holding bytes the next append can overwrite. The
	// delivered chunks must survive the read that produced them.
	raw := "abcdefghij"
	br := bufio.NewReader(strings.NewReader(raw))
	var kept [][]byte
	_, err := StreamResponse(br, streamHead("200 OK", "Transfer-Encoding: chunked"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Two chunks so the second append has a chance to overwrite the first chunk's backing array —
	// which is the whole hazard a retained slice would expose. Sizes are hex: 5 and 5.
	framed := "5\r\n" + raw[:5] + "\r\n5\r\n" + raw[5:] + "\r\n0\r\n\r\n"
	br2 := bufio.NewReader(strings.NewReader(framed))
	_, err = StreamResponse(br2, streamHead("200 OK", "Transfer-Encoding: chunked"), func(p []byte) {
		kept = append(kept, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) < 2 {
		t.Fatalf("got %d chunks, want at least 2", len(kept))
	}
	if string(kept[0]) != "abcde" || string(kept[1]) != "fghij" {
		t.Errorf("chunks = %q/%q, want abcde/fghij — a retained slice was overwritten by the next append", kept[0], kept[1])
	}
}

func TestTheBufferIsBoundedOnAnEndlessStream(t *testing.T) {
	// A stream that never stops must not grow the buffer without limit. The reader below produces
	// data forever; the cap is what stops the loop.
	endless := &endlessReader{}
	br := bufio.NewReader(endless)
	got, err := StreamResponse(br, streamHead("200 OK", "Content-Type: text/event-stream"), nil)
	if err != nil {
		t.Fatalf("StreamResponse: %v", err)
	}
	if len(got.Body) > MaxStreamingBodyBytes {
		t.Errorf("buffered %d bytes, over the %d cap", len(got.Body), MaxStreamingBodyBytes)
	}
	if !got.Truncated {
		t.Error("Truncated is false: the cap stopped an endless stream and the caller must know")
	}
}

// endlessReader produces data forever, in modest blocks, and never returns an error — the shape that
// would spin a reader with no cap.
type endlessReader struct{}

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestTheHeadIsNotIncludedInWhatOnChunkSees(t *testing.T) {
	// The caller already has the head and writes it itself; a callback that saw it would put a
	// second head on the wire.
	br := bufio.NewReader(strings.NewReader("5\r\nhello\r\n0\r\n\r\n"))
	var delivered bytes.Buffer
	_, err := StreamResponse(br, streamHead("200 OK", "Transfer-Encoding: chunked"), func(p []byte) { delivered.Write(p) })
	if err != nil {
		t.Fatal(err)
	}
	if delivered.String() != "hello" {
		t.Errorf("delivered = %q, want only the payload", delivered.String())
	}
}

func TestTheWindowIsTheCallersDeadlineNotThisFunctions(t *testing.T) {
	// Documents the contract this function deliberately does not enforce: the read deadline belongs
	// to the connection. A reader whose data runs out and then blocks forever is what an unbounded
	// window would look like from here, and the cap is the only bound this package imposes.
	//
	// The assertion is that StreamResponse returns as soon as the reader reports an error, so a
	// caller-set deadline is what ends an open-ended read — not a timeout hidden in this function.
	br := bufio.NewReader(&chunkReader{data: []byte("data: x\n\n"), stopWith: errWindowClosed})
	start := time.Now()
	_, err := StreamResponse(br, streamHead("200 OK", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("StreamResponse took %v; the reader's error should end the read immediately", elapsed)
	}
}
