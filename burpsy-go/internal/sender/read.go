package sender

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// maxInterimResponses bounds how many 1xx interim heads will be skipped before the peer is treated as
// misbehaving. A conformant server sends at most a handful — a 103 Early Hints then a 100 Continue is
// the realistic maximum — and an endless stream of them is a peer keeping the connection busy for
// nothing, which needs a floor rather than a spin.
const maxInterimResponses = 8

// maxStreamingBodyBytes bounds what one open-ended response contributes to memory.
//
// Deliberately smaller than httputil.MaxResponseBodyBytes: that cap bounds a response that intends to
// end, and this one bounds a response that does not. An event stream left open for the whole streaming
// window can produce bytes for as long as the window lasts, so the bound has to be one an operator can
// afford to hold per streaming exchange rather than the largest response worth storing.
const maxStreamingBodyBytes = 8 * 1024 * 1024

// readResponse reads one *final* response off br.
//
// # Two behaviours that were previously not decisions
//
// Interim statuses: a `100 Continue` is not a response, it is the peer saying "go on". Before this the
// raw read path returned it to its caller as though it were the answer — so a request carrying
// `Expect: 100-continue` against a compliant server produced a 100 in the repeater pane and the real
// response was never read off the socket. Skipping interim heads is what NetworkSettings.Continue's
// Understand100 turns on, and it is on by default because returning an interim status as a result is
// simply wrong. Turning it off is for the operator deliberately inspecting the interim exchange.
//
// A 101 is never skipped. It is not interim: it is the last HTTP response on that connection, and the
// bytes after it belong to whatever protocol was upgraded to. Reading past it would consume the first
// WebSocket frames as though they were an HTTP head.
//
// Streaming: for a host declared open-ended, the read deadline firing is the expected termination
// rather than a failure, so what arrived is returned instead of an error. Before this an event stream
// was indistinguishable from a hung target — the deadline fired inside the body read and the whole
// response, head included, came back as nothing but an error string.
func readResponse(br *bufio.Reader, understand100, streaming bool) ([]byte, error) {
	for interim := 0; ; interim++ {
		head, err := httputil.ReadResponseHead(br)
		if err != nil {
			return nil, err
		}

		if streaming {
			// Best effort by design: for a declared streaming host the only way this read ends is the
			// deadline or the cap, so the error is the expected outcome and the bytes are the result.
			// The head is returned even when no body byte arrived, which is the case the old path lost.
			body := drainStreamingBody(br)
			raw := make([]byte, 0, len(head)+len(body))
			raw = append(raw, head...)
			return append(raw, body...), nil
		}

		body, err := httputil.ReadResponseBody(br, head)
		if err != nil {
			return nil, err
		}
		raw := make([]byte, 0, len(head)+len(body))
		raw = append(raw, head...)
		raw = append(raw, body...)

		if !understand100 || !isInterimHead(head) {
			return raw, nil
		}
		if interim+1 >= maxInterimResponses {
			return raw, fmt.Errorf("peer sent %d interim responses without a final one",
				maxInterimResponses)
		}
		// A 1xx carries no body (httputil.ReadResponseBody enforces the same rule), so br is
		// positioned at the start of the next head and the loop reads it.
	}
}

// drainStreamingBody reads whatever a streaming response has produced, up to the cap.
//
// The error is dropped deliberately, and this is the one place in the package where that is right: the
// caller has declared that this host's responses do not end, so "the read stopped" is the terminating
// condition rather than a fault to report. io.CopyN reports io.EOF for a peer that closed and a
// deadline error for one that simply had nothing more to say inside the window, and neither is news.
func drainStreamingBody(br *bufio.Reader) []byte {
	var body bytes.Buffer
	io.CopyN(&body, br, maxStreamingBodyBytes)
	return body.Bytes()
}

// isInterimHead reports whether a response head is a 1xx that is not 101.
//
// Parsed off the status line rather than trusted from a caller, because this decides whether more
// bytes are read off the socket: reading again after a final response would block until the peer's
// next response or the deadline, and reading no further after an interim one returns the wrong answer.
func isInterimHead(head []byte) bool {
	code, ok := statusCode(head)
	if !ok {
		return false
	}
	return code >= 100 && code < 200 && code != 101
}

// statusCode reads the numeric status off a response's first line.
//
// Deliberately not httputil.ResponseStatus: that takes a whole response and returns a *int, and the
// decision here is made on a head alone and is a two-value question. The parse is positional the same
// way httputil's own noBody test is — "HTTP/1.1 100 Continue" puts the code at bytes 9..12 — but it
// finds the code by splitting on the first space rather than assuming that offset, so a peer answering
// "HTTP/1.10" or an unusual version string does not silently read as a 1xx.
func statusCode(head []byte) (int, bool) {
	line := head
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimRight(line, "\r")
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		return 0, false
	}
	rest := line[sp+1:]
	if end := bytes.IndexByte(rest, ' '); end >= 0 {
		rest = rest[:end]
	}
	code, err := strconv.Atoi(string(rest))
	if err != nil {
		return 0, false
	}
	return code, true
}
