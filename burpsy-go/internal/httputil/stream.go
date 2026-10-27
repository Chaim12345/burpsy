package httputil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// This file is the streaming half of the framing helpers. ReadResponseBody buffers a response that
// intends to end; this reads one that may not, and hands each chunk to a caller as it arrives
// instead of withholding everything until the peer closes.
//
// # Why the proxy needs this at all
//
// An open-ended response — an SSE stream, a long-poll, a server-sent event feed — has no
// Content-Length and no terminal chunk. ReadResponseBody's unframed branch copies until EOF, and on
// such a response EOF never comes, so the client is sent nothing at all until the proxy's own
// deadline eventually fires. To a browser that is indistinguishable from a hung target, and the
// event stream never renders. Burp's own documentation names the failure exactly: waiting for a
// response to end before forwarding any of it means "none of the response is ever forwarded" for
// this shape, and its answer is to pass these responses straight through in real time
// (burpsy-react-ui-wet3).
//
// The sender already had this shape (internal/sender/read.go's drainStreamingBody) and the proxy did
// not, which is the asymmetry the bead records. What is here is the shared form: the framing
// decision is made once, from the head, and the three cases — chunked, length-delimited, unframed —
// are told apart by the same header test ReadResponseBody uses.

// MaxStreamingBodyBytes bounds what one streaming response contributes to memory.
//
// Deliberately smaller than MaxResponseBodyBytes: that cap bounds a response that intends to end,
// and this one bounds a response that does not. A stream left open for the whole streaming window
// can produce bytes for as long as the window lasts, so the bound has to be one an operator can
// afford to hold per streaming exchange rather than the largest response worth storing. The same
// value and the same reasoning as internal/sender's maxStreamingBodyBytes — one cap, two callers, so
// a stream costs the same whether the operator sent it from Repeater or a browser sent it through
// the proxy.
const MaxStreamingBodyBytes = 8 * 1024 * 1024

// StreamResult is what a streaming read produced.
type StreamResult struct {
	// Body is everything read, up to the cap. On a stream that ended cleanly this is the whole
	// response; on one cut off by the window or the cap it is the prefix that arrived, which is
	// still worth showing — a partial event stream is the answer, and returning nothing for it is
	// the defect this path exists to fix.
	Body []byte
	// Truncated is true when the read stopped short of the response's own end: the peer's framing
	// never completed it, or the cap was reached. The caller says so rather than presenting a
	// cut-off body as a complete one.
	Truncated bool
	// Completed is true when the peer's own framing ended the body — a terminal chunk, a satisfied
	// Content-Length, or an EOF on an unframed response. That is a different fact from Truncated and
	// is reported differently.
	Completed bool
}

// StreamResponse reads a response body that may not end, delivering each chunk of payload to
// onChunk as it arrives and returning what was read.
//
// # The deadline is the caller's, not this function's
//
// There is no timeout parameter. An unframed body runs until the peer closes, until the cap, or
// until the connection's read deadline fires — and the connection is the caller's, because the
// proxy leg and the sender leg set their deadlines from their own settings. A bound this function
// imposed would be a second, invisible timeout that no operator could see or change, and the whole
// reason a streaming host is declared is that the operator chose a window for it. The cap is the
// only bound imposed here, and it is a memory bound rather than a time bound.
//
// # onChunk sees payload, not framing
//
// The chunk headers and trailers a chunked body carries are consumed here and not forwarded: onChunk
// receives the decoded payload. The response head is not included either — the caller already has
// it, and re-sending it would put a second head on the wire. For an unframed body, payload and wire
// bytes are the same thing, which is why a caller that wants to forward verbatim can forward this
// callback's output unchanged.
//
// # Errors versus a stream that stopped
//
// A malformed chunk size or a length-delimited body that ends short is an error: those are protocol
// faults, not the end of a stream. "The read stopped" — EOF on an unframed body, a deadline on any
// body, the cap — is not an error and is reported through Completed and Truncated instead. That
// split is why this returns a result struct rather than ([]byte, error): conflating them is how an
// event stream comes back as a bare failure with nothing in it.
//
// onChunk may be nil, for a caller that only wants the bytes.
func StreamResponse(br *bufio.Reader, head []byte, onChunk func([]byte)) (StreamResult, error) {
	if !responseHasBody(head) {
		return StreamResult{Completed: true}, nil
	}

	te, cl := ResponseFraming(head)

	var out bytes.Buffer
	remaining := MaxStreamingBodyBytes
	emit := func(p []byte) {
		if onChunk == nil {
			return
		}
		// onChunk is handed a copy. The buffer this read fills is returned to the caller, and a
		// callback that kept the slice would be holding a window into bytes about to be appended to.
		chunk := make([]byte, len(p))
		copy(chunk, p)
		onChunk(chunk)
	}

	if strings.EqualFold(te, "chunked") {
		return streamChunked(br, &out, remaining, emit)
	}
	if cl != "" {
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return StreamResult{}, fmt.Errorf("bad Content-Length %q", cl)
		}
		if n == 0 {
			return StreamResult{Completed: true}, nil
		}
		readN := n
		if readN > int64(remaining) {
			readN = int64(remaining)
		}
		// Read and forward the length-delimited body in pieces rather than one ReadFull, so a framed
		// event stream — a `text/event-stream` response the proxy admitted here because the operator
		// turned on "treat text/event-stream responses as streaming" — reaches the client as each piece
		// arrives instead of all at once when the body finishes. Without this an SSE feed that happens to
		// carry a Content-Length would stream in name only: the client would see nothing until the body
		// completed, which is the buffered behaviour the switch exists to escape.
		buf := make([]byte, 32*1024)
		var read int64
		for read < readN {
			want := int64(len(buf))
			if rem := readN - read; want > rem {
				want = rem
			}
			m, err := br.Read(buf[:want])
			if m > 0 {
				out.Write(buf[:m])
				emit(buf[:m])
				read += int64(m)
			}
			if err != nil {
				// A length-delimited body that ends short is a protocol fault, not a stream that stopped:
				// the peer declared a length and did not deliver it. Reporting the error rather than
				// returning the prefix keeps "this response was malformed" distinct from "this response
				// is still arriving".
				return StreamResult{Body: out.Bytes()}, fmt.Errorf("reading body: %w", err)
			}
		}
		return StreamResult{Body: out.Bytes(), Completed: true, Truncated: readN < n}, nil
	}

	// Unframed: the open-ended case, and the one this function exists for. Copy until the cap or the
	// peer stops, handing each read to emit as it lands.
	buf := make([]byte, 32*1024)
	for remaining > 0 {
		want := int64(len(buf))
		if want > int64(remaining) {
			want = int64(remaining)
		}
		n, err := br.Read(buf[:want])
		if n > 0 {
			out.Write(buf[:n])
			emit(buf[:n])
			remaining -= n
		}
		if err != nil {
			// EOF is how an unframed body legitimately ends (HTTP/1.0 close-delimited). Anything else
			// — a deadline, a reset — is the connection stopping, which for a declared open-ended host
			// is the terminating condition rather than a fault.
			return StreamResult{
				Body:      out.Bytes(),
				Completed: err == io.EOF,
				Truncated: err != io.EOF,
			}, nil
		}
		if n == 0 {
			return StreamResult{Body: out.Bytes(), Truncated: true}, nil
		}
	}
	return StreamResult{Body: out.Bytes(), Truncated: true}, nil
}

// streamChunked reads a chunk-framed body, forwarding payload as it lands. A terminal chunk ends it
// cleanly; a stream that simply stops is the open-ended case and reports what arrived.
func streamChunked(br *bufio.Reader, out *bytes.Buffer, remaining int, emit func([]byte)) (StreamResult, error) {
	for {
		sizeLine, err := br.ReadString('\n')
		if err != nil {
			// The stream stopped mid-body. What arrived is the answer for an open-ended response.
			return StreamResult{Body: out.Bytes(), Truncated: true}, nil
		}
		sizeStr := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return StreamResult{Body: out.Bytes()}, fmt.Errorf("bad chunk size %q: %w", sizeStr, err)
		}
		if size == 0 {
			// Terminal chunk; consume trailers to the blank line so the connection is framed again.
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return StreamResult{Body: out.Bytes()}, err
				}
				if strings.TrimSpace(line) == "" {
					return StreamResult{Body: out.Bytes(), Completed: true}, nil
				}
			}
		}
		readSize := size
		if readSize > int64(remaining) {
			readSize = int64(remaining)
		}
		chunk := make([]byte, readSize)
		if readSize > 0 {
			if _, err := io.ReadFull(br, chunk); err != nil {
				return StreamResult{Body: out.Bytes(), Truncated: true}, nil
			}
			out.Write(chunk)
			emit(chunk)
			remaining -= int(readSize)
		}
		// Drop the rest of an over-cap chunk and the CRLF, so the stream stays framed for whatever
		// comes after the cap.
		if drop := size - readSize; drop > 0 {
			if _, err := io.CopyN(io.Discard, br, drop); err != nil {
				return StreamResult{Body: out.Bytes(), Truncated: true}, nil
			}
		}
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(br, crlf); err != nil {
			return StreamResult{Body: out.Bytes(), Truncated: true}, nil
		}
		if remaining <= 0 {
			return StreamResult{Body: out.Bytes(), Truncated: true}, nil
		}
	}
}
