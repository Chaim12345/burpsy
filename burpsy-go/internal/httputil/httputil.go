// Package httputil provides shared HTTP/1.x framing helpers used by the
// proxy and the raw request sender.
package httputil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// ReadHTTPResponse reads one complete HTTP response from conn, respecting
// Content-Length and chunked transfer encoding instead of waiting for EOF
// (which never arrives on a keep-alive connection).
//
// The response is read through a private buffered reader that is discarded on
// return. Callers that must keep reading after the response — a 101 upgrade is
// the one that matters, where the bytes after the head are WebSocket frames —
// must use ReadResponseHead + ReadResponseBody on their own *bufio.Reader so
// the leftover buffered bytes survive.
func ReadHTTPResponse(conn net.Conn) ([]byte, error) {
	data, _, err := ReadHTTPResponseTimed(conn)
	return data, err
}

// ReadHTTPResponseTimed is ReadHTTPResponse plus the instant the response's first
// byte arrived, so a caller can report time-to-first-byte (Burp's "Start response
// timer") separately from the total (its "End response timer"). The read logic is
// exactly ReadHTTPResponse's — the untimed form is now a wrapper of this one, not a
// second copy of the parser — so the two cannot drift, which is the same rule the
// proxy's one-producer capture path follows.
//
// firstByte is meaningful only when err is nil; on error it is the zero time. See
// ReadResponseHeadTimed for how it is taken.
func ReadHTTPResponseTimed(conn net.Conn) ([]byte, time.Time, error) {
	br := bufio.NewReader(conn)
	head, firstByte, err := ReadResponseHeadTimed(br)
	if err != nil {
		return nil, time.Time{}, err
	}
	body, err := ReadResponseBody(br, head)
	if err != nil {
		return nil, time.Time{}, err
	}
	result := make([]byte, 0, len(head)+len(body))
	result = append(result, head...)
	result = append(result, body...)
	return result, firstByte, nil
}

// MaxResponseHeadBytes bounds a response head. A handshake answer is a few
// hundred bytes; the bound exists so a peer that never sends a terminator
// cannot make a caller buffer without limit.
const MaxResponseHeadBytes = 256 * 1024

// MaxResponseBodyBytes bounds a response body. A malicious upstream can declare
// an arbitrarily large Content-Length or chunk size; without a cap a single
// response can exhaust the proxy's memory. Reads past the cap are dropped and
// the body is returned truncated to the limit, exactly as the inflate path in
// the codec does. 64 MiB matches that cap's order of magnitude.
const MaxResponseBodyBytes = 64 * 1024 * 1024

// ReadResponseHead reads one HTTP response head — status line and headers,
// through the terminating blank line — from br. It reads nothing past the
// blank line, so on a 101 response the frame bytes that follow remain in br
// for the caller. The head bytes are returned exactly as they arrived.
func ReadResponseHead(br *bufio.Reader) ([]byte, error) {
	head, _, err := readResponseHead(br, false)
	return head, err
}

// ReadResponseHeadTimed reads one response head and reports when its first byte
// arrived from the peer — the measurement Burp's "Start response timer" is built
// on. The instant is taken by a one-byte Peek that blocks until data is readable,
// so it is the moment the origin's first byte crossed the socket, not the moment
// the whole head finished parsing. It reads nothing more than ReadResponseHead
// does; the two share one loop, differing only in whether the first-byte time is
// captured.
//
// firstByte is the zero time when err is non-nil.
func ReadResponseHeadTimed(br *bufio.Reader) ([]byte, time.Time, error) {
	return readResponseHead(br, true)
}

func readResponseHead(br *bufio.Reader, timed bool) ([]byte, time.Time, error) {
	var firstByte time.Time
	if timed {
		// Peek blocks until at least one byte is buffered, which is exactly the arrival
		// of the response's first byte; it consumes nothing, so the head read below is
		// unaffected and the persistent upstream reader keeps its position.
		if _, err := br.Peek(1); err != nil {
			return nil, time.Time{}, fmt.Errorf("reading response head: %w", err)
		}
		firstByte = time.Now()
	}
	var head bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("reading response head: %w", err)
		}
		head.WriteString(line)
		if head.Len() >= 4 && bytes.HasSuffix(head.Bytes(), []byte("\r\n\r\n")) {
			break
		}
		if head.Len() > MaxResponseHeadBytes {
			return nil, time.Time{}, fmt.Errorf("response head exceeds %d bytes without a terminator", MaxResponseHeadBytes)
		}
	}
	return head.Bytes(), firstByte, nil
}

// ResponseIsFrameless reports whether a response head says nothing about when its body ends — no
// Content-Length and no Transfer-Encoding — and can therefore carry one that does not.
//
// This is the test the proxy's streaming path branches on (burpsy-react-ui-wet3). A response that
// frames itself is buffered, because its end is knowable and the rules and the intercept hold are
// entitled to see the whole message before any of it reaches the client. A response that does not
// frame itself is open-ended by definition, and buffering it is what leaves a browser waiting for a
// stream that never closes.
//
// A status that never carries a body is not frameless for this purpose: it has no body to frame, and
// reading past a 101 would consume the first WebSocket frames as though they were an HTTP body.
func ResponseIsFrameless(head []byte) bool {
	if !responseHasBody(head) {
		return false
	}
	headerBlock := head
	if idx := bytes.IndexByte(headerBlock, '\n'); idx != -1 {
		headerBlock = headerBlock[idx+1:]
	}
	h := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerBlock)))
	mimeHead, err := h.ReadMIMEHeader()
	if err != nil {
		// An unparseable head is not treated as frameless. Refusing to stream is the safe direction:
		// the buffered path is what this proxy did for every response before streaming existed.
		return false
	}
	if strings.TrimSpace(mimeHead.Get("Content-Length")) != "" {
		return false
	}
	if strings.TrimSpace(mimeHead.Get("Transfer-Encoding")) != "" {
		return false
	}
	return true
}

// ResponseIsChunked reports whether a response head declares chunked transfer encoding.
//
// It is the streaming path's second open-ended test, and it exists because a chunked response is not
// a short one: a server-sent-event stream is chunk-framed and then never sends its terminal chunk,
// so "this is chunked" says nothing about whether the response ends (burpsy-react-ui-wet3). What
// makes it open-ended is the missing terminal chunk, which is known only once the read has run —
// so this predicate admits the response to the streaming path and StreamResponse reports at the end
// whether the framing completed.
func ResponseIsChunked(head []byte) bool {
	if !responseHasBody(head) {
		return false
	}
	headerBlock := head
	if idx := bytes.IndexByte(headerBlock, '\n'); idx != -1 {
		headerBlock = headerBlock[idx+1:]
	}
	h := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerBlock)))
	mimeHead, err := h.ReadMIMEHeader()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(mimeHead.Get("Transfer-Encoding")), "chunked")
}

// responseHasBody reports whether a response head can be followed by a body at all.
//
// Status codes that never carry one: every 1xx (including the 101 upgrade, whose bytes belong to
// another protocol), 204, and 304. It is one predicate rather than the inline test ReadResponseBody
// used to carry, because StreamResponse asks the identical question and a second copy of a status
// rule is how the buffered and streaming paths start disagreeing about which responses have bodies —
// one would stream a 204 and the other would not.
//
// The parse is positional on the status line, which is what "HTTP/1.1 204" puts at bytes 9..12, and
// the length guard means a truncated first line reads as "no body" rather than indexing off the
// end. A malformed status line therefore reads as bodiless, which is the same answer a bare LF gives
// in ReadResponseBody's own caller path.
func responseHasBody(head []byte) bool {
	statusLine := head
	if idx := bytes.IndexByte(statusLine, '\n'); idx >= 0 {
		statusLine = statusLine[:idx]
	}
	return !(len(statusLine) >= 12 && (statusLine[9] == '1' || string(statusLine[9:12]) == "204" || string(statusLine[9:12]) == "304"))
}

// ReadResponseBody reads the body that follows a response head, per the
// head's framing. head must be exactly what ReadResponseHead returned. A head
// that never carries a body — 1xx including the 101 upgrade, 204, 304 — reads
// nothing and returns an empty body, leaving whatever follows in br.
func ReadResponseBody(br *bufio.Reader, head []byte) ([]byte, error) {
	var body bytes.Buffer
	if responseHasBody(head) {
		// Skip the status line; ReadMIMEHeader expects headers only.
		headerBlock := head
		if idx := bytes.Index(headerBlock, []byte("\r\n")); idx != -1 {
			headerBlock = headerBlock[idx+2:]
		}
		h := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerBlock)))
		mimeHead, err := h.ReadMIMEHeader()
		if err != nil {
			return nil, fmt.Errorf("parsing response headers: %w", err)
		}

		// remaining bounds the total body we will buffer, so a malicious upstream
		// that declares a huge Content-Length or streams endless chunks cannot
		// exhaust the proxy's memory. Reads past the cap are truncated.
		remaining := MaxResponseBodyBytes

		if te := mimeHead.Get("Transfer-Encoding"); strings.EqualFold(te, "chunked") {
			// Read chunked body until the terminating zero chunk.
			for {
				sizeLine, err := br.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("reading chunk size: %w", err)
				}
				body.WriteString(sizeLine)
				sizeStr := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
				size, err := strconv.ParseInt(sizeStr, 16, 64)
				if err != nil {
					return nil, fmt.Errorf("bad chunk size %q: %w", sizeStr, err)
				}
				if size == 0 {
					// Trailer until blank line.
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return nil, fmt.Errorf("reading chunk trailer: %w", err)
						}
						body.WriteString(line)
						if line == "\r\n" || line == "\n" {
							break
						}
					}
					break
				}
				// Cap the chunk size before allocating: a malicious upstream can
				// declare a multi-exabyte chunk to OOM the proxy. We read at most
				// `remaining` of it and drop the rest of this chunk.
				readSize := size
				if readSize > int64(remaining) {
					readSize = int64(remaining)
				}
				chunk := make([]byte, readSize)
				if readSize > 0 {
					if _, err := io.ReadFull(br, chunk); err != nil {
						return nil, fmt.Errorf("reading chunk data: %w", err)
					}
					remaining -= int(readSize)
				}
				body.Write(chunk)
				// Drain the chunk bytes we chose not to keep, plus the trailing
				// CRLF, so the stream stays framed for any bytes after the cap.
				drop := int64(size - readSize)
				if drop > 0 {
					if _, err := io.CopyN(io.Discard, br, drop); err != nil {
						return nil, fmt.Errorf("discarding oversized chunk: %w", err)
					}
				}
				// Chunk data is followed by CRLF.
				crlf := make([]byte, 2)
				if _, err := io.ReadFull(br, crlf); err != nil {
					return nil, fmt.Errorf("reading chunk terminator: %w", err)
				}
				body.Write(crlf)
				if remaining <= 0 {
					// At the cap: stop reading further chunks rather than looping
					// forever on an endless stream.
					break
				}
			}
		} else if cl := mimeHead.Get("Content-Length"); cl != "" {
			n, err := strconv.ParseInt(cl, 10, 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("bad Content-Length %q", cl)
			}
			if n > 0 {
				// Cap the allocation: a declared Content-Length in the exabytes
				// must not allocate that much before we read a byte.
				readN := n
				if readN > int64(remaining) {
					readN = int64(remaining)
				}
				buf := make([]byte, readN)
				if _, err := io.ReadFull(br, buf); err != nil {
					return nil, fmt.Errorf("reading body: %w", err)
				}
				remaining -= int(readN)
				body.Write(buf)
			}
		} else {
			// No framing: body runs until EOF (HTTP/1.0 style), capped.
			if _, err := io.CopyN(&body, br, int64(remaining)); err != nil && err != io.EOF {
				return nil, fmt.Errorf("reading EOF-delimited body: %w", err)
			}
		}
	}

	return body.Bytes(), nil
}

// ResponseStatus parses the numeric status code from a raw response's first
// line, or nil when the line cannot be read. It exists so senders that talk in
// raw bytes can report a status without a second parse of the whole response.
func ResponseStatus(raw []byte) *int {
	first := raw
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		first = raw[:i]
	}
	fields := bytes.Fields(first)
	if len(fields) < 2 {
		return nil
	}
	if !bytes.HasPrefix(fields[0], []byte("HTTP/")) {
		return nil
	}
	n, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return nil
	}
	return &n
}
