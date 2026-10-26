// Package httputil provides shared HTTP/1.x framing helpers used by the
// proxy and the raw request sender.
package httputil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
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
	te, cl := ResponseFraming(head)
	if cl != "" {
		return false
	}
	if te != "" {
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
	te, _ := ResponseFraming(head)
	return strings.EqualFold(te, "chunked")
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

// ResponseFraming reads the two fields a body reader needs — Transfer-Encoding and
// Content-Length — out of a response head, tolerating header lines that are not well-formed.
//
// net/textproto's ReadMIMEHeader refuses a whole block over one malformed line: a header value
// split by a CRLF injection leaves a fragment with no colon, which is exactly the input the refusal
// fires on, and refusing turned the entire response — injected bytes included — into one "malformed
// MIME header" error. Those injected bytes are the evidence a CRLF probe exists to collect, so the
// reader must see past the line it cannot use rather than discard the message that carries it
// (burpsy-react-ui-0vzb.24). A line with no colon is not framing information, so skipping it costs
// the reader nothing; the framing fields themselves still parse, and obs-fold continuations join
// the field they continue the way ReadMIMEHeader joined them.
//
// Values come back as written (whitespace-trimmed), first occurrence winning — ReadMIMEHeader.Get's
// own rule — so callers keep their existing comparisons.
func ResponseFraming(head []byte) (transferEncoding, contentLength string) {
	// Skip the status line; the fields live after it.
	rest := head
	idx := bytes.IndexByte(rest, '\n')
	if idx < 0 {
		return "", ""
	}
	rest = rest[idx+1:]
	// continued says which field an obs-fold line continues, so "Transfer-Encoding: gzip" followed
	// by "\tchunked" reads the way ReadMIMEHeader would have joined it.
	var continued *string
	for len(rest) > 0 {
		var line []byte
		if idx := bytes.IndexByte(rest, '\n'); idx >= 0 {
			line, rest = rest[:idx], rest[idx+1:]
		} else {
			line, rest = rest, nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if continued != nil {
				*continued = *continued + " " + strings.TrimSpace(string(line))
			}
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			// The malformed line itself: evidence for whoever reads the bytes, not framing
			// information for whoever reads the body.
			continued = nil
			continue
		}
		value = bytes.TrimSpace(value)
		switch {
		case strings.EqualFold(string(name), "Transfer-Encoding") && transferEncoding == "":
			transferEncoding = string(value)
			continued = &transferEncoding
		case strings.EqualFold(string(name), "Content-Length") && contentLength == "":
			contentLength = string(value)
			continued = &contentLength
		default:
			continued = nil
		}
	}
	return transferEncoding, contentLength
}

// ReadResponseBody reads the body that follows a response head, per the
// head's framing. head must be exactly what ReadResponseHead returned. A head
// that never carries a body — 1xx including the 101 upgrade, 204, 304 — reads
// nothing and returns an empty body, leaving whatever follows in br.
func ReadResponseBody(br *bufio.Reader, head []byte) ([]byte, error) {
	var body bytes.Buffer
	if responseHasBody(head) {
		te, cl := ResponseFraming(head)

		// remaining bounds the total body we will buffer, so a malicious upstream
		// that declares a huge Content-Length or streams endless chunks cannot
		// exhaust the proxy's memory. Reads past the cap are truncated.
		remaining := MaxResponseBodyBytes

		if strings.EqualFold(te, "chunked") {
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
		} else if cl != "" {
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
				if n, err := io.ReadFull(br, buf); err != nil {
					// Only a clean end-of-stream shortage is a truncated body to
					// salvage: the peer closed short, so the partial is everything it
					// ever sent — OWASP Juice Shop's serve-index /ftp/ listing
					// declares 59 more bytes than it ever writes. Hand the partial
					// body back with a typed error so a caller that can frame it
					// honestly (close-delimited, see CloseDelimitedHead) may use it;
					// callers that cannot discard it on err exactly as before.
					//
					// Any other failure — a timeout, a cancellation, a reset — means
					// the origin was still writing when the read died, and salvaging
					// that partial as if the reply had completed would invent bytes
					// the origin never sent (PR #363 review: a body read that hits
					// the caller's deadline mid-stream must fail the send, not
					// complete it).
					if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
						return nil, fmt.Errorf("reading body: %w", err)
					}
					body.Write(buf[:n])
					return body.Bytes(), &TruncatedBodyError{Declared: cl, Received: len(body.Bytes()), Err: err}
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

// TruncatedBodyError reports a response body that ended before its declared
// Content-Length with a clean EOF: the peer closed (or stopped) short. A read
// that failed for any other reason — a timeout, a cancellation, a reset — is
// never this error, because the origin was still writing and the partial is
// not "everything it sent". It carries the partial
// body alongside (ReadResponseBody returns it as the result value) because the
// bytes that arrived are still evidence — the honest framing for them is
// close-delimited, which CloseDelimitedHead builds.
type TruncatedBodyError struct {
	Declared string // the Content-Length value the head claimed
	Received int    // the body bytes that actually arrived
	Err      error  // the underlying read error
}

func (e *TruncatedBodyError) Error() string {
	return fmt.Sprintf("reading body: %v (declared Content-Length %s, received %d)", e.Err, e.Declared, e.Received)
}

func (e *TruncatedBodyError) Unwrap() error { return e.Err }

// CloseDelimitedHead reframes a response head for a body that is delimited by
// the end of the connection rather than by its declared framing: Content-Length
// is now false, and Connection/Keep-Alive promise a reusable connection that a
// close-delimited body cannot keep. Transfer-Encoding is left alone: a chunked
// body that ended early is not salvageable this way (its partial bytes still
// carry chunk framing), so no caller should reach this helper for one.
func CloseDelimitedHead(head []byte) []byte {
	lines := bytes.Split(head, []byte("\r\n"))
	out := lines[:0]
	for _, line := range lines {
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("content-length:")) ||
			bytes.HasPrefix(lower, []byte("connection:")) ||
			bytes.HasPrefix(lower, []byte("keep-alive:")) {
			continue
		}
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\r\n"))
}

// EnsureConnectionClose returns rawRequest with its head declaring
// "Connection: close", replacing any Connection lines it already carries.
// The sender uses it after an authority has answered close-delimited once
// (an HTTP/1.0-style response, or a truncated Content-Length body salvaged
// via CloseDelimitedHead): on such an authority the connection is gone
// anyway, and asking for the close up front turns "wait out the peer's
// keep-alive timer for bytes that never come" into an EOF that arrives with
// the body - OWASP Juice Shop's serve-index /ftp/ listing otherwise costs
// ~5s per fetch (59 phantom bytes, server-side keep-alive hold).
//
// A request whose head is not CRLF-terminated is returned unchanged:
// editing bytes one cannot parse is how a proxy corrupts a body.
func EnsureConnectionClose(rawRequest []byte) []byte {
	head, rest, ok := bytes.Cut(rawRequest, []byte("\r\n\r\n"))
	if !ok {
		return rawRequest
	}
	lines := bytes.Split(head, []byte("\r\n"))
	out := lines[:1] // the request line is always kept
	wrote := false
	for _, line := range lines[1:] {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("connection:")) {
			if !wrote {
				out = append(out, []byte("Connection: close"))
				wrote = true
			}
			continue
		}
		out = append(out, line)
	}
	if !wrote {
		out = append(out, []byte("Connection: close"))
	}
	head = bytes.Join(out, []byte("\r\n"))
	out = nil
	result := make([]byte, 0, len(head)+4+len(rest))
	result = append(result, head...)
	result = append(result, '\r', '\n', '\r', '\n')
	return append(result, rest...)
}
