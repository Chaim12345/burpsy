package sender

// HTTP/1 keep-alive (burpsy-react-ui-ry5n): Burp's "Use keep-alive for HTTP/1 if the server supports
// it" (settings/network/http.html, project_options.http.http1.enable_keep_alive, off by default).
//
// Off, every raw send dials its own connection and closes it, which is what burpsy has always done
// and what Burp does by default. On, a connection whose exchange left it reusable is kept idle for
// its authority and the next raw HTTP/1 send to that authority writes on it instead of dialling.
// Burp "closes any open TCP connections after five seconds of inactivity", and so does this pool.
//
// What makes a connection reusable is decided from the bytes of the exchange, never assumed: the
// response must be HTTP/1.1, must not be a 101, must be framed (Content-Length, chunked, or a status
// or method that has no body) so the read ended where the response did, and neither side may have
// said Connection: close. An open-ended (streaming) host is never pooled.
//
// Only HTTP/1 connections are pooled. An h2 connection is never kept, and a TLS connection kept after
// an h2 offer that the target declined may serve a later send that would offer h2 again: the target
// already answered that question on this connection.
//
// A kept connection the server closed while it sat idle fails on first use; that send is retried
// once on a fresh connection when nothing of a response had been read, the same allowance every
// keep-alive client makes for the race between its write and the server's idle close.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// routeState fingerprints what a connection to this authority would be dialled under right
// now: the upstream rule that routes it and the client certificate its handshake would
// present. Both stores mutate in place (the network settings screens call Policy.Set and
// ClientCerts.Add on the live objects, and nothing rebuilds the sender), so the pool cannot
// wait for a flush event: it stamps every kept connection with this fingerprint and take
// closes any entry whose stamp no longer matches (burpsy-react-ui-o388).
func (s *Sender) routeState(host string, useTLS bool) string {
	route := "direct"
	if s.upstream != nil {
		route = s.upstream.For(host).Raw()
	}
	if !useTLS || s.config == nil || s.config.ClientCerts == nil {
		return route
	}
	if cert := s.config.ClientCerts.For(host); cert != nil && len(cert.Certificate) > 0 {
		sum := sha256.Sum256(cert.Certificate[0])
		return route + "\x00" + hex.EncodeToString(sum[:8])
	}
	return route + "\x00"
}

// http1IdleTimeout is Burp's five seconds of inactivity after which a kept connection is closed.
var http1IdleTimeout = 5 * time.Second

// maxIdlePerAuthority bounds the connections kept for one authority; the oldest goes first.
const maxIdlePerAuthority = 4

type idleConn struct {
	conn       net.Conn
	br         *bufio.Reader
	negotiated string
	// offeredH2 is true when the connection's handshake offered h2 and the target chose otherwise.
	offeredH2 bool
	// route fingerprints what the connection was dialled under - see Sender.routeState. A pooled
	// connection whose route no longer matches the live configuration is never reusable again.
	route string
	timer *time.Timer
}

type http1Pool struct {
	mu   sync.Mutex
	idle map[string][]*idleConn
}

func poolKey(host string, port uint16, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// take returns the most recently kept connection for key, or nil. With needOfferedH2, only a
// connection whose handshake already offered h2 qualifies.
func (p *http1Pool) take(key string, needOfferedH2 bool, route string) *idleConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	for i := len(list) - 1; i >= 0; i-- {
		ic := list[i]
		if ic.route != route {
			// Dialled under a different upstream rule or client identity than the live
			// configuration asks for now. Keeping it would resurrect it the moment the
			// route flipped back, so it is closed, not skipped.
			p.idle[key] = append(list[:i:i], list[i+1:]...)
			list = p.idle[key]
			ic.timer.Stop()
			go ic.conn.Close()
			continue
		}
		if needOfferedH2 && !ic.offeredH2 {
			continue
		}
		p.idle[key] = append(list[:i:i], list[i+1:]...)
		ic.timer.Stop()
		// A cancel watcher racing the end of the previous send may have left a past deadline.
		_ = ic.conn.SetDeadline(time.Time{})
		return ic
	}
	return nil
}

// put keeps ic for key, closing it after http1IdleTimeout unless it is taken first.
func (p *http1Pool) put(key string, ic *idleConn) {
	_ = ic.conn.SetDeadline(time.Time{})
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.idle == nil {
		p.idle = map[string][]*idleConn{}
	}
	list := append(p.idle[key], ic)
	for len(list) > maxIdlePerAuthority {
		list[0].timer.Stop()
		list[0].conn.Close()
		list = list[1:]
	}
	p.idle[key] = list
	ic.timer = time.AfterFunc(http1IdleTimeout, func() { p.expire(key, ic) })
}

func (p *http1Pool) expire(key string, ic *idleConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	for i, kept := range list {
		if kept == ic {
			p.idle[key] = append(list[:i:i], list[i+1:]...)
			ic.conn.Close()
			return
		}
	}
}

// closeAll drops every kept connection: settings changed, so a connection dialled under the old ones
// must not carry the next send.
func (p *http1Pool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, list := range p.idle {
		for _, ic := range list {
			ic.timer.Stop()
			ic.conn.Close()
		}
	}
	p.idle = nil
}

// idleCount is how many connections are kept, for tests.
func (p *http1Pool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, list := range p.idle {
		n += len(list)
	}
	return n
}

// reusableAfter reports whether a connection that carried request and response can carry another.
//
// The request is held to its own framing as strictly as the response is: bytes written past where
// the request's framing ends are a second request (pipelined, or smuggled on purpose by a desync
// probe), and the server's answer to it may arrive after the first response was read. Kept, that
// connection would hand the next send another request's response. So a request is only poolable when
// requestEndsAtFraming says the bytes written are exactly one request.
func reusableAfter(request, response []byte) bool {
	if !requestEndsAtFraming(request) {
		return false
	}
	reqHead, _, _ := bytes.Cut(request, []byte("\r\n\r\n"))
	respHead, _, ok := bytes.Cut(response, []byte("\r\n\r\n"))
	if !ok {
		return false
	}
	statusLine, _, _ := bytes.Cut(respHead, []byte("\r\n"))
	if !bytes.HasPrefix(statusLine, []byte("HTTP/1.1 ")) || len(statusLine) < 12 {
		return false
	}
	status, err := strconv.Atoi(string(statusLine[9:12]))
	if err != nil || status == 101 {
		return false
	}
	if headerHasToken(reqHead, "Connection", "close") || headerHasToken(respHead, "Connection", "close") {
		return false
	}
	method, _, _ := bytes.Cut(reqHead, []byte(" "))
	if string(method) == "HEAD" || status == 204 || status == 304 || (status >= 100 && status < 200) {
		return true
	}
	if headerHasToken(respHead, "Transfer-Encoding", "chunked") {
		return true
	}
	for _, line := range bytes.Split(respHead, []byte("\r\n"))[1:] {
		if field, _, ok := bytes.Cut(line, []byte(":")); ok && bytes.EqualFold(bytes.TrimSpace(field), []byte("Content-Length")) {
			return true
		}
	}
	return false
}

// requestEndsAtFraming reports whether raw is exactly one HTTP/1 request: a head, then the body its
// own framing declares (Content-Length bytes, or a chunked body through its last chunk and trailer
// section, or nothing), and not one byte more.
//
// It answers for pooling only, so every doubt answers false and costs a dial rather than a
// misattributed response: a head that is not CRLF-terminated, an unreadable request line or header
// line, CONNECT (whose 2xx turns the connection into a tunnel), more than one Content-Length or
// Transfer-Encoding field, both together, a Transfer-Encoding other than exactly "chunked", a
// Content-Length that is not plain digits, and a body shorter than declared (the server is still
// waiting for bytes, which the next send would supply). The header checks reuse planH2's octet rules
// (protocol.go) so the two readings of a request's head cannot disagree about what a field is.
func requestEndsAtFraming(raw []byte) bool {
	head, rest, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return false
	}
	lines := strings.Split(string(head), "\r\n")
	method, _, _, ok := splitRequestLine(lines[0])
	if !ok || strings.EqualFold(method, "CONNECT") {
		return false
	}
	contentLength, lengths, encodings := -1, 0, 0
	chunked := false
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !isFieldName(name) {
			return false
		}
		value = strings.Trim(value, " \t")
		if !isFieldValue(value) {
			return false
		}
		switch strings.ToLower(name) {
		case "content-length":
			lengths++
			if value == "" || len(value) > 18 || strings.Trim(value, "0123456789") != "" {
				return false
			}
			contentLength, _ = strconv.Atoi(value)
		case "transfer-encoding":
			encodings++
			chunked = strings.EqualFold(value, "chunked")
			if !chunked {
				return false
			}
		}
	}
	switch {
	case lengths > 1 || encodings > 1 || (lengths == 1 && encodings == 1):
		return false
	case chunked:
		n, ok := chunkedBodyLen(rest)
		return ok && n == len(rest)
	case lengths == 1:
		return len(rest) == contentLength
	default:
		return len(rest) == 0
	}
}

// chunkedBodyLen returns how many bytes of body make up one complete chunked body (RFC 9112 §7.1):
// chunks of hex size, optional extension and CRLF-terminated data, the zero-size last chunk, and the
// trailer section through its empty line. ok is false for anything else, including a body that ends
// before its terminator. Bytes after the terminator are not read; the caller compares the length.
func chunkedBodyLen(body []byte) (int, bool) {
	pos := 0
	for {
		eol := bytes.Index(body[pos:], []byte("\r\n"))
		if eol < 0 {
			return 0, false
		}
		sizeText := string(body[pos : pos+eol])
		if semi := strings.IndexByte(sizeText, ';'); semi >= 0 {
			sizeText = sizeText[:semi]
		}
		sizeText = strings.TrimRight(sizeText, " \t")
		if sizeText == "" || len(sizeText) > 15 || strings.Trim(sizeText, "0123456789abcdefABCDEF") != "" {
			return 0, false
		}
		size, err := strconv.ParseInt(sizeText, 16, 64)
		if err != nil {
			return 0, false
		}
		pos += eol + 2
		if size == 0 {
			for {
				eol := bytes.Index(body[pos:], []byte("\r\n"))
				if eol < 0 {
					return 0, false
				}
				pos += eol + 2
				if eol == 0 {
					return pos, true
				}
			}
		}
		if int64(len(body)-pos) < size+2 {
			return 0, false
		}
		pos += int(size)
		if body[pos] != '\r' || body[pos+1] != '\n' {
			return 0, false
		}
		pos += 2
	}
}

// headerHasToken reports whether any field called name in head carries token in its comma list.
func headerHasToken(head []byte, name, token string) bool {
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		field, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !bytes.EqualFold(bytes.TrimSpace(field), []byte(name)) {
			continue
		}
		for _, part := range bytes.Split(value, []byte(",")) {
			if bytes.EqualFold(bytes.TrimSpace(part), []byte(token)) {
				return true
			}
		}
	}
	return false
}

// writeFailure is a request that could not be written at all, so the server cannot have acted on it.
type writeFailure struct{ err error }

func (w *writeFailure) Error() string { return "write failed: " + w.err.Error() }
func (w *writeFailure) Unwrap() error { return w.err }

// staleReuse reports whether err on a kept connection is the server's idle close rather than an
// answer: the connection was gone before any response byte arrived.
func staleReuse(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed)
}

// retryOnFresh reports whether a send that failed on a kept connection may be sent again on a fresh
// one. A request that was never written may always be. One that was written and then met a closed
// connection may have been acted on by the server, so it is resent only when its method is idempotent
// (RFC 9110 §9.2.2): resending a POST the server already processed would do its work twice.
func retryOnFresh(err error, request []byte) bool {
	var wf *writeFailure
	if errors.As(err, &wf) {
		return true
	}
	if !staleReuse(err) {
		return false
	}
	method, _, _ := bytes.Cut(request, []byte(" "))
	switch string(method) {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	}
	return false
}
