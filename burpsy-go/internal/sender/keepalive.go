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
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

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
	timer     *time.Timer
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
func (p *http1Pool) take(key string, needOfferedH2 bool) *idleConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	for i := len(list) - 1; i >= 0; i-- {
		ic := list[i]
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
func reusableAfter(request, response []byte) bool {
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

// staleReuse reports whether err on a kept connection is the server's idle close rather than an
// answer: the connection was gone before any response byte arrived.
func staleReuse(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed)
}
