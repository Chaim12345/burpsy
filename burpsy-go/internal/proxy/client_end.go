package proxy

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// endsWithClose reports whether a response the client has just been sent can only end by the
// connection closing: a body with no Content-Length and no Transfer-Encoding (an origin's own
// frameless answer, or a truncated or capped one the salvage re-headed close-delimited). A HEAD
// response has no body whatever its head says, so it never ends that way.
func endsWithClose(method string, forwarded []byte) bool {
	if strings.EqualFold(method, "HEAD") {
		return false
	}
	head := forwarded
	if i := strings.Index(string(forwarded), "\r\n\r\n"); i >= 0 {
		head = forwarded[:i+4]
	}
	return httputil.ResponseIsFrameless(head)
}

// endClientWrite ends the client's half of a close-delimited response before the exchange is
// recorded.
//
// The record runs the passive scanner, the static DOM pass, the cookie jar and the page observer
// over the response, and the deferred Close that tells the client this response is over only runs
// after all of them return. A client reading a close-delimited body has no other way to learn it
// ended, so before this it waited for the whole passive scan — seconds on a large page, and forever
// when a scan hung (the self-reentrant scope cycle in dom_ast.go kept Juice Shop's /ftp/ listing
// open until the client's own timeout). Half-closing hands the client its end at once; the read
// side stays open, so nothing the record does depends on the client being gone.
//
// Over TLS the close_notify alert is the end the client reads; the TCP FIN under it follows so a
// client that ignores close_notify still sees EOF. A connection that cannot half-close (a test
// pipe) is left to the deferred Close, as before.
func endClientWrite(conn net.Conn) {
	for conn != nil {
		switch c := conn.(type) {
		case *tls.Conn:
			_ = c.CloseWrite()
			conn = c.NetConn()
		case *replayConn:
			conn = c.Conn
		case interface{ CloseWrite() error }:
			_ = c.CloseWrite()
			return
		default:
			return
		}
	}
}
