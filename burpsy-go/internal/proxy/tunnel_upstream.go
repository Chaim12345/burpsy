package proxy

// The intercepted tunnel's upstream connection, across requests.
//
// interceptTLS dials the origin once per tunnel and serves every request the client sends on that
// tunnel over it. A client keeps the tunnel open (python requests.Session, a browser), but the origin
// can end its side after any response: it says Connection: close, or an idle keep-alive timeout fires
// between two requests and it closes without saying anything. The relay used to write the next
// request into the dead socket — a write that succeeds into the kernel buffer — read EOF, and return,
// which closed the client's tunnel with no response: RemoteDisconnected on the client, nothing in the
// log, and the operator's request lost.
//
// Now a connection a previous request used is checked before reuse and replaced when it is gone; a
// close that races the request past the check is answered with a 502 rather than a silent close. The
// request itself is never re-sent: once it is on the wire, whether the origin acted on it is
// unknowable, and replaying a non-idempotent write would be worse than an error.

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// upstreamLivenessWait bounds the reuse check. An origin that closed — a FIN or a TLS close_notify
// already in the kernel buffer — reads as EOF at once; the wait only elapses on a live idle
// connection, which is what it is there to confirm.
const upstreamLivenessWait = time.Millisecond

// upstreamFreshFor is how long a newly dialled upstream is trusted without a liveness check. Past
// it the first request is checked like any later one: it waited (an intercept hold, a slow
// client), and an origin's idle timeout may have closed the connection meanwhile.
const upstreamFreshFor = time.Second

// upstreamStillUsable reports whether an upstream connection a previous request used can carry the
// next one: it is open and has nothing pending. Bytes waiting on an idle HTTP/1.1 connection are not
// a response to anything this proxy sent (a 408 an origin writes before it closes, for one), and
// reading them as the next request's answer would attribute them to it, so they make the connection
// unusable too. A connection that cannot be probed is assumed usable, which is the old behaviour; the
// 502 on a failed read still covers it.
func upstreamStillUsable(conn net.Conn, br *bufio.Reader) bool {
	if br.Buffered() > 0 {
		return false
	}
	if err := conn.SetReadDeadline(time.Now().Add(upstreamLivenessWait)); err != nil {
		return true
	}
	_, err := br.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// responseEndsConnection reports whether a response head says the connection it arrived on ends after
// it: a Connection: close, or an HTTP/1.0 response that did not ask to be kept alive.
func responseEndsConnection(head []byte) bool {
	h := string(head)
	if headerHasToken(h, "Connection", "close") {
		return true
	}
	return strings.HasPrefix(h, "HTTP/1.0 ") && !headerHasToken(h, "Connection", "keep-alive")
}

// redialTunnelUpstream opens a replacement upstream connection for a tunnel whose origin ended the
// last one. It offers exactly the protocol the tunnel already speaks (the client leg was negotiated
// to it and cannot change mid-tunnel), and refuses a reconnect that lands on anything but HTTP/1.1.
func (s *Server) redialTunnelUpstream(host, addr, negotiated string) (net.Conn, error) {
	conn, got, err := s.dialUpstreamTLS(host, addr, ClientALPNProtos(negotiated))
	if err != nil {
		return nil, err
	}
	if protocol, perr := NegotiatedProtocol(got); perr != nil || protocol != core.ProtocolHTTP1 {
		_ = conn.Close()
		return nil, fmt.Errorf("the origin negotiated %q on reconnect, not HTTP/1.1", got)
	}
	return conn, nil
}

// upstreamGoneResponse is the client's answer when the tunnel's origin connection could not carry a
// request: a 502 that says what happened and that nothing was re-sent, then the tunnel ends.
func upstreamGoneResponse(reason string) []byte {
	body := "burpsy could not get an answer from the origin on this tunnel: " + reason +
		". The request was not re-sent; send it again.\n"
	return []byte("HTTP/1.1 502 Bad Gateway\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body)
}
