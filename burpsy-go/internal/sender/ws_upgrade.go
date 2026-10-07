package sender

// SendUpgrade: the WebSocket half of the raw send path (burpsy-react-ui-6ex).
//
// A WebSocket resend needs the same two things every other raw send in this package needs —
// one dial that honours the hostname-resolution table and the upstream proxy policy, and the
// bytes the operator wrote going on the wire exactly as written — plus one thing no other
// send needs: the connection must stay OPEN after the response, because the frames are the
// point. So this is not SendRaw with a different request; it is a dial plus a handshake read
// that hands back the live socket rather than closing it.
//
// # Why the scope gate is the caller's, stated here
//
// AuthorisedSender.Send runs ScopeChecker.AuthoriseRaw on the request bytes before the dial,
// and SendUpgrade cannot do that from inside: the handshake's authority is the caller's fact,
// and this package's contract (see the package doc on authorisation) is that a caller holding
// a raw *Sender authorises its own bytes. The Repeater's WS endpoint does exactly that: the
// host-level gate at prepare time, then AuthoriseRaw on the handshake bytes this function is
// about to write — the same two layers the HTTP send applies, applied to the bytes that
// actually go out.
//
// # Why ALPN offers HTTP/1.1 only
//
// A WebSocket upgrade is an HTTP/1.1 request whose response is "101 Switching Protocols";
// there is no h2 shape of it here, and offering h2 on the dial would let a front end
// negotiate h2 and then answer the handshake with an error the caller reads as a broken
// target rather than as "this path does not speak WebSocket over h2". alpn.EgressOffer(false)
// is the same choice dialOne already makes for the HTTP/1.1-specific probes, for the same
// reason: negotiate only what this path can carry.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// UpgradeResult is one successful WebSocket handshake: the connection the frames go on, and
// the raw 101 response that accepted it.
//
// The raw response is carried rather than only a status because the handshake's headers are
// facts an operator can act on — a Sec-WebSocket-Protocol the server picked, an
// Sec-WebSocket-Extensions the server did not accept — and a resend that silently dropped the
// server's answer to "which subprotocol am I speaking" would be a lie about what the
// connection is.
//
// The conn is the caller's to close. Deliberately not a wrapper with a Close method: the
// caller already owns error handling for the frames, and a second closer is a second place
// the socket's lifetime could disagree with the frames'.
type UpgradeResult struct {
	Conn       net.Conn
	RawResp    []byte
	DurationMs int64
	// Reader wraps Conn with the buffered reader the head was consumed from, so bytes that
	// arrived with the 101 — a server that already wrote its first frame — are not lost
	// between the handshake and the caller's first read.
	Reader *bufio.Reader
}

// SendUpgrade dials one connection, writes rawUpgrade (the operator's HTTP/1.1 upgrade
// request, verbatim), reads the response head, and — when that response accepts the upgrade —
// hands back the live connection.
//
// The connection is returned only for a 101. Any other response is an error carrying the
// status line, and the connection is closed: a 404 from a mis-pathed upgrade is not a
// WebSocket conversation the caller could continue, and handing back a socket that is
// speaking HTTP rather than WebSocket would make every subsequent frame write a protocol
// violation the target is entitled to answer by dropping the connection.
//
// Only the response HEAD is read, not a body: a 101 has no body, and a non-101 response is
// read only far enough to refuse it coherently. The bytes after the head belong to the frame
// stream, and consuming them here would eat the first frame the caller is about to wait for.
func (s *Sender) SendUpgrade(ctx context.Context, host string, port uint16, useTLS bool, rawUpgrade []byte) (UpgradeResult, error) {
	started := time.Now()

	var conn net.Conn
	var err error
	if useTLS {
		conn, _, err = s.dialTLS(ctx, host, port, alpn.EgressOffer(false))
	} else {
		conn, err = s.dialPlain(ctx, host, port)
	}
	if err != nil {
		return UpgradeResult{}, fmt.Errorf("connection failed: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(rawUpgrade); err != nil {
		conn.Close()
		return UpgradeResult{}, fmt.Errorf("write upgrade request: %w", err)
	}
	br := bufio.NewReader(conn)
	head, err := httputil.ReadResponseHead(br)
	if err != nil {
		conn.Close()
		return UpgradeResult{}, fmt.Errorf("read upgrade response: %w", err)
	}
	if status := httputil.ResponseStatus(head); status == nil || *status != 101 {
		conn.Close()
		return UpgradeResult{}, fmt.Errorf("the target refused the WebSocket upgrade: %s",
			strings.TrimSpace(string(upgradeStatusLine(head))))
	}
	// The handshake's deadline comes off the socket: the frames the caller is about to
	// exchange are governed by the caller's own read loop and its timeouts, and leaving a
	// handshake-shaped deadline on the socket would silently bound a frame reads that were
	// never meant to share one. The reader below still holds any bytes that arrived with the
	// 101, which is why it is handed back too.
	_ = conn.SetDeadline(time.Time{})
	return UpgradeResult{Conn: conn, RawResp: head, DurationMs: time.Since(started).Milliseconds(), Reader: br}, nil
}

// upgradeStatusLine returns the response head's status line, for an error message that names
// what the target actually said rather than a parsed summary of it. Named for its purpose
// rather than generically: this package already has a firstLine (protocol_test.go's), and a
// helper that silently shadows a test helper is a confusing build error waiting to happen.
func upgradeStatusLine(raw []byte) []byte {
	if i := strings.IndexByte(string(raw), '\n'); i >= 0 {
		return raw[:i]
	}
	return raw
}
