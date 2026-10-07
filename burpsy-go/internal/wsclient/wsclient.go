// Package wsclient is Repeater's WebSocket send (burpsy-react-ui-6ex).
//
// Burp's Repeater is not HTTP-only: a WebSocket message can be sent there, edited, and resent
// against the live connection, with a choice of sending to server or client. burpsy's
// Repeater was HTTP-only, and its WebSocket traffic was visible only as read-only rows in
// WebSockets history.
//
// # The shape: one shot, honestly
//
// This package sends ONE frame over ONE freshly dialled WebSocket and reads what came back,
// then closes. It is not a held connection: burpsy's Repeater has no held-socket concept, and
// a persistent client-side connection pool is a subsystem whose failure modes (socket
// lifetime, reconnect policy, target-side connection limits) would swallow the deliverable.
// The bead's contract is send / edit / resend with a direction choice; a fresh dial per send
// satisfies all three, and the UI says so — the frame goes out on a NEW connection, which is
// also what Burp does when the original connection has already closed.
//
// # The direction choice
//
// "To server" is this package. "To client" — injecting a frame into a live connection toward
// the browser — is NOT: a fresh dial has no client to send to. The API layer offers it only
// when a live intercepted connection is holding that frame's connection, the same hold the
// proxy already implements, and refuses with the reason shown otherwise. Hiding the refusal
// would offer an operator a control that cannot act, which is the one thing this console
// does not do with a button.
//
// # What is reused rather than reinvented
//
// The frame codec is core's (EncodeWsFrame, WsReassembler) — the same code the proxy's relay
// runs, so a frame this package writes is encoded by the same rules the target's other
// clients are read by, and a reply this package reads is decoded by the same reassembler that
// built WebSockets history's rows. The dial is sender.SendUpgrade, so the
// hostname-resolution table and the upstream proxy policy apply exactly as they do to every
// other send, and no second transport exists here to disagree with the first.
package wsclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// ReplyDeadline bounds the wait for the reply frames after the send. Generous rather than
// short: a target that pushes its answer on its own schedule (a notification bus, a slow
// publish) is the normal case for a WebSocket resend, and a short deadline would turn every
// such target into "no reply" while the operator watches an empty pane.
const ReplyDeadline = 30 * time.Second

// HandshakeRequest rebuilds the upgrade request for one resend: the target's path, version 13,
// a fresh key, and no extensions. The original connection's negotiated extensions are
// deliberately NOT re-offered: permessage-deflate would make every frame this package writes
// a DEFLATE stream the operator did not ask to author, and the reply's decode would depend
// on a negotiation this fresh dial may not even get. A plain, uncompressed conversation is
// the one whose bytes are exactly what the operator edited.
//
// subprotocol, when non-empty, is the Sec-WebSocket-Protocol the original handshake
// negotiated. Carried rather than dropped: a target that expects one will close a socket
// that did not offer it, and an operator resending a frame from such a connection would read
// the refusal as a broken resend.
func HandshakeRequest(host string, port uint16, tls bool, path, subprotocol string) ([]byte, error) {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generate Sec-WebSocket-Key: %w", err)
	}
	authority := authorityOf(host, port, tls)
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", authority)
	fmt.Fprintf(&b, "Upgrade: websocket\r\n")
	fmt.Fprintf(&b, "Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", base64.StdEncoding.EncodeToString(keyBytes))
	fmt.Fprintf(&b, "Sec-WebSocket-Version: 13\r\n")
	if subprotocol != "" {
		fmt.Fprintf(&b, "Sec-WebSocket-Protocol: %s\r\n", subprotocol)
	}
	fmt.Fprintf(&b, "User-Agent: burpsy-repeater\r\n")
	fmt.Fprintf(&b, "\r\n")
	return []byte(b.String()), nil
}

// authorityOf renders the Host header's authority: the host, plus the port when it is not the
// scheme's default. net.JoinHostPort brackets an IPv6 literal, which a Sprintf would not — a
// Host: ::1:80 header is unparseable by the same RFC 6455 that everything else here follows.
func authorityOf(host string, port uint16, tls bool) string {
	def := uint16(80)
	if tls {
		def = 443
	}
	if port == def {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// Frame is one frame to send.
type Frame struct {
	// Opcode: text or binary. Control frames (ping/pong/close) are not sendable here: a
	// resend is a data frame the operator edited, and offering to author a close would be
	// offering to hang up a connection this package just opened for no reason the operator
	// can see.
	Opcode  core.WsOpcode
	Payload []byte
}

// Reply is what came back before the deadline: zero or more messages, each decoded by the
// same reassembler the proxy's capture path uses.
type Reply struct {
	// Messages, in arrival order.
	Messages []*core.WsEvent
	// RawHandshake is the 101 the target answered with, for the record.
	RawHandshake []byte
	// ClosedByPeer says the target closed the socket (a close frame arrived or the read
	// returned EOF) before the deadline. An operator watching an empty reply needs to know
	// whether to wait or to conclude the target is done talking.
	ClosedByPeer bool
	// CloseCode and CloseReason carry the close frame's payload when one arrived.
	CloseCode   uint16
	CloseReason string
}

// SendFrame performs the one-shot resend: dial, handshake, send one masked client frame, read
// until the reply deadline or the peer closes, and close.
//
// toServer is the only direction; the package doc explains why to-client is not this path.
// The mask is always applied (a client-to-server frame must be masked, RFC 6455 §5.3) using
// core.EncodeWsFrame, the same encoder the proxy's client-direction relay uses.
func SendFrame(ctx context.Context, s *sender.Sender, host string, port uint16, tls bool, path, subprotocol string, frame Frame) (Reply, error) {
	handshake, err := HandshakeRequest(host, port, tls, path, subprotocol)
	if err != nil {
		return Reply{}, err
	}
	up, err := s.SendUpgrade(ctx, host, port, tls, handshake)
	if err != nil {
		return Reply{}, err
	}
	defer up.Conn.Close()

	// The mask: clients mask, servers do not. EncodeWsFrame applies it when given.
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return Reply{}, fmt.Errorf("generate frame mask: %w", err)
	}
	if _, err := up.Conn.Write(core.EncodeWsFrame(frame.Opcode, frame.Payload, &mask)); err != nil {
		return Reply{}, fmt.Errorf("write frame: %w", err)
	}

	// Read the reply: everything that arrives before the deadline, decoded by the proxy's own
	// reassembler. Reading "until deadline" rather than "first message then stop" is
	// deliberate: a WebSocket reply is often more than one frame (a burst of notifications
	// around the one the operator asked for), and stopping at the first would silently drop
	// the rest of what the target did with the resend.
	reply := Reply{RawHandshake: up.RawResp}
	rs := core.NewWsReassembler(8 << 20)
	buf := make([]byte, 32*1024)
	deadline := time.Now().Add(ReplyDeadline)
	_ = up.Conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, rerr := up.Reader.Read(buf)
		if n > 0 {
			if ferr := rs.Feed(buf[:n]); ferr != nil {
				return reply, fmt.Errorf("decode reply: %w", ferr)
			}
			for {
				ev := rs.Pop()
				if ev == nil {
					break
				}
				if ev.Opcode == core.WsOpcodeClose {
					code, reason, _ := core.WsCloseStatus(ev.Payload)
					reply.ClosedByPeer = true
					reply.CloseCode = code
					reply.CloseReason = reason
					return reply, nil
				}
				reply.Messages = append(reply.Messages, ev)
			}
		}
		if rerr != nil {
			// EOF or deadline: the conversation is over either way, and what arrived is the
			// answer. A timeout is not an error to report — the operator asked what came
			// back, and "nothing more did" is the answer.
			if !isTimeout(rerr) {
				reply.ClosedByPeer = true
			}
			return reply, nil
		}
	}
	return reply, nil
}

// isTimeout reports whether an error is a deadline, so a read that ended on time is not
// reported as a closed peer.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
