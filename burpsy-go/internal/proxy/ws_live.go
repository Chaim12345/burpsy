package proxy

// Attaching to a live proxied WebSocket (burpsy-react-ui-wuwf).
//
// Burp's Repeater can "clone or attach to any open connection": attached, a frame the operator
// writes goes into the very socket the browser opened through the proxy, toward the server or
// toward the client, and the conversation that follows is the browser's own. This file is the
// proxy half of that: a registry of the connections this relay is pumping right now, and an
// injection path that splices one operator-authored frame into one direction of one of them.
//
// # Only what the relay holds
//
// The registry is filled by relayWebsocket itself, for the life of the relay goroutines, and
// emptied when they return. Nothing else adds to it, so "attach" can only ever name a socket that
// is open through this proxy at this moment — never an address, never a closed connection, never
// one the operator merely read about in history. Connections the relay does not capture (no
// handshake row, the out-of-scope case) are not registered: they have no WebSocket ID to name
// them by, and the operator chose not to retain them.
//
// # Where a frame may be spliced
//
// A WebSocket direction is one byte stream, and the relay writes it in whatever pieces the source
// produced — on the plain path those pieces are arbitrary chunks, not frames. A frame written in
// the middle of another frame is read by the peer as payload, and one written between two frames
// of a fragmented message breaks RFC 6455 §5.4. Either corrupts the live application, which is the
// one outcome this relay is built to never cause.
//
// So every write to a direction's sink goes through wsSink, which feeds the same reassembler the
// capture path uses with exactly the bytes written, under one mutex. An injection takes that mutex
// and writes only when the reassembler says the bytes so far end on a message boundary. If they do
// not (a large frame half-relayed, a fragmented message open), it waits briefly for the boundary
// and then refuses with the reason rather than writing; if the reassembler has lost the frame
// stream, it refuses outright, because a boundary we cannot locate is not one we can splice at.
//
// # What the frame is
//
// A data frame, FIN set, RSV clear. Masked toward the server and unmasked toward the client, as
// RFC 6455 §5.1 requires of each side — the injected frame must look like one the side it
// impersonates would have sent. Uncompressed even on a connection that negotiated
// permessage-deflate: RSV1 is per message (RFC 7692 §6), and an uncompressed message does not
// touch the compression context either peer holds.
//
// Interception and match & replace do not see it: the operator authored it and is sending it on
// purpose, which is the same reason Burp does not hold a frame Repeater sent. It is recorded on the
// connection's own history, in its direction, with a note saying who actually sent it — a frame the
// browser never sent must not read as one it did.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// wsSink is one direction's write side, shared between the relay goroutine and an injector.
type wsSink struct {
	mu  sync.Mutex
	dst net.Conn
	// rs is fed exactly the bytes written to dst, after they are written, under mu — so its state is
	// always the state of the stream the peer has received. Nil only in a sink built for a test.
	rs *core.WsReassembler
	// lost latches once rs can no longer locate frames in what was written: an injection then has
	// nowhere safe to go.
	lost bool
	// ended latches when the relay goroutine for this direction has returned.
	ended bool
}

// write puts b on the wire and feeds it to the reassembler, atomically with respect to an
// injection. werr is the sink's error (the peer is gone); ferr is the reassembler's (the capture
// lost the frame stream, and the caller decides what that means for the relay).
func (k *wsSink) write(b []byte) (werr, ferr error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, werr = k.dst.Write(b); werr != nil {
		return werr, nil
	}
	if k.rs != nil && !k.lost {
		if ferr = k.rs.Feed(b); ferr != nil {
			k.lost = true
		}
	}
	return nil, ferr
}

// writeRaw writes bytes the reassembler is NOT told about: the relay's own flush of a buffer it can
// no longer parse. The stream's boundary is unknown from then on, so it latches lost.
func (k *wsSink) writeRaw(b []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.lost = true
	_, err := k.dst.Write(b)
	return err
}

func (k *wsSink) markLost() {
	k.mu.Lock()
	k.lost = true
	k.mu.Unlock()
}

func (k *wsSink) markEnded() {
	k.mu.Lock()
	k.ended = true
	k.mu.Unlock()
}

// wsLiveConn is one connection the relay is pumping right now.
type wsLiveConn struct {
	exchange core.ExchangeID
	host     string
	port     uint16
	tls      bool
	path     string
	opened   time.Time
	// toServer writes to the upstream socket (the client→server direction's sink), toClient to
	// the browser's.
	toServer *wsSink
	toClient *wsSink
}

// wsLiveRegistry is the set of live connections, keyed by their handshake exchange — the
// WebSocket ID WebSockets history shows. The zero value is ready to use.
type wsLiveRegistry struct {
	mu    sync.Mutex
	conns map[core.ExchangeID]*wsLiveConn
}

func (r *wsLiveRegistry) add(c *wsLiveConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns == nil {
		r.conns = map[core.ExchangeID]*wsLiveConn{}
	}
	r.conns[c.exchange] = c
}

// remove drops c, and only c: a later connection registered under the same id (which cannot
// happen while ids are positions in an append-only store, but the registry should not depend on
// that) is not removed by an older relay's cleanup.
func (r *wsLiveRegistry) remove(c *wsLiveConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns[c.exchange] == c {
		delete(r.conns, c.exchange)
	}
}

func (r *wsLiveRegistry) get(id core.ExchangeID) *wsLiveConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[id]
}

// LiveWsConn is what the console is told about one open proxied WebSocket.
type LiveWsConn struct {
	Exchange core.ExchangeID
	Host     string
	Port     uint16
	TLS      bool
	Path     string
	Opened   time.Time
}

// LiveWebSockets lists the connections this proxy is relaying right now, by WebSocket ID.
func (s *Server) LiveWebSockets() []LiveWsConn {
	s.wsLive.mu.Lock()
	out := make([]LiveWsConn, 0, len(s.wsLive.conns))
	for _, c := range s.wsLive.conns {
		out = append(out, LiveWsConn{Exchange: c.exchange, Host: c.host, Port: c.port, TLS: c.tls, Path: c.path, Opened: c.opened})
	}
	s.wsLive.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Exchange < out[j].Exchange })
	return out
}

// LiveWebSocket reports one live connection by its WebSocket ID.
func (s *Server) LiveWebSocket(id core.ExchangeID) (LiveWsConn, bool) {
	c := s.wsLive.get(id)
	if c == nil {
		return LiveWsConn{}, false
	}
	return LiveWsConn{Exchange: c.exchange, Host: c.host, Port: c.port, TLS: c.tls, Path: c.path, Opened: c.opened}, true
}

// The injection refusals, distinct so the API can answer each with the status it deserves.
var (
	// ErrWsNotLive: no connection by that id is open through this proxy.
	ErrWsNotLive = errors.New("that WebSocket is not open through this proxy")
	// ErrWsDirectionEnded: the connection is still registered but this direction's relay has
	// stopped (its source closed), so there is nothing to write into.
	ErrWsDirectionEnded = errors.New("that direction of the connection has already closed")
	// ErrWsBoundaryLost: the relay can no longer locate frames in this direction, so there is no
	// position at which a frame can be spliced without corrupting the stream.
	ErrWsBoundaryLost = errors.New("the relay has lost track of frame boundaries in that direction, so a frame cannot be inserted without corrupting the connection")
	// ErrWsMidMessage: the direction stayed in the middle of a message for the whole wait.
	ErrWsMidMessage = errors.New("that direction stayed in the middle of a message (a large or fragmented frame was still being relayed), so the frame was not inserted")
)

// wsInjectBoundaryWait bounds how long an injection waits for its direction to reach a message
// boundary. Short: a relay mid-frame finishes the frame in milliseconds unless the peer is
// trickling a huge one, and an operator's click must not hang the console while it does. A var so
// the mid-message test does not spend the whole wait.
var wsInjectBoundaryWait = 2 * time.Second

// wsInjectWriteTimeout bounds the injected write itself, so a peer that stopped reading cannot
// hold the sink's mutex — and with it the relay — indefinitely on the operator's behalf.
const wsInjectWriteTimeout = 5 * time.Second

// InjectWsFrame writes one operator-authored data frame into a live proxied connection, toward
// the client when toClient is set and toward the server otherwise, and records it on the
// connection's history with a note naming its real sender. It returns the recorded message's id.
//
// The caller is responsible for authorisation (scope, confirmation); this only guarantees the
// frame lands whole, on a message boundary, in a socket the relay holds.
func (s *Server) InjectWsFrame(id core.ExchangeID, toClient bool, opcode core.WsOpcode, payload []byte) (core.MsgId, error) {
	if opcode != core.WsOpcodeText && opcode != core.WsOpcodeBinary {
		return 0, fmt.Errorf("only text and binary frames can be sent, not %s", opcode.Name())
	}
	c := s.wsLive.get(id)
	if c == nil {
		return 0, ErrWsNotLive
	}
	sink := c.toServer
	var mask *[4]byte
	if !toClient {
		var m [4]byte
		if _, err := rand.Read(m[:]); err != nil {
			return 0, fmt.Errorf("generate frame mask: %w", err)
		}
		mask = &m
	} else {
		sink = c.toClient
	}
	frame := core.EncodeWsFrame(opcode, payload, mask)

	deadline := time.Now().Add(wsInjectBoundaryWait)
	for {
		sink.mu.Lock()
		switch {
		case sink.ended:
			sink.mu.Unlock()
			return 0, ErrWsDirectionEnded
		case sink.lost || sink.rs == nil:
			sink.mu.Unlock()
			return 0, ErrWsBoundaryLost
		case sink.rs.AtMessageBoundary():
			_ = sink.dst.SetWriteDeadline(time.Now().Add(wsInjectWriteTimeout))
			_, werr := sink.dst.Write(frame)
			_ = sink.dst.SetWriteDeadline(time.Time{})
			if werr != nil {
				// A partial write leaves the peer holding part of a frame; the stream position is
				// unknowable from here, so nothing else may be spliced into it.
				sink.lost = true
				sink.mu.Unlock()
				return 0, fmt.Errorf("write the frame: %w", werr)
			}
			// Recorded while the sink is still held, so the injected frame sits in history between
			// the relayed frames it actually went out between.
			msgID := s.config.store.AddWsMessage(&core.WsMessage{
				Exchange:   c.exchange,
				FromClient: !toClient,
				Opcode:     opcode,
				Len:        len(payload),
				Fragments:  1,
				AtMs:       uint64(time.Now().UnixMilli()),
				Note:       wsInjectedNote(toClient),
			}, payload)
			sink.mu.Unlock()
			return msgID, nil
		}
		sink.mu.Unlock()
		if time.Now().After(deadline) {
			return 0, ErrWsMidMessage
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func wsInjectedNote(toClient bool) string {
	if toClient {
		return "[burpsy] sent to the client from Repeater, attached to this live connection; the server did not send this message."
	}
	return "[burpsy] sent to the server from Repeater, attached to this live connection; the client did not send this message."
}
