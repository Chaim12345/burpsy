package proxy

// WebSocket relay: once a handshake has been answered 101, this pumps frames
// both ways between the client and the upstream connection.
//
// # Relay first, capture second — always in that order
//
// Every byte read from one side is written to the other *before* the capture
// looks at it, and the bytes written are the bytes read. That ordering is the
// whole safety argument for this feature: no parse result, no cap, and no bug
// in the reassembler can change what the two peers see. A WebSocket carries
// the live application — a chat, a trading feed, a terminal — and a proxy that
// corrupts it is worse than a proxy that cannot see it.
//
// # Interception is the one exception, and it is opt-in
//
// Holding a frame means not relaying it yet, so WebSocket interception cannot
// obey the rule above — holding after forwarding would be a review tool rather
// than an interception tool. Burp intercepts WebSocket messages, so burpsy does
// too, and the honest statement of the invariant is therefore narrower than it
// used to be:
//
//   - It holds absolutely for capture. Nothing on the capture path can delay,
//     reorder or alter a byte, whatever the reassembler does.
//   - It holds absolutely for any direction without an active WebSocket rule
//     list, which is the default and takes a byte-for-byte unchanged path.
//   - It is deliberately suspended for a direction the operator has switched
//     interception on for, and only for the frames that direction can hold:
//     control frames, compressed frames and fragments are still relayed
//     untouched. See wsHoldable.
//
// The tests in ws_intercept_test.go pin the inert cases with no operator
// running, so anything that started holding a frame it should not would hang
// rather than pass quietly.
//
// # One goroutine per direction
//
// The Rust reference pumps both directions from a single task with a select!,
// so a connection's cost stays on the connection's own task. Goroutines are
// cheap enough that the equivalent here is two — one blocked on each read —
// which cannot lose a byte for the same reason the select! cannot: each
// direction is an independent byte stream, and only the owning goroutine reads
// from its source and writes to its sink.
//
// # Desynchronisation stops the capture, not the connection
//
// If the frame stream can no longer be located — the one WsError case — every
// later "message" this side decoded would be fiction. So capture for that
// direction stops, the reason is reported so it can be recorded, and relaying
// continues untouched. The alternative, tearing the connection down because
// *our* view of it broke, would make an inspection tool the cause of the
// outage.
//
// # Scope is asked per message, not once at the handshake
//
// A WebSocket can stay open for the whole engagement, so authorising it at
// Upgrade and never again means an operator who narrows scope at 14:00 keeps
// retaining traffic they excluded until the socket happens to close. The check
// therefore runs for every message, against the handshake's host, port, path
// and scheme — a connection has exactly one of each, so the *subject* of the
// decision is fixed even though the *policy* is not. Scope governs retention,
// never egress: an out-of-scope message is relayed and not stored, exactly as
// out-of-scope HTTP traffic is.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// wsRelayChunk is the read buffer per direction, matching the response-streaming
// buffer in proxy.go.
const wsRelayChunk = 16 * 1024

// wsCapture is the per-connection capture configuration. Nil means the
// connection is relayed and not recorded — the out-of-scope case.
type wsCapture struct {
	scope *core.Scope
	host  string
	port  uint16
	tls   bool
	path  string
}

// wsCaptureStats counts what the relay wrote to the index. Both directions
// update it from separate goroutines, so the counters are atomic.
type wsCaptureStats struct {
	messages atomic.Int64
	skipped  atomic.Int64
	// dropped counts frames the operator dropped while intercepting. Counted
	// separately from skipped, which means "relayed but out of scope": one is a
	// frame the peer never received, the other is a frame the peer received and
	// this index does not mention. Reporting them as one number would hide the
	// only case where burpsy changed what the application saw.
	dropped atomic.Int64
}

// wsPeer is the connection's fixed identity: a WebSocket has exactly one host,
// port, scheme and path for its whole life. Carried into the relay so a held
// frame can say which connection it belongs to — the capture path reaches this
// through wsCapture, but that is nil for an uncaptured connection and
// interception must still work on one.
type wsPeer struct {
	host string
	port uint16
	tls  bool
	path string
}

// stripWsHandshake removes the client's Sec-WebSocket-Extensions offer from an
// upgrade request, returning the request to forward and the offers removed.
// Called on every handshake before it is stored or sent, so the bytes upstream
// receives and the bytes history shows are one and the same.
//
// A request the parser cannot read is forwarded untouched and nothing is
// claimed about it. Reporting a strip that did not happen would be worse than
// not stripping: the operator would read "extensions removed" on a handshake
// that still offers them, and then trust a compressed capture.
func (s *Server) stripWsHandshake(requestData []byte) ([]byte, []string) {
	if !s.config.stripWsExtensions {
		return requestData, nil
	}
	out, removed, err := core.StripWsExtensionsHeader(requestData)
	if err != nil {
		s.config.logger.Warn("websocket handshake forwarded unmodified", zap.Error(err))
		return requestData, nil
	}
	return out, removed
}

// wsStripNote renders the exchange note for a handshake this proxy rewrote, or
// nil when it rewrote nothing.
//
// The note exists because the recorded request is the one sent upstream, not
// the one the client sent — a difference that is invisible in the bytes, since
// what was removed is precisely what is no longer there. Burp performs the same
// rewrite and shows the result without comment; an operator comparing their
// client's traffic against history would find a header missing and no
// explanation for it. Naming the removed offer verbatim also preserves the only
// evidence of what the client actually asked for.
func wsStripNote(removed []string) *string {
	if len(removed) == 0 {
		return nil
	}
	note := fmt.Sprintf(
		"[burpsy] removed Sec-WebSocket-Extensions: %s from this handshake before forwarding it, so the origin cannot negotiate permessage-deflate and this connection's frames are captured in the clear rather than as DEFLATE blocks. The request recorded here is the one sent upstream; the client's own request carried that header. Disable stripping for an origin that requires the extension — compressed frames are then recorded with a note rather than decoded.",
		strings.Join(removed, ", "))
	return &note
}

// handleWebSocketUpgrade takes over a connection whose request asked to upgrade
// and whose origin answered 101. Called with nothing yet stored: the request
// bytes are carried in so both halves of the handshake reach the shared producer
// together. An origin that refused the upgrade takes the ordinary response path
// instead, so a refused upgrade is handled exactly like any other response.
// strippedExtensions carries whatever stripWsHandshake removed from the request,
// so the exchange can say the handshake was rewritten.
func (s *Server) handleWebSocketUpgrade(clientConn net.Conn, clientReader *bufio.Reader, method string, host string, port uint16, path string, requestData []byte, startTime time.Time, strippedExtensions []string) {
	upstream, err := s.dialUpstream(context.Background(), host, port)
	if err != nil {
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(requestData); err != nil {
		return
	}
	upstreamBR := bufio.NewReader(upstream)

	head, err := httputil.ReadResponseHead(upstreamBR)
	if err != nil {
		return
	}

	if !core.IsWsUpgradeResponse(head) {
		// The origin refused the upgrade. What it sent is an ordinary response,
		// and the bytes already read are its beginning — hand them to the
		// normal path rather than losing them.
		body, err := httputil.ReadResponseBody(upstreamBR, head)
		if err != nil {
			return
		}
		responseData := append(head, body...)
		s.completeResponse(clientConn, method, host, port, false, path, requestData, responseData, startTime)
		return
	}

	// The handshake response is recorded before the relay starts, not after it
	// ends. A WebSocket can stay open for hours, and an exchange whose response
	// only appears when the socket finally closes would leave history showing a
	// request that never got an answer for the entire session — which is also the
	// shape the shared producer now refuses outright, so recording it here is not
	// merely nicer, it is the only way this row exists at all.
	//
	// The 101 head is the response, and it goes through scanner.Capture.Record
	// like every other captured exchange. One consequence is deliberate: the
	// handshake response is now passively scanned, where the hand-rolled version
	// stored it and never scanned it. A 101's headers are headers, and "the same
	// path as proxied traffic" is the requirement.
	handshake := s.record(scanner.CapturedExchange{
		Host:     host,
		Port:     port,
		TLS:      false,
		Method:   method,
		Path:     path,
		Request:  requestData,
		Response: head,
		Started:  startTime,
		Duration: time.Since(startTime),
		Protocol: core.ProtocolHTTP1,
		// A handshake this proxy rewrote must not look pristine.
		Notes: wsStripNote(strippedExtensions),
	})
	// The 101 goes to the client before frames start flowing.
	if _, err := clientConn.Write(head); err != nil {
		return
	}

	// A handshake that could not be captured relays anyway, uncaptured — the same
	// rule this file already applies when the frame stream desynchronises: the
	// capture stops, the connection does not. Tearing down a working socket
	// because our own bookkeeping failed would make the inspection tool the cause
	// of the outage. Frames are only attached when there is a row to attach them
	// to, so nothing accumulates against an exchange id that does not exist.
	var capture *wsCapture
	exchangeID := core.ExchangeID(0)
	if handshake != nil {
		exchangeID = handshake.ID
		capture = &wsCapture{scope: s.config.scope, host: host, port: port, path: path}
	} else {
		s.config.logger.Warn("relaying a websocket that could not be captured",
			zap.String("host", host), zap.Uint16("port", port), zap.String("path", path))
	}
	s.relayWebsocket(exchangeID, clientConn, clientReader, upstream, upstreamBR,
		host, port, false, path, capture)
}

// relayWebsocket pumps frames between the client and upstream until either side
// closes. The 101 head must already have been written to the client. The two
// readers may each hold buffered bytes that arrived with the handshake — the
// client's first frame sent without waiting for the 101, or the server's first
// frames in the same read as its response — and those are the first bytes
// relayed, because dropping them would lose the opening of every conversation.
// capture nil means relay without recording, the out-of-scope case.
func (s *Server) relayWebsocket(exchangeID core.ExchangeID, clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader, host string, port uint16, tls bool, path string, capture *wsCapture) {
	var stats wsCaptureStats
	faults := make([]string, 2)
	peer := wsPeer{host: host, port: port, tls: tls, path: path}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		faults[0] = s.wsDirection(exchangeID, clientReader, upstreamConn, true, peer, capture, &stats)
	}()
	go func() {
		defer wg.Done()
		faults[1] = s.wsDirection(exchangeID, upstreamReader, clientConn, false, peer, capture, &stats)
	}()
	wg.Wait()

	// The skipped count is named unconditionally, including when it is zero:
	// "0 excluded" and a sentence that omits the subject are not the same
	// statement to someone checking coverage.
	s.config.logger.Info("websocket connection closed",
		zap.String("host", host), zap.Uint16("port", port), zap.String("path", path),
		zap.Uint64("exchange", uint64(exchangeID)),
		zap.Int64("messages", stats.messages.Load()),
		zap.Int64("skipped_out_of_scope", stats.skipped.Load()),
	)
	for _, fault := range faults {
		if fault != "" {
			s.recordWsCaptureStopped(exchangeID, host, port, tls, path, fault)
			break
		}
	}
}

// wsDirection relays one direction until the source or sink gives up, feeding
// the reassembler and draining completed messages into the store. It returns
// why capture stopped, if it did; relaying is unaffected either way.
//
// Two byte paths live here, and which one runs is decided per read:
//
//   - Interception off, which is the default and the overwhelmingly common case:
//     the original relay-first path, byte for byte unchanged. A chunk is written
//     to the sink before anything looks at it.
//   - Interception on for this direction: the frame-boundary path, which must
//     buffer, because a frame cannot be held until it is whole. See wsIntercept
//     for the full argument.
//
// The gate is re-read every read rather than once per connection, so enabling
// interception takes effect on an already-open socket — the same reason scope is
// asked per message rather than at the handshake.
func (s *Server) wsDirection(exchangeID core.ExchangeID, src *bufio.Reader, dst net.Conn, fromClient bool, peer wsPeer, capture *wsCapture, stats *wsCaptureStats) string {
	rs := core.NewWsReassembler(core.DefaultMaxWsMessageBytes)
	buf := make([]byte, wsRelayChunk)

	// pending holds bytes the interception path has read but not yet placed on the
	// wire, because they are the beginning of a frame whose remainder has not
	// arrived. It is empty whenever interception is off.
	var pending []byte
	// degraded latches when frame boundaries can no longer be located. From then
	// on this direction relays and never holds again: a hold decision needs to
	// know where the frame is, and guessing would corrupt the stream. Latching is
	// deliberate — recovering mid-connection would mean resuming holds on a
	// boundary we already know we lost.
	degraded := false

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			dir, holding := s.wsInterceptDirection(fromClient)
			// Bytes already buffered must go out through the same path that
			// buffered them, even if interception was switched off in between.
			// Relaying a newer chunk ahead of an older partial frame would
			// reorder the stream, which is worse than either path alone.
			if !degraded && (holding || len(pending) > 0) {
				fault, gone := s.wsIntercept(dir, &pending, chunk, dst, rs, exchangeID, fromClient, peer, stats)
				if gone {
					return ""
				}
				if fault != "" {
					// The frame stream is unreadable. Whatever is still buffered
					// is relayed untouched — those bytes are the peer's, and our
					// inability to parse them is not a reason to swallow them —
					// and this direction becomes a plain relay.
					if len(pending) > 0 {
						if _, werr := dst.Write(pending); werr != nil {
							return fault
						}
						pending = nil
					}
					degraded = true
					s.drainWs(rs, exchangeID, fromClient, capture, stats)
					return fault
				}
				s.drainWs(rs, exchangeID, fromClient, capture, stats)
				if err != nil {
					return ""
				}
				continue
			}

			// Relay first, capture second — the ordering is the safety argument.
			if _, werr := dst.Write(chunk); werr != nil {
				return ""
			}
			if cerr := rs.Feed(chunk); cerr != nil {
				fault := fmt.Sprintf("%s: %v", wsWhich(fromClient), cerr)
				s.config.logger.Warn("websocket capture stopped",
					zap.String("direction", wsWhich(fromClient)), zap.String("exchange", fmt.Sprintf("%d", exchangeID)), zap.Error(cerr))
				// A read can carry several frames, and messages decoded before
				// the bad header are complete and real — drain them rather than
				// losing evidence the parser already has. Then stop capturing
				// this direction; the connection keeps relaying.
				s.drainWs(rs, exchangeID, fromClient, capture, stats)
				return fault
			}
			s.drainWs(rs, exchangeID, fromClient, capture, stats)
		}
		if err != nil {
			return ""
		}
	}
}

func wsWhich(fromClient bool) string {
	if fromClient {
		return "client→server"
	}
	return "server→client"
}

// wsInterceptDirection reports the intercept direction for this side of the
// relay and whether frames on it should currently be held.
//
// Both conditions are required, and the second one is why an operator with
// interception enabled but no WebSocket rule list still gets the untouched
// relay-first path: Rules(dir).Active is the switch the WS interception panel
// owns. Without this check, turning interception on for HTTP would silently
// start buffering every WebSocket frame in the process.
func (s *Server) wsInterceptDirection(fromClient bool) (intercept.Direction, bool) {
	dir := intercept.DirectionWebSocketToClient
	if fromClient {
		dir = intercept.DirectionWebSocketToServer
	}
	if s.config.intercept == nil || !s.config.intercept.Enabled() {
		return dir, false
	}
	return dir, s.config.intercept.Rules(dir).Active
}

// wsHoldable reports whether a frame may be held, and when it may not, the
// reason — which is recorded rather than dropped, because "this frame was not
// offered to you" is a fact the operator needs in order to trust the ones that
// were.
//
// Three kinds of frame are relayed untouched:
//
//   - Control frames. Holding a ping stalls the peer's keepalive and holding a
//     close prevents the connection from shutting down; an operator staring at a
//     held close frame would be watching a socket they can no longer end. Burp
//     does not offer control frames for editing either.
//   - Compressed frames, meaning any RSV bit set. With permessage-deflate the
//     payload is a DEFLATE block, so showing it as text would be fiction and
//     accepting an edit would put an invalid block on the wire. burpsy strips the
//     extension offer from handshakes by default (see stripWsHandshake), so this
//     case only arises when the operator has deliberately turned stripping off.
//   - Fragmented frames, meaning FIN clear or a continuation opcode. A held
//     fragment is half a message, and an edit to it cannot be length-checked
//     against the rest, which has already gone.
//
// Each of these is a real gap against Burp, which reassembles fragments and
// inflates compressed frames before offering them. They are refused out loud
// here rather than half-supported.
// wsIntercept consumes chunk on the frame-boundary path: it appends to pending,
// then for every frame that is now whole decides whether to hold it, and puts
// the result on the wire.
//
// # Why this path cannot relay first
//
// The module doc above states that every byte is written to the sink before the
// capture looks at it, and that this is the whole safety argument. Interception
// is the one deliberate exception, and the exception is the point of the
// feature: an operator who asks to hold a frame is asking for it *not* to be
// relayed yet. Holding after forwarding would be a review tool, not an
// interception tool.
//
// So the invariant is narrowed rather than abandoned. It still holds absolutely
// for capture — nothing on the capture path can delay or alter a byte — and it
// still holds for every connection whose direction has no active WebSocket rule
// list, which takes the untouched path in wsDirection. What an operator gives up
// by enabling WS interception is stated where they enable it, and it is the same
// trade Burp makes.
//
// # What goes to the sink, and what goes to the index
//
// Exactly the same bytes, always. A forwarded frame is written and then fed to
// the reassembler; a dropped frame is neither, because it never happened on the
// wire and an index that showed it would be describing a frame the server never
// received. This is the file's existing rule that "the bytes forwarded upstream
// equal the bytes recorded", preserved through editing.
//
// Returns a fault when frame boundaries are lost, and connGone when the sink is
// closed. A fault leaves pending intact for the caller to flush.
func (s *Server) wsIntercept(dir intercept.Direction, pending *[]byte, chunk []byte, dst net.Conn, rs *core.WsReassembler, exchangeID core.ExchangeID, fromClient bool, peer wsPeer, stats *wsCaptureStats) (string, bool) {
	*pending = append(*pending, chunk...)

	for {
		hdr, need, err := core.ParseWsFrameHeader(*pending)
		if err != nil {
			s.config.logger.Warn("websocket interception stopped; relaying without holding",
				zap.String("direction", wsWhich(fromClient)),
				zap.String("exchange", fmt.Sprintf("%d", exchangeID)), zap.Error(err))
			return fmt.Sprintf("%s: %v", wsWhich(fromClient), err), false
		}
		if need {
			return "", false
		}
		total := hdr.HeaderLen + int(hdr.PayloadLen)
		if len(*pending) < total {
			// The frame is identified but incomplete. Nothing goes out: half a
			// frame on the wire is worse than a late one.
			return "", false
		}

		frame := (*pending)[:total]
		*pending = (*pending)[total:]
		if len(*pending) == 0 {
			// Release the read buffer rather than carrying a grown array for the
			// life of a connection that may stay open for hours.
			*pending = nil
		}

		out, drop := s.wsDecideFrame(dir, hdr, frame, fromClient, peer)
		if drop {
			stats.dropped.Add(1)
			continue
		}
		if _, werr := dst.Write(out); werr != nil {
			return "", true
		}
		if cerr := rs.Feed(out); cerr != nil {
			// The frame went out; only the index lost track. Same treatment as on
			// the relay-first path.
			return fmt.Sprintf("%s: %v", wsWhich(fromClient), cerr), false
		}
	}
}

// wsDecideFrame offers one whole frame to the operator and returns the bytes to
// relay, or drop=true when the operator dropped it.
//
// frame is the complete frame as it arrived, header included. The returned slice
// is either frame itself — the untouched case, which is the common one — or a
// freshly encoded frame carrying the operator's edit.
func (s *Server) wsDecideFrame(dir intercept.Direction, hdr *core.WsFrameHeader, frame []byte, fromClient bool, peer wsPeer) ([]byte, bool) {
	if holdable, reason := wsHoldable(hdr); !holdable {
		// Logged at Debug rather than recorded per frame: a busy socket would
		// otherwise write a note for every ping. The aggregate is what matters
		// and it is visible as a gap between relayed and held counts.
		s.config.logger.Debug("websocket frame relayed without offering it for interception",
			zap.String("direction", wsWhich(fromClient)), zap.String("reason", reason))
		return frame, false
	}

	// The payload the operator sees is unmasked. Masking is a wire-level
	// obfuscation with no security property — RFC 6455 §10.3 is explicit that it
	// exists to defeat cache poisoning by intermediaries — so showing it masked
	// would be showing noise.
	payload := make([]byte, hdr.PayloadLen)
	copy(payload, frame[hdr.HeaderLen:total(hdr)])
	if hdr.Masked {
		core.WsUnmask(payload, hdr.Mask, 0)
	}

	held := s.config.intercept.Hold(&intercept.Message{
		Direction: dir,
		Host:      peer.host,
		Port:      peer.port,
		TLS:       peer.tls,
		Path:      peer.path,
		Opcode:    hdr.Opcode.Name(),
		Raw:       payload,
	})
	if held == nil {
		// No rule matched, so this frame was never offered. Relay it exactly as it
		// arrived rather than re-encoding it: an unmatched frame must be
		// indistinguishable on the wire from one this proxy never inspected.
		return frame, false
	}

	action, edited := held.Wait()
	if action == intercept.ActionDrop {
		return nil, true
	}
	if bytes.Equal(edited, payload) {
		// Forwarded unchanged. Relay the original bytes, mask and all, so an
		// untouched frame is byte-identical to what the peer sent.
		return frame, false
	}

	// Edited. A client-to-server frame must be masked and a server-to-client
	// frame must not be (RFC 6455 §5.1), and a peer receiving the wrong one is
	// required to fail the connection — so the mask is decided by direction, not
	// by what happened to arrive.
	var mask *[4]byte
	if fromClient {
		var m [4]byte
		if _, err := rand.Read(m[:]); err != nil {
			// Without a fresh mask the only choices are an unmasked client frame,
			// which the server must reject, or the operator's edit silently not
			// happening. Neither is acceptable quietly, so the original frame goes
			// on the wire and the failure is logged loudly.
			s.config.logger.Error("could not generate a WebSocket mask; the operator's edit was NOT sent and the original frame was relayed instead",
				zap.Error(err), zap.String("direction", wsWhich(fromClient)))
			return frame, false
		}
		mask = &m
	}
	return core.EncodeWsFrame(hdr.Opcode, edited, mask), false
}

// total is the whole frame length for a parsed header.
func total(hdr *core.WsFrameHeader) int { return hdr.HeaderLen + int(hdr.PayloadLen) }

func wsHoldable(hdr *core.WsFrameHeader) (bool, string) {
	switch {
	case hdr.Opcode.IsControl():
		return false, "control frame (" + hdr.Opcode.Name() + ")"
	case hdr.RSV != 0:
		return false, "compressed frame (RSV bits set); disable extension stripping only if you accept that compressed frames are not interceptable"
	case hdr.Opcode == core.WsOpcodeContinuation:
		return false, "continuation of a fragmented message"
	case !hdr.FIN:
		return false, "first fragment of a fragmented message"
	default:
		return true, ""
	}
}

// drainWs writes every completed message to the index, or counts it as skipped
// when scope excludes this connection right now.
func (s *Server) drainWs(rs *core.WsReassembler, exchangeID core.ExchangeID, fromClient bool, capture *wsCapture, stats *wsCaptureStats) {
	for {
		ev := rs.Pop()
		if ev == nil {
			return
		}
		// Asked here, per message, so narrowing scope on an open socket takes
		// effect at once. A connection this relay never captures has capture
		// nil and skips the whole decision.
		if capture != nil && !capture.scope.Contains(capture.host, capture.port, capture.path, capture.tls) {
			stats.skipped.Add(1)
			continue
		}
		if capture == nil {
			continue
		}
		m := &core.WsMessage{
			Exchange:   exchangeID,
			FromClient: fromClient,
			Opcode:     ev.Opcode,
			Len:        len(ev.Payload),
			Dropped:    ev.Dropped,
			Fragments:  ev.Fragments,
			AtMs:       uint64(time.Now().UnixMilli()),
			Note:       ev.Note,
		}
		s.config.store.AddWsMessage(m, ev.Payload)
		stats.messages.Add(1)
	}
}

// recordWsCaptureStopped records that a connection's message index stopped
// short, and why. A marker row rather than silence: a history that shows 40
// messages on a socket that carried 4000 is worse than one that says it lost
// track. Written when the connection ends, so it sits after the messages it is
// qualifying. The frames themselves were relayed unmodified throughout — the
// note says so, because an operator reading "capture stopped" will otherwise
// reasonably wonder whether their app broke.
func (s *Server) recordWsCaptureStopped(exchangeID core.ExchangeID, host string, port uint16, tls bool, path string, reason string) {
	if exchangeID == 0 {
		// Out-of-scope connections have no handshake exchange to key a marker
		// to, and nothing was recorded anyway.
		return
	}
	synthetic := fmt.Sprintf("[burpsy: WebSocket capture stopped — %s. Frames continued to be relayed unmodified, so the connection was not affected; the message index below this point is incomplete.]", reason)
	m := &core.WsMessage{
		Exchange:   exchangeID,
		FromClient: false,
		Opcode:     core.WsOpcodeText,
		Len:        len(synthetic),
		Fragments:  1,
		AtMs:       uint64(time.Now().UnixMilli()),
		Note:       "websocket capture stopped",
	}
	s.config.store.AddWsMessage(m, []byte(synthetic))
}
