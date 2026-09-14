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
//     interception on for. Control frames are still always relayed immediately —
//     holding a ping stalls the peer's keepalive and holding a close leaves a
//     socket that cannot be ended — and so are compressed frames, whose payload
//     is a DEFLATE block rather than anything an operator could edit.
//     Fragmented messages ARE reassembled and held; see wsFragments.
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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
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
	// deflate is what the 101 response agreed. Carried so drainWs can inflate a compressed message
	// for the operator's view where that is provably safe — see core.WsDeflateParams.InflatableFor.
	deflate core.WsDeflateParams
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
	// Read live: the same option set the Proxy settings panel writes, so the
	// next handshake obeys the operator's switch without a restart. Get is
	// nil-safe (reads as off), matching the nil option set's all-off contract.
	if !s.config.options.Get(OptStripWsExtensions) {
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
// requestEdited is whether the operator's own hold edited the handshake request, threaded in for the
// same reason handleTLSResponse threads it: the hold resolved before this function was called, and
// the row below is the only record of it.
func (s *Server) handleWebSocketUpgrade(clientConn net.Conn, clientReader *bufio.Reader, method string, host string, port uint16, path string, requestData []byte, reqStages messageStages, startTime time.Time, strippedExtensions []string, requestEdited bool) {
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
		s.completeResponse(clientConn, method, host, port, false, path, requestData, reqStages, responseData, startTime, "", "", serverIPOf(upstream), requestEdited)
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

		// The handshake's request stages, so an operator can see what a Match & Replace rule or
		// their own intercept edit did to the handshake (burpsy-react-ui-c05). No response stages:
		// the 101 head is recorded as the origin sent it, because the response rules deliberately
		// do not run against an upgrade — see the note above on why rewriting a handshake would
		// break it, and there is therefore no earlier version of it to retain.
		RequestOriginal: reqStages.original,
		RequestAuto:     reqStages.auto,

		ServerIP:     serverIPOf(upstream),
		ListenerPort: listenerPortOf(clientConn),

		// A handshake the operator edited in the hold is "Edited" in history, by the same rule as
		// every other row (burpsy-react-ui-sd0d).
		UserEdited: requestEdited,

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
		capture = &wsCapture{
			scope: s.config.scope, host: host, port: port, path: path,
			// The response is authoritative: the client offers extensions, the server chooses.
			deflate: core.ParseWsDeflateParams(head),
		}
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
	// frag accumulates a fragmented message so it can be offered whole. Per direction, because
	// one message's fragments cannot interleave with another's on the same connection
	// (RFC 6455 §5.4) — only control frames may appear between them.
	var frag wsFragments
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

			dir, _ := s.wsInterceptDirection(fromClient)
			// Bytes already buffered must go out through the same path that
			// buffered them, even if interception was switched off in between.
			// Relaying a newer chunk ahead of an older partial frame would
			// reorder the stream, which is worse than either path alone.
			//
			// A buffered fragment counts too: mid-message, the accumulator holds bytes that have not
			// been relayed, so switching to the chunk path would emit the rest of the message ahead
			// of its own beginning.
			if !degraded && (s.wsNeedsFrames(fromClient) || len(pending) > 0 || frag.active) {
				fault, gone := s.wsIntercept(dir, &pending, chunk, dst, rs, exchangeID, fromClient, peer, stats, &frag)
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

// wsMatchReplaceDirection is the match/replace direction for this side of the relay, and whether any
// enabled rule targets it.
func (s *Server) wsMatchReplaceDirection(fromClient bool) (matchreplace.Direction, bool) {
	dir := matchreplace.DirWebSocketToClient
	if fromClient {
		dir = matchreplace.DirWebSocketToServer
	}
	if s.config.matchReplace == nil {
		return dir, false
	}
	return dir, s.config.matchReplace.Affects(dir)
}

// wsNeedsFrames reports whether this direction must be parsed into frames rather than relayed as
// opaque chunks.
//
// Two independent reasons, and either alone is enough: interception has to hold whole messages, and
// match & replace has to rewrite whole payloads. Tying the frame path to interception alone was a
// real bug for a moment during this work — WebSocket match/replace rules would have installed,
// reported success, and rewritten nothing whenever interception happened to be off, which is the
// decorative-control failure this project keeps finding.
func (s *Server) wsNeedsFrames(fromClient bool) bool {
	if _, holding := s.wsInterceptDirection(fromClient); holding {
		return true
	}
	_, rewriting := s.wsMatchReplaceDirection(fromClient)
	return rewriting
}

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
func (s *Server) wsIntercept(dir intercept.Direction, pending *[]byte, chunk []byte, dst net.Conn, rs *core.WsReassembler, exchangeID core.ExchangeID, fromClient bool, peer wsPeer, stats *wsCaptureStats, frag *wsFragments) (string, bool) {
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

		// Zero or more frames out: a mid-message fragment relays nothing until the message is
		// complete, and the final fragment may relay several at once. See wsFragments.
		outs, drop := s.wsDecideFrames(dir, hdr, frame, fromClient, peer, frag)
		if drop {
			stats.dropped.Add(1)
			continue
		}
		for _, out := range outs {
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
}

// wsFragments accumulates one fragmented message so it can be offered whole.
//
// A fragmented message arrives as a data frame with FIN clear, then continuation frames, the last
// with FIN set (RFC 6455 §5.4). Burp reassembles these before offering them; burpsy used to relay
// them untouched, because a held fragment is half a message and an edit to it cannot be
// length-checked against a remainder that has already gone.
//
// So on an intercepting direction nothing goes on the wire until the message is complete. That is a
// real behavioural change — fragments are delayed rather than relayed as they arrive — and like
// every other part of this path it applies only where the operator switched interception on.
type wsFragments struct {
	// active is set once a first fragment has been seen. Distinct from len(frames) > 0, because a
	// message may legitimately carry an empty payload.
	active bool
	// opcode is the first fragment's; continuation frames do not carry one.
	opcode core.WsOpcode
	// payload is the unmasked, accumulated message.
	payload []byte
	// frames keeps the original frames in order, so a message forwarded unchanged is relayed exactly
	// as it arrived rather than re-framed. That keeps "forwarded untouched" byte-identical to "never
	// intercepted" — the same property the unfragmented path has.
	frames [][]byte
}

func (f *wsFragments) reset() {
	f.active = false
	f.opcode = 0
	f.payload = nil
	f.frames = nil
}

// add buffers one fragment, returning false when the message has outgrown the cap.
func (f *wsFragments) add(hdr *core.WsFrameHeader, frame, payload []byte) bool {
	if len(f.payload)+len(payload) > core.DefaultMaxWsMessageBytes {
		return false
	}
	if !f.active {
		f.active = true
		f.opcode = hdr.Opcode
	}
	f.payload = append(f.payload, payload...)
	// frame points into the read buffer, which the next read reuses, so it must be copied. Getting
	// this wrong would corrupt the relay in a way that only appears under fragmentation.
	kept := make([]byte, len(frame))
	copy(kept, frame)
	f.frames = append(f.frames, kept)
	return true
}

// wsFramePayload returns a frame's payload, unmasked. Copied because the caller keeps it past the
// next read, and because unmasking in place would corrupt the frame that may still be relayed.
func wsFramePayload(hdr *core.WsFrameHeader, frame []byte) []byte {
	payload := make([]byte, hdr.PayloadLen)
	copy(payload, frame[hdr.HeaderLen:total(hdr)])
	if hdr.Masked {
		core.WsUnmask(payload, hdr.Mask, 0)
	}
	return payload
}

// wsDecideFrames handles one whole frame and returns the frames to relay, in order.
//
// A slice rather than a single frame, because of fragmentation: a mid-message fragment relays
// nothing, and a final fragment may relay several frames at once when the operator forwarded the
// message unchanged. drop=true means the operator dropped it and nothing goes on the wire.
func (s *Server) wsDecideFrames(dir intercept.Direction, hdr *core.WsFrameHeader, frame []byte, fromClient bool, peer wsPeer, frag *wsFragments) ([][]byte, bool) {
	// Control frames may be interleaved inside a fragmented message (RFC 6455 §5.4), so they are
	// handled first and must never disturb the accumulator. Holding a ping stalls the peer's
	// keepalive; holding a close leaves a socket that cannot be ended. Burp does not offer them
	// either.
	if hdr.Opcode.IsControl() {
		return [][]byte{frame}, false
	}

	// Compressed frames stay untouched: the payload is a DEFLATE block, so concatenating fragments
	// would produce a longer DEFLATE block rather than a longer message, and offering it as editable
	// text would be fiction. Only reachable when the operator disabled extension stripping.
	if hdr.RSV != 0 {
		if frag.active {
			// A compressed frame mid-message means our model of this stream is wrong. Flush what is
			// buffered rather than holding it forever, and stop reassembling.
			out := append(frag.frames, frame)
			frag.reset()
			s.config.logger.Debug("websocket reassembly abandoned: compressed frame mid-message",
				zap.String("direction", wsWhich(fromClient)))
			return out, false
		}
		s.config.logger.Debug("websocket frame relayed without offering it for interception",
			zap.String("direction", wsWhich(fromClient)), zap.String("reason", "compressed frame"))
		return [][]byte{frame}, false
	}

	continuation := hdr.Opcode == core.WsOpcodeContinuation
	fragmentStart := !hdr.FIN && !continuation

	switch {
	case fragmentStart, continuation && !hdr.FIN:
		if continuation && !frag.active {
			// A continuation with nothing to continue is a protocol error. Relay it and let the peers
			// deal with it — inventing a message here would be worse than passing the fault along.
			return [][]byte{frame}, false
		}
		if !frag.add(hdr, frame, wsFramePayload(hdr, frame)) {
			// Over the cap: flush and give up on this message rather than buffering without bound.
			// Same cap and same reasoning as the capture path.
			out := append(frag.frames, frame)
			frag.reset()
			s.config.logger.Debug("websocket message too large to reassemble for interception",
				zap.String("direction", wsWhich(fromClient)),
				zap.Int("cap", core.DefaultMaxWsMessageBytes))
			return out, false
		}
		// Incomplete, so there is nothing to offer and nothing to relay yet.
		return nil, false

	case continuation && hdr.FIN:
		if !frag.active {
			return [][]byte{frame}, false
		}
		if !frag.add(hdr, frame, wsFramePayload(hdr, frame)) {
			out := append(frag.frames, frame)
			frag.reset()
			return out, false
		}
		opcode, payload, originals := frag.opcode, frag.payload, frag.frames
		frag.reset()
		return s.wsOfferMessage(dir, opcode, payload, originals, fromClient, peer)

	default:
		// An unfragmented data frame: FIN set, a data opcode. The common case.
		return s.wsOfferMessage(dir, hdr.Opcode, wsFramePayload(hdr, frame), [][]byte{frame}, fromClient, peer)
	}
}

// wsOfferMessage offers one complete message to the operator and returns what to relay.
//
// originals are the frames it arrived as — one for an unfragmented message, several for a
// reassembled one — and they are relayed verbatim when the operator forwards without editing, so a
// message that went through interception untouched is byte-identical to one that never entered it.
// An edit is re-encoded as a single unfragmented frame, which is legal and is what Burp sends.
func (s *Server) wsOfferMessage(dir intercept.Direction, opcode core.WsOpcode, payload []byte, originals [][]byte, fromClient bool, peer wsPeer) ([][]byte, bool) {
	// Match & replace runs before interception, exactly as it does on the HTTP path in proxy.go: the
	// operator's standing rewrite rules are part of what the peer is deemed to have sent, so the
	// message offered for interception is the rewritten one. The other order would show the operator
	// a message, then silently alter it after they approved it.
	rewritten := payload
	if s.config.matchReplace != nil {
		mrDir := matchreplace.DirWebSocketToClient
		if fromClient {
			mrDir = matchreplace.DirWebSocketToServer
		}
		if s.config.matchReplace.Affects(mrDir) {
			rewritten = s.config.matchReplace.Apply(mrDir, payload)
		}
	}
	// A rewrite means the original frames are no longer what should go out, so the untouched-relay
	// shortcut below must not fire on them.
	rewrote := !bytes.Equal(rewritten, payload)
	payload = rewritten

	// Interception may be off while match & replace is on — the frame path runs for either reason —
	// so this must not assume there is an engine to offer the message to.
	var held *intercept.Held
	if _, holding := s.wsInterceptDirection(fromClient); holding {
		held = s.config.intercept.Hold(&intercept.Message{
			Direction: dir,
			Host:      peer.host,
			Port:      peer.port,
			TLS:       peer.tls,
			Path:      peer.path,
			Opcode:    opcode.Name(),
			Raw:       payload,
		})
	}
	if held == nil {
		// No interception rule matched, so this was never offered. Relay exactly as it arrived —
		// unless match & replace changed it, in which case the rewritten message is what goes out.
		if rewrote {
			return [][]byte{s.wsEncode(opcode, payload, fromClient, originals)}, false
		}
		return originals, false
	}

	// The destination is ignored: a WebSocket frame has no addressing of its own, and the engine
	// refuses a retarget on one (see intercept.Engine.Forward). The value is still discarded here
	// rather than defaulted so the compiler makes any future Wait caller state what it does with it.
	//
	// So is the edited flag. A frame is relayed, not recorded: this package's only rows for a
	// WebSocket are the handshake's, and the handshake's own flag comes from the request hold. An
	// edit to a frame therefore has nowhere to be reported — a gap rather than a decision, filed as
	// burpsy-react-ui-d7bu so it does not read as an oversight here.
	action, edited, _, _ := held.Wait()
	if action == intercept.ActionDrop {
		return nil, true
	}
	if bytes.Equal(edited, payload) {
		// Forwarded without further editing. If match & replace had rewritten it, that rewrite still
		// has to reach the wire; only an entirely unmodified message relays its original frames.
		if rewrote {
			return [][]byte{s.wsEncode(opcode, payload, fromClient, originals)}, false
		}
		return originals, false
	}

	// A client-to-server frame must be masked and a server-to-client frame must not be
	// (RFC 6455 §5.1). The direction decides, not what happened to arrive.
	return [][]byte{s.wsEncode(opcode, edited, fromClient, originals)}, false
}

// wsEncode frames a payload for the wire.
//
// A client-to-server frame must be masked and a server-to-client frame must not be (RFC 6455 §5.1),
// and a peer receiving the wrong one is required to fail the connection — so the mask is decided by
// direction, never by what happened to arrive.
//
// fallback is what to relay if a mask cannot be generated. Without one the only choices are an
// unmasked client frame, which the server must reject, or silently not sending the change; so the
// original goes out and the failure is logged loudly rather than swallowed.
func (s *Server) wsEncode(opcode core.WsOpcode, payload []byte, fromClient bool, fallback [][]byte) []byte {
	var mask *[4]byte
	if fromClient {
		var m [4]byte
		if _, err := rand.Read(m[:]); err != nil {
			s.config.logger.Error("could not generate a WebSocket mask; the modified message was NOT sent and the original was relayed instead",
				zap.Error(err), zap.String("direction", wsWhich(fromClient)))
			if len(fallback) > 0 {
				return fallback[0]
			}
			return nil
		}
		mask = &m
	}
	return core.EncodeWsFrame(opcode, payload, mask)
}

// total is the whole frame length for a parsed header.
func total(hdr *core.WsFrameHeader) int { return hdr.HeaderLen + int(hdr.PayloadLen) }

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
		payload, note := s.wsInflateForView(ev, capture.deflate, fromClient)
		m := &core.WsMessage{
			Exchange:   exchangeID,
			FromClient: fromClient,
			Opcode:     ev.Opcode,
			Len:        len(payload),
			Dropped:    ev.Dropped,
			Fragments:  ev.Fragments,
			AtMs:       uint64(time.Now().UnixMilli()),
			Note:       note,
		}
		s.config.store.AddWsMessage(m, payload)
		stats.messages.Add(1)
	}
}

// wsInflateForView returns the payload to record and the note to record with it.
//
// For an uncompressed message this is the event unchanged. For a compressed one it inflates when
// that is provably correct, and otherwise keeps the DEFLATE bytes and says why — because a message
// inflated against a window we do not have would be plausible-looking wrong plaintext, and on a tool
// whose output is read as evidence that is worse than showing nothing.
//
// Read-only by construction: this runs on the capture path, so whatever it returns affects the
// operator's view and never the bytes between the peers. That is the property that makes inflating
// here safe at all, and it is why editing a compressed message is still refused in wsDecideFrames.
func (s *Server) wsInflateForView(ev *core.WsEvent, params core.WsDeflateParams, fromClient bool) ([]byte, string) {
	if !ev.Compressed {
		return ev.Payload, ev.Note
	}
	if !params.InflatableFor(fromClient) {
		which := "client_no_context_takeover"
		if !fromClient {
			which = "server_no_context_takeover"
		}
		return ev.Payload, ev.Note + " This connection did not negotiate " + which +
			", so the sender's compression window carries across messages and this one cannot be " +
			"decoded on its own; burpsy does not keep that state, and decoding it against a fresh " +
			"window would show you convincing but wrong plaintext."
	}

	out, err := core.InflateWsMessage(ev.Payload, core.DefaultMaxWsMessageBytes)
	switch {
	case errors.Is(err, core.ErrWsDeflateTooLarge):
		// The data is fine, there is simply too much of it. What was inflated is true, so it is kept
		// and the shortfall is stated rather than the whole message being discarded.
		return out, "[burpsy] permessage-deflate message inflated up to the " +
			"1 MiB cap and truncated there; the bytes above are the message, the remainder was not decoded."
	case err != nil:
		s.config.logger.Debug("websocket message could not be inflated; recording it compressed",
			zap.String("direction", wsWhich(fromClient)), zap.Error(err))
		return ev.Payload, ev.Note + " Inflating it failed (" + err.Error() +
			"), so the compressed bytes are recorded as they arrived."
	default:
		return out, "[burpsy] decoded from permessage-deflate (RFC 7692); the bytes above are the " +
			"message, not the DEFLATE stream that carried it."
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
