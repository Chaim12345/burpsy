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
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
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
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	upstream, err := net.Dial("tcp", addr)
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
	exchangeID := uint64(0)
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
func (s *Server) relayWebsocket(exchangeID uint64, clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader, host string, port uint16, tls bool, path string, capture *wsCapture) {
	var stats wsCaptureStats
	faults := make([]string, 2)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		faults[0] = s.wsDirection(exchangeID, clientReader, upstreamConn, true, capture, &stats)
	}()
	go func() {
		defer wg.Done()
		faults[1] = s.wsDirection(exchangeID, upstreamReader, clientConn, false, capture, &stats)
	}()
	wg.Wait()

	// The skipped count is named unconditionally, including when it is zero:
	// "0 excluded" and a sentence that omits the subject are not the same
	// statement to someone checking coverage.
	s.config.logger.Info("websocket connection closed",
		zap.String("host", host), zap.Uint16("port", port), zap.String("path", path),
		zap.Uint64("exchange", exchangeID),
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
func (s *Server) wsDirection(exchangeID uint64, src *bufio.Reader, dst net.Conn, fromClient bool, capture *wsCapture, stats *wsCaptureStats) string {
	rs := core.NewWsReassembler(core.DefaultMaxWsMessageBytes)
	buf := make([]byte, wsRelayChunk)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			// Relay first, capture second — the ordering is the safety argument.
			if _, werr := dst.Write(chunk); werr != nil {
				return ""
			}
			if cerr := rs.Feed(chunk); cerr != nil {
				which := "client→server"
				if !fromClient {
					which = "server→client"
				}
				fault := fmt.Sprintf("%s: %v", which, cerr)
				s.config.logger.Warn("websocket capture stopped",
					zap.String("direction", which), zap.String("exchange", fmt.Sprintf("%d", exchangeID)), zap.Error(cerr))
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

// drainWs writes every completed message to the index, or counts it as skipped
// when scope excludes this connection right now.
func (s *Server) drainWs(rs *core.WsReassembler, exchangeID uint64, fromClient bool, capture *wsCapture, stats *wsCaptureStats) {
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
func (s *Server) recordWsCaptureStopped(exchangeID uint64, host string, port uint16, tls bool, path string, reason string) {
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
