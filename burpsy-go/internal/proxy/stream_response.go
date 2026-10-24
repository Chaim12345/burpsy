package proxy

import (
	"bufio"
	"errors"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
	"go.uber.org/zap"
)

// This file is the proxy leg's streaming response path: the one that forwards a response to the
// client as its bytes arrive instead of holding them until the response ends.
//
// # The defect, in one sentence
//
// Burp's documentation (settings/network/http.html:96-104) names it exactly: waiting for a response
// to end before forwarding any of it means that for an open-ended response "none of the response is
// ever forwarded", and the fix is that "The Proxy passes these responses straight through to the
// client in real time." burpsy buffered every response — httputil's ReadResponseBody copies an
// unframed body until EOF, and on an SSE stream or a long-poll EOF never comes — so a browser got
// nothing until the connection's own deadline fired, which it reads as a hung target
// (burpsy-react-ui-wet3).
//
// # Why the streaming write is separate from the ordinary one
//
// The order is head-then-body, and it is the only order that works: a browser cannot begin rendering
// an event stream without the status and headers, and the whole point is that the client starts
// consuming before the response ends. So the head goes out immediately and each body chunk follows as
// it arrives, flushed.
//
// The rules, the intercept hold and the record then run on what arrived, through handleTLSResponse
// with its write suppressed. That reuses the one implementation of those four steps rather than
// copying them, and it is why a streamed row has the same four stage boundaries every other row
// has. It also means a streamed response is NOT held for the operator: a rule cannot rewrite a byte
// the client has already been sent, and a hold cannot hold a stream open for an operator who has
// nothing to edit yet. An operator who needs to edit one sends it to Repeater instead — a worse
// workflow than a hold, and the right one, because the alternative is that the stream never arrives.

// streamsResponse reports whether this response should be forwarded as it arrives.
//
// The condition is that nothing frames the response: no Content-Length, no Transfer-Encoding, and a
// status that can carry a body. Such a response is open-ended by definition, and this branch is what
// saves the operator who has not declared the host in Settings → Network.
//
// A framed response is never streamed on its framing alone. Content-Length and a terminal chunk both
// say when the response ends, and honouring that is what lets Match & Replace and the hold see the
// whole message before any of it reaches the client. An operator who declares a well-behaved host
// open-ended gets the buffered path, which is the correct answer and not a silent override: a
// declared-open-ended host answering with a Content-Length is a host that ended its response.
//
// The one exception is the "treat text/event-stream responses as streaming" switch: when it is on, a
// framed response whose Content-Type is text/event-stream is streamed anyway, because an SSE feed that
// carries a Content-Length is still a feed the operator wants to watch arrive. That is the only way a
// framed response reaches this path.
//
// The host list is consulted for the window and the diagnostic, not for the decision — the decision
// is a property of the response's framing, which is knowable, where the host list is an operator's
// guess about a target. A close-delimited HTTP/1.0 body has the same frameless shape and does end, so
// the policy counts these (NoteUnframed) and the counter is how an operator tells "the proxy streamed
// my ordinary response" from "the proxy streamed my event stream and it arrived empty".
func (s *Server) streamsResponse(host string, head []byte) bool {
	// Both frameless AND chunked-without-a-terminal-chunk are open-ended, and the second is the
	// common one: Go's own http server, and most SSE frameworks, frame an event stream as
	// Transfer-Encoding: chunked and then simply never send the terminal chunk. Testing only for
	// "no framing" would classify every real event stream as ordinary and buffer it — which is the
	// defect, not a fix for it.
	//
	// So the predicate is the union, and what actually distinguishes them is decided at the end of
	// the read: a response that reaches its own terminal framing was ordinary all along, and one that
	// did not was a stream. That is why the buffered path re-reads rather than guessing here.
	_ = host
	if httputil.ResponseIsFrameless(head) || httputil.ResponseIsChunked(head) {
		return true
	}
	// The text/event-stream switch admits the one streaming shape framing alone does not: an SSE
	// response that carries a Content-Length and would otherwise be buffered until it ended. The two
	// branches above already stream every frameless or chunked response, so this only ever adds the
	// framed event stream, and only when the operator turned the switch on — a host that answered a
	// request with an ordinary framed body is untouched.
	if s.config.Streaming().TreatEventStreamAsStreaming() && headIsEventStream(head) {
		return true
	}
	return false
}

// headIsEventStream reports whether a response head declares a text/event-stream body.
//
// The comparison ignores parameters (a `; charset=utf-8` suffix) and case, because `Content-Type:
// text/event-stream; charset=utf-8` is the same media type as `text/event-stream` and an operator
// who turned the switch on means both.
func headIsEventStream(head []byte) bool {
	ct := headerValue(head, "Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

var (
	streamCRLF          = []byte("\r\n")
	streamTerminalChunk = []byte("0\r\n\r\n")
)

// streamFraming decides how a streamed response is written to the client, reconciling the three
// shapes a streamed response takes once framing and the strip switch are accounted for.
//
// The problem it solves: StreamResponse hands back the DECODED payload — it consumes the chunk size
// lines and trailers. So a chunked response forwarded with its Transfer-Encoding header intact but its
// body dechunked is unreadable: a client told the body is chunked tries to parse "data: ..." as a
// chunk size and fails with "unexpected EOF". The proxy did exactly that for every chunked response
// before this, the latent half of burpsy-react-ui-wet3. The two honest answers are to re-frame the
// payload as chunks (keep the header true) or to drop the header and send the body close-delimited —
// which is precisely Burp's "strip chunked encoding metadata" switch off and on.
type streamFraming struct {
	head     []byte // the head to forward to the client
	rechunk  bool   // re-frame each decoded chunk as a chunk and emit a terminal chunk on completion
	closeEnd bool   // the forwarded response is close-delimited, so the connection must end with it
}

// framingFor builds the framing decision from the policy and the upstream head.
func framingFor(policy *StreamingPolicy, head []byte) streamFraming {
	if !httputil.ResponseIsChunked(head) {
		// Frameless already: no Content-Length and no Transfer-Encoding, so the body is close-delimited
		// and there is nothing to re-frame or strip.
		return streamFraming{head: head, closeEnd: true}
	}
	if policy.StripChunkedMetadata() {
		// Strip on: drop Transfer-Encoding and send the decoded payload close-delimited.
		stripped, _ := removeHeader(head, "Transfer-Encoding")
		return streamFraming{head: stripped, closeEnd: true}
	}
	// Strip off (the default): keep the chunked head and re-frame the decoded payload as chunks, so the
	// header stays true to the body and a strict client can read it.
	return streamFraming{head: head, rechunk: true}
}

// writeChunk writes one decoded payload to the client, re-framed as a chunk when the framing calls for
// it. StreamResponse never hands an empty payload to its callback, so a re-framed chunk is never a
// spurious terminal chunk.
func (f streamFraming) writeChunk(clientConn net.Conn, chunk []byte) {
	if !f.rechunk {
		_, _ = clientConn.Write(chunk)
		return
	}
	_, _ = clientConn.Write(strconv.AppendInt(nil, int64(len(chunk)), 16))
	_, _ = clientConn.Write(streamCRLF)
	_, _ = clientConn.Write(chunk)
	_, _ = clientConn.Write(streamCRLF)
}

// writeTerminal closes a re-framed chunked response with its terminal chunk, but only when the
// upstream response actually ended: a truncated stream has no terminal chunk and the connection
// closing is what tells the client it stopped.
func (f streamFraming) writeTerminal(clientConn net.Conn, result httputil.StreamResult) {
	if f.rechunk && result.Completed {
		_, _ = clientConn.Write(streamTerminalChunk)
	}
}

// keepAlive reports whether the connection may carry a next request after this response. Only a
// self-framed response that ended qualifies — a re-chunked response with its terminal chunk. A
// close-delimited response (stripped or frameless) and a truncated one both end with the connection.
func (f streamFraming) keepAlive(result httputil.StreamResult) bool {
	return f.rechunk && result.Completed
}

// streamTLSResponse forwards one open-ended response over an intercepted TLS tunnel live, then runs
// the ordinary rules-and-record path on what arrived.
//
// # The window is the policy's, set on the upstream leg
//
// The upstream connection is the thing that will not end, so the read deadline goes there rather
// than being imposed by the read loop: a window that expires closes the read, and whatever arrived is
// sent to the client and recorded. That is the operator's declared bound doing what they set it for,
// and it is why a stream cannot pin a connection past the window.
//
// The deadline is cleared afterwards, because the tunnel serves more than one request on a
// keep-alive connection and a second request inheriting the first's expired deadline would fail
// before it sent anything.
//
// # What the client receives when the window closes
//
// The head, then whatever body bytes arrived, then nothing more. No framing is synthesised: the
// response was unframed inbound and stays unframed outbound, so a browser reading it as a stream sees
// the stream end at the point the window closed, which is the truth.
func (s *Server) streamTLSResponse(
	clientConn net.Conn,
	upstream net.Conn,
	upstreamBR *bufio.Reader,
	method, host string,
	port uint16,
	tls bool,
	path string,
	head []byte,
	requestData []byte,
	reqStages messageStages,
	inScope bool,
	startTime, firstByte time.Time,
	requestEdited bool,
	downgrade string,
) bool {
	policy := s.config.Streaming()
	window := policy.Window()
	if deadlineConn, ok := upstream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetReadDeadline(time.Now().Add(window))
		defer func() { _ = deadlineConn.SetReadDeadline(time.Time{}) }()
	}

	// How the streamed response is framed to the client: a re-chunked chunked response, a stripped
	// close-delimited one, or an already-frameless one. StreamResponse is still handed the original
	// head so it decodes the chunk framing — the framing decision only changes what the client is told.
	framing := framingFor(policy, head)

	// The head first: a browser cannot begin rendering an event stream without the status and
	// headers, and streaming is the point at which the client starts consuming early.
	if _, err := clientConn.Write(framing.head); err != nil {
		return false
	}

	// Each body chunk is written and flushed as it arrives. Without the flush the bytes sit in the
	// client's socket buffer until the response ends, which is the buffered path wearing a streaming
	// hat.
	result, err := httputil.StreamResponse(upstreamBR, head, func(chunk []byte) {
		framing.writeChunk(clientConn, chunk)
	})
	if err != nil {
		// A malformed frame is a protocol fault. The head has already gone to the client, so the
		// honest thing is to stop rather than append a body the framing never described.
		s.config.logger.Warn("streaming response stopped on a malformed frame",
			zap.String("host", host), zap.Error(err))
		return false
	}
	framing.writeTerminal(clientConn, result)

	// The client has its bytes. Now the ordinary machinery runs on what arrived — the rules, the
	// record, the note — with handleTLSResponse's write suppressed, because the write is the one step
	// this path has already done differently.
	completed := time.Now()
	note := streamingNote(result, window)
	responseData := make([]byte, 0, len(head)+len(result.Body))
	responseData = append(responseData, head...)
	if policy.Store() {
		responseData = append(responseData, result.Body...)
	} else {
		// Store off: the client already has the body; history keeps the head and a note rather than
		// the streamed bytes. That is Burp's "Store streaming responses (may result in large temp
		// files)" turned off — the operator watched the stream and chose not to pay to keep it.
		note = joinNotes(streamNotStoredNote(result), note)
	}

	kept := s.handleTLSResponse(clientConn, method, host, port, tls, path, requestData, reqStages,
		inScope, responseData, startTime, firstByte, completed, serverIPOf(upstream), requestEdited,
		downgrade, true, note)
	// Keep the tunnel alive only for a self-framed response that ended. A stripped or frameless body
	// is close-delimited and a truncated one never finished, so either must close rather than carry a
	// next request on a framing that no longer says where this response ended.
	return kept && framing.keepAlive(result)
}

// streamingResponseNote says what kind of response this was, in the row's own terms.
//
// A streamed exchange that completed is an ordinary one that happened to arrive in pieces, and
// saying so would be noise. One that did not is a different fact — the peer never ended it — and that
// fact is the only way an operator reading history can tell a truncated stream from a short response.
func streamingResponseNote(result httputil.StreamResult, window time.Duration) string {
	if result.Completed && !result.Truncated {
		return ""
	}
	if result.Truncated && !result.Completed {
		return "open-ended response: forwarded as it arrived, stopped at the " +
			window.String() + " window with " + formatByteCount(len(result.Body)) + " read"
	}
	return "open-ended response: " + formatByteCount(len(result.Body)) + " read before the cap"
}

// streamingNote is streamingResponseNote as the *string the record path takes, and nil rather than
// a pointer to "" when there is nothing to say — because a pointer to an empty string is a note that
// exists, and the store would carry it as one.
func streamingNote(result httputil.StreamResult, window time.Duration) *string {
	text := streamingResponseNote(result, window)
	if text == "" {
		return nil
	}
	return &text
}

// streamNotStoredNote is the history note for a streamed response whose body the operator chose not
// to store. It names the byte count so the row still says how much was forwarded, which is the one
// fact the missing body would otherwise have carried.
func streamNotStoredNote(result httputil.StreamResult) string {
	return "streaming response body not stored: " + formatByteCount(len(result.Body)) +
		" forwarded to the client (store off)"
}

// joinNotes combines a leading note with an optional trailing one into the *string the TLS record
// path takes, keeping both facts and returning nil when there is nothing to say.
func joinNotes(lead string, rest *string) *string {
	text := mergeNoteText(lead, derefNote(rest))
	if text == "" {
		return nil
	}
	return &text
}

// mergeNoteText joins two note fragments with "; ", dropping either when it is empty so a missing
// fragment does not leave a dangling separator.
func mergeNoteText(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

func derefNote(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// formatByteCount renders a streamed body size for a history note, at the precision an operator
// reading a row needs. Bytes below a kibibyte are counted exactly because a small stream is a
// specific thing ("it got four events"); above that the unit is the fact.
func formatByteCount(n int) string {
	switch {
	case n < 1024:
		return strconv.Itoa(n) + " bytes"
	case n < 1024*1024:
		return strconv.Itoa(n/1024) + " KiB"
	default:
		return strconv.Itoa(n/(1024*1024)) + " MiB"
	}
}

// streamPlainResponse is handleHTTP's half of the streaming path, for a plaintext listener.
//
// It duplicates forwardRequest's dial-and-write because that function owns its connection and
// closes it on return — by which time a stream has already ended, which is the defect. So the dial,
// the write and the read are done here, on a connection that stays open for exactly as long as the
// stream does.
//
// The result is handed to completeResponse with its client write suppressed, the same relationship
// the TLS path has with handleTLSResponse: the stream does the writing, the ordinary function does
// the rules, the hold and the record.
func (s *Server) streamPlainResponse(
	clientConn net.Conn,
	requestData []byte,
	host string,
	port uint16,
	tls bool,
	path string,
	method string,
	reqStages messageStages,
	inScope bool,
	startTime time.Time,
	heldNote, heldHighlight string,
	serverIP string,
	requestEdited bool,
) {
	upstreamConn, err := s.dialUpstreamFor(context.Background(), host, port, tls)
	if err != nil {
		s.config.logger.Error("streaming forward failed", zap.String("host", host), zap.Error(err))
		return
	}
	defer upstreamConn.Close()
	if serverIP == "" {
		serverIP = serverIPOf(upstreamConn)
	}

	window := s.config.Streaming().Window()
	if deadlineConn, ok := upstreamConn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetReadDeadline(time.Now().Add(window))
		defer func() { _ = deadlineConn.SetReadDeadline(time.Time{}) }()
	}

	// The credential is attached here for the same reason it is at the other two forward sites: this
	// function owns the upstream connection and the write, so this is the last point at which the
	// bytes going out can still be the bytes that were recorded. A platform credential the operator
	// configured is part of those bytes (burpsy-react-ui-trcy).
	if _, err := upstreamConn.Write(s.forForwarding(requestData, host, method, path)); err != nil {
		s.config.logger.Warn("forward failed: upstream write", zap.String("path", path), zap.Error(err))
		return
	}

	br := bufio.NewReader(upstreamConn)
	head, firstByte, err := readStreamingHead(br, s.config.network)
	if err != nil {
		s.config.logger.Warn("forward failed: reading response head", zap.String("path", path), zap.Error(err))
		return
	}

	// A 401's challenge is the nonce a Digest credential is computed against, so it is recorded as
	// soon as the head is in hand and the NEXT request can answer it. This is the whole of Digest's
	// reachability on the proxy leg: there is no retry, because re-sending a request the browser did
	// not ask to repeat against a host that is refusing it is how an account gets locked out. One
	// refused request followed by an authenticated one is a fair price; a credential storm is not.
	learnFromChallenge(s.config.platformAuth, host, platformAuthChallenges(head))

	if !s.streamsResponse(host, head) {
		// The origin framed the response after all, or answered with a status that carries no body.
		// Reading it the ordinary way from the same buffered reader is correct and costs nothing: the
		// head is already in hand, so this is ReadResponseBody and the rest of handleHTTP unchanged.
		body, err := httputil.ReadResponseBody(br, head)
		var truncated *httputil.TruncatedBodyError
		if err != nil && !(errors.As(err, &truncated) && len(body) > 0) {
			s.config.logger.Warn("forward failed: reading response body", zap.String("path", path), zap.Error(err))
			return
		}
		if truncated != nil {
			// The upstream closed short of its declared Content-Length but did
			// send bytes. Dropping the whole exchange is the worst answer: the
			// client gets an empty reply to a request the origin answered, and
			// history shows nothing at all. Forward what arrived instead. The
			// declared framing is now false, so the head is rewritten
			// close-delimited — safe on this leg, whose connection ends with
			// this response — and the exchange is recorded with a note saying
			// exactly what was lost, the same honesty rule the streaming path's
			// truncation note follows. (Juice Shop's /ftp/ listing is the
			// exhibit: it declares 59 bytes more than it ever sends.)
			head = httputil.CloseDelimitedHead(head)
			note := "upstream closed the response body short of its declared Content-Length (" +
				truncated.Declared + " declared, " + strconv.Itoa(len(body)) + " received); " +
				"the partial body was forwarded close-delimited"
			s.config.logger.Warn("response body truncated by upstream",
				zap.String("path", path), zap.String("declared", truncated.Declared),
				zap.Int("received", len(body)), zap.Error(err))
			if heldNote == "" {
				heldNote = note
			} else {
				heldNote = note + "; " + heldNote
			}
		}
		responseData := append(head, body...)
		completed := time.Now()
		s.completeResponse(clientConn, method, host, port, tls, path, requestData, reqStages,
			responseData, startTime, firstByte, completed, heldNote, heldHighlight, serverIP, requestEdited, "", false)
		return
	}

	// The framing decision, the same as the TLS leg: a chunked response is re-framed as chunks (strip
	// off) or stripped to a close-delimited body (strip on), and a frameless one is already
	// close-delimited. The plain path serves one request per connection (handleHTTP's caller defers
	// Close), so a close-delimited response needs no extra signalling — the connection ends when this
	// returns — but a chunked response still has to be re-framed or a strict client cannot read it.
	policy := s.config.Streaming()
	framing := framingFor(policy, head)
	if _, err := clientConn.Write(framing.head); err != nil {
		return
	}

	// Each chunk goes to the client as it lands. A raw net.Conn has no user-space buffer — Write
	// hands the bytes to the kernel and the peer reads them — so the write IS the flush, and that is
	// what makes this streaming rather than the buffered path wearing a streaming hat.
	result, err := httputil.StreamResponse(br, head, func(chunk []byte) {
		framing.writeChunk(clientConn, chunk)
	})
	if err != nil {
		s.config.logger.Warn("streaming response stopped on a malformed frame",
			zap.String("host", host), zap.Error(err))
		return
	}
	framing.writeTerminal(clientConn, result)

	completed := time.Now()
	responseData := make([]byte, 0, len(head)+len(result.Body))
	responseData = append(responseData, head...)
	// The stream note is merged into whatever the request hold already left, for the same reason
	// handleTLSResponse seeds it: both are facts about this exchange and neither replaces the other.
	noteText := streamingResponseNote(result, window)
	if policy.Store() {
		responseData = append(responseData, result.Body...)
	} else {
		// Store off: history keeps the head and a note; the client already has the body.
		noteText = mergeNoteText(streamNotStoredNote(result), noteText)
	}
	if noteText != "" {
		if heldNote == "" {
			heldNote = noteText
		} else {
			heldNote = noteText + "; " + heldNote
		}
	}
	s.completeResponse(clientConn, method, host, port, tls, path, requestData, reqStages,
		responseData, startTime, firstByte, completed, heldNote, heldHighlight, serverIP, requestEdited, "", true)
}

// streamH2Body copies an open-ended HTTP/2 response body to w as it arrives, and returns what it read
// so the exchange can be recorded with it.
//
// # Why the deadline is the context's, not this function's
//
// An h2 response body is an io.ReadCloser driven by the stream's own context, and a read deadline
// cannot be set on it — there is no socket underneath that this function owns. So the bound is the
// copy loop's own: it stops after the window, which is the operator's declared patience, and the
// bytes read so far are what it returns.
//
// # Why it writes to w rather than returning a channel
//
// The body has to reach the ResponseWriter while it is being read; a channel would only move the
// buffering somewhere else and make the ordering depend on a second goroutine. Writing inline is
// the whole point: the browser sees each chunk at the moment it is read.
//
// The response is NOT offered to the intercept hold here, and no modification rule runs on it — the
// same two limits relayH2Stream's comment states about the re-rendering. Streaming changes when the
// bytes arrive, not which bytes.
func (s *Server) streamH2Body(body io.Reader, w http.ResponseWriter, window time.Duration) []byte {
	flusher, canFlush := w.(http.Flusher)
	var out bytes.Buffer
	buf := make([]byte, 32*1024)
	deadline := time.Now().Add(window)
	for {
		if time.Now().After(deadline) {
			// The window closed. What arrived is the answer for an open-ended response, and the row
			// records it with a note saying so rather than presenting it as a complete body.
			return out.Bytes()
		}
		n, err := body.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				return out.Bytes()
			}
			// The flush is what makes it streaming rather than the buffered path wearing a hat:
			// without it the bytes sit in net/http's response buffer until the handler returns.
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			return out.Bytes()
		}
	}
}

// readStreamingHead reads one response head, reading past interim 1xx heads when the operator's
// 100-continue handling says to (burpsy-react-ui-o1eu).
//
// The streaming leg needs this for the same reason the buffered leg does, and it is the leg where
// the failure is worst: a declared streaming host that answers `Expect: 100-continue` with a 100
// would have the interim head recorded and relayed as the whole response, and the event stream the
// operator declared the host for never reaches the client. A 101 is never skipped — it is an upgrade
// and the bytes after it belong to the other protocol.
func readStreamingHead(br *bufio.Reader, n *NetworkSettings) ([]byte, time.Time, error) {
	understand100 := n == nil || n.Continue.Understand100
	firstByte := time.Time{}
	for interim := 0; ; interim++ {
		head, at, err := httputil.ReadResponseHeadTimed(br)
		if err != nil {
			return nil, time.Time{}, err
		}
		if firstByte.IsZero() {
			firstByte = at
		}
		if !understand100 || !isInterimResponseHead(head) {
			return head, firstByte, nil
		}
		if interim+1 >= maxInterimResponses {
			return head, firstByte, fmt.Errorf("peer sent %d interim responses without a final one", maxInterimResponses)
		}
	}
}
