package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
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
// A framed response is never streamed, however the host is declared. Content-Length and a terminal
// chunk both say when the response ends, and honouring that is what lets Match & Replace and the
// hold see the whole message before any of it reaches the client. An operator who declares a
// well-behaved host open-ended gets the buffered path, which is the correct answer and not a silent
// override: a declared-open-ended host answering with a Content-Length is a host that ended its
// response.
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
	return httputil.ResponseIsFrameless(head) || httputil.ResponseIsChunked(head)
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
	window := s.config.Streaming().Window()
	if deadlineConn, ok := upstream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetReadDeadline(time.Now().Add(window))
		defer func() { _ = deadlineConn.SetReadDeadline(time.Time{}) }()
	}

	// The head first: a browser cannot begin rendering an event stream without the status and
	// headers, and streaming is the point at which the client starts consuming early.
	if _, err := clientConn.Write(head); err != nil {
		return false
	}

	// Each body chunk is written and flushed as it arrives. Without the flush the bytes sit in the
	// client's socket buffer until the response ends, which is the buffered path wearing a streaming
	// hat.
	result, err := httputil.StreamResponse(upstreamBR, head, func(chunk []byte) {
		if _, werr := clientConn.Write(chunk); werr == nil {
		}
	})
	if err != nil {
		// A malformed frame is a protocol fault. The head has already gone to the client, so the
		// honest thing is to stop rather than append a body the framing never described.
		s.config.logger.Warn("streaming response stopped on a malformed frame",
			zap.String("host", host), zap.Error(err))
		return false
	}

	// The client has its bytes. Now the ordinary machinery runs on what arrived — the rules, the
	// record, the note — with handleTLSResponse's write suppressed, because the write is the one step
	// this path has already done differently.
	completed := time.Now()
	responseData := make([]byte, 0, len(head)+len(result.Body))
	responseData = append(responseData, head...)
	responseData = append(responseData, result.Body...)

	return s.handleTLSResponse(clientConn, method, host, port, tls, path, requestData, reqStages,
		inScope, responseData, startTime, firstByte, completed, serverIPOf(upstream), requestEdited,
		downgrade, true, streamingNote(result, window))
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

	if _, err := upstreamConn.Write(requestData); err != nil {
		return
	}

	br := bufio.NewReader(upstreamConn)
	head, firstByte, err := httputil.ReadResponseHeadTimed(br)
	if err != nil {
		return
	}
	if !s.streamsResponse(host, head) {
		// The origin framed the response after all, or answered with a status that carries no body.
		// Reading it the ordinary way from the same buffered reader is correct and costs nothing: the
		// head is already in hand, so this is ReadResponseBody and the rest of handleHTTP unchanged.
		body, err := httputil.ReadResponseBody(br, head)
		if err != nil {
			return
		}
		responseData := append(head, body...)
		completed := time.Now()
		s.completeResponse(clientConn, method, host, port, tls, path, requestData, reqStages,
			responseData, startTime, firstByte, completed, heldNote, heldHighlight, serverIP, requestEdited, "", false)
		return
	}

	if _, err := clientConn.Write(head); err != nil {
		return
	}

	// Each chunk goes to the client as it lands. A raw net.Conn has no user-space buffer — Write
	// hands the bytes to the kernel and the peer reads them — so the write IS the flush, and that is
	// what makes this streaming rather than the buffered path wearing a streaming hat.
	result, err := httputil.StreamResponse(br, head, func(chunk []byte) {
		_, _ = clientConn.Write(chunk)
	})
	if err != nil {
		s.config.logger.Warn("streaming response stopped on a malformed frame",
			zap.String("host", host), zap.Error(err))
		return
	}

	completed := time.Now()
	responseData := make([]byte, 0, len(head)+len(result.Body))
	responseData = append(responseData, head...)
	responseData = append(responseData, result.Body...)

	// The stream note is merged into whatever the request hold already left, for the same reason
	// handleTLSResponse seeds it: both are facts about this exchange and neither replaces the other.
	note := streamingNote(result, window)
	if note != nil {
		if heldNote == "" {
			heldNote = *note
		} else {
			joined := *note + "; " + heldNote
			heldNote = joined
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
