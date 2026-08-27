package sender

// This file is sender's second connection primitive: one socket carrying more than one exchange.
// writeHTTP1 (sender.go:597) dials fresh and reads exactly one response per send, which is exactly
// right for every check that sends independent probes — but it cannot represent a front-end/back-end
// framing disagreement, because that disagreement only exists *across* two requests sharing one
// reused socket. checks_cache.go declines "HTTP request smuggling" and "Client-side desync" for
// precisely this reason: "sender has no keep-alive/pipelining primitive". SendPipelined,
// SendKeepAlive and TimedRead are that primitive. writeHTTP1 itself is untouched: 29 native checks
// already ride it, and this file dials, writes and reads on its own, never calling it.
//
// # Authorisation is the caller's job
//
// Sender carries no scope handle — only AuthorisedSender does (HARD-03), and every other
// unauthorised primitive on this type says so in its own doc comment (Send, SendRaw,
// SendRawOutcome). SendPipelined, SendKeepAlive and TimedRead are the same shape of primitive with
// the same absence: nothing in this file can ask "is this authorised", because Sender has no scope
// handle to ask it of. A caller MUST run every raw request through a ScopeChecker.AuthoriseRaw gate
// (one call per raw, for the batch entry points — a smuggled prefix can address a different target
// than the socket it rides in on) before it ever reaches SendPipelined, SendKeepAlive or TimedRead.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// Framing names which HTTP/1.1 rule delimited a PipelinedExchange's response body — see
// PipelinedExchange.Framing.
const (
	// framingContentLength means Content-Length bounded the body.
	framingContentLength = "content-length"
	// framingChunked means a chunked Transfer-Encoding bounded the body, even when a Content-Length
	// was also present: RFC 7230 §3.3.3 gives Transfer-Encoding precedence, and that precedence is
	// exactly the disagreement a smuggling check is built to notice, so it is named, not silently
	// resolved.
	framingChunked = "chunked"
	// framingEOF means neither header was present, so the body was read until the connection closed
	// (HTTP/1.0-style). Against a peer that keeps the connection open, this framing never completes
	// before a deadline fires — which is not a bug in this package, it is the ambiguity the caller
	// asked to observe.
	framingEOF = "eof"
	// framingNone means the response cannot carry a body at all (1xx, 204, 304) or its head could not
	// be parsed, so no delimiting rule applies.
	framingNone = "none"
)

// PipelinedExchange is one raw request written on a connection this package shares across several
// requests, and whatever could be established about the response that followed it.
//
// Response and Framing are only useful together: Framing names the rule that decided where Response
// ends, so a caller comparing two takes on the same bytes — the whole point of a smuggling or desync
// check — learns *why* the boundary landed where it did, not just where it landed.
type PipelinedExchange struct {
	// Raw is the exact bytes this exchange sent, so a []PipelinedExchange is self-describing and a
	// caller never has to zip it back up against the raws slice it was built from.
	Raw []byte
	// Response is the response bytes read for this exchange, head and body concatenated exactly as
	// they arrived on the wire — chunk-size lines and terminators included, nothing decoded. When
	// ReadErr names a body-read failure, Response still holds the head that was read before it, since
	// a partial answer is evidence and a guessed one is not.
	Response []byte
	// Framing names the rule that delimited Response's body: framingContentLength, framingChunked,
	// framingEOF or framingNone. Empty when no response head was read at all.
	Framing string
	// ResponseComplete is true only when Response was read to a boundary this package is confident of.
	// False never comes with a nil ReadErr: an incomplete response always names why.
	ResponseComplete bool
	// ReadErr names why ResponseComplete is false: a connection that closed before answering, or a
	// framing rule — typically framingEOF against a peer that never closes — that never reached a
	// delimitable end before the deadline. That ambiguity is the signal a smuggling or desync check
	// reads; it is reported, never papered over with a fabricated empty success.
	ReadErr error
}

// classifyFraming names the rule httputil.ReadResponseBody will use to delimit the body that follows
// head, without reading that body itself.
//
// It duplicates the small decision ReadResponseBody makes internally — not the chunked/Content-Length
// reading loop that decision protects with size caps, only the branch that picks between them — using
// the identical inputs (the same status-line byte offsets, the same net/textproto header parse, the
// same case-insensitive "chunked" comparison) so the two can never disagree about what a given head
// means. A second implementation of this predicate that could ever drift from the reader it describes
// would misreport which rule produced the exact bytes in PipelinedExchange.Response — the silent
// disagreement this whole package exists to catch, just relocated into burpsy instead of the target.
func classifyFraming(head []byte) string {
	statusLine := string(bytes.SplitN(head, []byte("\r\n"), 2)[0])
	// Mirrors ReadResponseBody's own noBody test exactly: 1xx, 204 and 304 never carry a body, so
	// there is no body reader — and no framing rule to name for one — regardless of what
	// Content-Length or Transfer-Encoding claims.
	if len(statusLine) >= 12 && (statusLine[9] == '1' || statusLine[9:12] == "204" || statusLine[9:12] == "304") {
		return framingNone
	}

	headerBlock := head
	if idx := bytes.Index(headerBlock, []byte("\r\n")); idx != -1 {
		headerBlock = headerBlock[idx+2:]
	}
	mimeHead, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerBlock))).ReadMIMEHeader()
	if err != nil {
		// ReadResponseBody will fail identically parsing the same headers; there is no successful
		// body read here to name a framing for.
		return framingNone
	}
	if te := mimeHead.Get("Transfer-Encoding"); strings.EqualFold(te, "chunked") {
		return framingChunked
	}
	if cl := mimeHead.Get("Content-Length"); cl != "" {
		return framingContentLength
	}
	return framingEOF
}

// readFramedResponse reads one HTTP/1.1 response off br, naming which rule delimits its body before
// reading it.
//
// The bytes are read through httputil.ReadResponseHead and ReadResponseBody — the same capped,
// exercised reader writeHTTP1 already trusts via ReadHTTPResponse — rather than a second
// chunked/Content-Length loop written here: naming the framing is new information those functions
// have no reason to expose on a single-response caller, but the actual reading is not reimplemented,
// because a second reader that could ever drift from the one this package already relies on would be
// a worse defect than the one this file exists to surface.
//
// A body read that fails — most often a deadline firing while a framingEOF body waits for a close
// that never comes — returns the head bytes already read, complete=false and err naming what
// happened, never a truncated or guessed body.
func readFramedResponse(br *bufio.Reader) (raw []byte, framing string, complete bool, err error) {
	head, err := httputil.ReadResponseHead(br)
	if err != nil {
		return nil, "", false, err
	}
	framing = classifyFraming(head)
	body, err := httputil.ReadResponseBody(br, head)
	if err != nil {
		return head, framing, false, err
	}
	raw = make([]byte, 0, len(head)+len(body))
	raw = append(raw, head...)
	raw = append(raw, body...)
	return raw, framing, true, nil
}

// dialOne opens the single connection SendPipelined, SendKeepAlive and TimedRead each need,
// mirroring how the rest of this package already dials: a plain net.Dialer for cleartext, exactly
// like sendHTTP1Plain, and s.dialTLS's shared certificate-verification path for TLS, exactly like
// SendRawOutcome.
//
// It offers only HTTP/1.1 on a TLS handshake — alpn.EgressOffer(false), not the h2-preferring offer
// SendRawOutcome uses — because pipelining and keep-alive desync detection are HTTP/1.1-specific: an
// h2 connection multiplexes independent streams instead of interleaving bytes on one, so there is no
// framing disagreement here for it to carry. Negotiating h2 anyway would silently turn a smuggling
// probe into a no-op instead of a refusal.
func (s *Sender) dialOne(ctx context.Context, host string, port uint16, useTLS bool) (net.Conn, error) {
	if !useTLS {
		// dialPlain, not a hand-rolled dial: it is the one place the hostname-resolution table and
		// the upstream proxy policy are composed. A probe that ignored the resolution override would
		// be sent to a different machine from the ordinary request it is being compared against,
		// which is the one thing a smuggling probe cannot afford.
		conn, err := s.dialPlain(ctx, host, port)
		if err != nil {
			return nil, fmt.Errorf("connection failed: %w", err)
		}
		return conn, nil
	}
	conn, _, err := s.dialTLS(ctx, host, port, alpn.EgressOffer(false))
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	return conn, nil
}

// SendPipelined dials one connection, writes every request in raws back-to-back without waiting for
// a response in between, then reads one response per request off that same socket, in order.
//
// This is the shape a front-end/back-end Content-Length-vs-Transfer-Encoding disagreement needs to
// become observable: two requests that share one socket, where the back end's idea of where the
// first one ends decides what it reads as the start of the second. See the package doc above on
// authorisation — every raw in raws must already have cleared a ScopeChecker.AuthoriseRaw call.
//
// The returned slice always has one PipelinedExchange per raws entry, in order, even when a write or
// a read fails partway through: a request that could not be written gets its own ReadErr rather than
// being silently dropped, and the exchanges before a failure are unaffected by it. The error return is
// only for a failure before any exchange could be attempted at all — dialling the connection.
func (s *Sender) SendPipelined(ctx context.Context, host string, port uint16, useTLS bool, raws [][]byte) ([]PipelinedExchange, error) {
	conn, err := s.dialOne(ctx, host, port, useTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// See cancel.go. Installed per connection, not per request: the loops below re-arm the
	// deadline each iteration, and one watcher per iteration would leave stale ones behind.
	defer watchCancel(ctx, conn)()
	// One deadline for the whole batch, set once, exactly like writeHTTP1 sets one for its single
	// exchange: SendPipelined is one connection carrying one unit of work, and re-arming the deadline
	// per read would let a large batch's total duration grow without the bound the caller asked for.
	s.setDeadline(ctx, conn, host)

	// stoppedWriting is the index of the first request never written onto the socket, or
	// len(raws) when every request went out: a write failure on a shared connection is fatal to
	// every request after it, not only the one that failed, so nothing from this index onward was
	// even attempted.
	stoppedWriting := len(raws)
	var writeErr error
	for i, raw := range raws {
		if _, werr := conn.Write(raw); werr != nil {
			stoppedWriting = i
			writeErr = fmt.Errorf("request %d of %d not sent, and no later request in this batch was attempted: %w", i, len(raws), werr)
			break
		}
	}

	br := bufio.NewReader(conn)
	exchanges := make([]PipelinedExchange, len(raws))
	for i, raw := range raws {
		exchanges[i].Raw = raw
		if i >= stoppedWriting {
			// Never sent, so there is no response to read: recording the write failure as this
			// exchange's ReadErr is the honest answer, not an attempt to read a reply to a request
			// that never went out.
			exchanges[i].ReadErr = writeErr
			continue
		}
		resp, framing, complete, rerr := readFramedResponse(br)
		exchanges[i].Response = resp
		exchanges[i].Framing = framing
		exchanges[i].ResponseComplete = complete
		exchanges[i].ReadErr = rerr
	}
	return exchanges, nil
}

// SendKeepAlive dials one connection and, unlike SendPipelined, writes and fully reads one exchange
// at a time in sequence before writing the next — the non-pipelined sibling a desync check needs,
// where the second request's *treatment* is the evidence rather than a framing collision between two
// requests already in flight together. Separating the two is deliberate: a pipelined write can mask
// a server that closes the connection between requests, which is exactly the behaviour this function
// is meant to expose.
//
// See SendPipelined's doc comment on authorisation and on the returned slice's shape: the same rules
// apply here — one PipelinedExchange per raws entry, a per-exchange ReadErr rather than a dropped
// entry when a write or a read fails, and an error return reserved for a dial failure.
//
// Each exchange gets its own deadline, reset before its write: a keep-alive send is N independent
// round trips rather than SendPipelined's one shared unit of work, so the configured timeout bounds
// every round trip individually instead of the batch's total duration.
func (s *Sender) SendKeepAlive(ctx context.Context, host string, port uint16, useTLS bool, raws [][]byte) ([]PipelinedExchange, error) {
	conn, err := s.dialOne(ctx, host, port, useTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// See cancel.go. Installed per connection, not per request: the loops below re-arm the
	// deadline each iteration, and one watcher per iteration would leave stale ones behind.
	defer watchCancel(ctx, conn)()

	br := bufio.NewReader(conn)
	exchanges := make([]PipelinedExchange, len(raws))
	for i, raw := range raws {
		exchanges[i].Raw = raw
		s.setDeadline(ctx, conn, host)
		if _, werr := conn.Write(raw); werr != nil {
			exchanges[i].ReadErr = fmt.Errorf("request %d of %d not sent: %w", i, len(raws), werr)
			continue
		}
		resp, framing, complete, rerr := readFramedResponse(br)
		exchanges[i].Response = resp
		exchanges[i].Framing = framing
		exchanges[i].ResponseComplete = complete
		exchanges[i].ReadErr = rerr
	}
	return exchanges, nil
}

// TimedRead sends one request on its own connection and reads the response with a short,
// caller-chosen deadline, reporting a deadline firing before the response was fully read as
// timedOut=true rather than as an error.
//
// Timing is the CL.TE/TE.CL detection signal that needs no second request at all: a front end that
// forwarded a smuggled request body onward as (what it believes is) the start of the *next* request
// leaves the back end waiting for bytes that already left inside the first request's body, so the
// socket goes quiet for exactly as long as settle allows where a well-framed exchange would have
// answered. A caller needs "waited on purpose and got silence" as a value it can compare across
// probes, not as an error string it has to pattern-match — which is what timedOut is for.
//
// See SendPipelined's doc comment on authorisation: raw must already have cleared a
// ScopeChecker.AuthoriseRaw call before it reaches this function.
func (s *Sender) TimedRead(ctx context.Context, host string, port uint16, useTLS bool, raw []byte, settle time.Duration) (response []byte, timedOut bool, err error) {
	conn, err := s.dialOne(ctx, host, port, useTLS)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	// See cancel.go. Installed per connection, not per request: the loops below re-arm the
	// deadline each iteration, and one watcher per iteration would leave stale ones behind.
	defer watchCancel(ctx, conn)()

	s.setDeadline(ctx, conn, host)
	if _, err = conn.Write(raw); err != nil {
		return nil, false, fmt.Errorf("write failed: %w", err)
	}

	// The read gets its own deadline, independent of the write's: settle is how long a caller treats
	// "no bytes yet" as evidence, which is usually far shorter than the ordinary per-request timeout
	// the write above just used.
	conn.SetReadDeadline(time.Now().Add(settle))
	br := bufio.NewReader(conn)
	response, _, _, err = readFramedResponse(br)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return response, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return response, false, nil
}
