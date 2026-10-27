package sender

// HTTP/1 connection reuse for a stream of independent sends (burpsy-react-ui-xhqr).
//
// Burp's Intruder setting "HTTP/1 connection reuse … can greatly increase the speed of your attacks";
// "if you deselect HTTP/1 connection reuse, Burp opens a new connection for each request and closes
// it after receiving a response". Before this, the second sentence was the only behaviour burpsy had:
// SendRawOutcome dials, writes, reads one response and closes, every time.
//
// # What makes a connection safe to hand to the next request
//
// Reuse is only correct when this side and the peer agree where the last response ended. A pooled
// connection whose previous response was mis-delimited hands the tail of that response to the next
// request as the start of its own — which in a tool that reports per-payload differences is a
// fabricated result, not a slow one. So a connection goes back to the pool only when every one of
// these holds, and is closed otherwise:
//
//   - the response was read to a boundary its own framing declared (Content-Length, chunked, or a
//     status that carries no body) — never one delimited by the peer closing (framingEOF);
//   - nothing was buffered past that boundary (a peer that sent more than one response is a
//     framing disagreement, and the extra bytes belong to no request);
//   - the request ended exactly where its own framing said it did (requestEndsAtFraming, keepalive.go):
//     a request carrying a second request past its framing — pipelined, or a smuggling payload sent on
//     purpose — has a response still to come, and the next request would read it as its own;
//   - neither the request nor the response said Connection: close, and neither was HTTP/1.0;
//   - the response was final (not 1xx — a 100 returned with Understand100 off leaves the real
//     response on the socket; a 101 hands the socket to another protocol), the request was not HEAD
//     (the body reader cannot frame a HEAD response without knowing the method) or CONNECT, and the
//     response was not read as an open-ended stream;
//   - the send was not cancelled and did not fail.
//
// # What is not pooled
//
// h2. HTTP/2 multiplexes on one connection by design, and keeping an h2 client connection alive across
// sends is a different mechanism (Burp's separate "HTTP/2 connection reuse"). A send whose plan offers
// h2 to an authority not already known to decline it dials a fresh connection; if ALPN chooses h2 the
// exchange happens on that connection and it is closed, counted as opened and never as reused. An
// operator who wants reuse against an h2-capable target pins HTTP/1 — which is what Burp's "HTTP/1
// connection reuse" means too. gaps.md records this.
//
// # Authorisation
//
// The pool authorises nothing. AuthorisedSender.SendReusing is the only exported way in, and it runs
// the same AuthoriseRaw gate SendAs runs, on every raw request, before a connection is checked out.
// A reused socket is not a reused decision.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// livenessProbe is how long a checkout waits to learn whether an idle connection is still open. A
// peer that closed an idle keep-alive socket has already sent its FIN, so the read returns EOF at once;
// a healthy socket has nothing to say and the probe times out. One millisecond is the whole cost of
// reuse on a healthy connection.
const livenessProbe = time.Millisecond

// ConnPool holds idle HTTP/1 connections between sends, keyed by authority, and bounds how many
// connections exist at once.
//
// # The bound
//
// At most max connections are live — checked out or idle — at any moment. Checkouts are bounded by a
// semaphore of size max; a fresh dial happens only when the authority has no idle connection, and
// before it dials, idle connections to *other* authorities are closed until the total fits. With one
// authority (an Intruder attack's AuthorisedSender is bound to one), that means N sends at
// concurrency k open at most k sockets.
//
// A ConnPool is safe for concurrent use. Close it when the work that owns it is finished; idle
// connections are otherwise held open until the peer closes them.
type ConnPool struct {
	max   int
	slots chan struct{}

	mu     sync.Mutex
	idle   map[string][]*pooledConn
	nIdle  int
	closed bool

	opened atomic.Int64
	reused atomic.Int64
}

// pooledConn owns one connection and the reader positioned on it. They travel together: a fresh
// bufio.Reader per exchange (writeHTTP1's shape) would drop whatever the old one had buffered, and
// whether anything *was* buffered is one of the reuse conditions.
type pooledConn struct {
	conn net.Conn
	br   *bufio.Reader
	// negotiated is what ALPN chose when this connection was dialled ("" for cleartext or a peer that
	// sent no ALPN), kept so a send that reuses it reports the same downgrade a fresh dial would.
	negotiated string
	// read counts bytes read off conn, so a failure on a reused connection can tell "the peer closed
	// before saying anything" (stale; safe to retry an idempotent request) from a partial answer.
	read *atomic.Int64
	key  string
	// owner, route and dialAddr are the reuse stamp (o388, caller-owned pool). A ConnPool is passed
	// in and may be shared between Senders, and two Senders' generation numbers are independent
	// counters that can be equal while their settings differ, so the generation alone cannot say
	// "same settings". The owner pointer says which Sender dialled this connection; only that
	// Sender may take it. route and dialAddr let that Sender re-check, at take time, that its
	// settings are still the ones the connection was dialled under (same helper as the Sender pools).
	owner    *Sender
	route    string
	dialAddr string
}

// countingConn counts what is read off a connection.
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// NewConnPool builds a pool bounded at max live connections. A max below 1 is treated as 1.
func NewConnPool(max int) *ConnPool {
	if max < 1 {
		max = 1
	}
	return &ConnPool{max: max, slots: make(chan struct{}, max), idle: map[string][]*pooledConn{}}
}

// Opened counts connections this pool dialled successfully.
func (p *ConnPool) Opened() int64 { return p.opened.Load() }

// Reused counts sends that completed on a connection an earlier send had already used.
func (p *ConnPool) Reused() int64 { return p.reused.Load() }

// Max is the live-connection bound.
func (p *ConnPool) Max() int { return p.max }

// Close closes every idle connection and makes the pool refuse to hold any more. Connections checked
// out at the time are closed when they are checked in.
func (p *ConnPool) Close() {
	p.mu.Lock()
	idle := p.idle
	p.idle = map[string][]*pooledConn{}
	p.nIdle = 0
	p.closed = true
	p.mu.Unlock()
	for _, list := range idle {
		for _, pc := range list {
			pc.conn.Close()
		}
	}
}

// acquireSlot blocks until a checkout may proceed, or ctx ends.
func (p *ConnPool) acquireSlot(ctx context.Context) error {
	select {
	case p.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *ConnPool) releaseSlot() { <-p.slots }

// takeIdle pops the most recently returned idle connection for key, or nil.
func (p *ConnPool) takeIdle(key string) *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	if len(list) == 0 {
		return nil
	}
	pc := list[len(list)-1]
	p.idle[key] = list[:len(list)-1]
	p.nIdle--
	return pc
}

// makeRoom closes idle connections to other authorities until a fresh dial keeps the live count
// within max. inUse is the number of checkouts in progress, this one included.
func (p *ConnPool) makeRoom() {
	p.mu.Lock()
	var evict []*pooledConn
	for p.nIdle > 0 && p.nIdle+len(p.slots) > p.max {
		for key, list := range p.idle {
			if len(list) == 0 {
				continue
			}
			evict = append(evict, list[0])
			p.idle[key] = list[1:]
			p.nIdle--
			break
		}
	}
	p.mu.Unlock()
	for _, pc := range evict {
		pc.conn.Close()
	}
}

// checkin returns a connection to the pool when reusable, and closes it otherwise. It always releases
// the checkout's slot.
func (p *ConnPool) checkin(pc *pooledConn, reusable bool) {
	defer p.releaseSlot()
	if pc == nil {
		return
	}
	if reusable {
		// Clear the exchange's deadline, so an idle socket is not poisoned by a bound that belonged
		// to the send that used it last.
		if err := pc.conn.SetDeadline(time.Time{}); err != nil {
			reusable = false
		}
	}
	p.mu.Lock()
	if reusable && !p.closed {
		p.idle[pc.key] = append(p.idle[pc.key], pc)
		p.nIdle++
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	pc.conn.Close()
}

// aliveCheck is alive, as a variable so a test can switch the probe off and reach the race it guards.
var aliveCheck = alive

// alive reports whether an idle connection is still usable: the peer has not closed it and has not
// sent anything unsolicited. A probe that times out is the healthy answer.
func alive(pc *pooledConn) bool {
	if pc.br.Buffered() > 0 {
		return false
	}
	// A FIN that has already arrived is decided here, without a deadline: see socketShut.
	if socketShut(pc.conn) {
		return false
	}
	if err := pc.conn.SetReadDeadline(time.Now().Add(livenessProbe)); err != nil {
		return false
	}
	_, err := pc.br.Peek(1)
	if err == nil {
		// Bytes nobody asked for. Whatever they are, they are not the answer to the next request.
		return false
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		return false
	}
	return pc.conn.SetReadDeadline(time.Time{}) == nil
}

// SendReusing is SendAs over a ConnPool: the same AuthoriseRaw gate on the same bytes, bound to the
// same authority, the same pacing, and the same Sent/Refused counters — and then the request rides an
// idle HTTP/1 connection to this authority when the pool has a usable one. See connpool.go's header for
// when a connection is reused and when it is closed.
func (a *AuthorisedSender) SendReusing(ctx context.Context, pool *ConnPool, raw []byte, pref ProtocolPreference) (AuthorisedResult, error) {
	if pool == nil {
		return a.SendAs(ctx, raw, pref)
	}
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
		a.refused.Add(1)
		return AuthorisedResult{}, err
	}
	release, err := a.pacing(ctx)
	if err != nil {
		return AuthorisedResult{}, err
	}
	defer release()
	start := time.Now()
	resp, outcome, err := a.net.sendReusing(ctx, pool, a.host, a.port, a.tls, raw, pref)
	if err != nil {
		return AuthorisedResult{}, err
	}
	a.sent.Add(1)
	return AuthorisedResult{
		Raw:      resp,
		Duration: time.Since(start),
		Status:   httputil.ResponseStatus(resp),
		Outcome:  outcome,
	}, nil
}

// sendReusing is SendRawOutcome over a pool. Unexported: like every Sender primitive it authorises
// nothing, and SendReusing is the gate in front of it.
func (s *Sender) sendReusing(
	ctx context.Context, pool *ConnPool, host string, port uint16, useTLS bool, raw []byte, pref ProtocolPreference,
) ([]byte, SendOutcome, error) {
	plan, err := planSend(raw, useTLS, pref)
	if err != nil {
		return nil, SendOutcome{}, err
	}
	// An h2 offer to an authority not known to decline it may come back h2, and an h2 exchange is
	// not pooled — so it never takes an idle HTTP/1 connection, which would silently send over
	// HTTP/1.1 a request a fresh dial would have carried as h2.
	mayIdle := !useTLS || !plan.wantH2 || s.protocols.Lookup(host, port, useTLS) == ProtocolSupportHTTP11
	key := formatAuthority(host, port, useTLS)

	if err := pool.acquireSlot(ctx); err != nil {
		return nil, SendOutcome{}, err
	}
	if mayIdle {
		routeFor := s.routeForDialAddr(host, useTLS)
		for {
			pc := pool.takeIdle(key)
			if pc == nil {
				break
			}
			if pc.owner != s || pc.route != routeFor(pc.dialAddr) {
				// Dialled by another Sender, or under settings since changed: never carries this
				// request. Closed like a dead connection; the slot is already held.
				_ = pc.conn.Close()
				continue
			}
			if !aliveCheck(pc) {
				pc.conn.Close()
				continue
			}
			resp, out, stale, err := s.exchangePooled(ctx, pool, pc, host, port, useTLS, plan, raw)
			if err == nil {
				pool.reused.Add(1)
				return resp, out, nil
			}
			if !stale || !idempotent(raw) {
				return nil, out, err
			}
			// The peer closed a connection it had kept idle, between the liveness probe and the
			// write — before saying a single byte about this request. net/http retries exactly this
			// case for idempotent requests, and so does this: on a fresh connection, below. A
			// non-idempotent request is not retried here, because "the peer said nothing" does not
			// prove it did not act; the caller's own retry policy decides.
			if err := pool.acquireSlot(ctx); err != nil {
				return nil, SendOutcome{}, err
			}
			break
		}
	}

	// A fresh connection, within the live bound.
	pool.makeRoom()
	id, cerr := s.captureDialIdentity(ctx, host, port, useTLS)
	if cerr != nil {
		pool.releaseSlot()
		return nil, SendOutcome{}, cerr
	}
	pc, err := s.dialPooled(ctx, host, port, useTLS, plan, key, id)
	if err != nil {
		pool.releaseSlot()
		return nil, SendOutcome{}, fmt.Errorf("connection failed: %w", err)
	}
	pool.opened.Add(1)
	if plan.wantH2 && pc.negotiated == alpn.H2 {
		// The h2 exchange runs on this connection and the connection is closed: see the file header.
		defer pool.checkin(pc, false)
		stop := watchCancel(ctx, pc.conn)
		defer stop()
		s.setDeadline(ctx, pc.conn, host)
		resp, err := sendOverH2(ctx, pc.conn, plan.http2)
		out := s.finish(host, port, useTLS, pc.negotiated, nil, plan.rewrites, plan.http2.render(), remoteIP(pc.conn), err)
		return resp, out, err
	}
	resp, out, _, err := s.exchangePooled(ctx, pool, pc, host, port, useTLS, plan, raw)
	return resp, out, err
}

// dialPooled opens one connection for the pool, through the same dial sites SendRawOutcome uses.
func (s *Sender) dialPooled(ctx context.Context, host string, port uint16, useTLS bool, plan sendPlan, key string, id dialIdentity) (*pooledConn, error) {
	var conn net.Conn
	negotiated := ""
	if !useTLS {
		c, err := s.dialPlain(ctx, host, port, id)
		if err != nil {
			return nil, err
		}
		conn = c
	} else {
		c, n, err := s.dialTLS(ctx, host, port, alpn.EgressOffer(plan.wantH2), id)
		if err != nil {
			return nil, err
		}
		if plan.wantH2 {
			// Learnt only when h2 was offered, for the reason SendRawOutcome gives.
			s.protocols.learn(host, port, useTLS, n)
		}
		conn, negotiated = c, n
	}
	read := &atomic.Int64{}
	return &pooledConn{
		conn:       conn,
		br:         bufio.NewReader(countingConn{Conn: conn, n: read}),
		negotiated: negotiated,
		read:       read,
		key:        key,
		owner:      s,
		route:      id.route,
		dialAddr:   id.dialAddr,
	}, nil
}

// exchangePooled writes one HTTP/1.1 request on a checked-out connection, reads one final response,
// and checks the connection back in — pooled when the exchange left it clean, closed otherwise. stale
// is true when the failure was the peer closing before a single response byte arrived.
func (s *Sender) exchangePooled(
	ctx context.Context, pool *ConnPool, pc *pooledConn, host string, port uint16, useTLS bool, plan sendPlan, raw []byte,
) (resp []byte, out SendOutcome, stale bool, err error) {
	reusable := false
	defer func() { pool.checkin(pc, reusable) }()

	down := plan.block
	if down == nil {
		// Offered h2 and got HTTP/1.1, now or when this connection was dialled — the same two reasons
		// SendRawOutcome names.
		if pc.negotiated == "" {
			down = &Downgrade{Reason: DowngradeNoALPN, Forced: plan.mustH2}
		} else {
			down = &Downgrade{Reason: DowngradeNegotiatedHTTP11, Forced: plan.mustH2}
			if pc.negotiated != alpn.HTTP11 {
				down.Detail = pc.negotiated
			}
		}
	}

	settings := s.Network()
	startRead := pc.read.Load()
	s.setDeadline(ctx, pc.conn, host)
	stop := watchCancelSync(ctx, pc.conn)
	if _, werr := pc.conn.Write(plan.http1); werr != nil {
		fired := stop()
		err = fmt.Errorf("write failed: %w", explainCancellation(ctx, werr))
		out = s.finish(host, port, useTLS, pc.negotiated, down, nil, nil, remoteIP(pc.conn), err)
		return nil, out, !fired && ctx.Err() == nil, err
	}
	streaming := settings.Streaming.isStreaming(host)
	promoted := false
	promote := eventStreamPromoter(ctx, pc.conn, settings)
	var hook func([]byte) bool
	if promote != nil {
		hook = func(head []byte) bool {
			if promote(head) {
				promoted = true
				return true
			}
			return false
		}
	}
	resp, rerr := readResponse(pc.br, settings.Continue.Understand100, streaming, hook)
	fired := stop()
	if rerr != nil {
		err = fmt.Errorf("read failed: %w", explainCancellation(ctx, rerr))
		out = s.finish(host, port, useTLS, pc.negotiated, down, nil, nil, remoteIP(pc.conn), err)
		silent := pc.read.Load() == startRead && !fired && ctx.Err() == nil && peerClosed(rerr)
		return nil, out, silent, err
	}
	out = s.finish(host, port, useTLS, pc.negotiated, down, nil, nil, remoteIP(pc.conn), nil)
	reusable = !fired && ctx.Err() == nil && !streaming && !promoted &&
		pc.br.Buffered() == 0 && exchangeAllowsReuse(plan.http1, resp)
	return resp, out, false, nil
}

// peerClosed reports whether a read failed because the peer closed or reset the connection.
func peerClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// idempotent reports whether a request's method is one net/http would retry on a fresh connection
// after a reused one closed under it.
func idempotent(raw []byte) bool {
	line := raw
	if i := bytes.IndexByte(line, ' '); i > 0 {
		line = line[:i]
	}
	switch string(line) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

// watchCancelSync is watchCancel for a connection that outlives the exchange. watchCancel's stop
// returns without waiting, so a context that ends just as it is called can still fire a past deadline
// afterwards — harmless on a connection about to be closed, poison on one about to be pooled. This
// stop waits for the watcher to finish and reports whether it fired.
func watchCancelSync(ctx context.Context, conn net.Conn) (stop func() (fired bool)) {
	if ctx.Done() == nil {
		return func() bool { return false }
	}
	stopped := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
			done <- true
		case <-stopped:
			done <- false
		}
	}()
	return func() bool {
		close(stopped)
		return <-done
	}
}

// exchangeAllowsReuse applies the request- and response-side reuse rules from the file header to one
// completed exchange. Any head it cannot parse answers false: an exchange this cannot read is not one
// it can vouch for.
func exchangeAllowsReuse(req, resp []byte) bool {
	if !requestEndsAtFraming(req) {
		return false
	}
	reqLine, reqHeaders, ok := splitHead(req)
	if !ok {
		return false
	}
	method, _, version, ok := splitRequestLine(reqLine)
	if !ok || version != "HTTP/1.1" || method == "HEAD" || method == "CONNECT" {
		return false
	}
	if connectionSaysClose(reqHeaders) {
		return false
	}
	statusLine, respHeaders, ok := splitHead(resp)
	if !ok || !strings.HasPrefix(statusLine, "HTTP/1.1 ") {
		return false
	}
	code, ok := statusCode([]byte(statusLine))
	if !ok || code < 200 {
		return false
	}
	if connectionSaysClose(respHeaders) {
		return false
	}
	head, _, ok := httputil.CutHead(resp)
	if !ok {
		return false
	}
	return classifyFraming(resp[:len(head)+4]) != framingEOF
}

// splitHead cuts a message into its start line and parsed header fields.
func splitHead(msg []byte) (start string, headers textproto.MIMEHeader, ok bool) {
	head, _, ok := httputil.CutHead(msg)
	if !ok {
		return "", nil, false
	}
	block := msg[:len(head)+4]
	nl := bytes.Index(block, []byte("\r\n"))
	start = string(block[:nl])
	headers, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(block[nl+2:]))).ReadMIMEHeader()
	if err != nil {
		return "", nil, false
	}
	return start, headers, true
}

// connectionSaysClose reports whether any Connection field carries the close token.
func connectionSaysClose(h textproto.MIMEHeader) bool {
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "close") {
				return true
			}
		}
	}
	return false
}
