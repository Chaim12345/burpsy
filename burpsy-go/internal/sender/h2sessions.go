package sender

// HTTP/2 connection reuse across sends (burpsy-react-ui-adkx).
//
// Burp (desktop/http2/index.html): "By default, Repeater reuses the same connection for multiple HTTP/2
// requests. Some servers treat the first request on each connection differently to subsequent requests
// … If you run into either of these problems, you can mitigate them by disabling this option so that
// the request you send is always the first one on the connection."
//
// Every raw send here dials fresh, so the request is always the first on its connection — the
// "disabled" half. H2Sessions is the other half: an h2 client connection kept open after a send and
// handed to the next send with the same key (a Repeater tab and an authority), so "first request on the
// connection" and "a later one" can be compared on purpose. The send's outcome says which it was
// (SendOutcome.ConnectionReused), because a reuse the operator cannot see is no use for isolating a
// first-request effect.
//
// # Bounds
//
// At most max sessions are held; an idle session older than ttl is closed when the pool is next
// touched, and x/net/http2's own IdleConnTimeout closes it on the wire. The server never learns when a
// tab closes, so the TTL is what releases a closed tab's connection.
//
// # What is never reused
//
// A session that the peer has told to stop (GOAWAY) or that has died is not handed out
// (ClientConn.CanTakeNewRequest). A session in use is not in the map, so two concurrent sends with
// one key never share a stream — the second dials fresh. A send whose request cannot be carried over
// h2 never touches the pool. A send that fails on a reused session closes it; nothing is retried,
// because the request may already have reached the server.

import (
	"crypto/tls"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// H2Sessions holds idle h2 client connections between sends. Safe for concurrent use.
type H2Sessions struct {
	mu       sync.Mutex
	sessions map[string]*h2Session
	max      int
	ttl      time.Duration
	opened   atomic.Int64
	reused   atomic.Int64
}

type h2Session struct {
	cc       *http2.ClientConn
	conn     *tls.Conn
	ip       string
	lastUsed time.Time
}

// NewH2Sessions makes a pool of at most max idle sessions, each closed after ttl unused.
func NewH2Sessions(max int, ttl time.Duration) *H2Sessions {
	if max < 1 {
		max = 1
	}
	return &H2Sessions{sessions: map[string]*h2Session{}, max: max, ttl: ttl}
}

// Opened and Reused count sessions dialled for the pool and sends that rode an existing one.
func (p *H2Sessions) Opened() int64 { return p.opened.Load() }
func (p *H2Sessions) Reused() int64 { return p.reused.Load() }

// Idle is how many sessions are held right now.
func (p *H2Sessions) Idle() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// Close closes every idle session.
func (p *H2Sessions) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, sess := range p.sessions {
		sess.cc.Close()
		delete(p.sessions, key)
	}
}

// take removes and returns the live session for key, or nil. Expired and unusable sessions are closed.
func (p *H2Sessions) take(key string) *h2Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evictLocked(time.Now())
	sess := p.sessions[key]
	if sess == nil {
		return nil
	}
	delete(p.sessions, key)
	if !sess.cc.CanTakeNewRequest() {
		sess.cc.Close()
		return nil
	}
	return sess
}

// put returns a session to the pool after a successful send, or closes it when it cannot take another
// request. When the pool is full the least recently used session is closed to make room.
func (p *H2Sessions) put(key string, sess *h2Session) {
	if !sess.cc.CanTakeNewRequest() {
		sess.cc.Close()
		return
	}
	sess.lastUsed = time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if old := p.sessions[key]; old != nil {
		// A concurrent send with the same key dialled its own; keep the newer, close the other.
		old.cc.Close()
	}
	p.sessions[key] = sess
	if len(p.sessions) > p.max {
		keys := make([]string, 0, len(p.sessions))
		for k := range p.sessions {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return p.sessions[keys[i]].lastUsed.Before(p.sessions[keys[j]].lastUsed) })
		for _, k := range keys[:len(p.sessions)-p.max] {
			p.sessions[k].cc.Close()
			delete(p.sessions, k)
		}
	}
}

func (p *H2Sessions) evictLocked(now time.Time) {
	if p.ttl <= 0 {
		return
	}
	for key, sess := range p.sessions {
		if now.Sub(sess.lastUsed) > p.ttl {
			sess.cc.Close()
			delete(p.sessions, key)
		}
	}
}

// newClientConn wraps a negotiated h2 connection for pooling.
func (p *H2Sessions) newClientConn(conn *tls.Conn) (*http2.ClientConn, error) {
	tr := &http2.Transport{IdleConnTimeout: p.ttl}
	return tr.NewClientConn(conn)
}
