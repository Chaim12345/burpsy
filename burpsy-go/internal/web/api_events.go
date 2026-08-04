package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ---- GET /api/events (server-sent events) -------------------------------------------------------
//
// # Why SSE and not WebSockets
//
// This traffic is one-directional (the server tells the browser something changed; the browser answers
// by fetching an endpoint it already had), so the half of a WebSocket that carries client frames would
// go unused. SSE buys three things for that: it is ordinary HTTP, so every proxy, TLS terminator and
// curl in the chain already handles it; reconnection with backoff is implemented by the browser rather
// than by us; and it needs no dependency at either end — net/http can write it and EventSource can
// read it. A WebSocket would mean either a third-party library in a tree that has none for its own API
// or hand-rolling a frame codec, to carry frames in a direction nothing sends.
//
// The cost SSE charges is one connection held open per browser tab and a hard limit of six per origin
// on HTTP/1.1. One tab is what the UI opens, and the fallback below is what covers a browser that
// cannot open even that.
//
// # The frame shape
//
// One JSON object per frame, on the default `message` event so the client has exactly one parse path:
//
//	{"kind":"hello","window_ms":150}   sent first, and the client's proof the stream really flows
//	{"kind":"ping"}                    every 20s, so an idle stream is not mistaken for a dead one
//	{"kind":"history","changes":412}   something changed; refetch what reads it
//
// `changes` is how many underlying changes the frame stands for — see the coalescing note in events.go.
// Deliberately no row data and no ids: the client refetches through the handler that already owns that
// shape, so there is exactly one place that serialises an exchange, a finding or a log entry.

// liveFrame is one frame on the stream. The three frame families share a struct because they share a
// parse path on the client; omitempty keeps a change frame from carrying an empty window and a ping
// from carrying a zero count.
type liveFrame struct {
	Kind     string `json:"kind"`
	Changes  uint64 `json:"changes,omitempty"`
	WindowMs int64  `json:"window_ms,omitempty"`
}

// Reserved frame kinds. Distinct from every changeKind name, because the client dispatches on this one
// field: a change kind called "ping" would silently become a keepalive.
const (
	frameHello = "hello"
	framePing  = "ping"
)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Without a Flusher every frame would sit in the response buffer until the stream closed, which for
	// a stream that never closes means the operator sees nothing at all. Better to say so than to serve
	// a connection that looks alive and delivers nothing — the client falls back to polling on the error.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "response writer cannot stream", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	// Reverse proxies buffer a proxied response body by default, and for an event stream that turns
	// every frame into "later". This is the header nginx and its imitators read to stop; everything
	// else ignores it.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Subscribe before the hello frame, so a change landing between the two is announced rather than
	// missed. The unsubscribe is what makes a reconnect free: no slot and no goroutine survives a
	// closed connection.
	sub, unsubscribe := s.live.subscribe()
	defer unsubscribe()

	// retry: is the browser's reconnect delay for this stream. Set explicitly rather than left to the
	// default so a server restart is picked up in a known time.
	if _, err := fmt.Fprintf(w, "retry: %d\n\n", reconnectDelay.Milliseconds()); err != nil {
		return
	}
	if !writeFrame(w, flusher, liveFrame{Kind: frameHello, WindowMs: s.live.window.Milliseconds()}) {
		return
	}

	ping := time.NewTicker(pingInterval)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// The browser closed the tab, navigated away, or the server is shutting down.
			return
		case <-ping.C:
			if !writeFrame(w, flusher, liveFrame{Kind: framePing}) {
				return
			}
		case <-sub.signal:
			// One wake drains everything pending, however many windows the client fell behind by.
			for _, frame := range s.live.take(sub) {
				if !writeFrame(w, flusher, frame) {
					return
				}
			}
		}
	}
}

// writeFrame writes one SSE frame and flushes it, reporting whether the connection is still usable.
//
// A write error means the client is gone; the caller returns, which unsubscribes. Nothing is retried
// and nothing is logged: a browser closing a tab is the normal end of a stream, not a fault.
func writeFrame(w http.ResponseWriter, flusher http.Flusher, frame liveFrame) bool {
	payload, err := json.Marshal(frame)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// handleEventsStats reports what the stream has actually done — subscribers, frames, the changes those
// frames stood for, and how often a subscriber was still behind when the next flush arrived.
//
// It exists because a push stream that quietly stops pushing looks exactly like a quiet system. These
// counters are how an operator (or a test) tells those apart without reading the server's mind.
func (s *Server) handleEventsStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.live.stats())
}
