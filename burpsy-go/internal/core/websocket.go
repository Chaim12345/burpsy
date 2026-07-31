package core

import (
	"sync"
	"time"
)

// WsOpcode represents a WebSocket opcode.
type WsOpcode int

const (
	WsOpcodeContinuation WsOpcode = 0
	WsOpcodeText         WsOpcode = 1
	WsOpcodeBinary       WsOpcode = 2
	WsOpcodeClose        WsOpcode = 8
	WsOpcodePing         WsOpcode = 9
	WsOpcodePong         WsOpcode = 10
)

// WsMessage represents a captured WebSocket message.
type WsMessage struct {
	ID        MsgId
	Timestamp uint64
	FromClient bool
	Opcode    WsOpcode
	Data      Span
}

// Reassembler reassembles fragmented WebSocket messages.
type Reassembler struct {
	mu          sync.Mutex
	fragments   [][]byte
	messageType WsOpcode
	closed      bool
}

// NewReassembler creates a new WebSocket message reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{
		fragments: make([][]byte, 0),
	}
}

// AddFragment adds a fragment to the reassembler.
func (r *Reassembler) AddFragment(opcode WsOpcode, data []byte, fin bool) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.closed && opcode != WsOpcodeContinuation {
		r.fragments = r.fragments[:0]
		r.messageType = opcode
	}

	if opcode != WsOpcodeContinuation {
		r.messageType = opcode
	}

	if fin {
		r.fragments = append(r.fragments, data)
		result := r.assemble()
		r.fragments = r.fragments[:0]
		return result, true
	}

	r.fragments = append(r.fragments, data)
	return nil, false
}

// assemble combines all fragments into a single message.
func (r *Reassembler) assemble() []byte {
	total := 0
	for _, f := range r.fragments {
		total += len(f)
	}

	result := make([]byte, total)
	offset := 0
	for _, f := range r.fragments {
		copy(result[offset:], f)
		offset += len(f)
	}

	return result
}

// Close marks the reassembler as closed.
func (r *Reassembler) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}

// WsEvent represents a WebSocket event for capture.
type WsEvent struct {
	Timestamp  uint64
	FromClient bool
	Opcode     WsOpcode
	Data       []byte
	IsFinal    bool
}

// WsCapture captures WebSocket traffic.
type WsCapture struct {
	mu       sync.Mutex
	messages []*WsMessage
	nextID   MsgId
	stats    WsStats
}

// WsStats holds WebSocket capture statistics.
type WsStats struct {
	MessagesSent     int
	MessagesReceived int
	BytesSent        int64
	BytesReceived    int64
	Fragments        int
}

// NewWsCapture creates a new WebSocket capture instance.
func NewWsCapture() *WsCapture {
	return &WsCapture{
		messages: make([]*WsMessage, 0),
	}
}

// Capture records a WebSocket event.
func (wc *WsCapture) Capture(event WsEvent) MsgId {
	wc.mu.Lock()
	defer wc.mu.Unlock()

	id := wc.nextID
	wc.nextID++

	msg := &WsMessage{
		ID:         id,
		Timestamp:  uint64(time.Now().UnixMilli()),
		FromClient: event.FromClient,
		Opcode:     event.Opcode,
		Data:       Span{Offset: 0, Len: len(event.Data)}, // Simplified for now
	}

	wc.messages = append(wc.messages, msg)

	if event.FromClient {
		wc.stats.MessagesSent++
		wc.stats.BytesSent += int64(len(event.Data))
	} else {
		wc.stats.MessagesReceived++
		wc.stats.BytesReceived += int64(len(event.Data))
	}

	if !event.IsFinal {
		wc.stats.Fragments++
	}

	return id
}

// Messages returns all captured messages.
func (wc *WsCapture) Messages() []*WsMessage {
	wc.mu.Lock()
	defer wc.mu.Unlock()

	result := make([]*WsMessage, len(wc.messages))
	copy(result, wc.messages)
	return result
}

// Stats returns capture statistics.
func (wc *WsCapture) Stats() WsStats {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.stats
}
