// Package core provides the HTTP message model and append-only traffic store.
package core

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
)

// DefaultSegmentTargetBytes is the default target size for segment files.
const DefaultSegmentTargetBytes = 100 * 1024 * 1024 // 100 MB

// MsgId is a handle to a stored message. Cheap to copy; carries no payload.
type MsgId uint64

// Span represents a span within a message: the only thing we ever hold instead of bytes.
type Span struct {
	Offset int
	Len    int
}

func (s Span) End() int {
	return s.Offset + s.Len
}

func (s Span) IsEmpty() bool {
	return s.Len == 0
}

// Direction indicates which half of an exchange a stored blob is.
type Direction int

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

// HeaderSpan represents a header name and value as spans.
type HeaderSpan struct {
	Name  Span
	Value Span
}

// MessageShape is the parsed structure of an HTTP message, expressed purely as spans into stored bytes.
type MessageShape struct {
	Direction   Direction
	FirstToken  Span  // Request: method. Response: HTTP version.
	SecondToken Span  // Request: target (path+query). Response: status code.
	ThirdToken  Span  // Request: HTTP version. Response: reason phrase.
	Headers     []HeaderSpan
	Body        Span
}

// StoredMessage represents a stored HTTP message: raw bytes plus its span map.
type StoredMessage struct {
	ID    MsgId
	Raw   []byte
	Shape MessageShape
}

// Slice returns a span as bytes (zero-copy view).
func (m *StoredMessage) Slice(s Span) []byte {
	if s.End() > len(m.Raw) {
		return []byte{}
	}
	return m.Raw[s.Offset:s.End()]
}

// Text returns a lossy UTF-8 view of a span for display.
func (m *StoredMessage) Text(s Span) string {
	return string(m.Slice(s))
}

// Header returns a header value by name (case-insensitive).
func (m *StoredMessage) Header(name string) []byte {
	want := []byte(name)
	for _, h := range m.Shape.Headers {
		n := m.Slice(h.Name)
		if len(n) == len(want) && bytes.EqualFold(n, want) {
			return m.Slice(h.Value)
		}
	}
	return nil
}

// Body returns the message body.
func (m *StoredMessage) Body() []byte {
	return m.Slice(m.Shape.Body)
}

// Protocol indicates which protocol carried an exchange.
type Protocol int

const (
	ProtocolHTTP1 Protocol = iota
	ProtocolHTTP2
)

func (p Protocol) VersionToken() string {
	switch p {
	case ProtocolHTTP1:
		return "HTTP/1.1"
	case ProtocolHTTP2:
		return "HTTP/2"
	default:
		return "HTTP/1.1"
	}
}

// ChildRef is a reference from an exchange to a related record.
type ChildRef struct {
	Type ChildType
	ID   MsgId
}

type ChildType int

const (
	ChildWsFrame ChildType = iota
	ChildH2Frame
)

// Exchange represents one proxied exchange. Holds IDs, never payloads.
type Exchange struct {
	ID           uint64
	Request      MsgId
	Response     *MsgId
	Host         string
	Port         uint16
	TLS          bool
	Method       string
	Path         string
	Status       *uint16
	ResponseLen  int
	StartedMs    uint64
	DurationMs   uint64
	Notes        *string
	Related      []ChildRef
	Protocol     Protocol
}

// TrafficStore is an append-only message log plus an exchange index.
type TrafficStore struct {
	mu          sync.RWMutex
	messages    []*StoredMessage
	exchanges   []*Exchange
	wsMessages  []*WsMessage
	bytes       int64
	nextID      uint64
	captureDir  string
	segmentLog  *SegmentLog
	segmentSize uint64
}

// NewTrafficStore creates an in-memory traffic store.
func NewTrafficStore() *TrafficStore {
	return &TrafficStore{
		messages:  make([]*StoredMessage, 0),
		exchanges: make([]*Exchange, 0),
		wsMessages: make([]*WsMessage, 0),
	}
}

// NewTrafficStoreWithCaptureDir creates a traffic store with disk-backed segments.
func NewTrafficStoreWithCaptureDir(dir string, segmentSize uint64) (*TrafficStore, error) {
	segmentLog, err := NewSegmentLog(dir, segmentSize)
	if err != nil {
		return nil, err
	}

	return &TrafficStore{
		messages:    make([]*StoredMessage, 0),
		exchanges:   make([]*Exchange, 0),
		wsMessages:  make([]*WsMessage, 0),
		captureDir:  dir,
		segmentLog:  segmentLog,
		segmentSize: segmentSize,
	}, nil
}

// Put stores a raw HTTP message and returns its ID.
func (ts *TrafficStore) Put(raw []byte, direction Direction) (MsgId, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := MsgId(ts.nextID)
	ts.nextID++

	shape, err := Parse(raw, direction)
	if err != nil {
		return 0, fmt.Errorf("failed to parse message: %w", err)
	}

	var storedRaw []byte
	if ts.segmentLog != nil {
		// Write to segment file
		loc, err := ts.segmentLog.Append(raw)
		if err != nil {
			return 0, fmt.Errorf("failed to write to segment: %w", err)
		}
		// For now, also keep in memory for simplicity
		storedRaw = raw
		_ = loc
	} else {
		storedRaw = make([]byte, len(raw))
		copy(storedRaw, raw)
	}

	msg := &StoredMessage{
		ID:    id,
		Raw:   storedRaw,
		Shape: shape,
	}

	ts.messages = append(ts.messages, msg)
	atomic.AddInt64(&ts.bytes, int64(len(raw)))

	return id, nil
}

// AddExchange adds an exchange record.
func (ts *TrafficStore) AddExchange(ex *Exchange) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ex.ID = uint64(len(ts.exchanges))
	ts.exchanges = append(ts.exchanges, ex)
}

// Get retrieves a message by ID.
func (ts *TrafficStore) Get(id MsgId) (*StoredMessage, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if uint64(id) >= uint64(len(ts.messages)) {
		return nil, fmt.Errorf("message not found: %d", id)
	}

	return ts.messages[id], nil
}

// GetExchange retrieves an exchange by ID.
func (ts *TrafficStore) GetExchange(id uint64) (*Exchange, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if id >= uint64(len(ts.exchanges)) {
		return nil, fmt.Errorf("exchange not found: %d", id)
	}

	return ts.exchanges[id], nil
}

// Exchanges returns all exchanges (for history listing).
func (ts *TrafficStore) Exchanges() []*Exchange {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make([]*Exchange, len(ts.exchanges))
	copy(result, ts.exchanges)
	return result
}

// Count returns the number of messages and exchanges.
func (ts *TrafficStore) Count() (messages, exchanges int) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.messages), len(ts.exchanges)
}

// Bytes returns the total stored bytes.
func (ts *TrafficStore) Bytes() int64 {
	return atomic.LoadInt64(&ts.bytes)
}
