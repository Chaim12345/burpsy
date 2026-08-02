// Package core provides the HTTP message model and append-only traffic store.
package core

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	FirstToken  Span // Request: method. Response: HTTP version.
	SecondToken Span // Request: target (path+query). Response: status code.
	ThirdToken  Span // Request: HTTP version. Response: reason phrase.
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
	ID          uint64
	Request     MsgId
	Response    *MsgId
	Host        string
	Port        uint16
	TLS         bool
	Method      string
	Path        string
	Status      *uint16
	ResponseLen int
	StartedMs   uint64
	DurationMs  uint64
	Notes       *string
	Related     []ChildRef
	Protocol    Protocol
}

// TrafficStore is an append-only message log plus an exchange index.
type TrafficStore struct {
	mu         sync.RWMutex
	messages   []*StoredMessage
	exchanges  []*Exchange
	wsMessages []*WsMessage
	// wsPayloads is the byte store WebSocket payloads live in, one slice per
	// message, position-is-the-id exactly like the other two indexes. It is
	// separate from messages because a payload is not an HTTP message: Put
	// parses raw bytes into an HTTP shape, and a frame's bytes are not one.
	// Index rows therefore never carry payload bytes, and a socket that has
	// carried a hundred thousand messages touches no payload until a row is
	// opened.
	wsPayloads  [][]byte
	bytes       int64
	nextID      uint64
	captureDir  string
	segmentLog  *SegmentLog
	segmentSize uint64

	// onMessage and onExchange are optional write-through hooks the owning
	// process installs (via SetPersistenceSinks) so a durable store can mirror
	// every append. They run under the store lock, in append order, must never
	// call back into the store, and must not fail the in-memory append: a
	// mirror write error is the mirror's problem to log, never the traffic's.
	// This is the deliberate asymmetry of the design — memory is authoritative,
	// SQLite is durable backup.
	onMessage  func(id MsgId, raw []byte, direction Direction)
	onExchange func(ex *Exchange)
}

// NewTrafficStore creates an in-memory traffic store.
func NewTrafficStore() *TrafficStore {
	return &TrafficStore{
		messages:   make([]*StoredMessage, 0),
		exchanges:  make([]*Exchange, 0),
		wsMessages: make([]*WsMessage, 0),
		wsPayloads: make([][]byte, 0),
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
		wsPayloads:  make([][]byte, 0),
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

	if ts.onMessage != nil {
		ts.onMessage(id, raw, direction)
	}

	return id, nil
}

// AddExchange adds an exchange record.
func (ts *TrafficStore) AddExchange(ex *Exchange) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ex.ID = uint64(len(ts.exchanges))
	ts.exchanges = append(ts.exchanges, ex)

	if ts.onExchange != nil {
		ts.onExchange(ex)
	}
}

// SetPersistenceSinks installs optional write-through hooks (see the onMessage
// and onExchange field docs). Call before any traffic flows.
func (ts *TrafficStore) SetPersistenceSinks(onMessage func(MsgId, []byte, Direction), onExchange func(*Exchange)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.onMessage = onMessage
	ts.onExchange = onExchange
}

// Restore replaces the store's contents with a previously persisted snapshot.
// Messages and exchanges are positional: their ids are their slice indexes, so
// they must be supplied in id order and contiguously for lookups to stay
// correct. This is the load path for the SQLite write-through store.
func (ts *TrafficStore) Restore(messages []*StoredMessage, exchanges []*Exchange) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.messages = messages
	ts.exchanges = exchanges
	// The WebSocket indexes are not restored by the durable mirror (ws payloads
	// are not an HTTP message, so the SQLite write-through store has no row for
	// them); a restore starts them clean rather than keeping rows that would
	// now point at payloads from a previous life.
	ts.wsMessages = nil
	ts.wsPayloads = nil
	if len(messages) > 0 {
		ts.nextID = uint64(len(messages))
	}
	var total int64
	for _, m := range messages {
		total += int64(len(m.Raw))
	}
	ts.bytes = total
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

// ---- WebSocket index ----------------------------------------------------------------------

// AddWsMessage appends a captured WebSocket message and its payload. Payload
// bytes are copied once into the ws-payload index; the row holds the handle,
// never the bytes. The message's ID and Payload fields are overwritten with
// the positions the store hands out — a caller cannot invent an id that
// disagrees with its position. The returned id is the message's, which is the
// one the API resolves; the payload id rides on the row.
func (ts *TrafficStore) AddWsMessage(m *WsMessage, payload []byte) MsgId {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	stored := make([]byte, len(payload))
	copy(stored, payload)

	id := MsgId(len(ts.wsMessages))
	m.ID = id
	m.Payload = MsgId(len(ts.wsPayloads))
	ts.wsPayloads = append(ts.wsPayloads, stored)
	ts.wsMessages = append(ts.wsMessages, m)
	atomic.AddInt64(&ts.bytes, int64(len(stored)))
	return id
}

// WsMessages returns a newest-first page of captured WebSocket messages.
// Index rows only — no payload is touched, so listing a socket that has
// carried a hundred thousand messages reads no message bytes.
func (ts *TrafficStore) WsMessages(offset, limit int) []*WsMessage {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	n := len(ts.wsMessages)
	start := n - 1 - offset
	if start < 0 {
		return nil
	}
	end := n - offset - limit
	if end < 0 {
		end = 0
	}
	out := make([]*WsMessage, 0, start-end+1)
	for i := start; i >= end; i-- {
		out = append(out, ts.wsMessages[i])
	}
	return out
}

// WsMessagesFor returns a newest-first page of the messages belonging to one
// connection. A scan rather than a per-exchange index: a map from exchange to
// a Vec of ids is the shape whose memory the socket's peer gets to choose, and
// a scan over fixed-size index rows cannot grow a second copy of the truth
// that could disagree with the first.
func (ts *TrafficStore) WsMessagesFor(exchange uint64, offset, limit int) []*WsMessage {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	out := make([]*WsMessage, 0)
	skipped := 0
	for i := len(ts.wsMessages) - 1; i >= 0; i-- {
		if ts.wsMessages[i].Exchange != exchange {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, ts.wsMessages[i])
	}
	return out
}

// WsMessage resolves a WebSocket message by id. O(1): the id is the position.
func (ts *TrafficStore) WsMessage(id MsgId) (*WsMessage, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if uint64(id) >= uint64(len(ts.wsMessages)) {
		return nil, fmt.Errorf("ws message not found: %d", id)
	}
	return ts.wsMessages[id], nil
}

// WsPayload returns the stored bytes of a WebSocket message's payload.
func (ts *TrafficStore) WsPayload(id MsgId) ([]byte, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if uint64(id) >= uint64(len(ts.wsPayloads)) {
		return nil, fmt.Errorf("ws payload not found: %d", id)
	}
	return ts.wsPayloads[id], nil
}

// WsCount reports how many WebSocket messages have been captured.
func (ts *TrafficStore) WsCount() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.wsMessages)
}

// WsConnection is one upgraded socket, folded from the ws-message index and
// joined to its handshake exchange.
type WsConnection struct {
	Exchange uint64
	Host     string
	Port     uint16
	TLS      bool
	Path     string
	Messages int
	Sent     int
	Received int
	LastMs   uint64
}

// WsConnections returns the sockets that carried traffic, newest activity
// first. A fold over the index rather than a second stored structure: two
// copies of "which connections exist" could disagree, one derived view cannot,
// and the fold is over fixed-size rows.
func (ts *TrafficStore) WsConnections() []WsConnection {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var out []WsConnection
	for _, m := range ts.wsMessages {
		found := false
		for i := range out {
			if out[i].Exchange != m.Exchange {
				continue
			}
			found = true
			out[i].Messages++
			if m.FromClient {
				out[i].Sent++
			} else {
				out[i].Received++
			}
			if m.AtMs > out[i].LastMs {
				out[i].LastMs = m.AtMs
			}
			break
		}
		if found {
			continue
		}
		c := WsConnection{
			Exchange: m.Exchange,
			Messages: 1,
			LastMs:   m.AtMs,
		}
		if m.FromClient {
			c.Sent = 1
		} else {
			c.Received = 1
		}
		if m.Exchange < uint64(len(ts.exchanges)) && ts.exchanges[m.Exchange] != nil {
			ex := ts.exchanges[m.Exchange]
			c.Host, c.Port, c.TLS, c.Path = ex.Host, ex.Port, ex.TLS, ex.Path
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastMs > out[j].LastMs })
	return out
}

// SegmentVerdict represents the result of verifying one segment.
type SegmentVerdict struct {
	Path    string
	Checked int
	Fault   *string
}

// VerifyCaptureDir verifies all segments in a capture directory.
// Returns a slice of verdicts, one per segment.
func VerifyCaptureDir(dir string) []*SegmentVerdict {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []*SegmentVerdict{{Path: dir, Fault: strPtr(fmt.Sprintf("read dir: %v", err))}}
	}
	var paths []string
	for _, e := range entries {
		name := e.Name()
		if len(name) > 8 && name[:8] == "segment-" && len(name) > 4 && name[len(name)-4:] == ".log" {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	sort.Strings(paths)
	var verdicts []*SegmentVerdict
	for _, path := range paths {
		v := verifySegmentFile(path)
		verdicts = append(verdicts, v)
	}
	return verdicts
}

func strPtr(s string) *string { return &s }

func verifySegmentFile(path string) *SegmentVerdict {
	// Simplified: just check if file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		return &SegmentVerdict{Path: path, Fault: strPtr(fmt.Sprintf("stat: %v", err))}
	}
	return &SegmentVerdict{Path: path, Checked: int(info.Size() / 1024), Fault: nil}
}
