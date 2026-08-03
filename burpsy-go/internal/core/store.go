// Package core provides the HTTP message model and append-only traffic store.
package core

import (
	"bytes"
	"fmt"
	"io"
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

// StoredMessage represents a stored HTTP message: its span map, plus a way to
// reach the bytes those spans index.
//
// The bytes are held one of two ways, and which one decides the store's entire
// memory profile. A resident message owns a heap copy. A disk-backed message
// owns nothing: it carries a Location and reads through the segment log's
// mapping, so the row costs about a hundred bytes whether the body was 200
// bytes or 200 KB. Measured over a 419 MB capture of 43,823 exchanges, that is
// 645 MB resident against 17.5 MB disk-backed, and a restart of 3.1s/623 MB
// against 288ms/22 MB.
type StoredMessage struct {
	ID    MsgId
	Shape MessageShape

	// Exactly one of these carries the payload: resident is non-nil for a heap
	// copy, otherwise loc and src say where to read it from.
	resident []byte
	loc      Location
	src      *SegmentLog
}

// NewResidentMessage builds a message owning a heap copy of raw. The caller's
// buffer is copied, so it may be reused afterwards.
func NewResidentMessage(id MsgId, raw []byte, shape MessageShape) *StoredMessage {
	owned := make([]byte, len(raw))
	copy(owned, raw)
	return &StoredMessage{ID: id, Shape: shape, resident: owned}
}

// NewDiskMessage builds a message whose bytes stay in a segment file. It holds
// no payload at all; Raw reads through src on demand.
func NewDiskMessage(id MsgId, shape MessageShape, loc Location, src *SegmentLog) *StoredMessage {
	return &StoredMessage{ID: id, Shape: shape, loc: loc, src: src}
}

// Raw returns the message bytes. For a disk-backed message the result is a view
// into the segment mapping: valid while the store is open, and never to be
// mutated.
//
// A failed read yields nil rather than a short buffer. Callers slice spans off
// this, and a partial buffer would silently truncate them into plausible-looking
// nonsense — refusing outright is the only honest answer.
func (m *StoredMessage) Raw() []byte {
	if m.resident != nil {
		return m.resident
	}
	if m.src == nil {
		return nil
	}
	raw, err := m.src.ReadAt(m.loc)
	if err != nil {
		return nil
	}
	return raw
}

// Len reports the message length without materialising the message.
func (m *StoredMessage) Len() int {
	if m.resident != nil {
		return len(m.resident)
	}
	return int(m.loc.Length)
}

// Location reports where the payload lives, zero-valued for a resident message.
func (m *StoredMessage) Location() Location { return m.loc }

// Slice returns a span as bytes (zero-copy view).
func (m *StoredMessage) Slice(s Span) []byte {
	raw := m.Raw()
	if s.End() > len(raw) {
		return []byte{}
	}
	return raw[s.Offset:s.End()]
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
	// locations holds, per message, where its bytes were appended on disk for a
	// disk-backed store — position-is-the-id exactly like messages. Zero for an
	// in-memory store. This is the Go counterpart of the Rust store's
	// `Body::OnDisk(loc)`: it is what lets VerifyIndex cross-check the index
	// against the segment files rather than trusting the append path.
	locations []Location
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
	onMessage  func(m *StoredMessage)
	onExchange func(ex *Exchange)
}

// NewTrafficStore creates an in-memory traffic store.
func NewTrafficStore() *TrafficStore {
	return &TrafficStore{
		messages:   make([]*StoredMessage, 0),
		exchanges:  make([]*Exchange, 0),
		wsMessages: make([]*WsMessage, 0),
		wsPayloads: make([][]byte, 0),
		locations:  make([]Location, 0),
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
		locations:   make([]Location, 0),
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

	var loc Location
	if ts.segmentLog != nil {
		// Write to segment file; the returned location is kept so VerifyIndex
		// can later prove the index and the log have not drifted apart.
		var err error
		loc, err = ts.segmentLog.Append(raw)
		if err != nil {
			return 0, fmt.Errorf("failed to write to segment: %w", err)
		}
	}

	// Once the bytes are in a segment and that segment can be mapped, this row
	// keeps none of them. The previous implementation appended to the segment
	// and *also* held raw, so a disk-backed store paid the write and the ingest
	// cost for no memory saving whatever — 419 MB on disk and 446 MB on the
	// heap for the same capture. An append that yielded no location, or a
	// platform that cannot map, still falls back to a resident copy: better to
	// spend the memory than to hold a span we cannot resolve.
	var msg *StoredMessage
	if loc.Segment != "" && ts.segmentLog.Mappable() {
		msg = NewDiskMessage(id, shape, loc, ts.segmentLog)
	} else {
		msg = NewResidentMessage(id, raw, shape)
	}

	ts.messages = append(ts.messages, msg)
	ts.locations = append(ts.locations, loc)
	atomic.AddInt64(&ts.bytes, int64(len(raw)))

	if ts.onMessage != nil {
		// The mirror is handed the message itself: it carries the id, the shape
		// to persist, the location to persist instead of a blob, and — for a
		// resident message, the only case where the mirror needs them — the
		// bytes. Passing the message beats growing the parameter list every
		// time the mirror learns to store one more thing about it.
		ts.onMessage(msg)
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
func (ts *TrafficStore) SetPersistenceSinks(onMessage func(*StoredMessage), onExchange func(*Exchange)) {
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
	// The locations index is rebuilt from the messages themselves, in lockstep.
	// A disk-backed message restored from the durable mirror carries the span
	// its bytes live at, so the index comes back intact and VerifyIndex can
	// still cross-check it against the log. A resident message reports a zero
	// location, which VerifyIndex reads as "the payload is in memory" — the
	// same fallback the Rust store uses when an append fails.
	ts.locations = make([]Location, len(messages))
	for i, m := range messages {
		ts.locations[i] = m.loc
	}
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
		total += int64(m.Len())
	}
	ts.bytes = total
}

// Sync seals the capture without invalidating anything, so it is safe to call
// while traffic is still being served. Use it at shutdown; use Close only once
// the store is quiescent.
func (ts *TrafficStore) Sync() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	if ts.segmentLog == nil {
		return nil
	}
	return ts.segmentLog.Sync()
}

// Close seals the capture and releases its mappings. It is safe to call on an
// in-memory store, where it does nothing.
//
// Every StoredMessage handed out by a disk-backed store becomes unusable
// afterwards: its bytes were a view into a mapping, and reading one post-Close
// is a segmentation fault rather than an error. So this belongs at process
// shutdown, once nothing can still be holding a message — which is also the
// moment the active segment gets its final sync.
func (ts *TrafficStore) Close() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.segmentLog == nil {
		return nil
	}
	return ts.segmentLog.Close()
}

// SegmentLog exposes the byte store so the durable mirror can rebuild
// disk-backed messages on restore: the mirror holds spans, and a span is only
// resolvable against the log it was recorded from. Nil for an in-memory store.
func (ts *TrafficStore) SegmentLog() *SegmentLog {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.segmentLog
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

// VerifyIndex checks the position-is-the-id invariant every O(1) lookup in
// this store depends on, the cross-references between the three indexes, and —
// for a disk-backed store — that every message still resolves on disk to a
// payload of the length the index believes it has. It returns the first
// disagreement it finds, naming the id, so a failure is actionable rather than
// a bare "mismatch". This is the port of the Rust store's `verify_index`.
//
// Like the Rust original, this proves the in-memory index is self-consistent
// and deliberately does NOT re-read segment files for corruption — that is the
// separate `VerifyCaptureDir` failure class. A byte flip that keeps a
// payload's length still passes here; the two checks are never conflated.
func (ts *TrafficStore) VerifyIndex() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for i, m := range ts.messages {
		if uint64(m.ID) != uint64(i) {
			return fmt.Errorf("message at position %d carries id %d — position is not the id", i, m.ID)
		}
	}
	for i, e := range ts.exchanges {
		if e.ID != uint64(i) {
			return fmt.Errorf("exchange at position %d carries id %d — position is not the id", i, e.ID)
		}
		for _, child := range e.Related {
			if uint64(child.ID) >= uint64(len(ts.messages)) {
				return fmt.Errorf("exchange %d references child message %d which does not exist", i, child.ID)
			}
		}
		if e.Response != nil && uint64(*e.Response) >= uint64(len(ts.messages)) {
			return fmt.Errorf("exchange %d references response message %d which does not exist", i, *e.Response)
		}
	}
	for i, m := range ts.wsMessages {
		if uint64(m.ID) != uint64(i) {
			return fmt.Errorf("ws message at position %d carries id %d — position is not the id", i, m.ID)
		}
		if uint64(m.Payload) >= uint64(len(ts.wsPayloads)) {
			return fmt.Errorf("ws message %d references payload %d which does not exist", i, m.Payload)
		}
		if m.Exchange >= uint64(len(ts.exchanges)) {
			return fmt.Errorf("ws message %d belongs to exchange %d which does not exist", i, m.Exchange)
		}
	}

	// Every message must resolve to a payload of the length the index believes
	// it has. In segment mode this is the check that the store and the log have
	// not drifted apart: a Location that no longer resolves, or resolves to the
	// wrong length, is exactly the silent mis-resolution position-is-the-id
	// exists to rule out.
	var summed int64
	for i, m := range ts.messages {
		var length int64
		if i < len(ts.locations) && ts.locations[i].Segment != "" {
			loc := ts.locations[i]
			if ts.segmentLog == nil {
				return fmt.Errorf("message %d is recorded on disk but this store has no segment log", i)
			}
			got, err := ts.segmentLog.Read(loc)
			if err != nil {
				return fmt.Errorf("message %d does not resolve: segment %s offset %d len %d is not a record: %v",
					i, loc.Segment, loc.Offset, loc.Length, err)
			}
			if int64(len(got)) != loc.Length {
				return fmt.Errorf("message %d resolves to %d bytes but its location says %d — the index and the log have drifted apart",
					i, len(got), loc.Length)
			}
			if loc.Length != int64(m.Len()) {
				return fmt.Errorf("message %d reports %d bytes but its location says %d — the index and the log have drifted apart",
					i, m.Len(), loc.Length)
			}
			length = loc.Length
		} else {
			length = int64(m.Len())
		}
		summed += length
	}
	// The Go store's byte counter tracks WebSocket payloads as well as messages
	// (AddWsMessage bumps it), so unlike the Rust original — whose tally counts
	// only messages — the tally here must include the ws-payload index.
	for _, p := range ts.wsPayloads {
		summed += int64(len(p))
	}
	if summed != atomic.LoadInt64(&ts.bytes) {
		return fmt.Errorf("byte total drifted: counted %d, tracked %d", summed, atomic.LoadInt64(&ts.bytes))
	}
	return nil
}

// VerifyCaptureDir verifies every segment in a capture directory and returns one
// verdict per segment, plus a single verdict naming the directory if it cannot
// be read at all. An empty result means the directory holds no segments — which
// is a real answer, not a pass.
//
// What this can and cannot prove is worth stating plainly, because the project's
// value is honest counting. The segment format carries no per-record checksum
// yet, so this verifies that each segment is readable end to end and reports how
// many bytes it read. It does not detect a byte flip that leaves the file the
// same length: that class of fault needs a CRC in the format, and adding one
// changes the on-disk layout every recorded Location is expressed against.
//
// Previously this looked for "segment-*.log" while the writer produced
// "segment_%d.dat", so it matched nothing and reported success having examined
// no files at all.
func VerifyCaptureDir(dir string) []*SegmentVerdict {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []*SegmentVerdict{{Path: dir, Fault: strPtr(fmt.Sprintf("read dir: %v", err))}}
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		var segNum int
		if _, err := fmt.Sscanf(e.Name(), segmentNameFormat, &segNum); err == nil {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(paths)
	var verdicts []*SegmentVerdict
	for _, path := range paths {
		verdicts = append(verdicts, verifySegmentFile(path))
	}
	return verdicts
}

func strPtr(s string) *string { return &s }

// verifySegmentFile reads a segment through to its end and reports the number of
// bytes it actually read. Checked is a byte count: it used to report
// size/1024 under the same name, which made a 2 MB segment look like it had
// checked 2048 of something.
func verifySegmentFile(path string) *SegmentVerdict {
	file, err := os.Open(path)
	if err != nil {
		return &SegmentVerdict{Path: path, Fault: strPtr(fmt.Sprintf("open: %v", err))}
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return &SegmentVerdict{Path: path, Fault: strPtr(fmt.Sprintf("stat: %v", err))}
	}

	buf := make([]byte, 1<<20)
	var read int64
	for {
		n, err := file.Read(buf)
		read += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return &SegmentVerdict{
				Path:    path,
				Checked: int(read),
				Fault:   strPtr(fmt.Sprintf("read failed %d bytes in: %v", read, err)),
			}
		}
	}
	if read != info.Size() {
		return &SegmentVerdict{
			Path:    path,
			Checked: int(read),
			Fault:   strPtr(fmt.Sprintf("read %d bytes but the segment is %d — it is being truncated under us", read, info.Size())),
		}
	}
	return &SegmentVerdict{Path: path, Checked: int(read)}
}
