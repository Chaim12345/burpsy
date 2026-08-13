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
	"time"
)

// DefaultSegmentTargetBytes is the default target size for segment files.
const DefaultSegmentTargetBytes = 100 * 1024 * 1024 // 100 MB

// MsgId is a handle to a stored message. Cheap to copy; carries no payload.
type MsgId uint64

// ExchangeID is a handle to a stored exchange.
//
// A distinct type, not a bare uint64, and the reason is a bug this cost us. Messages and exchanges
// are both dense counters from zero — six proxied requests give messages 0..11 and exchanges 0..5 —
// so every exchange id is also a valid message id and most message ids are also valid exchange ids.
// While both were uint64, `GetExchange(uint64(occ.Request))` compiled, and instead of failing it
// returned a real exchange belonging to an unrelated request: findings on /search were reported
// against /login, in the issues API and in every exported report. Separate types make that a build
// error rather than a wrong answer an operator would act on.
//
// Note what this does not fix, because no type can: zero is a legitimate value in both spaces, so it
// is never an "unset" marker. Absence is a pointer or a documented sentinel, never a zero test.
type ExchangeID uint64

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

// ExchangeDuration is how long an exchange took, **and whether anything measured it at all**.
//
// # The two states this exists to keep apart
//
// This replaced a plain `DurationMs uint64`, which could not tell "fast" from "unrecorded". A
// millisecond count rounds a sub-millisecond exchange — every loopback fetch, every replay from a
// local origin — down to 0, and 0 is also what a producer that never timed anything leaves behind. So
// a reader of an exchange row could not distinguish "this took under a millisecond" from "nobody
// timed this", and neither could a test: internal/proxy/parity_test.go had to classify the field as
// "the two producers may differ" and assert nothing about it, because asserting non-zero would have
// been asserting that the test machine is slow. That is a coverage hole of exactly the kind
// scanner.CoverageTracker exists to close, in the shape of a struct field.
//
// # Why microseconds *and* a flag, rather than one or the other
//
// Microseconds alone would only move the boundary: a measured 0 µs would still be indistinguishable
// from an unmeasured one, and the sub-microsecond case is reachable for an exchange served out of
// memory. A flag alone would keep the millisecond rounding, so "0 ms, measured" would still be the
// answer for most of a loopback crawl. Both together make the two states unrepresentable as one —
// Measured says whether a claim is being made, Us says what the claim is.
//
// A pointer (*uint64) was the other candidate and was rejected for one reason: the zero value has to
// be the safe one. A struct's zero value is {0, false} — unmeasured, which is the honest default for a
// producer that forgets to set it, and it cannot be nil-dereferenced by a reader that forgets to check.
// That is the same fail-safe direction Source takes by not defaulting to SourceProxy.
type ExchangeDuration struct {
	// Us is the duration in microseconds. Meaningful only when Measured is true.
	Us uint64
	// Measured says whether a producer actually timed this exchange. False is the zero value, so an
	// exchange nobody timed reports as untimed rather than as instantaneous.
	Measured bool
}

// MeasuredDuration records a duration a producer actually measured.
//
// A negative duration — a clock that went backwards between two reads — is clamped to zero and still
// counts as measured: the measurement happened, and reporting it as unmeasured would lose that.
func MeasuredDuration(d time.Duration) ExchangeDuration {
	if d < 0 {
		return ExchangeDuration{Us: 0, Measured: true}
	}
	return ExchangeDuration{Us: uint64(d.Microseconds()), Measured: true}
}

// MeasuredMicros records a duration already in microseconds — the form a durable store holds, so a
// restore does not have to round-trip through time.Duration to rebuild one.
func MeasuredMicros(us uint64) ExchangeDuration {
	return ExchangeDuration{Us: us, Measured: true}
}

// UnmeasuredDuration is the zero value, named so a producer that genuinely cannot time an exchange
// says so on purpose instead of leaving a field out and hoping the default means what it wants.
func UnmeasuredDuration() ExchangeDuration { return ExchangeDuration{} }

// Millis is the duration in whole milliseconds, truncated, and 0 when nothing was measured.
//
// Lossy by construction, and that is the point: this is the legacy wire and storage shape, kept so an
// existing consumer keeps working. Never test it against zero to decide whether an exchange was timed
// — that is the exact confusion this type exists to end. Ask Measured.
func (d ExchangeDuration) Millis() uint64 { return d.Us / 1000 }

// Micros is the duration in microseconds, and 0 when nothing was measured.
func (d ExchangeDuration) Micros() uint64 {
	if !d.Measured {
		return 0
	}
	return d.Us
}

// Duration is the measurement as a time.Duration, and 0 when nothing was measured.
func (d ExchangeDuration) Duration() time.Duration {
	if !d.Measured {
		return 0
	}
	return time.Duration(d.Us) * time.Microsecond
}

// String renders the duration for an operator, naming the unmeasured case rather than printing a zero
// that reads as an instantaneous exchange.
func (d ExchangeDuration) String() string {
	if !d.Measured {
		return "unmeasured"
	}
	if d.Us < 1000 {
		return fmt.Sprintf("%dµs", d.Us)
	}
	return d.Duration().Round(time.Microsecond).String()
}

// Exchange represents one proxied exchange. Holds IDs, never payloads.
type Exchange struct {
	ID          ExchangeID
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
	// Duration is how long the exchange took, or the explicit "nobody measured this". See
	// ExchangeDuration for why it is not a millisecond count.
	Duration ExchangeDuration
	Notes    *string
	// Highlight is the operator's colour tag for this row, empty when unset. It mirrors the UI's
	// Organizer highlight vocabulary (see ValidHighlights) rather than inventing a second one, so the
	// same colour means the same thing whichever tool set it. Unlike organizer.Item.Highlight, the wire
	// spelling of "no highlight" is "" here, not "none" — there is no sentinel string to confuse with a
	// real colour.
	Highlight string
	Related   []ChildRef
	Protocol  Protocol
	// Source names the surface that produced this exchange. See the Source type: the zero value is
	// deliberately *not* proxy.
	Source Source
	// TaskID is the dash registry task this exchange was produced by, or 0 for traffic no task
	// owns — everything the operator's own client sends through the proxy.
	//
	// Source and TaskID answer different questions and neither substitutes for the other. Source says
	// *what kind* of surface sent it ("an intruder attack"); TaskID says *which run* ("attack #7"), so
	// "show me the traffic this attack produced" is answerable at all. Zero is a safe sentinel here
	// only because registry ids start at 1 — see dash.Registry.Start, and the same convention on
	// dash.Event.TaskID.
	TaskID uint64
	// ParentID is the exchange this one came from — the request a Repeater resend was built on, the
	// base request an Intruder payload was substituted into, the hop a redirect was followed from.
	// Nil for an exchange with no antecedent.
	//
	// A pointer rather than a zero sentinel, because exchange 0 is a real exchange and is very often
	// the first thing an operator sends to Repeater.
	ParentID *ExchangeID
}

// Source names the surface an exchange came from.
//
// # Why the zero value is not SourceProxy
//
// It would be convenient: the proxy is the overwhelming majority of traffic, so defaulting to it
// would let most producers say nothing. That convenience is exactly the trap. A producer added later
// that forgets to set this would silently claim to be proxy traffic, every per-source count would be
// quietly wrong, and nothing anywhere would detect it — the count would still add up.
//
// So SourceUnattributed is the zero value and renders as such. A forgetful producer shows up as
// unattributed, which is visible and fixable, rather than as a plausible lie. This is the same
// fail-safe direction CheckCoverage takes with never-dispatched (see internal/scanner/coverage.go):
// the default state is "no evidence", never "fine".
//
// # Why this exists at all
//
// CRAWL-02 requires crawled traffic to travel the identical capture/scan path as proxied traffic, so
// by construction nothing downstream can tell them apart. That is correct, and it costs DASH-03 the
// ability to say "9 issues from proxied traffic, 3 from the crawl" — it can only say "12". One field
// buys that back. It cannot be added retroactively to exchanges already recorded, which is why it
// lands with the crawler rather than after it.
type Source string

const (
	// SourceUnattributed is the zero value: no producer claimed this exchange. Never treat it as
	// proxy traffic — see the type doc.
	SourceUnattributed Source = ""
	// SourceProxy is traffic the operator's own client sent through the proxy.
	SourceProxy Source = "proxy"
	// SourceCrawl is traffic the crawler originated.
	SourceCrawl Source = "crawl"
	// SourceRepeater is a hand-driven resend.
	SourceRepeater Source = "repeater"
	// SourceIntruder is an attack payload.
	SourceIntruder Source = "intruder"
	// SourceScanner is an active audit probe.
	SourceScanner Source = "scanner"
)

// Attributed reports whether a producer named this exchange's origin.
func (s Source) Attributed() bool { return s != SourceUnattributed }

// String renders the source for an operator, naming the unattributed case rather than showing an
// empty cell that reads as though the field did not apply.
func (s Source) String() string {
	if s == SourceUnattributed {
		return "unattributed"
	}
	return string(s)
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
	wsPayloads [][]byte
	// byRequest maps an exchange's request message id back to that exchange.
	//
	// Message ids and exchange ids are both dense counters from zero, which makes them trivially
	// confusable and impossible to tell apart by inspection: passing one where the other belongs
	// resolves to a real row of the wrong kind rather than failing. That is exactly what the issues
	// API did — it looked an exchange up by its request *message* id, and reported findings against
	// whichever unrelated exchange happened to share that number. This index makes the correct
	// lookup available so callers holding a message id never have to guess.
	byRequest   map[MsgId]*Exchange
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
	// exchangeObservers are live derived views of the exchange index — the site
	// map, today — that must be told about an arrival as it happens rather than
	// rebuilding themselves when someone asks. They run under the same lock and
	// the same contract as onExchange.
	//
	// A separate list rather than more work inside onExchange, because the two
	// have different arities and different owners. onExchange has exactly one
	// owner (the durable mirror) and is replaced wholesale; this fans out to
	// however many views the process has wired, and folding a view into the
	// mirror's single slot would make each the other's failure mode: installing
	// persistence would silently unsubscribe the site map, and vice versa.
	exchangeObservers []func(ex *Exchange)
	// onWsChange is an optional signal that a WebSocket frame was captured, for
	// the live-update stream. A single slot rather than a list, and no payload:
	// its only consumer tells a browser that the ws history endpoint is stale, so
	// it needs to know that something arrived and nothing about what. Runs under
	// the write lock, and under exactly the contract ObserveExchanges documents.
	onWsChange func()
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

	// The id is the position this message will take, and it is only consumed once the message is
	// actually in the index. Incrementing first meant a rejected Put — a malformed message, a segment
	// write that failed — burned an id nothing was ever stored at, so every later message's id sat one
	// past its own slot. Get resolves by slot (position-is-the-id), so from that point on every
	// exchange row pointed at the message before the one it meant, and the last id resolved to nothing:
	// one unparseable response silently re-labelled the whole rest of the capture. Restore relies on
	// the same invariant — it sets nextID to len(messages) — so this is what that path already assumes.
	id := MsgId(ts.nextID)

	shape, err := Parse(raw, direction)
	if err != nil {
		return 0, fmt.Errorf("failed to parse message: %w", err)
	}

	var loc Location
	if ts.segmentLog != nil {
		// Write to segment file; the returned location is kept so VerifyIndex
		// can later prove the index and the log have not drifted apart. The id
		// and direction go into the record's own header, which is what lets
		// VerifyCaptureDir read the file back as messages rather than as bytes.
		var err error
		loc, err = ts.segmentLog.Append(id, direction, raw)
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
	ts.nextID++
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

	ex.ID = ExchangeID(len(ts.exchanges))
	ts.exchanges = append(ts.exchanges, ex)
	if ts.byRequest == nil {
		ts.byRequest = make(map[MsgId]*Exchange)
	}
	ts.byRequest[ex.Request] = ex

	if ts.onExchange != nil {
		ts.onExchange(ex)
	}
	for _, observe := range ts.exchangeObservers {
		observe(ex)
	}
}

// ObserveExchanges registers fn to be called for every exchange added from now
// on, and returns the exchanges already in the store.
//
// Registration and the snapshot happen inside one lock hold because the two must
// partition exactly: a live derived view backfills from the returned slice and
// is told about everything after it, so no exchange is counted twice and none is
// missed. Calling Exchanges() and then registering cannot promise that — an
// AddExchange landing between the two calls is either double-counted or dropped
// depending on which order the caller picked, and a site map that double-counts
// one request is a site map nobody trusts the rest of.
//
// fn runs under the store's write lock, in append order, and must not call back
// into the store — the same contract as the persistence sinks.
//
// It must also be cheap, and this is a hard constraint rather than a preference,
// permanently. The lock it runs under is the one every AddExchange takes, so an
// observer is simultaneously a per-response latency tax on the proxy and the
// ceiling on how fast a crawler can capture. Fold into a map, increment a
// counter, take a slice index: O(1)-ish and allocation-light. Anything that
// formats a string, marshals JSON, writes to a network connection or a file,
// takes a second lock, sends on an unbuffered channel, or grows without bound
// belongs on an explicit call at the point the thing happened, not here. In
// particular the dashboard's event log is deliberately NOT fed from this hook —
// see the note in internal/dash/events.go.
//
// The two observers in the tree are both shaped by that. The site map folds the
// arrival into a tree it already holds. The live-update stream (internal/web's
// event hub) does one atomic increment and one non-blocking channel send, and a
// goroutine that is not on this stack decides who to tell and writes the bytes —
// an observer that wrote to a browser's connection from here would make one slow
// client the whole capture path's speed limit.
//
// This is what makes the site map continuous (CRAWL-05) for *every* producer at
// once. Anything that records traffic does so through AddExchange — the proxy,
// the crawler, any future tool — so a view registered here sees all of it
// without each producer having to remember to update it.
func (ts *TrafficStore) ObserveExchanges(fn func(*Exchange)) []*Exchange {
	if fn == nil {
		return nil
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	existing := make([]*Exchange, len(ts.exchanges))
	copy(existing, ts.exchanges)
	ts.exchangeObservers = append(ts.exchangeObservers, fn)
	return existing
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
//
// Restore does not notify exchange observers, and must therefore run before any
// are registered — which is the existing order: the durable mirror restores the
// shared stores before the web server that owns the derived views is built.
// Replaying the snapshot to observers instead would be worse than the ordering
// rule it replaced: a view that had already backfilled would be handed every
// restored exchange a second time and would double-count all of it.
func (ts *TrafficStore) Restore(messages []*StoredMessage, exchanges []*Exchange) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.messages = messages
	ts.exchanges = exchanges
	// Rebuilt in lockstep with the exchange slice: a finding restored from the durable mirror holds
	// a request message id, and without this index its host and path could not be resolved after a
	// restart even though both were captured.
	ts.byRequest = make(map[MsgId]*Exchange, len(exchanges))
	for _, ex := range exchanges {
		ts.byRequest[ex.Request] = ex
	}
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
func (ts *TrafficStore) GetExchange(id ExchangeID) (*Exchange, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if uint64(id) >= uint64(len(ts.exchanges)) {
		return nil, fmt.Errorf("exchange not found: %d", id)
	}

	return ts.exchanges[id], nil
}

// ValidHighlights is the wire vocabulary for Exchange.Highlight: exactly the UI's HIGHLIGHTS list
// (organizer.tsx) minus its "none" sentinel, which the wire represents as "" rather than as a member
// of this set. A caller validating a PATCH should accept "" (clear) or a key of this map, and reject
// anything else rather than coercing it.
var ValidHighlights = map[string]bool{
	"red": true, "orange": true, "yellow": true, "green": true, "cyan": true,
	"blue": true, "pink": true, "magenta": true, "gray": true,
}

// UpdateExchangeAnnotation sets an exchange's Notes and/or Highlight in place, leaving every other
// field untouched, and mirrors the result through the same persistence sink AddExchange writes
// through — so an annotation survives a restart exactly like the traffic it is attached to.
//
// notesSet and highlightSet exist because a *string alone cannot distinguish "the caller left this
// field out" from "the caller set it to nil/empty": PATCH's contract is that an omitted field is
// unchanged while an explicit null (notes) or "" (highlight, meaning "none") is a real value to write.
// Only the caller parsing the request body knows which case it saw, so it is threaded through here
// rather than re-guessed.
//
// Highlight vocabulary validation is deliberately not this function's job — it mutates the store
// exactly as told, and the 400 for an unknown colour belongs to the HTTP layer that can see the
// request that caused it.
func (ts *TrafficStore) UpdateExchangeAnnotation(id ExchangeID, notes *string, notesSet bool, highlight string, highlightSet bool) (*Exchange, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if uint64(id) >= uint64(len(ts.exchanges)) {
		return nil, fmt.Errorf("exchange not found: %d", id)
	}
	ex := ts.exchanges[id]
	if notesSet {
		ex.Notes = notes
	}
	if highlightSet {
		ex.Highlight = highlight
	}
	if ts.onExchange != nil {
		ts.onExchange(ex)
	}
	return ex, nil
}

// ExchangeByRequest resolves the exchange whose request is the given message.
//
// This is the lookup a caller holding an occurrence needs. GetExchange takes an exchange id, and a
// message id passed to it silently returns the wrong exchange rather than an error, because both id
// spaces are dense counters from zero — so "not found" is the rare case and "found, but wrong" is
// the common one. Anything that starts from a message must come through here.
func (ts *TrafficStore) ExchangeByRequest(id MsgId) (*Exchange, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if ex, ok := ts.byRequest[id]; ok {
		return ex, nil
	}
	return nil, fmt.Errorf("no exchange has request message %d", id)
}

// PriorExchange returns the most recent exchange against the same origin+path that was added
// before the given exchange, for a second-order check to compare against.
//
// Second-order (stored) checks — Burp's `getStoredActivePerInsertionPointChecksFactory` — submit a
// payload on one request and then read a *different* request's response to see whether it
// persisted. The factory that detects it resolves "the other request" as a prior capture of the
// same endpoint, so that is what this lookup returns: the highest-indexed exchange whose
// origin (scheme+host+port), path, and — when the request carried one — query string match the
// given exchange's, which was indexed before it. A match requires an earlier exchange of the
// same endpoint existing at all: when the given exchange is the first capture of its endpoint,
// or every other candidate was added *after* it, the second return value is false and the
// caller passes a nil StoredExchange — exactly as today, for checks that have no prior to read.
//
// The lookup is a pure read over the already-indexed exchange slice; it adds no duplicate
// storage and copies no message bytes (an Exchange holds IDs, never payloads). Exchange IDs are
// their positions, so the highest-indexed match is also the most recent, and "before" is a
// positional comparison rather than a wall-clock one — two captures of one endpoint are always
// ordered by when they were added, and that is the order a stored check threads them in.
func (ts *TrafficStore) PriorExchange(host string, port uint16, tls bool, path string, before ExchangeID) (*Exchange, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var best *Exchange
	for i, ex := range ts.exchanges {
		if ExchangeID(i) >= before {
			continue
		}
		if ex.Host != host || ex.Port != port || ex.TLS != tls {
			continue
		}
		// The path carries the query string, so an exact match is one endpoint: "/a" and "/a?x=1"
		// are different endpoints, and a stored check threads a payload through the same one.
		if ex.Path != path {
			continue
		}
		// ex.ID == ExchangeID(i); the first match is the earliest, each later match supersedes it.
		best = ex
	}
	if best == nil {
		return nil, false
	}
	return best, true
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
	if ts.onWsChange != nil {
		ts.onWsChange()
	}
	return id
}

// OnWsChange installs the signal called after every captured WebSocket frame, or
// nil to remove it. Single slot, so re-installing replaces rather than doubling.
//
// A signal rather than an observer because the caller that wants it — the live
// update stream — needs to know that the ws index changed, not what changed: it
// tells the browser to refetch, and /api/ws/history renders the row. It runs
// under the store's write lock on the WebSocket capture path, so it is held to
// the same O(1)-and-allocation-light contract as ObserveExchanges, for the same
// reason: a relay pumping a busy socket waits behind it.
func (ts *TrafficStore) OnWsChange(fn func()) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.onWsChange = fn
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
func (ts *TrafficStore) WsMessagesFor(exchange ExchangeID, offset, limit int) []*WsMessage {
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
	Exchange ExchangeID
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
		if uint64(m.Exchange) < uint64(len(ts.exchanges)) && ts.exchanges[m.Exchange] != nil {
			ex := ts.exchanges[m.Exchange]
			c.Host, c.Port, c.TLS, c.Path = ex.Host, ex.Port, ex.TLS, ex.Path
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastMs > out[j].LastMs })
	return out
}

// SegmentVerdict is what one segment file reported when it was re-read.
//
// Records and PayloadBytes count what was actually checked before the walk
// stopped, so a verdict that names a fault still says how much of the file was
// good — "412 records, then byte 91,120" is actionable where a bare pass/fail
// is not.
//
// The fields used to be a single Checked, which the writer set to a byte count
// and the CLI printed as a record count. Naming both separately is the only way
// neither reading can be wrong.
type SegmentVerdict struct {
	Path string
	// Records is how many records were read and had their checksum recomputed
	// and matched.
	Records int
	// PayloadBytes is the message bytes those records cover: the file header
	// and the per-record framing are not message bytes and are not counted.
	PayloadBytes int64
	// Fault is the operator-facing reason this segment did not verify, nil when
	// it did. It is set for a whole-file fault (unreadable, not one of ours, a
	// format version this build does not write) *and* for a corrupt record, so
	// a caller that checks only Fault never misses corruption.
	Fault *string
	// Corrupt is the typed detail behind Fault when the fault was in a record
	// rather than in the file as a whole. Nil for a clean segment and for a
	// whole-file fault; check Fault, not this, to decide whether a segment
	// verified.
	Corrupt *CorruptRecord
}

// VerifyIndex checks the position-is-the-id invariant every O(1) lookup in
// this store depends on, the cross-references between the three indexes, and —
// for a disk-backed store — that every message still resolves on disk to a
// payload of the length the index believes it has. It returns the first
// disagreement it finds, naming the id, so a failure is actionable rather than
// a bare "mismatch". This is the port of the Rust store's `verify_index`.
//
// Like the Rust original, this proves the in-memory index is self-consistent
// and deliberately does NOT recompute record checksums — that is the separate
// `VerifyCaptureDir` failure class, which walks the segment files themselves. A
// byte flip that keeps a payload's length still passes here, and is caught
// there; the two checks answer different questions and are never conflated.
func (ts *TrafficStore) VerifyIndex() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for i, m := range ts.messages {
		if uint64(m.ID) != uint64(i) {
			return fmt.Errorf("message at position %d carries id %d — position is not the id", i, m.ID)
		}
	}
	for i, e := range ts.exchanges {
		if uint64(e.ID) != uint64(i) {
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
		if uint64(m.Exchange) >= uint64(len(ts.exchanges)) {
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
// value is honest counting. Each segment is walked record by record through the
// headers written with it, and every record's payload is checksummed against the
// CRC32 stored in its header, so a byte flip that leaves the file exactly as long
// as it was is now caught and named — the one fault the old read-to-EOF byte
// count could never see.
//
// The checksum is corruption detection, not a security control. It catches torn
// writes, bit rot, and truncation. It proves nothing about an adversary, who can
// recompute a CRC exactly as easily as this code can.
//
// Two earlier defects are worth remembering here. This looked for "segment-*.log"
// while the writer produced "segment_%d.dat", so it matched nothing and reported
// success having examined no files at all; and once it did match, it could only
// confirm that a file was readable to its end.
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

// verifySegmentFile walks one segment record by record, recomputing each
// record's checksum, and folds the walk into a verdict.
//
// It used to read the file to EOF and report the byte count — a check that
// passes on any file that can be read, including one whose bytes have been
// rewritten in place. Everything it can now say beyond "readable" comes from
// ScanSegmentFile; this function only decides how a scan reads as a verdict.
func verifySegmentFile(path string) *SegmentVerdict {
	scan, err := ScanSegmentFile(path)
	if err != nil {
		// A whole-file fault: there are no per-record verdicts to give about a
		// file that is not a segment of ours, so Records stays zero rather than
		// implying something was checked.
		return &SegmentVerdict{Path: path, Fault: strPtr(err.Error())}
	}
	verdict := &SegmentVerdict{
		Path:         path,
		Records:      len(scan.Records),
		PayloadBytes: scan.PayloadBytes(),
	}
	if scan.Corrupt != nil {
		verdict.Corrupt = scan.Corrupt
		verdict.Fault = strPtr(scan.Corrupt.Error())
	}
	return verdict
}
