// Package toollog records every request burpsy's tools (Repeater, Intruder,
// Scanner, Sequencer) sent, kept separate from proxy history. Mirrors the
// Rust burpsy-tools logger module.
package toollog

import (
	"sync"
	"sync/atomic"
	"time"
)

// Tool identifies which tool sent a request. There is deliberately no
// Proxy variant — proxy traffic lives in the TrafficStore's exchange index.
type Tool int

const (
	ToolRepeater Tool = iota
	ToolIntruder
	ToolScanner
	ToolSequencer
	ToolComparer
	ToolSession
	ToolDecoder
	// ToolCrawler is the crawler's own fetches. Appended at the end rather than
	// slotted in alphabetically because the ordinal is what the durable mirror
	// stores: inserting a variant would relabel every persisted row above it.
	ToolCrawler
	ToolProxy
)

// ToolAll is every tool, so a caller can build a per-tool histogram without
// hard-coding the set — the reason a filter that pre-seeds its own list of tool
// names silently reported zero for any tool added after it was written.
var ToolAll = [9]Tool{
	ToolRepeater,
	ToolIntruder,
	ToolScanner,
	ToolSequencer,
	ToolComparer,
	ToolSession,
	ToolDecoder,
	ToolCrawler,
	ToolProxy,
}

func (t Tool) String() string {
	switch t {
	case ToolRepeater:
		return "repeater"
	case ToolIntruder:
		return "intruder"
	case ToolScanner:
		return "scanner"
	case ToolSequencer:
		return "sequencer"
	case ToolComparer:
		return "comparer"
	case ToolSession:
		return "session"
	case ToolDecoder:
		return "decoder"
	case ToolCrawler:
		return "crawler"
	case ToolProxy:
		return "proxy"
	default:
		return "unknown"
	}
}

// ToolFromName resolves a tool name (as Tool.String produces) back to its
// Tool, for wire round-trips that must speak names not ordinals. The second
// return is false for "unknown" and for any other unrecognised string, so a
// caller can refuse rather than silently mis-record.
func ToolFromName(name string) (Tool, bool) {
	for _, t := range ToolAll {
		if t.String() == name {
			return t, true
		}
	}
	return Tool(0), false
}

// Entry is one record in the tool log.
type Entry struct {
	ID     uint64
	Tool   Tool
	Host   string
	Port   uint16
	TLS    bool
	Method string
	Path   string
	Status int
	// ResponseLen is how many response bytes came back, or nil when this row has no single response to
	// measure: a send that failed at the transport received nothing, and a row that stands for a whole
	// run (an intruder attack, an audit) does not correspond to one response at all.
	ResponseLen *int
	StartedMs   uint64
	DurationMs  uint64
	Note        string
	ExchangeID  *uint64
}

// Bytes wraps a measured response length for Record's respLen argument. Callers that received no
// response pass nil instead, and keeping that spelling visible at every call site is the point — see
// Entry.ResponseLen.
func Bytes(n int) *int { return &n }

// ToolLog is a bounded, oldest-first-evicting log of tool activity.
//
// It carries two independent axes, and they must not be collapsed into one:
// the **capture** axis decides which tools' requests are recorded at all, and
// the display axis (the caller's filter over All()) decides what is shown.
// The distinction is Burp Logger's Zfp2 model and it is not cosmetic: capture
// is destructive — a request refused here is gone forever, because no bytes
// were kept — while hiding a row is reversible. A UI that presented "stop
// showing scanner rows" as the same control as "stop recording scanner
// requests" would let an operator believe unrecorded traffic could be
// un-hidden later. See the uncaptured counters below for how the loss is
// reported rather than hidden.
type ToolLog struct {
	mu       sync.RWMutex
	entries  []*Entry
	capacity int
	dropped  uint64
	nextID   uint64

	// capturing is the capture axis as a bitmask over tool ordinals: bit t set
	// means Tool(t)'s Record calls store an entry; clear means they are
	// refused. Atomic rather than lock-held because Record sits on the path of
	// every request any tool sends (see OnChange) and the read must stay a
	// single word load there. Every tool captures by default — the zero value
	// of this field would mean nothing records, so New seeds it explicitly.
	capturing atomic.Uint32

	// uncaptured counts, per tool ordinal, the Record calls capture refused.
	// This is the honest-counting counterpart of the axis: switching a tool's
	// capture off must not look like an empty log — it looks like a log plus a
	// number of requests that were sent and deliberately not kept. Like
	// Dropped, these survive Clear (clearing the buffer does not un-send the
	// traffic it no longer describes) and reset on Restore (a snapshot carries
	// no such history to restore).
	uncaptured [len(ToolAll)]atomic.Uint64

	// onRecord is an optional write-through hook (see SetPersistenceSink). It
	// runs under the lock, must not call back into the log, and must not fail
	// the in-memory record.
	onRecord func(e *Entry)
	// onChange is an optional signal that the log changed at all (see OnChange).
	// Separate from onRecord because the two have different owners — that one is
	// the durable mirror's single slot — and because this one also fires for a
	// clear, which a live pane has to hear about as much as an arrival.
	onChange func()
}

const DefaultCapacity = 100000

// captureAll is every tool-ordinal bit set: the seed New applies so the zero
// value of an unseeded log cannot mean "record nothing". 1<<n - 1 sets the low
// n bits, which is exactly the eight tool ordinals.
const captureAll = uint32(1)<<len(ToolAll) - 1

func New() *ToolLog {
	l := &ToolLog{capacity: DefaultCapacity}
	l.capturing.Store(captureAll)
	return l
}

func (l *ToolLog) WithCapacity(c int) *ToolLog {
	l.mu.Lock()
	l.capacity = c
	l.mu.Unlock()
	return l
}

// Record adds one entry and returns its ID, or 0 when the tool's capture is
// switched off — in which case nothing was stored and the request is gone; the
// Uncaptured counter for the tool is what says so. respLen is the response's
// byte count, or nil when no response was received — see Entry.ResponseLen for
// why the caller must choose between the two rather than defaulting to zero.
//
// 0 is unambiguous as the refusal marker because ids come from nextID, which
// counts *stored* rows from 1: a stored row never has id 0.
func (l *ToolLog) Record(tool Tool, host string, port uint16, tls bool, method, path string, status int, respLen *int, durMs uint64, note string) uint64 {
	return l.RecordWithExchange(tool, host, port, tls, method, path, status, respLen, durMs, note, nil)
}

func (l *ToolLog) RecordWithExchange(tool Tool, host string, port uint16, tls bool, method, path string, status int, respLen *int, durMs uint64, note string, exchangeID *uint64) uint64 {
	if !l.Capturing(tool) {
		if tool >= 0 && int(tool) < len(l.uncaptured) {
			l.uncaptured[tool].Add(1)
		}
		return 0
	}
	id := atomic.AddUint64(&l.nextID, 1)
	var length *int
	if respLen != nil {
		n := *respLen
		length = &n
	}
	var exID *uint64
	if exchangeID != nil {
		n := *exchangeID
		exID = &n
	}
	e := &Entry{
		ID:          id,
		Tool:        tool,
		Host:        host,
		Port:        port,
		TLS:         tls,
		Method:      method,
		Path:        path,
		Status:      status,
		ResponseLen: length,
		StartedMs:   uint64(time.Now().UnixMilli()),
		DurationMs:  durMs,
		Note:        note,
		ExchangeID:  exID,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	if len(l.entries) > l.capacity {
		evict := len(l.entries) - l.capacity
		l.dropped += uint64(evict)
		l.entries = l.entries[evict:]
	}
	if l.onRecord != nil {
		l.onRecord(e)
	}
	if l.onChange != nil {
		l.onChange()
	}
	return id
}

var (
	// ToolBits masks the tool ordinal's single bit in the capturing bitmask. The
	// shifted 1 is `int64(1) << uint(tool)` per tool; encoding it per-tool keeps
	// the per-call shift off Record's hot path (Record looks up capturing via
	// Capturing, below, which still shifts — see its doc).
	ToolBits = [...]uint32{
		ToolRepeater:  1 << 0,
		ToolIntruder:  1 << 1,
		ToolScanner:   1 << 2,
		ToolSequencer: 1 << 3,
		ToolComparer:  1 << 4,
		ToolSession:   1 << 5,
		ToolDecoder:   1 << 6,
		ToolCrawler:   1 << 7,
		ToolProxy:     1 << 8,
	}
)

// Capturing reports whether the tool's requests are currently recorded.
// A single word load, meant for Record's per-send path.
func (l *ToolLog) Capturing(tool Tool) bool {
	if tool < 0 || int(tool) >= len(ToolBits) {
		return false
	}
	return l.capturing.Load()&uint32(ToolBits[tool]) != 0
}

// SetCapturing switches one tool's capture on or off. Switching off is the
// destructive act: the requests are sent and deliberately not kept, and the
// Uncaptured counter starts counting them rather than letting the log read as
// empty.
func (l *ToolLog) SetCapturing(tool Tool, on bool) {
	if tool < 0 || int(tool) >= len(ToolBits) {
		return
	}
	mask := uint32(ToolBits[tool])
	for {
		cur := l.capturing.Load()
		var next uint32
		if on {
			next = cur | mask
		} else {
			next = cur &^ mask
		}
		if l.capturing.CompareAndSwap(cur, next) {
			return
		}
	}
}

// SetAllCapturing switches every tool's capture at once. on=false is the
// nuclear "capture nothing" state; it is still reported as uncaptured counts
// rather than as an empty log.
func (l *ToolLog) SetAllCapturing(on bool) {
	var next uint32
	if on {
		next = captureAll
	}
	l.capturing.Store(next)
}

// Uncaptured reports how many requests the tool sent that capture refused.
// The counter only moves forward: clearing the log does not un-send traffic.
func (l *ToolLog) Uncaptured(tool Tool) uint64 {
	if tool < 0 || int(tool) >= len(l.uncaptured) {
		return 0
	}
	return l.uncaptured[tool].Load()
}

// UncapturedAll returns a copy of the per-tool uncaptured counters, indexed by
// the tool ordinal, for callers that project the whole axis to the wire. The
// returned slice is fresh; mutating it does not touch the log.
func (l *ToolLog) UncapturedAll() []uint64 {
	out := make([]uint64, len(l.uncaptured))
	for i := range l.uncaptured {
		out[i] = l.uncaptured[i].Load()
	}
	return out
}

// OnChange installs the signal called after the log changes, or nil to remove it.
// Single slot, so re-installing replaces rather than doubling.
//
// It carries no entry: its consumer is the live-update stream, which tells the
// browser that /api/tools/log is stale and lets that handler render the row. It
// runs under the log's write lock, on the path of every request any tool sends, so
// it must stay O(1) and allocation-light — an intruder attack at a hundred
// requests a second records a hundred entries a second.
func (l *ToolLog) OnChange(fn func()) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = fn
}

// SetPersistenceSink installs an optional write-through hook (see the onRecord
// field doc). Call before any activity is recorded.
func (l *ToolLog) SetPersistenceSink(onRecord func(e *Entry)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onRecord = onRecord
}

// Restore replaces the log's contents with a previously persisted snapshot.
// nextID resumes above the highest restored id so ids stay unique. This is the
// load path for the SQLite write-through store.
func (l *ToolLog) Restore(entries []*Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append([]*Entry{}, entries...)
	var max uint64
	for _, e := range entries {
		if e.ID >= max {
			max = e.ID + 1
		}
	}
	if max > l.nextID {
		l.nextID = max
	}
	l.dropped = 0
	for i := range l.uncaptured {
		l.uncaptured[i].Store(0)
	}
}

func (l *ToolLog) All() []*Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *ToolLog) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

func (l *ToolLog) Dropped() uint64 {
	return atomic.LoadUint64(&l.dropped)
}

// Clear empties the log, keeping the nextID counter (ids stay unique).
func (l *ToolLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:0]
	if l.onChange != nil {
		l.onChange()
	}
}
