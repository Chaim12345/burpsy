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
)

// ToolAll is every tool, so a caller can build a per-tool histogram without
// hard-coding the set — the reason a filter that pre-seeds its own list of tool
// names silently reported zero for any tool added after it was written.
var ToolAll = [8]Tool{
	ToolRepeater,
	ToolIntruder,
	ToolScanner,
	ToolSequencer,
	ToolComparer,
	ToolSession,
	ToolDecoder,
	ToolCrawler,
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
	default:
		return "unknown"
	}
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
	//
	// A pointer because 0 and "there wasn't one" are different facts. The field did not exist until
	// now, and the wire projection filled it with a hardcoded 0 for every row, so Logger's Length
	// column read as "every response was empty" — the single worst reading for the pane an operator
	// uses to reconcile what a tool sent against what came back. Never widen this back to a plain int:
	// the zero is precisely the lie being removed.
	ResponseLen *int
	StartedMs   uint64
	DurationMs  uint64
	Note        string
}

// Bytes wraps a measured response length for Record's respLen argument. Callers that received no
// response pass nil instead, and keeping that spelling visible at every call site is the point — see
// Entry.ResponseLen.
func Bytes(n int) *int { return &n }

// ToolLog is a bounded, oldest-first-evicting log of tool activity.
type ToolLog struct {
	mu       sync.RWMutex
	entries  []*Entry
	capacity int
	dropped  uint64
	nextID   uint64

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

func New() *ToolLog { return &ToolLog{capacity: DefaultCapacity} }

func (l *ToolLog) WithCapacity(c int) *ToolLog {
	l.mu.Lock()
	l.capacity = c
	l.mu.Unlock()
	return l
}

// Record adds one entry and returns its ID. respLen is the response's byte count, or nil when no
// response was received — see Entry.ResponseLen for why the caller must choose between the two rather
// than defaulting to zero.
func (l *ToolLog) Record(tool Tool, host string, port uint16, tls bool, method, path string, status int, respLen *int, durMs uint64, note string) uint64 {
	id := atomic.AddUint64(&l.nextID, 1)
	// Copied rather than aliased: the length belongs to the caller, who is free to reuse or overwrite
	// it once this returns, and a logged row whose value changed after it was recorded is not a log.
	var length *int
	if respLen != nil {
		n := *respLen
		length = &n
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
