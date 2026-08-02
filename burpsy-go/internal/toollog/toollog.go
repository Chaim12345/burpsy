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
)

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
	default:
		return "unknown"
	}
}

// Entry is one record in the tool log.
type Entry struct {
	ID        uint64
	Tool      Tool
	Host      string
	Port      uint16
	TLS       bool
	Method    string
	Path      string
	Status    int
	StartedMs uint64
	DurationMs uint64
	Note      string
}

// ToolLog is a bounded, oldest-first-evicting log of tool activity.
type ToolLog struct {
	mu       sync.RWMutex
	entries  []*Entry
	capacity int
	dropped  uint64
	nextID   uint64
}

const DefaultCapacity = 100000

func New() *ToolLog { return &ToolLog{capacity: DefaultCapacity} }

func (l *ToolLog) WithCapacity(c int) *ToolLog {
	l.mu.Lock()
	l.capacity = c
	l.mu.Unlock()
	return l
}

// Record adds one entry and returns its ID.
func (l *ToolLog) Record(tool Tool, host string, port uint16, tls bool, method, path string, status int, durMs uint64, note string) uint64 {
	id := atomic.AddUint64(&l.nextID, 1)
	e := &Entry{
		ID:        id,
		Tool:      tool,
		Host:      host,
		Port:      port,
		TLS:       tls,
		Method:    method,
		Path:      path,
		Status:    status,
		StartedMs: uint64(time.Now().UnixMilli()),
		DurationMs: durMs,
		Note:      note,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	if len(l.entries) > l.capacity {
		evict := len(l.entries) - l.capacity
		l.dropped += uint64(evict)
		l.entries = l.entries[evict:]
	}
	return id
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
