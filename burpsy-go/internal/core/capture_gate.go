package core

import "sync/atomic"

// CaptureGate acquires an outer lock and returns its release. A store with a gate installed takes
// it BEFORE its own mutex in every method that calls a persistence sink, and releases it after.
//
// It exists because of lock order (burpsy-react-ui-switch-deadlock). The owning process
// serializes a project switch against durable writes with a lock of its own; the switch holds
// that lock and then takes the stores' mutexes (Restore, SegmentLog, SetPersistenceSinks). The
// sinks run under the stores' mutexes, so a sink that took the process lock itself inverted the
// order — store mutex, then process lock — and capture plus a switch deadlocked the process.
// Taking the gate here instead gives one order everywhere: process lock, then store mutex. It
// also keeps a capture's in-memory append and its mirror write inside one hold of the process
// lock, so a switch can never fall between the two and leave a row in one project's memory and
// the other project's file.
//
// The sinks must therefore NOT take the same lock: a sync.RWMutex read side is not reentrant
// once a writer is queued.
type CaptureGate func() (release func())

// captureGateSlot holds an optional CaptureGate. Atomic, because it is read before the store's
// mutex is held and replaced on a project switch while capture continues.
type captureGateSlot struct{ p atomic.Pointer[CaptureGate] }

func (s *captureGateSlot) set(g CaptureGate) {
	if g == nil {
		s.p.Store(nil)
		return
	}
	s.p.Store(&g)
}

func noRelease() {}

// enter takes the gate if one is installed and returns its release.
func (s *captureGateSlot) enter() func() {
	if g := s.p.Load(); g != nil {
		return (*g)()
	}
	return noRelease
}

// CaptureHold keeps the capture gate held across several writes that belong together — one
// exchange's request, response, earlier stages and index row — so a project switch can never fall
// between them and leave the messages in one project and the exchange row in the other
// (burpsy-react-ui-capture-split). Its Put and AddExchange do not take the gate again: a
// sync.RWMutex read side is not reentrant once a writer is queued, so re-entering would deadlock
// against a waiting switch. Release exactly once, and before anything that may take the gate on
// another store (a passive scan adding findings).
type CaptureHold struct {
	ts      *TrafficStore
	release func()
}

// HoldCapture takes the capture gate (a no-op without one) and returns the hold.
func (ts *TrafficStore) HoldCapture() *CaptureHold {
	return &CaptureHold{ts: ts, release: ts.gate.enter()}
}

// Put stores a message under the hold.
func (h *CaptureHold) Put(raw []byte, direction Direction) (MsgId, error) {
	return h.ts.put(raw, direction)
}

// AddExchange adds an exchange row under the hold.
func (h *CaptureHold) AddExchange(ex *Exchange) { h.ts.addExchange(ex) }

// Release lets the gate go. Safe to call more than once.
func (h *CaptureHold) Release() {
	if h.release != nil {
		h.release()
		h.release = nil
	}
}
