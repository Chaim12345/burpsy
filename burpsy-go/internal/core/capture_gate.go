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
