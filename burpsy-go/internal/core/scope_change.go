package core

// Scope-change notification (burpsy-react-ui-e05t).
//
// # Why this exists
//
// Burp's extension API carries a ScopeChangeHandler: a plugin registers one and is told when the
// scope moves (Montoya ScopeChangeHandler.java:20-26, with ScopeChange an empty marker interface —
// the callback carries no payload, and the plugin is expected to re-read the scope).
//
// burpsy had no way to say this. Anything holding a scope decision — an extension, a crawler
// frontier, the live-audit sweep — either re-reads the scope on every request forever or caches it and
// goes stale with no event to invalidate it. There is no third option, and the third option is what
// this file adds.
//
// # Why a callback and not an event on the bus
//
// The console already has a live event stream (dash.EventBus, and the Settings page already consumes
// EventScopeChanged from it), so publishing there was the obvious first choice. It is the wrong one for
// the extension case, and the reason is liveness rather than taste: a bus subscriber is HTTP-shaped —
// it is a websocket fan-out to whatever is connected — and an extension is a child process whose
// plugin host is not necessarily serving a console at all. Putting the extension behind an HTTP-shaped
// channel would mean a plugin cannot be notified unless a console happens to be listening.
//
// So this is an in-process callback on the Scope itself, and the event bus is left to whoever wants a
// console to reflect the change. A caller that wants both calls both.
//
// # Lock discipline — the part that is load-bearing
//
// Every mutator in scope.go runs under `defer s.mu.Unlock()`, so a notification fired INSIDE the
// critical section would be a deadlock the moment a handler did the obvious thing and called
// Contains() to see what changed. The rules here, and they are the reason the fire sites look the way
// they do:
//
//  1. Handlers run AFTER the write lock is released, always.
//  2. A handler that panics does not take the scope with it — recover, and keep the change that was
//     already applied. A subscriber must not be able to un-apply an operator's scope edit by
//     panicking in a callback.
//  3. Handlers run synchronously. An asynchronous fire would let the caller return before its
//     subscriber had been told, which makes a test of "did the handler hear about it" a race, and an
//     extension host that shuts down immediately after an edit would silently lose the notification.
//     The cost is that a slow handler slows the edit, which is the honest trade: the alternative is a
//     notification nobody can rely on having arrived.
//
// # What a handler is told
//
// The count of rules before and after, and whether the scope went from or to the "allow everything"
// state. Deliberately NOT the rules themselves: a handler that wants them calls Rules(), which
// returns a copy under the lock. Handing out the live slice would make the callback capable of
// mutating the scope while it is being read, and every subscriber would be a candidate for the race
// the locking above exists to prevent.

import (
	"sync"
	"sync/atomic"
)

// ScopeChange describes a change to the scope, as a subscriber is told about it.
//
// The two counts are what a subscriber needs to decide whether its cached view is still valid without
// reading anything: a handler that saw the same rule count twice can skip the expensive re-read, and
// one that saw AllowAll change knows the whole authorisation answer moved.
type ScopeChange struct {
	// Before and After are the number of rules on each side. A rule EDITED in place (SetRuleEnabled)
	// leaves both equal, which is why they cannot be the whole signal — hence the operation name.
	Before int
	After  int
	// AllowAllBefore and AllowAllAfter report the permissive state either side of the change.
	AllowAllBefore bool
	AllowAllAfter  bool
	// Operation names what happened, in the Scope's own vocabulary: "add", "remove", "replace",
	// "enable", "clear". A free string rather than an enum because a subscriber forwards it to a
	// client that may be a different burpsy version, and an unknown verb is more useful than a
	// decode error.
	Operation string
}

// Changed reports whether the change could have altered an authorisation decision.
//
// Not "did the rule list differ" — a rule toggled off and on between two reads is a difference with
// no change in meaning. What matters is the pair that decides every request: the count, and the
// allow-all state.
func (c ScopeChange) Changed() bool {
	return c.Before != c.After || c.AllowAllBefore != c.AllowAllAfter
}

// onChange holds the registered handlers.
//
// A separate lock from the scope's own, so a handler that registers another handler while being
// called cannot deadlock against the write lock it is being called under — and handlers are held
// under their own read lock only long enough to copy the slice, never while one runs, so a handler
// that subscribes mid-notification does not make the copy a live view.
type scopeWatchers struct {
	mu       sync.RWMutex
	handlers []scopeHandler
}

// scopeHandler is one registration, with an id so its own remover can find it.
//
// The id rather than comparing function values: two registrations of the SAME named function from
// different call sites are two subscriptions as far as the caller is concerned, and a remover that
// matched by value would take both. Go does not permit == on funcs, so identity here is positional
// and explicit rather than accidental.
type scopeHandler struct {
	id      uint64
	handler func(ScopeChange)
}

// nextHandlerID hands out registration ids. Package-level rather than a field on Scope so an id is
// unique across every Scope in the process — two scopes must not be able to remove each other's
// handler by id, and a package counter makes that impossible rather than unlikely.
var nextHandlerID uint64

// OnChange registers a handler called whenever the scope's rules change, and returns a function that
// unregisters it.
//
// Returning the unregister function rather than exposing a second call is what makes this safe to
// hold: a caller cannot leak a handler by forgetting to remove it, because the only way to hold one is
// to also hold the thing that removes it.
//
// Called with no handler it is a no-op rather than a nil-deref later, because the obvious way to
// "unregister" without keeping the function is to pass nil, and a panic at the next scope edit would
// be a bad answer to that.
func (s *Scope) OnChange(handler func(ScopeChange)) func() {
	if s == nil || handler == nil {
		return func() {}
	}
	id := atomic.AddUint64(&nextHandlerID, 1)
	s.watchers.mu.Lock()
	s.watchers.handlers = append(s.watchers.handlers, scopeHandler{id: id, handler: handler})
	s.watchers.mu.Unlock()

	// sync.Once so a double call is a no-op rather than a confusing no-op: the second one would find
	// nothing to remove and silently succeed, and a caller that calls it twice on an error path
	// should not have to reason about whether it did anything.
	var once sync.Once
	return func() {
		once.Do(func() {
			s.watchers.mu.Lock()
			defer s.watchers.mu.Unlock()
			for i, existing := range s.watchers.handlers {
				if existing.id == id {
					s.watchers.handlers = append(s.watchers.handlers[:i], s.watchers.handlers[i+1:]...)
					return
				}
			}
		})
	}
}

// notify runs every handler with a change, after the caller has released the write lock.
//
// SKIPPED when the change cannot have altered an authorisation decision — a mutation that found
// nothing to remove, or one that changed nothing. A subscriber is told about decisions, not about
// attempts; a handler woken by every no-op Remove would be a handler an extension author has to
// filter, and that is the failure this whole file exists to remove.
//
// Never called with the lock held. That is the whole contract of this file and the reason the fire
// sites in scope.go sit after the unlock rather than inside the critical section.
func (s *Scope) notify(change ScopeChange) {
	if !change.Changed() {
		return
	}
	s.notifyUnconditional(change)
}

// notifyUnconditional runs every handler whatever the change's counts say.
//
// For the mutations that change MEANING without changing the counts: a rule toggled off, a rule
// edited in place, a Clear of an already-empty scope. Those are exactly the events a subscriber most
// needs and exactly the ones a count-difference filter would drop — a toggle leaves the rule count
// identical and silently changes every answer the scope gives. The distinction between notify and
// notifyUnconditional is therefore load-bearing, and merging them would reintroduce the stale-cache
// bug this file fixes.
func (s *Scope) notifyUnconditional(change ScopeChange) {
	if s == nil {
		return
	}
	s.watchers.mu.RLock()
	handlers := make([]func(ScopeChange), 0, len(s.watchers.handlers))
	for _, h := range s.watchers.handlers {
		if h.handler != nil {
			handlers = append(handlers, h.handler)
		}
	}
	s.watchers.mu.RUnlock()

	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		safeNotify(handler, change)
	}
}

// safeNotify runs one handler, containing a panic.
//
// A subscriber here is an extension: third-party code this repository does not control, running in the
// same process. A panic in it would unwind through the operator's scope edit, and the edit HAS already
// been applied — so the operator would be left with their change applied and the request reporting
// failure, which is the worst of both. Recovering keeps the edit and loses the notification, and the
// notification is the cheaper of the two to lose.
func safeNotify(handler func(ScopeChange), change ScopeChange) {
	defer func() { _ = recover() }()
	handler(change)
}

// changeSnapshot reads the counts a change produced. Callers hold at least the read lock.
func (s *Scope) changeSnapshot() (rules int, allowAll bool) {
	return len(s.rules), s.allowAll
}
