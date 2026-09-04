package pool

// One live limiter per named pool, and the seam that carries it to a tool with no driver loop.
//
// # Why the registry hands out limiters and not just limits
//
// Pool.Limit() answers "what are this pool's bounds"; it returns a value, and a caller that built its
// own limiter from it would get bounds that apply to *that caller alone*. That is the wrong answer
// for a shared object: two audits running under one pool of four concurrent requests must together
// send four, not four each. So the pool that has an identity also has one limiter, cached here, and
// every tool running under that name contends for the same slots and spends the same rate budget.
// This is the whole difference between a named pool and the inline limits that came before it.
//
// # Why a cache needs invalidation, and where it happens
//
// A cached limiter is a copy of the pool's bounds from the moment it was built, so an edited pool
// with a live limiter would keep enforcing the old numbers. Update and Remove therefore drop the
// entry, and the next run builds a fresh one. Work already in flight keeps the limiter it started
// under — deliberately, and it is the only honest option: retuning a token bucket underneath a
// running audit would either release a burst it was holding back or strand requests already queued
// on it. The bound an operator edits applies to the next run, which is what "saved object" means.

import (
	"context"

	"github.com/burpsy-go/burpsy/internal/intruder"
)

// Limiter returns the one live limiter for this pool, building it on first use.
//
// The error is ErrNoSuchPool for a name nothing holds, never a limiter with default bounds: a tool
// that ran unbounded because its pool had been deleted is the exact failure this package exists to
// prevent, and it would happen at the moment nobody is watching.
func (r *Registry) Limiter(name string) (*intruder.RateLimiter, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	k := key(p.Name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limiters == nil {
		r.limiters = map[string]*intruder.RateLimiter{}
	}
	// Re-checked under the write lock rather than trusting the read above: two tools starting under
	// one pool at once must not each build a limiter, because then neither bounds the other.
	if l, ok := r.limiters[k]; ok {
		return l, nil
	}
	limit := p.Limit()
	l := intruder.NewRateLimiter(&limit)
	r.limiters[k] = l
	return l, nil
}

// dropLimiter forgets a pool's cached limiter, so the next run builds one from the current bounds.
// Called with r.mu already held by the mutation that invalidated it.
func (r *Registry) dropLimiter(k string) {
	delete(r.limiters, k)
}

// contextKey is unexported so nothing outside this package can put a limiter in a context that
// ContextPacer would then honour. A pool's bounds are set at the one resolution point or not at all.
type contextKey struct{}

// WithLimiter carries a resolved pool's limiter down a call tree, for the tool paths that have no
// single place to put an Acquire.
//
// # Why a context value, which is usually the wrong tool
//
// The audit path has dozens of checks that each build a sender and send; there is no line above them
// all to bound, and threading a limiter through every check signature would touch every check in the
// tree to give most of them a parameter they do not use. The scanner solves the same problem the same
// way for the same reason: one pacer is installed on the scanner at wiring time (see
// ActiveScanner.WithPace), and *which pool this particular audit runs under* is the per-call fact —
// which is precisely what a request-scoped context is for. The context that reaches the sender is
// the same one the audit was started with, so the limiter cannot be lost on the way down.
//
// The alternative was mutating the shared scanner's pacer per request. Two concurrent audits under
// two different pools would then race, and the loser would run under bounds its operator did not
// choose — silently, since a limiter reports the name it was built with and not the name that was
// asked for.
func WithLimiter(ctx context.Context, l *intruder.RateLimiter) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, l)
}

// LimiterFrom returns the limiter carried in this context, if any.
func LimiterFrom(ctx context.Context) (*intruder.RateLimiter, bool) {
	l, ok := ctx.Value(contextKey{}).(*intruder.RateLimiter)
	return l, ok && l != nil
}

// ContextPacer bounds a send by whatever pool the context says the work is running under, and by
// nothing at all when it says none.
//
// It satisfies sender.Pacer structurally rather than by importing the sender package — the method
// set is the whole contract — so this package still owns no limiter behaviour and adds no import.
//
// Installed once, on a long-lived scanner, it is safe to share across every concurrent audit: it
// holds no state, and the state it reads belongs to the call.
type ContextPacer struct{}

// noopRelease is what an unpaced send gets back. A function rather than a nil, because Pacer's
// contract is that a successful Pace always returns something safe to call — a nil check at every
// call site is a nil check someone eventually forgets.
func noopRelease() {}

// Pace blocks until this send may go out under the context's pool, and returns the release.
//
// No limiter in the context means unpaced, which is the honest default and not a failure: a repeater
// send, a session macro and an audit that named no pool have never been rate limited, and inventing
// a bound here would impose one nobody configured. What cannot happen is a *named* pool silently
// arriving as no limiter — the name is resolved at the API boundary, which refuses an unknown one
// there rather than defaulting it here.
func (ContextPacer) Pace(ctx context.Context) (func(), error) {
	l, ok := LimiterFrom(ctx)
	if !ok {
		return noopRelease, nil
	}
	return l.Pace(ctx)
}
