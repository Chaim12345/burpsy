// Package pool holds named resource pools: an operator's saved answer to "how hard may a tool hit
// this target", referable by name from every tool instead of retyped per run.
//
// # The gap this closes
//
// The throttling machinery already existed and was already correct — internal/intruder/limit.go has
// a token bucket, an in-flight semaphore and an auto-throttle, and every intruder attack goes
// through it. What it did not have was an *identity*. `RateLimit.Name` is documented there as "an
// identifier, not a handle: nothing here looks it up", so every caller re-specified its own bounds:
// POST /api/intruder/run took rps/max_in_flight/auto_throttle per call, the crawler hard-coded
// 5 rps and DefaultAutoThrottle, and the audit path was not rate limited at all. Three tools, three
// unrelated answers, and no way for an operator to say "everything in this engagement runs at two
// requests a second" once.
//
// A pool is that saying-it-once. It is a *name plus three bounds*, saved and persisted, and a tool
// references it by name. Resolution happens in exactly one place (Registry.Limit), so the bounds a
// tool ends up running under are the bounds the operator typed rather than each tool's
// interpretation of them.
//
// # Why this is not in internal/intruder
//
// limit.go states, as a design decision, that it "keeps no registry of pools" and that "cross-attack
// state belongs to whichever layer owns the attacks". Putting the registry there would contradict
// that and would make the scanner import the intruder to look a name up. This package is that
// layer: it owns names and lifetimes, and it owns *no limiter behaviour at all*. Every pool
// resolves to an intruder.RateLimit and the limiting is done by intruder.RateLimiter. Two limiters
// of one shape drift; there is one.
//
// # Burp's dialog, in this package's vocabulary
//
// burp.Zxsx (the resource-pool dialog) carries a name, "Max concurrent requests:", "Delay between
// requests:", and "Automatic throttling" with "Increase delay in increments of". Three of those map
// straight across. The fourth does not, and the translation is stated rather than fudged — see
// Throttle.
package pool

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/intruder"
)

// MaxConcurrentCeiling bounds a pool's concurrency, matching the ceiling POST /api/intruder/run
// already enforces on max_in_flight. A pool is not a way around a bound the inline form has.
const MaxConcurrentCeiling = 999

// MaxDelayMs bounds the delay between requests. Twelve hours is already far past the point where an
// operator would conclude the tool has hung, and the arithmetic below (1000/delay) needs a floor on
// the rate it produces, not just a ceiling.
const MaxDelayMs = 12 * 60 * 60 * 1000

// MaxThrottleStatuses matches the intruder route's own cap on how many statuses may mean "slow down".
const MaxThrottleStatuses = 32

// MaxPools bounds how many pools may be saved. A pool is an operator-typed object, so this is not a
// resource bound — it is the point past which a name-keyed list stops being something a human picks
// from, and a "pool" nobody can find is not a shared object.
const MaxPools = 200

// MaxNameLen bounds a pool name. Long enough for "engagement 4 — production, out of hours".
const MaxNameLen = 120

// ErrNoSuchPool is returned by Get and Limit for a name nothing holds. Distinguishable with
// errors.Is so a caller can tell "this pool is gone" from "this pool is malformed" — a tool that
// silently fell back to its own defaults on a dangling name would run unbounded traffic while the
// operator believed a pool was in force, which is exactly the failure this package exists to stop.
var ErrNoSuchPool = errors.New("no pool of that name is saved")

// ErrDuplicateName is returned when a name is already taken. The name is the pool's identity — it is
// what a tool references — so two pools sharing one is not a cosmetic clash.
var ErrDuplicateName = errors.New("a pool of that name already exists")

// Throttle is Burp's "Automatic throttling", expressed in the terms intruder.AutoThrottle already
// works in.
//
// # The one translation in this package
//
// Burp says "increase delay in increments of I milliseconds". intruder.AutoThrottle says "divide the
// rate by Factor". Those are the same statement written two ways, and the arithmetic is exact rather
// than approximate: a delay of D ms is a rate of 1000/D per second, so raising the delay to D+I is a
// rate of 1000/(D+I), which is the original rate divided by (D+I)/D. So the operator types an
// increment — Burp's word, the thing they can reason about against a target — and Factor is derived
// from it. Nothing here invents a second throttle model.
//
// The identity has one hole, and it is refused rather than papered over: when D is 0 there is no
// delay to increase, and 0+I cannot be written as 0×Factor for any Factor. So automatic throttling
// with no delay between requests is not expressible, and Validate says so. Silently treating it as
// "throttle to some rate we picked" would be this package deciding an engagement's traffic policy.
type Throttle struct {
	// IncrementMs is how much the delay between requests grows while the throttle is engaged. Burp's
	// "Increase delay in increments of". Must be positive: a throttle that increases the delay by
	// nothing is off, and saving it as on would show an operator a safeguard that does nothing.
	IncrementMs int `json:"increment_ms"`
	// Statuses are the response statuses that mean "slow down". Empty takes 429 and 503 — 429 is the
	// status that exists to say this, and 503 is what a target says when it is the truth rather than
	// a policy.
	Statuses []int `json:"statuses,omitempty"`
	// After is how many consecutive listed responses precede the increase. Zero takes 3: a single
	// 503 on a busy target is noise, a run of them is the target telling you something.
	After int `json:"after,omitempty"`
	// RecoverAfter is how many requests the increased delay lasts for. Zero takes 50.
	RecoverAfter int `json:"recover_after,omitempty"`
}

// Default throttle parameters, matching intruder.DefaultAutoThrottle so a pool that leaves them
// unset behaves exactly as an intruder attack with auto-throttling on already did.
const (
	DefaultThrottleAfter        = 3
	DefaultThrottleRecoverAfter = 50
)

// DefaultThrottleStatuses returns a fresh copy of the default status list. A function rather than a
// package-level slice so a caller that appends to what it is handed cannot edit the default.
func DefaultThrottleStatuses() []int { return []int{429, 503} }

// Pool is one named resource pool: what an operator saved, and nothing derived.
type Pool struct {
	// Name is the pool's identity. Tools reference a pool by this and nothing else, which is why it
	// is also the persisted primary key: the uniqueness invariant is enforced by the database rather
	// than asserted in a comment.
	Name string `json:"name"`
	// MaxConcurrent is Burp's "Max concurrent requests" — how many requests from tools running under
	// this pool may be in flight at once. At least 1: zero would deadlock rather than throttle.
	MaxConcurrent int `json:"max_concurrent"`
	// DelayMs is Burp's "Delay between requests". 0 means no rate cap, and only MaxConcurrent
	// bounds the tool — a real choice, and the reason this is a count rather than a pointer: the
	// operator typing 0 into a "delay" box is stating it.
	DelayMs int `json:"delay_ms"`
	// Throttle is Burp's "Automatic throttling". nil means off, and off changes nothing about how a
	// tool under this pool behaves.
	Throttle *Throttle `json:"throttle,omitempty"`
}

// DefaultPool is the pool a New dialog should open on: the intruder's own long-standing defaults
// (20 requests a second, 10 in flight) written as a pool, so the first pool an operator saves is not
// more aggressive than what the tool already did.
//
// 50ms is 20 requests a second exactly. Auto-throttling on, because DefaultRateLimit's comment
// applies here too: nobody should discover their default was "as fast as the network allows" from
// the target's incident channel.
func DefaultPool(name string) Pool {
	return Pool{
		Name:          name,
		MaxConcurrent: 10,
		DelayMs:       50,
		Throttle:      &Throttle{IncrementMs: 50},
	}
}

// Validate reports the first thing wrong with this pool, naming the field and why.
//
// Called on every write path *and* on load, for the same reason persist's session-rule restore
// re-validates: a pool saved before a check existed must be refused with its reason rather than
// installed as an exception to the rule.
func (p Pool) Validate() error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return errors.New("a pool needs a name: it is what a tool references, so an unnamed pool cannot be referenced")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("the pool name is %d characters, more than the %d allowed", len(name), MaxNameLen)
	}
	if p.MaxConcurrent < 1 {
		return fmt.Errorf("max concurrent requests is %d: it must be at least 1, because 0 in flight would deadlock rather than throttle", p.MaxConcurrent)
	}
	if p.MaxConcurrent > MaxConcurrentCeiling {
		return fmt.Errorf("max concurrent requests is %d, more than the %d ceiling the intruder route already enforces", p.MaxConcurrent, MaxConcurrentCeiling)
	}
	if p.DelayMs < 0 {
		return fmt.Errorf("delay between requests is %dms: a negative delay is not a rate", p.DelayMs)
	}
	if p.DelayMs > MaxDelayMs {
		return fmt.Errorf("delay between requests is %dms, more than the %dms allowed", p.DelayMs, MaxDelayMs)
	}
	t := p.Throttle
	if t == nil {
		return nil
	}
	if p.DelayMs == 0 {
		return errors.New("automatic throttling needs a non-zero delay between requests: it works by increasing that delay, and there is no multiple of zero that is larger than zero")
	}
	if t.IncrementMs < 1 {
		return fmt.Errorf("the throttle increment is %dms: a throttle that increases the delay by nothing is off, and saving it as on would show a safeguard that does nothing", t.IncrementMs)
	}
	if t.IncrementMs > MaxDelayMs {
		return fmt.Errorf("the throttle increment is %dms, more than the %dms allowed", t.IncrementMs, MaxDelayMs)
	}
	if len(t.Statuses) > MaxThrottleStatuses {
		return fmt.Errorf("the throttle lists %d statuses, more than the %d allowed", len(t.Statuses), MaxThrottleStatuses)
	}
	for _, s := range t.Statuses {
		if s < 100 || s > 599 {
			return fmt.Errorf("%d is not an HTTP status code, so it cannot be a status that means slow down", s)
		}
	}
	if t.After < 0 {
		return fmt.Errorf("the throttle's consecutive count is %d: it cannot be negative", t.After)
	}
	if t.RecoverAfter < 0 {
		return fmt.Errorf("the throttle's recovery count is %d: it cannot be negative", t.RecoverAfter)
	}
	return nil
}

// RequestsPerSecond is the rate this pool's delay expresses, and whether it caps the rate at all.
//
// Two return values rather than a sentinel: 0 requests a second and "no rate cap" are opposite
// statements, and a caller that read a bare 0 as either one would be wrong half the time.
func (p Pool) RequestsPerSecond() (float64, bool) {
	if p.DelayMs <= 0 {
		return 0, false
	}
	return 1000.0 / float64(p.DelayMs), true
}

// ThrottleFactor is the divisor intruder.AutoThrottle needs to express this pool's delay increment,
// and whether there is a throttle at all. See Throttle for the derivation.
func (p Pool) ThrottleFactor() (float64, bool) {
	if p.Throttle == nil || p.DelayMs <= 0 {
		return 0, false
	}
	return float64(p.DelayMs+p.Throttle.IncrementMs) / float64(p.DelayMs), true
}

// Limit is this pool as the bound every tool actually runs under.
//
// Burst is 1 and not configurable, because "delay between requests" *means* strict spacing: a burst
// of N would let N requests go out back-to-back after an idle moment, which is the one thing an
// operator who typed a delay was asking not to happen.
func (p Pool) Limit() intruder.RateLimit {
	limit := intruder.RateLimit{Burst: 1, MaxInFlight: p.MaxConcurrent, Name: p.Name}
	if rps, capped := p.RequestsPerSecond(); capped {
		limit.PerSecond = &rps
	}
	if factor, on := p.ThrottleFactor(); on {
		t := p.Throttle
		statuses := t.Statuses
		if len(statuses) == 0 {
			statuses = DefaultThrottleStatuses()
		}
		after := t.After
		if after < 1 {
			after = DefaultThrottleAfter
		}
		recover := t.RecoverAfter
		if recover < 1 {
			recover = DefaultThrottleRecoverAfter
		}
		limit.AutoThrottle = &intruder.AutoThrottle{
			Statuses: statuses, After: after, Factor: factor, RecoverAfter: recover,
		}
	}
	return limit
}

// Registry is the saved set of pools, keyed by name.
//
// Order is kept, but unlike session_rules' `ord` this order is *presentation only*: a tool names the
// pool it wants, so nothing here is evaluated first-match. The order is preserved anyway because it
// is the order the operator arranged the list in, and a list that reshuffles itself on every restart
// is a list nobody can navigate.
type Registry struct {
	mu    sync.RWMutex
	order []string
	byKey map[string]Pool
	// limiters is the one live limiter per pool, built on first use and dropped when the pool it was
	// built from changes. See limiter.go for why a shared object needs a shared limiter, and why an
	// edit applies to the next run rather than to work already in flight.
	limiters map[string]*intruder.RateLimiter
	// onChange fires after every mutation, so the owner can persist and notify without every call
	// site remembering to. Never called while mu is held.
	onChange func()
}

// New creates an empty registry. Empty is the honest starting state: no pool has been saved, and
// every tool runs under its own documented default until one is.
func New() *Registry {
	return &Registry{byKey: map[string]Pool{}, limiters: map[string]*intruder.RateLimiter{}}
}

// OnChange installs the post-mutation hook. One slot; re-installing replaces.
func (r *Registry) OnChange(fn func()) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.onChange = fn
	r.mu.Unlock()
}

// key normalises a name for lookup. Case-insensitive, because "Default" and "default" being two
// pools is a trap rather than a feature: an operator who typed one meaning the other would get
// bounds they did not choose. The stored Name keeps the operator's own capitalisation.
func key(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// notify calls the change hook with no lock held.
func (r *Registry) notify() {
	r.mu.RLock()
	fn := r.onChange
	r.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// Add saves a new pool, refusing a duplicate name.
func (r *Registry) Add(p Pool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	p.Name = strings.TrimSpace(p.Name)
	r.mu.Lock()
	if len(r.order) >= MaxPools {
		r.mu.Unlock()
		return fmt.Errorf("%d pools are already saved, which is the maximum", MaxPools)
	}
	k := key(p.Name)
	if _, taken := r.byKey[k]; taken {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrDuplicateName, p.Name)
	}
	r.byKey[k] = p
	r.order = append(r.order, k)
	r.mu.Unlock()
	r.notify()
	return nil
}

// Update replaces the pool currently named `name` with p, which may carry a different name (a
// rename). A rename onto a name another pool holds is refused, and the pool keeps its position in
// the list — an edit is not a delete and a re-add, and treating it as one would send the edited pool
// to the bottom.
//
// Renaming does not rewrite anything that referenced the old name. Callers that hold references —
// schedules, in this tree — are responsible for reporting the ones they have; see
// Registry.Get's contract on a name nothing holds.
func (r *Registry) Update(name string, p Pool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	p.Name = strings.TrimSpace(p.Name)
	from, to := key(name), key(p.Name)
	r.mu.Lock()
	if _, ok := r.byKey[from]; !ok {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNoSuchPool, name)
	}
	if to != from {
		if _, taken := r.byKey[to]; taken {
			r.mu.Unlock()
			return fmt.Errorf("%w: %s", ErrDuplicateName, p.Name)
		}
		delete(r.byKey, from)
		for i, k := range r.order {
			if k == from {
				r.order[i] = to
				break
			}
		}
	}
	r.byKey[to] = p
	// Both keys, because a rename moves the pool: the old name must stop resolving to a limiter, and
	// the new one must not inherit one built from bounds that have just been replaced.
	r.dropLimiter(from)
	r.dropLimiter(to)
	r.mu.Unlock()
	r.notify()
	return nil
}

// Remove deletes a pool, reporting whether there was one to delete.
func (r *Registry) Remove(name string) bool {
	k := key(name)
	r.mu.Lock()
	if _, ok := r.byKey[k]; !ok {
		r.mu.Unlock()
		return false
	}
	delete(r.byKey, k)
	r.dropLimiter(k)
	kept := r.order[:0]
	for _, existing := range r.order {
		if existing != k {
			kept = append(kept, existing)
		}
	}
	r.order = kept
	r.mu.Unlock()
	r.notify()
	return true
}

// Get returns the pool saved under this name.
//
// The error is ErrNoSuchPool rather than a zero Pool and a bool, because a zero Pool has
// MaxConcurrent 0 and would resolve to a limiter that deadlocks — a caller that ignored a bool would
// get something worse than an error. A dangling reference must be reported, never defaulted.
func (r *Registry) Get(name string) (Pool, error) {
	if r == nil {
		return Pool{}, fmt.Errorf("%w: %s", ErrNoSuchPool, name)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byKey[key(name)]
	if !ok {
		return Pool{}, fmt.Errorf("%w: %s", ErrNoSuchPool, name)
	}
	return p, nil
}

// Limit resolves a pool name to the bound a tool runs under. The single resolution point: every
// tool that accepts a pool name calls this, so "what does this pool mean" has one answer.
func (r *Registry) Limit(name string) (intruder.RateLimit, error) {
	p, err := r.Get(name)
	if err != nil {
		return intruder.RateLimit{}, err
	}
	return p.Limit(), nil
}

// List returns the saved pools in the operator's order.
func (r *Registry) List() []Pool {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Pool, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, r.byKey[k])
	}
	return out
}

// Len is how many pools are saved.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.order)
}

// Names returns the saved names, sorted, for an error message that can say what *is* available.
func (r *Registry) Names() []string {
	out := make([]string, 0, r.Len())
	for _, p := range r.List() {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

// Restore replaces the registry's contents with a persisted set, in the given order, and reports
// every pool it refused and why.
//
// Refusals are returned rather than logged-and-dropped for the same reason persist's session-rule
// restore counts them: a pool that silently vanished on restart leaves a schedule or a saved run
// referencing a name nothing holds, and the tool would then either fail at the worst moment or —
// far worse — fall back to bounds nobody chose. A restore that drops something says so.
func (r *Registry) Restore(pools []Pool) []error {
	if r == nil {
		return nil
	}
	var refused []error
	order := make([]string, 0, len(pools))
	byKey := make(map[string]Pool, len(pools))
	for _, p := range pools {
		if err := p.Validate(); err != nil {
			refused = append(refused, fmt.Errorf("pool %q was not restored: %w", p.Name, err))
			continue
		}
		p.Name = strings.TrimSpace(p.Name)
		k := key(p.Name)
		if _, taken := byKey[k]; taken {
			refused = append(refused, fmt.Errorf("%w: %s — one of the two was not restored", ErrDuplicateName, p.Name))
			continue
		}
		byKey[k] = p
		order = append(order, k)
	}
	r.mu.Lock()
	r.order, r.byKey = order, byKey
	// Every cached limiter goes, not just the ones whose pool changed: Restore replaces the whole set,
	// so a limiter surviving it would be enforcing bounds from a set that is no longer the saved one.
	r.limiters = map[string]*intruder.RateLimiter{}
	r.mu.Unlock()
	return refused
}
