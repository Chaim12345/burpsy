// Package schedule starts registered work at a wall-clock time or on an interval.
//
// # Why this is not in internal/dash
//
// dash's own docs are explicit: "The registry observes, it does not schedule. It owns no goroutines."
// That is load-bearing — a registry that started work would have to hold every caller's collaborators
// and would become the hub nothing can be built without. So a schedule is the opposite half: this
// package owns the clock and knows nothing about tasks. It calls a Starter the owner registered by
// kind, and that Starter is what registers a dash task. Neither package imports the other.
//
// # The missed-window decision, made rather than left emergent
//
// A schedule outlives the process. So the interesting case is not "the time arrived" but "the time
// arrived while burpsy was not running", and there are three possible answers:
//
//  1. fire now — replay every occurrence that was missed;
//  2. fire once now — collapse the missed occurrences into one late run;
//  3. do not fire — count what was missed and arm the next occurrence.
//
// This package does (3), and Grace is the seam. Answer (1) is a thundering herd: a nightly crawl and
// a week of downtime is seven crawls at once against a production target, which is a denial of
// service dressed as catching up. Answer (2) is worse than it looks, because "now" is not the window
// the operator chose: an out-of-hours scan scheduled for 02:00 would start at 09:30 on the morning
// the process came back, in the middle of the working day it was scheduled to avoid. A schedule is a
// statement about *when*, and firing it at the wrong time is not a partial version of honouring it.
//
// So a due occurrence fires only if it is at most Grace late. Everything older is counted into
// Schedule.Missed and reported — never silently dropped, which is the fourth answer and the only
// unacceptable one.
//
// # Why Tick takes the time
//
// The only interesting behaviour here is time-dependent, so the time is a parameter. Tick(now)
// decides and fires synchronously; Run is a thin loop that calls it. Tests therefore drive real
// firing decisions at chosen instants with no sleeping and no fake-clock plumbing, and there is no
// second code path that only the tests exercise.
package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultGrace is how late a due occurrence may fire and still count as having fired.
//
// A minute, chosen from both ends: long enough that a busy tick, a slow start or a clock nudge does
// not turn a scheduled run into a missed one, and short enough that nothing fires in a window the
// operator would not recognise as the one they picked. It is not a catch-up budget — see the package
// docs on why catching up is the wrong answer.
const DefaultGrace = time.Minute

// DefaultResolution is how often Run consults the clock. A second, because the smallest unit a
// schedule is expressed in is a second and a coarser tick would make its own lateness the dominant
// term in Grace.
const DefaultResolution = time.Second

// MaxSchedules bounds the saved set, for the same reason pool.MaxPools does: this is an
// operator-typed list, and past a few dozen it stops being one a human can audit.
const MaxSchedules = 200

// MaxNameLen bounds a schedule name.
const MaxNameLen = 120

// MaxIntervalSecs is a year. Longer than this and the schedule is a note in a calendar, not a timer
// a process should be holding.
const MaxIntervalSecs = 365 * 24 * 60 * 60

// MinIntervalSecs is a minute. Anything shorter is a loop with extra steps, and a one-second
// interval starting a crawl is a way to run unbounded concurrent crawls by accident.
const MinIntervalSecs = 60

// ErrNoSuchSchedule is returned for a name nothing holds.
var ErrNoSuchSchedule = errors.New("no schedule of that name is saved")

// ErrDuplicateName is returned when a schedule name is already taken.
var ErrDuplicateName = errors.New("a schedule of that name already exists")

// Schedule is one saved schedule: what the operator configured, plus what has happened to it.
//
// The two halves are deliberately in one struct and deliberately distinguishable: the configured
// fields are what a PUT replaces, and the observed fields (NextMs, LastRunMs, Runs, Missed, LastNote)
// are what the process fills in. A PUT that reset the counters would erase the record of a schedule
// that has been failing every night, which is the one thing an operator most needs to see.
type Schedule struct {
	// Name is the schedule's identity, as a pool's is.
	Name string `json:"name"`
	// Kind names the work to start. It is matched against the Starters the owner registered; an
	// unregistered kind is refused at save time rather than discovered at 02:00.
	Kind string `json:"kind"`
	// Enabled off keeps the schedule and stops it firing. Distinct from deleting it, and distinct
	// from a schedule whose one occurrence has passed.
	Enabled bool `json:"enabled"`
	// FirstMs is the first occurrence, Unix milliseconds. Required — a schedule with no first time
	// has no occurrences to compute, and defaulting it to "now" would fire something the moment it
	// was saved.
	FirstMs int64 `json:"first_ms"`
	// IntervalSecs is 0 for a one-shot, or the repeat period. See MinIntervalSecs.
	IntervalSecs int `json:"interval_secs"`
	// Pool is the named resource pool the started work runs under, empty for the tool's own
	// defaults. Carried here rather than inside Params because it is the one parameter every kind
	// has, and because a UI that lists schedules should be able to show what bounds each one without
	// parsing a per-kind blob.
	Pool string `json:"pool,omitempty"`
	// Params is the kind's own configuration — a crawl's seeds, an audit's exchange id. Opaque here
	// on purpose: this package would otherwise have to learn every kind's shape, which is exactly
	// the coupling that keeps dash free of the packages it tracks.
	Params json.RawMessage `json:"params,omitempty"`

	// NextMs is the next occurrence this schedule will be considered at, Unix milliseconds. Zero
	// means there is no next one: a one-shot that has fired, or one whose only occurrence was missed.
	NextMs int64 `json:"next_ms"`
	// LastRunMs is when it last fired, 0 for never.
	LastRunMs int64 `json:"last_run_ms"`
	// Runs counts firings. Missed counts occurrences that passed without firing — the number the
	// package's whole missed-window decision exists to make visible.
	Runs   int `json:"runs"`
	Missed int `json:"missed"`
	// Failures counts firings whose Starter returned an error, and is a subset of Runs rather than an
	// alternative to it.
	//
	// Both counts exist because "it fired" and "it worked" are different facts and an operator needs
	// both. A nightly audit whose target moved fires every night and fails every night: counting only
	// Runs shows 30 and reads as healthy, counting only failures shows 30 and reads as never having
	// started. Runs 30 / Failures 30 is the only pair that says what is actually happening. This is
	// the same reason the crawler's Report partitions fetched/refused/failed/not-captured instead of
	// reporting one total.
	Failures int `json:"failures"`
	// LastNote is what the last firing (or refusal to fire) said about itself.
	LastNote string `json:"last_note,omitempty"`
}

// Validate reports the first thing wrong with the configured half of this schedule.
func (s Schedule) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("a schedule needs a name")
	}
	if len(s.Name) > MaxNameLen {
		return fmt.Errorf("the schedule name is %d characters, more than the %d allowed", len(s.Name), MaxNameLen)
	}
	if strings.TrimSpace(s.Kind) == "" {
		return errors.New("a schedule needs a kind: it is what says which work to start")
	}
	if s.FirstMs <= 0 {
		return errors.New("a schedule needs a first occurrence: with none there is nothing to count intervals from, and defaulting it to now would fire the moment it was saved")
	}
	if s.IntervalSecs < 0 {
		return fmt.Errorf("the interval is %ds: it cannot be negative", s.IntervalSecs)
	}
	if s.IntervalSecs > 0 && s.IntervalSecs < MinIntervalSecs {
		return fmt.Errorf("the interval is %ds, shorter than the %ds minimum: at that rate a schedule is a loop, and a run that outlasts its own interval would overlap itself", s.IntervalSecs, MinIntervalSecs)
	}
	if s.IntervalSecs > MaxIntervalSecs {
		return fmt.Errorf("the interval is %ds, longer than the %ds maximum", s.IntervalSecs, MaxIntervalSecs)
	}
	if len(s.Params) > 0 && !json.Valid(s.Params) {
		return errors.New("the schedule's params are not valid JSON")
	}
	return nil
}

// OneShot reports whether this schedule has a single occurrence.
func (s Schedule) OneShot() bool { return s.IntervalSecs <= 0 }

// Armed reports whether there is a future occurrence to wait for.
func (s Schedule) Armed() bool { return s.Enabled && s.NextMs > 0 }

// advanceTo moves this schedule past every occurrence at or before nowMs, and says whether the most
// recent of those is close enough to fire.
//
// The arithmetic is closed-form rather than a loop, so a schedule left armed across a month of
// downtime costs one division instead of forty thousand iterations. `missed` counts occurrences that
// will never run: every occurrence strictly older than the most recent one, plus the most recent one
// itself when it falls outside the grace window.
func (s *Schedule) advanceTo(nowMs int64, grace time.Duration) (fire bool, missed int) {
	if s.NextMs == 0 || s.NextMs > nowMs {
		return false, 0
	}
	graceMs := grace.Milliseconds()
	if s.OneShot() {
		late := nowMs - s.NextMs
		s.NextMs = 0
		if late > graceMs {
			return false, 1
		}
		return true, 0
	}
	step := int64(s.IntervalSecs) * 1000
	// k is how many whole intervals fit between the armed occurrence and now, so latest is the most
	// recent occurrence that is due.
	k := (nowMs - s.NextMs) / step
	latest := s.NextMs + k*step
	s.NextMs = latest + step
	if nowMs-latest > graceMs {
		return false, int(k) + 1
	}
	return true, int(k)
}

// Starter begins the work one kind names. It is called with no lock held and must not block for
// long: the returned note goes on the schedule, and anything long-running belongs on a goroutine the
// Starter itself owns (which is what the dash task registry is for).
type Starter func(ctx context.Context, s Schedule) (note string, err error)

// Fired is what one Tick did to one schedule. Returned as a slice so a caller — a test, or the
// owner's logging — sees every decision the tick made rather than only the last.
type Fired struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Started is true when a Starter ran. False with Missed>0 is the missed-window case; false with
	// Err set and Missed 0 is a kind with no registered Starter.
	Started bool `json:"started"`
	// Missed is how many occurrences this decision wrote off. See the package docs.
	Missed int    `json:"missed"`
	Note   string `json:"note,omitempty"`
	Err    string `json:"error,omitempty"`
}

// Runner is the saved set of schedules plus the clock decisions over them.
type Runner struct {
	mu        sync.RWMutex
	order     []string
	byKey     map[string]*Schedule
	starters  map[string]Starter
	grace     time.Duration
	onChange  func()
	fired     int
	failed    int
	missed    int
	unstarted int
}

// NewRunner creates an empty runner at the default grace.
func NewRunner() *Runner {
	return &Runner{byKey: map[string]*Schedule{}, starters: map[string]Starter{}, grace: DefaultGrace}
}

// WithGrace overrides how late an occurrence may fire. Non-positive is refused into the default: a
// zero grace would make every occurrence a missed one unless a tick landed on the exact millisecond.
func (r *Runner) WithGrace(g time.Duration) *Runner {
	if g <= 0 {
		g = DefaultGrace
	}
	r.mu.Lock()
	r.grace = g
	r.mu.Unlock()
	return r
}

// OnChange installs the post-mutation hook, so the owner can persist and notify without every call
// site remembering to. Never called with the lock held.
func (r *Runner) OnChange(fn func()) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.onChange = fn
	r.mu.Unlock()
}

// Register makes a kind schedulable. Called once per kind by the owner that can actually start that
// work; a kind with no Starter is refused at save time, so an operator cannot arm a schedule that
// this build has no way to honour.
func (r *Runner) Register(kind string, start Starter) {
	if r == nil || start == nil {
		return
	}
	r.mu.Lock()
	r.starters[strings.ToLower(strings.TrimSpace(kind))] = start
	r.mu.Unlock()
}

// Kinds returns the registered kinds, sorted. The list a UI offers, and the list an error message
// names when a kind is refused.
func (r *Runner) Kinds() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.starters))
	for k := range r.starters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func skey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func (r *Runner) notify() {
	r.mu.RLock()
	fn := r.onChange
	r.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// knownKind reports whether a Starter is registered for this kind.
func (r *Runner) knownKind(kind string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.starters[skey(kind)]
	return ok
}

// arm sets the observed half of a freshly-saved schedule: its first occurrence is FirstMs, and the
// counters start at zero. Called on Add and on Update, because an edit to the timing has to re-arm —
// a schedule whose first occurrence moved and whose NextMs did not is a schedule that fires at the
// old time.
func arm(s *Schedule) {
	s.Name = strings.TrimSpace(s.Name)
	s.Kind = strings.ToLower(strings.TrimSpace(s.Kind))
	s.NextMs = s.FirstMs
}

// Add saves a new schedule.
func (r *Runner) Add(s Schedule) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !r.knownKind(s.Kind) {
		return fmt.Errorf("this build cannot start %q on a schedule; it can start: %s",
			s.Kind, strings.Join(r.Kinds(), ", "))
	}
	arm(&s)
	r.mu.Lock()
	if len(r.order) >= MaxSchedules {
		r.mu.Unlock()
		return fmt.Errorf("%d schedules are already saved, which is the maximum", MaxSchedules)
	}
	k := skey(s.Name)
	if _, taken := r.byKey[k]; taken {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrDuplicateName, s.Name)
	}
	r.byKey[k] = &s
	r.order = append(r.order, k)
	r.mu.Unlock()
	r.notify()
	return nil
}

// Update replaces the configured half of the schedule named `name` and re-arms it, keeping the
// observed counters.
//
// Keeping the counters is the point: Runs and Missed are the record of what this schedule has
// actually done, and an operator who fixes a broken schedule's params needs to still be able to see
// that it missed the last four nights. NextMs is *not* kept, because an edit may have moved the
// timing and an un-re-armed schedule would fire at the old one.
func (r *Runner) Update(name string, s Schedule) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !r.knownKind(s.Kind) {
		return fmt.Errorf("this build cannot start %q on a schedule; it can start: %s",
			s.Kind, strings.Join(r.Kinds(), ", "))
	}
	arm(&s)
	from, to := skey(name), skey(s.Name)
	r.mu.Lock()
	existing, ok := r.byKey[from]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNoSuchSchedule, name)
	}
	if to != from {
		if _, taken := r.byKey[to]; taken {
			r.mu.Unlock()
			return fmt.Errorf("%w: %s", ErrDuplicateName, s.Name)
		}
		delete(r.byKey, from)
		for i, k := range r.order {
			if k == from {
				r.order[i] = to
				break
			}
		}
	}
	s.Runs, s.Failures, s.Missed = existing.Runs, existing.Failures, existing.Missed
	s.LastRunMs, s.LastNote = existing.LastRunMs, existing.LastNote
	r.byKey[to] = &s
	r.mu.Unlock()
	r.notify()
	return nil
}

// Remove deletes a schedule, reporting whether there was one.
func (r *Runner) Remove(name string) bool {
	k := skey(name)
	r.mu.Lock()
	if _, ok := r.byKey[k]; !ok {
		r.mu.Unlock()
		return false
	}
	delete(r.byKey, k)
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

// Get returns a copy of one schedule.
func (r *Runner) Get(name string) (Schedule, error) {
	if r == nil {
		return Schedule{}, fmt.Errorf("%w: %s", ErrNoSuchSchedule, name)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byKey[skey(name)]
	if !ok {
		return Schedule{}, fmt.Errorf("%w: %s", ErrNoSuchSchedule, name)
	}
	return *s, nil
}

// List returns copies of the saved schedules, in the operator's order.
func (r *Runner) List() []Schedule {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Schedule, 0, len(r.order))
	for _, k := range r.order {
		if s := r.byKey[k]; s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// Len is how many schedules are saved.
func (r *Runner) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.order)
}

// UsingPool returns the names of schedules that reference this pool. The reason a pool cannot be
// deleted out from under a schedule: a dangling reference would leave the scheduled run to fall back
// to whatever bounds the tool defaults to, at the exact hour nobody is watching.
func (r *Runner) UsingPool(pool string) []string {
	if r == nil {
		return nil
	}
	want := skey(pool)
	var out []string
	for _, s := range r.List() {
		if skey(s.Pool) == want {
			out = append(out, s.Name)
		}
	}
	return out
}

// Totals is the runner's own count of what it has done. Four numbers, because there are four
// outcomes and every occurrence this runner considered lands in exactly one of the last three:
// it fired, it was written off as missed, or nothing could start it. `failed` is a subset of
// `fired` — see Runner.record — and is the one number that is not part of that partition.
//
// Reported rather than derived from the schedule list because the list is mutable — deleting a
// schedule that missed four nights should not make those four nights un-missed in the process's own
// account of itself.
func (r *Runner) Totals() (fired, failed, missed, unstarted int) {
	if r == nil {
		return 0, 0, 0, 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fired, r.failed, r.missed, r.unstarted
}

// Restore replaces the saved set with a persisted one, and reports what it refused.
//
// This is where the missed-window decision actually pays out: a schedule comes back with the NextMs
// it was persisted with, which is usually in the past, and the first Tick after startup applies
// exactly the same rule to it as any other late occurrence. There is no separate startup path — one
// rule, one implementation, and the restart case is not a special case.
func (r *Runner) Restore(schedules []Schedule) []error {
	if r == nil {
		return nil
	}
	var refused []error
	order := make([]string, 0, len(schedules))
	byKey := make(map[string]*Schedule, len(schedules))
	for i := range schedules {
		s := schedules[i]
		if err := s.Validate(); err != nil {
			refused = append(refused, fmt.Errorf("schedule %q was not restored: %w", s.Name, err))
			continue
		}
		// Not refused for an unregistered kind: the kinds are registered by the owner, and Restore may
		// run before every registration has happened. A schedule whose kind is still unknown when it
		// comes due is counted as unstarted by Tick and says so, which is a truer report than dropping
		// it on load and telling the operator their schedule never existed.
		s.Name = strings.TrimSpace(s.Name)
		s.Kind = strings.ToLower(strings.TrimSpace(s.Kind))
		k := skey(s.Name)
		if _, taken := byKey[k]; taken {
			refused = append(refused, fmt.Errorf("%w: %s — one of the two was not restored", ErrDuplicateName, s.Name))
			continue
		}
		byKey[k] = &s
		order = append(order, k)
	}
	r.mu.Lock()
	r.order, r.byKey = order, byKey
	r.mu.Unlock()
	return refused
}

// Tick decides what is due at `now` and starts it, returning one entry per schedule it acted on.
//
// The lock is taken to pick the due set and released before any Starter runs, then taken again to
// record the outcome. Holding it across a Starter would make the schedule table's lock a dependency
// of whatever a scheduled crawl touches, which is the lock-ordering hazard dash's event log is
// arranged to avoid for the same reason.
func (r *Runner) Tick(now time.Time) []Fired {
	if r == nil {
		return nil
	}
	nowMs := now.UnixMilli()

	type due struct {
		snapshot Schedule
		missed   int
		fire     bool
	}
	r.mu.Lock()
	grace := r.grace
	var pending []due
	for _, k := range r.order {
		s := r.byKey[k]
		if s == nil || !s.Enabled || s.NextMs == 0 || s.NextMs > nowMs {
			continue
		}
		fire, missed := s.advanceTo(nowMs, grace)
		if missed > 0 {
			s.Missed += missed
			r.missed += missed
			s.LastNote = fmt.Sprintf("%d occurrence(s) passed while nothing ran them; the next one is armed rather than caught up", missed)
		}
		pending = append(pending, due{snapshot: *s, missed: missed, fire: fire})
	}
	starters := make(map[string]Starter, len(r.starters))
	for k, v := range r.starters {
		starters[k] = v
	}
	r.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}

	out := make([]Fired, 0, len(pending))
	for _, d := range pending {
		rec := Fired{Name: d.snapshot.Name, Kind: d.snapshot.Kind, Missed: d.missed}
		if !d.fire {
			rec.Note = d.snapshot.LastNote
			out = append(out, rec)
			continue
		}
		start, ok := starters[skey(d.snapshot.Kind)]
		if !ok {
			rec.Err = fmt.Sprintf("nothing in this build can start %q, so this occurrence did not run", d.snapshot.Kind)
			r.record(d.snapshot.Name, nowMs, false, true, rec.Err)
			out = append(out, rec)
			continue
		}
		note, err := start(context.Background(), d.snapshot)
		rec.Started = err == nil
		rec.Note = note
		if err != nil {
			rec.Err = err.Error()
		}
		r.record(d.snapshot.Name, nowMs, err == nil, false, firstNonEmpty(rec.Err, note))
		out = append(out, rec)
	}
	r.notify()
	return out
}

// record writes one firing's outcome back onto the schedule.
//
// A Starter that returned an error still counts as a run: it happened, it is in LastNote, and
// pretending it did not would make a schedule that fails every night look like one that has never
// fired. So `ok` does not decide *whether* to count the run — it decides whether to also count a
// failure, and Schedule.Failures is a subset of Schedule.Runs.
//
// `unstarted` is the third outcome and not a kind of failure: an occurrence nothing in this build
// could start never ran at all, so it increments neither Runs nor Failures. The distinction is the
// whole reason this function takes two bools rather than one — "the work ran and returned an error"
// and "there was no work to run" have different causes and different fixes (a broken target versus a
// schedule naming a kind this binary does not have), and collapsing them would tell an operator
// their audit is failing when in fact it never happened. Kept apart for the same reason persist
// keeps session-rule id collisions apart from validation refusals.
func (r *Runner) record(name string, nowMs int64, ok, unstarted bool, note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byKey[skey(name)]
	if s == nil {
		return
	}
	switch {
	case unstarted:
		r.unstarted++
	default:
		s.Runs++
		s.LastRunMs = nowMs
		r.fired++
		if !ok {
			s.Failures++
			r.failed++
		}
	}
	if note != "" {
		s.LastNote = note
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Run consults the clock every `resolution` until ctx ends, calling Tick.
//
// Deliberately thin: every decision is in Tick, which takes the time as a parameter, so this loop has
// no behaviour of its own to get wrong and no behaviour the tests cannot reach. A non-positive
// resolution takes DefaultResolution.
func (r *Runner) Run(ctx context.Context, resolution time.Duration) {
	if r == nil {
		return
	}
	if resolution <= 0 {
		resolution = DefaultResolution
	}
	ticker := time.NewTicker(resolution)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			r.Tick(t)
		}
	}
}
