package web

import (
	"sync"
	"sync/atomic"
	"time"
)

// ---- live change events (LIVE-01) ---------------------------------------------------------------
//
// # What this is
//
// The UI used to learn that something had been captured by asking again: a four-second poll on the
// header and the dashboard, a 1.5-second poll on the intercept queue, and a Refresh button on
// everything else. Proxying a request and then waiting — or clicking — to see it is the complaint this
// answers. The hub below is the server half: every producer of change signals it, and one goroutine
// fans a coalesced "kind X changed" frame out to the browsers watching /api/events.
//
// # Why the frame carries what changed and not the change
//
// A frame is a kind and a count, never a row. Serialising an exchange into the stream would duplicate
// the wire shape that /api/history already owns, and two producers of the same shape drift — that has
// already bitten this tree twice. So the client is told *which endpoint is stale* and re-fetches it
// through the one handler that has always rendered it. The count is there because it is the honest
// number: one frame can stand for four hundred exchanges, and saying so is better than implying one.
//
// # Why coalescing, and why 150ms
//
// A crawl or an active scan appends hundreds of exchanges a second. One frame per exchange would spend
// the browser's render loop on parsing frames it is about to supersede, and the re-fetch each frame
// triggers would arrive slower than the next frame. So notify() only ever bumps a counter, and the
// fan-out goroutine waits out a trailing window before flushing whatever accumulated: a burst of five
// hundred appends becomes one frame that says 500.
//
// 150ms is chosen from both ends. The floor is what an operator reads as instant — the intercept queue
// is the latency-critical case, because someone is sitting there waiting for a held request, and 150ms
// against the 1500ms poll it replaces is a tenth of the wait. The ceiling is the browser: at most
// ~6.7 flushes a second per kind, so even a saturated crawl cannot make the UI re-fetch faster than it
// can render. Windows below ~100ms stop coalescing anything useful (a fast crawl arrives in bursts
// tens of milliseconds apart); windows above ~250ms start being felt as lag on the intercept tab.
//
// # Why the producer side is atomics only
//
// The exchange signal is installed as a core.TrafficStore exchange observer, which runs *under the
// store's write lock on the capture path* — every proxied response and every crawler fetch waits
// behind it. So notify() is one atomic add and one non-blocking send on a size-1 channel: no lock, no
// allocation, no formatting, and no way for a subscriber to be in the path. Everything expensive —
// deciding who is listening, building frames, writing bytes — happens on the fan-out goroutine, off
// every producer's stack. See the contract on core.TrafficStore.ObserveExchanges, which this is the
// second consumer of.
//
// # Why a slow subscriber cannot block anything, and why nothing is dropped
//
// Each subscriber owns a pending set (a count per kind) and a size-1 signal channel. A flush ORs into
// the pending set under the hub's own mutex — microseconds, never a network write — and then tries the
// signal channel non-blockingly. A subscriber that has not drained its previous signal keeps the
// buffered token, and the token is only ever a "there is something pending" flag: the writer drains
// *all* pending on wake. So a stalled subscriber makes frames coarser, never fewer, and a dead one
// costs a fixed-size struct until its connection closes.
//
// That is deliberately not a lossy ring buffer with a drop counter. A frame says "refetch this kind",
// so merging two frames for the same kind loses nothing an extra refetch would have found — dropping
// the *last* one, on the other hand, leaves a pane silently stale for as long as nothing else changes,
// which is exactly the failure that makes a live-looking stream worse than a poll. What is counted
// instead is merges: how many times a subscriber was still behind when the next flush arrived, which
// is the same "this subscriber cannot keep up" signal without the staleness. /api/events/stats reports
// it alongside the frame and change totals.

// changeKind is what changed. Coarse on purpose: a kind is a hint that one endpoint is stale, and a
// finer set (an exchange id, a finding id) would only be finer than the client's refetch granularity —
// nothing consumes it, and it would have to be kept correct forever anyway.
type changeKind int

const (
	// changeHistory is an exchange captured: the history table, the site map, the header's byte and
	// exchange counts, and every dashboard count derived from traffic.
	changeHistory changeKind = iota
	// changeIssues is a finding added, deleted or cleared — passive, live-audit or an explicit audit.
	changeIssues
	// changeToolLog is a tool log entry: a request some tool in this process sent.
	changeToolLog
	// changeDashboard is an activity event: a task started or finished, the scope was edited, a live
	// audit was switched on, a crawl refused a link. Task *progress* has no hook of its own — it rides
	// on the traffic and the tool-log entries the task is producing, which is what a task that is
	// advancing at all necessarily produces. One fewer hook, on a pane that refetches on those kinds
	// anyway.
	changeDashboard
	// changeWS is a captured WebSocket frame.
	changeWS
	// changeIntercept is the held queue or the intercept switch. The one kind an operator is actively
	// waiting on, which is why the window is sized for it.
	changeIntercept
	// changeOrganizer is a saved item added, edited or removed.
	changeOrganizer
	// changeSession is a session-rule event: a rule was added or edited, or — the one an operator
	// is actively waiting on — a browser-recovery prompt became pending or was resolved. The
	// console refetches the pending-prompt list on it, which is how the modal appears and
	// dismisses without a poll.
	changeSession
	changeKindCount
)

// changeKindNames are the wire names, indexed by kind. An array rather than a switch so the wire name
// and the pending-set slot cannot disagree about which kind they mean.
var changeKindNames = [changeKindCount]string{
	changeHistory:   "history",
	changeIssues:    "issues",
	changeToolLog:   "toollog",
	changeDashboard: "dashboard",
	changeWS:        "ws",
	changeIntercept: "intercept",
	changeOrganizer: "organizer",
	changeSession:   "session",
}

func (k changeKind) String() string {
	if k < 0 || k >= changeKindCount {
		return "unknown change kind"
	}
	return changeKindNames[k]
}

// coalesceWindow is how long a flush waits after the first unannounced change. See the package note
// above for why 150ms rather than 10ms or 1s.
const coalesceWindow = 150 * time.Millisecond

// pingInterval is how often an idle stream emits a frame nobody asked for.
//
// Two reasons, both about intermediaries: a proxy or a load balancer will close a connection it
// believes is idle (commonly at 60s), and a client cannot tell a healthy quiet stream from a stream
// that died mid-flight without hearing something. 20s leaves a client watchdog room to miss two pings
// before declaring the stream dead, still inside the usual 60s idle bound.
const pingInterval = 20 * time.Second

// reconnectDelay is the retry hint handed to the browser's EventSource. Short enough that a restarted
// server is picked up while the operator is still looking at the tab, long enough that a server that
// is down does not turn into a reconnect storm.
const reconnectDelay = 3 * time.Second

// eventSub is one connected browser's slot.
type eventSub struct {
	// signal is a size-1 "you have pending changes" flag, never a queue of frames. The writer drains
	// the whole pending set on wake, so one token is enough however far behind the subscriber is.
	signal chan struct{}
	// pending and merges are guarded by eventHub.mu, not by the subscriber's own lock: they are only
	// ever touched by a flush (which holds it) and by take (which takes it), and a second lock would
	// buy nothing but an ordering to get wrong.
	pending [changeKindCount]uint64
	merges  uint64
}

// eventHub coalesces change notifications and fans them out to /api/events subscribers.
//
// The zero value is not usable; call newEventHub.
type eventHub struct {
	// changes counts unannounced changes per kind. Atomic rather than mutex-guarded because the
	// exchange producer runs under the traffic store's write lock — see the package note.
	changes [changeKindCount]atomic.Uint64
	// wake carries at most one "there is something to flush" token.
	wake chan struct{}

	mu     sync.Mutex
	subs   map[uint64]*eventSub
	nextID uint64
	// stop closes the fan-out goroutine, and is non-nil exactly while one is running. The goroutine
	// exists only while somebody is subscribed: a headless proxy run with no browser attached should
	// not have a timer-parked goroutine, and a test that never subscribes should not leak one.
	stop chan struct{}

	window time.Duration

	// Honest counting, all reported by /api/events/stats. frames is frames handed to subscribers,
	// announced is the underlying changes those frames stood for (so announced/frames is the coalescing
	// ratio actually achieved), merges is how many times a flush landed on a subscriber that had not
	// drained its previous one. Both totals are summed over subscribers, because the same change
	// announced to two browsers is two frames written — the ratio is per-stream either way.
	frames    atomic.Uint64
	announced atomic.Uint64
	merges    atomic.Uint64
}

func newEventHub() *eventHub {
	return &eventHub{
		wake:   make(chan struct{}, 1),
		subs:   make(map[uint64]*eventSub),
		window: coalesceWindow,
	}
}

// notify records that something of kind k changed.
//
// This is the only method producers call, and it is deliberately the cheapest thing that can carry the
// fact: one atomic add, one non-blocking send. It never blocks, never allocates, never takes a lock,
// and does not care whether anybody is listening — which is what makes it safe to call from under the
// traffic store's write lock on the capture path. Everything else happens on the fan-out goroutine.
func (h *eventHub) notify(k changeKind) {
	if h == nil || k < 0 || k >= changeKindCount {
		return
	}
	h.changes[k].Add(1)
	select {
	case h.wake <- struct{}{}:
	default:
		// A flush is already pending; this change will be included in it. That is the coalescing.
	}
}

// subscribe registers a new subscriber and returns it with the function that removes it. The caller
// must call that function when its connection ends — it is what keeps a reconnect from leaking a slot.
func (h *eventHub) subscribe() (*eventSub, func()) {
	sub := &eventSub{signal: make(chan struct{}, 1)}
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	h.subs[id] = sub
	if len(h.subs) == 1 {
		h.stop = make(chan struct{})
		go h.run(h.stop)
	}
	h.mu.Unlock()
	return sub, func() { h.unsubscribe(id) }
}

// unsubscribe removes a subscriber, stopping the fan-out goroutine with the last one. Calling it
// twice for the same subscriber is harmless, so a handler may both defer it and call it explicitly.
func (h *eventHub) unsubscribe(id uint64) {
	h.mu.Lock()
	delete(h.subs, id)
	if len(h.subs) == 0 && h.stop != nil {
		close(h.stop)
		h.stop = nil
	}
	h.mu.Unlock()
}

// run is the fan-out goroutine: the only place that decides who hears about what.
func (h *eventHub) run(stop chan struct{}) {
	// Flush once at the start, so whatever changed while nobody was watching is announced to the
	// browser that has just connected. Discarding the backlog instead would be a race with a real cost:
	// a change landing between the pane's own load and this goroutine starting would then be lost, and
	// the pane would sit silently stale until something else happened. One extra refetch of data the
	// client wants anyway is the cheaper mistake.
	select {
	case h.wake <- struct{}{}:
	default:
	}
	for {
		select {
		case <-stop:
			return
		case <-h.wake:
			// Trailing edge: wait out the window first, so the changes that arrive during it join this
			// flush instead of each earning their own. A stop during the wait wins — a browser that
			// closed its tab should not hold the goroutine open for another window.
			timer := time.NewTimer(h.window)
			select {
			case <-timer.C:
			case <-stop:
				timer.Stop()
				return
			}
			h.flush()
		}
	}
}

// flush claims every unannounced change and folds it into each subscriber's pending set.
//
// Claiming with Swap is what makes a change announced exactly once: a notify racing this flush either
// lands before the swap (announced now) or after it (announced by the next flush, which its own wake
// token guarantees will happen).
func (h *eventHub) flush() {
	var claimed [changeKindCount]uint64
	any := false
	for k := range claimed {
		claimed[k] = h.changes[k].Swap(0)
		if claimed[k] > 0 {
			any = true
		}
	}
	if !any {
		return
	}
	h.mu.Lock()
	for _, sub := range h.subs {
		for k := range claimed {
			if claimed[k] == 0 {
				continue
			}
			if sub.pending[k] > 0 {
				// Still behind from last time: this flush merges into the frame it has not taken yet.
				sub.merges++
				h.merges.Add(1)
			}
			sub.pending[k] += claimed[k]
		}
		select {
		case sub.signal <- struct{}{}:
		default:
			// Its token is already buffered, and the token means "drain everything pending" — so the
			// write it has not woken for yet will carry these changes too. Nothing is lost by not
			// signalling twice.
		}
	}
	h.mu.Unlock()
}

// take claims one subscriber's pending changes as frames to write, newest counts included. Returns
// nil when there is nothing pending, which happens when a flush landed between the subscriber's last
// take and the wake it was already holding a token for.
func (h *eventHub) take(sub *eventSub) []liveFrame {
	if h == nil || sub == nil {
		return nil
	}
	var out []liveFrame
	h.mu.Lock()
	for k := range sub.pending {
		if sub.pending[k] == 0 {
			continue
		}
		out = append(out, liveFrame{Kind: changeKind(k).String(), Changes: sub.pending[k]})
		h.announced.Add(sub.pending[k])
		sub.pending[k] = 0
	}
	h.mu.Unlock()
	h.frames.Add(uint64(len(out)))
	return out
}

// subscriberCount is how many streams are connected. Reported by /api/events/stats, and the assertion
// a disconnect test needs: a reconnect that leaked would show here.
func (h *eventHub) subscriberCount() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// fanoutRunning reports whether a fan-out goroutine is alive. Only the stats surface and the tests
// care: it is how "the last subscriber left" is observable without waiting on a goroutine dump.
func (h *eventHub) fanoutRunning() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stop != nil
}

// hubStats is the honest accounting of what the stream has done. See /api/events/stats.
type hubStats struct {
	Subscribers int    `json:"subscribers"`
	WindowMs    int64  `json:"window_ms"`
	Frames      uint64 `json:"frames"`
	Changes     uint64 `json:"changes"`
	Merges      uint64 `json:"merges"`
	Running     bool   `json:"fanout_running"`
	// Pending is what is currently owed to the slowest subscriber, per kind. Non-zero here for any
	// length of time means a client is not keeping up.
	Pending map[string]uint64 `json:"pending"`
}

func (h *eventHub) stats() hubStats {
	if h == nil {
		return hubStats{Pending: map[string]uint64{}}
	}
	out := hubStats{
		WindowMs: h.window.Milliseconds(),
		Frames:   h.frames.Load(),
		Changes:  h.announced.Load(),
		Merges:   h.merges.Load(),
		Pending:  map[string]uint64{},
	}
	h.mu.Lock()
	out.Subscribers = len(h.subs)
	out.Running = h.stop != nil
	for _, sub := range h.subs {
		for k := range sub.pending {
			if sub.pending[k] > out.Pending[changeKind(k).String()] {
				out.Pending[changeKind(k).String()] = sub.pending[k]
			}
		}
	}
	h.mu.Unlock()
	return out
}
