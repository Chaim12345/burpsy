package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- LIVE-01: the UI is told what changed, it does not ask ---------------------------------------
//
// Before this, the operator's only way to see a proxied request was a four-second poll or the Refresh
// button. These tests are written so they can only pass through the stream: they subscribe, change
// something through the same call the proxy or the scanner would use, and require the frame to arrive.
// Delete the wiring and every one of them fails with a timeout rather than quietly falling back to a
// poll — which is exactly how this project has shipped ported-but-unwired code twice before.
//
// The one that matters most is the stalled-subscriber test. The store's exchange observers run under
// its write lock on the capture path, so a subscriber that cannot keep up must not be able to slow a
// crawl or add latency to a proxied response. It asserts the capture path finishes *while* a subscriber
// is stalled, with a deadline, so a regression fails the test instead of hanging it.

// liveTestServer builds a server whose store the test can write to directly, which is how the proxy
// and the crawler write to it.
func liveTestServer() (*Server, *core.TrafficStore) {
	store := core.NewTrafficStore()
	return NewServer(store, core.NewScope()), store
}

// eventStream is a connected /api/events subscriber, parsed into frames on a channel so a test can
// wait for one with a deadline rather than blocking on a read that may never return.
type eventStream struct {
	frames chan liveFrame
	cancel context.CancelFunc
	body   io.Closer
}

func openEventStream(t *testing.T, baseURL string) *eventStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/events", nil)
	if err != nil {
		cancel()
		t.Fatalf("build stream request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("GET /api/events: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("GET /api/events: status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream — a browser's EventSource refuses anything else", got)
	}
	stream := &eventStream{frames: make(chan liveFrame, 64), cancel: cancel, body: resp.Body}
	go func() {
		defer close(stream.frames)
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if payload, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "data: "); ok {
				var frame liveFrame
				if json.Unmarshal([]byte(payload), &frame) == nil {
					stream.frames <- frame
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return stream
}

// next returns the next frame, failing the test if none arrives in time.
func (s *eventStream) next(t *testing.T, timeout time.Duration) liveFrame {
	t.Helper()
	select {
	case frame, ok := <-s.frames:
		if !ok {
			t.Fatalf("the stream closed while a frame was expected")
		}
		return frame
	case <-time.After(timeout):
		t.Fatalf("no frame within %s", timeout)
		return liveFrame{}
	}
}

func (s *eventStream) close() {
	s.cancel()
	s.body.Close()
}

// takeWithin drains one subscriber's frames until wantKind shows up, or fails at the deadline. Frames
// for other kinds are counted in, not treated as an error: a single flush can carry several kinds.
func takeWithin(t *testing.T, hub *eventHub, sub *eventSub, wantKind changeKind, timeout time.Duration) uint64 {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-sub.signal:
			for _, frame := range hub.take(sub) {
				if frame.Kind == wantKind.String() {
					return frame.Changes
				}
			}
		case <-deadline:
			t.Fatalf("no %q frame within %s", wantKind, timeout)
			return 0
		}
	}
}

func TestAStreamSubscriberIsToldWhenAnExchangeIsCaptured(t *testing.T) {
	s, store := liveTestServer()
	httpServer := httptest.NewServer(s.mux)
	defer httpServer.Close()

	stream := openEventStream(t, httpServer.URL)
	defer stream.close()

	// The hello frame is the client's proof that the stream really flows — a buffering intermediary can
	// let the headers through and swallow every frame after them, and the UI falls back to polling on
	// exactly this frame's absence.
	hello := stream.next(t, 5*time.Second)
	if hello.Kind != frameHello {
		t.Fatalf("first frame kind = %q, want %q", hello.Kind, frameHello)
	}
	if hello.WindowMs != coalesceWindow.Milliseconds() {
		t.Errorf("hello window_ms = %d, want %d — the client sizes its own throttle from this",
			hello.WindowMs, coalesceWindow.Milliseconds())
	}

	addTraffic(t, store, "live.test", "GET", "/one")

	frame := stream.next(t, 5*time.Second)
	if frame.Kind != changeHistory.String() {
		t.Fatalf("frame kind = %q, want %q", frame.Kind, changeHistory)
	}
	if frame.Changes != 1 {
		t.Errorf("frame changes = %d, want 1 — one capture is one change", frame.Changes)
	}
}

// A burst is the case that decides whether this is usable at all: a crawl appends hundreds of
// exchanges a second, and one frame each would spend the browser's render loop parsing frames it is
// about to supersede. Far fewer frames than changes, and not one change unaccounted for.
func TestABurstOfChangesArrivesAsFarFewerFramesThanChanges(t *testing.T) {
	s, _ := liveTestServer()
	sub, unsubscribe := s.live.subscribe()
	defer unsubscribe()

	const burst = 500
	for i := 0; i < burst; i++ {
		s.live.notify(changeHistory)
	}

	var frames int
	var changes uint64
	deadline := time.After(10 * time.Second)
	for changes < burst {
		select {
		case <-sub.signal:
			for _, frame := range s.live.take(sub) {
				frames++
				changes += frame.Changes
			}
		case <-deadline:
			t.Fatalf("only %d of %d changes announced, in %d frames", changes, burst, frames)
		}
	}
	if changes != burst {
		t.Errorf("announced %d changes, want exactly %d — coalescing must merge frames, never lose changes",
			changes, burst)
	}
	// The bound is deliberately loose: what is being asserted is the order of magnitude, not a frame
	// count that would turn scheduler jitter into a failing test. 500 changes inside one 150ms window
	// is normally one frame; anything under ten is still coalescing.
	if frames > 10 {
		t.Errorf("%d changes produced %d frames, want far fewer (window %s)", burst, frames, coalesceWindow)
	}
}

// The important one. The store runs its exchange observers under its own write lock, so if a subscriber
// could push back on the fan-out — or worse, if fan-out happened on the observer's stack — one slow
// browser would become the crawl's throughput ceiling and a per-response latency tax on the proxy.
func TestAStalledSubscriberBlocksNeitherTheCapturePathNorAnotherSubscriber(t *testing.T) {
	s, store := liveTestServer()

	// Subscribed and never read from: the dead-TCP-connection case.
	stalled, unsubscribeStalled := s.live.subscribe()
	defer unsubscribeStalled()
	reader, unsubscribeReader := s.live.subscribe()
	defer unsubscribeReader()

	const captures = 2000
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < captures; i++ {
			store.AddExchange(&core.Exchange{Host: "flood.test", Port: 80, Method: "GET", Path: "/p"})
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("the capture path did not finish %d exchanges while a subscriber was stalled — "+
			"the observer or the fan-out is blocking on a subscriber", captures)
	}

	if got := takeWithin(t, s.live, reader, changeHistory, 5*time.Second); got == 0 {
		t.Errorf("the live subscriber was told about 0 changes while another was stalled")
	}

	// And the stalled subscriber is owed those changes rather than having lost them: pending is what
	// merging preserves, and it is why there is no drop counter to report. A dropped last frame would
	// leave its pane stale with no later frame to correct it.
	if pending := s.live.stats().Pending[changeHistory.String()]; pending == 0 {
		t.Errorf("the stalled subscriber is owed 0 changes, so its frames were dropped rather than merged")
	}
	_ = stalled
}

func TestClosingTheStreamRemovesTheSubscriberAndStopsTheFanout(t *testing.T) {
	s, _ := liveTestServer()
	httpServer := httptest.NewServer(s.mux)
	defer httpServer.Close()

	for attempt := 0; attempt < 3; attempt++ {
		stream := openEventStream(t, httpServer.URL)
		if hello := stream.next(t, 5*time.Second); hello.Kind != frameHello {
			t.Fatalf("attempt %d: first frame kind = %q, want %q", attempt, hello.Kind, frameHello)
		}
		if got := s.live.subscriberCount(); got != 1 {
			t.Fatalf("attempt %d: subscribers = %d while one stream is connected, want 1", attempt, got)
		}
		stream.close()

		// A reconnect that leaked a slot or a goroutine would show up as a count that never returns to
		// zero — which, three attempts in, is what a per-reconnect leak looks like.
		waitFor(t, 5*time.Second, "the subscriber to be removed", func() bool {
			return s.live.subscriberCount() == 0
		})
		waitFor(t, 5*time.Second, "the fan-out goroutine to stop", func() bool {
			return !s.live.fanoutRunning()
		})
	}
}

// waitFor polls cond until it holds, failing with what it was waiting for at the deadline. Polling
// rather than a channel because the conditions here are observed state, not a signal.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// Every producer of change is wired, and each announces its own kind. One table rather than seven
// tests, because the failure this guards against is a source nobody connected — and a table is the
// shape that makes the missing row obvious.
func TestEveryChangeSourceAnnouncesItsOwnKind(t *testing.T) {
	s, store := liveTestServer()
	engine := intercept.NewEngine()
	s.WithIntercept(engine)
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("arm the intercept request list: %v", err)
	}
	exchange := addTraffic(t, store, "ws.test", "GET", "/socket")

	// Subscribed after the arming above, so the table starts from silence.
	sub, unsubscribe := s.live.subscribe()
	defer unsubscribe()

	cases := []struct {
		name   string
		want   changeKind
		change func()
	}{
		{"an exchange captured", changeHistory, func() {
			addTraffic(t, store, "live.test", "GET", "/one")
		}},
		{"a finding added", changeIssues, func() {
			s.findings.Add(core.NewFinding{Name: "passive finding"})
		}},
		{"a tool log entry", changeToolLog, func() {
			s.toolLog.Record(toollog.ToolRepeater, "live.test", 80, false, "GET", "/one", 200, toollog.Bytes(42), 3, "")
		}},
		{"an activity event", changeDashboard, func() {
			s.events.Record(dash.EventScopeChanged, dash.SeverityInfo, "scope edited")
		}},
		{"a websocket frame", changeWS, func() {
			addWsMessage(store, exchange.ID, true, core.WsOpcodeText, "hello", 1000)
		}},
		{"a held message", changeIntercept, func() {
			if held := engine.Hold(&intercept.Message{
				Direction: intercept.DirectionRequest, Host: "live.test", Port: 80,
				Method: "GET", Path: "/held", Raw: []byte("GET /held HTTP/1.1\r\n\r\n"),
			}); held == nil {
				t.Fatalf("the armed engine held nothing, so there is no queue change to announce")
			}
		}},
		{"an organizer save", changeOrganizer, func() {
			rec := postJSON(t, s, "/api/tools/organizer", map[string]int{"exchange": 1})
			if rec.Code != http.StatusOK {
				t.Fatalf("POST /api/tools/organizer: status = %d (%s)", rec.Code, rec.Body.String())
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			if got := takeWithin(t, s.live, sub, tc.want, 5*time.Second); got == 0 {
				t.Errorf("%s announced 0 changes of kind %q", tc.name, tc.want)
			}
		})
	}
}

// notify is called from under the traffic store's write lock, on the path of every proxied response.
// An allocation there is a per-request tax and a garbage source at crawl rates, so this is a guard
// against the natural future edit — formatting a message, building a struct — rather than a behaviour
// test.
func TestNotifyingDoesNotAllocate(t *testing.T) {
	hub := newEventHub()
	if got := testing.AllocsPerRun(1000, func() { hub.notify(changeHistory) }); got != 0 {
		t.Errorf("notify allocates %.1f times per call, want 0 — it runs under the store's write lock", got)
	}
}

func TestEventStatsReportSubscribersAndWhatWasAnnounced(t *testing.T) {
	s, store := liveTestServer()
	httpServer := httptest.NewServer(s.mux)
	defer httpServer.Close()

	stream := openEventStream(t, httpServer.URL)
	defer stream.close()
	stream.next(t, 5*time.Second) // hello

	for i := 0; i < 3; i++ {
		addTraffic(t, store, "live.test", "GET", "/one")
	}
	if frame := stream.next(t, 5*time.Second); frame.Kind != changeHistory.String() {
		t.Fatalf("frame kind = %q, want %q", frame.Kind, changeHistory)
	}

	rec := get(t, s, "/api/events/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/events/stats: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var stats hubStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats %q: %v", rec.Body.String(), err)
	}
	if stats.Subscribers != 1 {
		t.Errorf("subscribers = %d, want 1", stats.Subscribers)
	}
	if !stats.Running {
		t.Errorf("fanout_running = false while a subscriber is connected")
	}
	if stats.WindowMs != coalesceWindow.Milliseconds() {
		t.Errorf("window_ms = %d, want %d", stats.WindowMs, coalesceWindow.Milliseconds())
	}
	if stats.Frames == 0 || stats.Changes < 3 {
		t.Errorf("frames = %d, changes = %d, want at least 1 frame standing for at least the 3 captures — "+
			"a stream that has stopped pushing must not look like a quiet system", stats.Frames, stats.Changes)
	}
}
