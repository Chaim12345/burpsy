package crawler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The dashboard's "Pause all tasks" has to reach the crawl loop (burpsy-react-ui-cijs).
//
// dash.Registry.GateCheck had exactly one caller in the whole tree — the sequencer's capture loop —
// so pressing the button flipped the banner, the button and /api/dashboard's `paused` while a long
// crawl carried on fetching at the same rate. "A long crawl" is the example the pause feature's own
// commit message uses to motivate it, and it was the case that did not work.
func TestTheCrawlLoopAsksTheSuiteGate(t *testing.T) {
	pages := map[string]string{
		"/":      `<html><body><a href="/alpha">Alpha</a><a href="/beta">Beta</a></body></html>`,
		"/alpha": `<html><body><a href="/gamma">Gamma</a></body></html>`,
		"/beta":  `<html><body><p>beta</p></body></html>`,
		"/gamma": `<html><body><p>gamma</p></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()

	c, err := New(h.config(tg.URL + "/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var calls atomic.Int64
	c.WithSuiteGate(func(context.Context) { calls.Add(1) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep := c.Run(ctx)

	if rep.Fetched == 0 {
		t.Fatal("setup: the crawl fetched nothing, so reaching the gate would prove nothing")
	}
	if calls.Load() == 0 {
		t.Fatal("the crawl loop never called the suite gate, so Pause all tasks cannot hold it")
	}
	// Once per turn of the loop, so the gate is a real hold point rather than a single check at
	// the start that a long crawl would run straight past.
	if calls.Load() < int64(rep.Fetched) {
		t.Errorf("gate called %d times for %d fetches; it must be asked between fetches, not once",
			calls.Load(), rep.Fetched)
	}
}

// A held gate actually stops the crawl: the fetch count must not advance while it is holding.
func TestAHeldSuiteGateStopsTheCrawlFetching(t *testing.T) {
	pages := map[string]string{
		"/":      `<html><body><a href="/alpha">Alpha</a><a href="/beta">Beta</a></body></html>`,
		"/alpha": `<html><body><a href="/gamma">Gamma</a></body></html>`,
		"/beta":  `<html><body><a href="/delta">Delta</a></body></html>`,
		"/gamma": `<html><body><p>gamma</p></body></html>`,
		"/delta": `<html><body><p>delta</p></body></html>`,
	}
	tg := newTarget(t, pages)
	h := newHarness()

	c, err := New(h.config(tg.URL + "/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	release := make(chan struct{})
	var calls atomic.Int64
	c.WithSuiteGate(func(context.Context) {
		if calls.Add(1) == 2 {
			<-release
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan Report, 1)
	go func() { done <- c.Run(ctx) }()

	// Wait until the gate is holding, then give an unheld crawl ample time to get ahead.
	deadline := time.After(5 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("the gate was never reached twice; the loop is not calling it between fetches")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond)

	select {
	case rep := <-done:
		t.Fatalf("the crawl finished (%d fetched) while the suite gate was held", rep.Fetched)
	default:
	}

	close(release)
	rep := <-done
	if rep.Fetched == 0 {
		t.Error("releasing the gate did not let the crawl proceed")
	}
}

// Nil is every caller that is not the web layer — the CLI, the MCP surface, every other test in
// this package. They must keep their current behaviour exactly.
func TestACrawlWithNoSuiteGateIsUnaffected(t *testing.T) {
	tg := newTarget(t, map[string]string{"/": `<html><body><a href="/alpha">Alpha</a></body></html>`, "/alpha": `<html><body><p>a</p></body></html>`})
	h := newHarness()
	if rep := run(t, h.config(tg.URL+"/")); rep.Fetched == 0 {
		t.Error("a crawl with no gate fetched nothing")
	}
}
