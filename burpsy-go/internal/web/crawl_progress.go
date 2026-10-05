package web

import (
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/dash"
)

// crawlProgress advances a crawl's task row as the crawl fetches (burpsy-react-ui-hbjo).
//
// Burp computes a real crawl percentage (Zbcc.java:71-77); burpsy called task.Advance once, after Run
// returned, so the row read 0% for the whole crawl and then jumped to 100% — a long crawl looked
// exactly like a hung one. The crawler already announces every fetch that reaches the capture path
// (Config.OnFetch, built for the crawl→audit bridge), so the row is advanced there, one per fetch.
//
// Why one per fetch rather than a batch: a fetch is network-bound and Advance is a mutex and a slice
// lookup, so per-fetch is both the finest-grained and cheap. The denominator is the request budget
// the row was started with, which is the bound the crawl actually enforces.
type crawlProgress struct {
	// task is set once, by bind, before the crawl goroutine starts; atomic so a reader never needs to
	// reason about which goroutine wrote it.
	task     atomic.Pointer[dash.Handle]
	advanced atomic.Uint64
}

// hook returns the OnFetch the crawler is given: it advances the row and then hands the fetch to
// next (the audit feed's offer), or only advances when there is no audit half. OnFetch runs
// synchronously on the crawl goroutine, so this does the minimum and returns.
func (p *crawlProgress) hook(next func(crawler.Fetch)) func(crawler.Fetch) {
	return func(f crawler.Fetch) {
		if t := p.task.Load(); t != nil {
			t.Advance(1)
			p.advanced.Add(1)
		}
		if next != nil {
			next(f)
		}
	}
}

// bind attaches the task row the hook advances.
func (p *crawlProgress) bind(task *dash.Handle) { p.task.Store(task) }

// settle credits what the report counted and the hook never saw — so the final Done is the report's
// Fetched, never double-counted and never short.
func (p *crawlProgress) settle(fetched uint64) {
	t := p.task.Load()
	if t == nil {
		return
	}
	if seen := p.advanced.Load(); fetched > seen {
		t.Advance(fetched - seen)
	}
}
