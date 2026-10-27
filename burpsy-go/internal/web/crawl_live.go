package web

// The live crawl view (burpsy-react-ui-1l3x): Burp's "Live crawl view" — "a rendered view of the page
// that Burp Scanner is currently crawling" (desktop/running-scans/results/live-crawl-view.html).
//
// # What this can show, and what it says when it cannot
//
// burpsy's crawler fetches over HTTP; a browser is in the loop only for the render pass, and only when
// a -dom engine is configured. So the view is three things, each honest about its own absence:
//
//   - the request in flight right now (OnSend) and what the crawl is doing — fetching, rendering, or
//     logging in with a recorded login;
//   - the most recent fetches, newest first, as they complete (OnFetch);
//   - a frame: a viewport JPEG taken by the render pass inside the same tab that read the DOM,
//     throttled to one a second at the source. With no browser the frame is null and frame_note says
//     why — never a blank picture that reads as a blank page — and the console falls back to the last
//     HTML location's wire bytes, rendered with scripts and every network load disabled.
//
// No frame is taken while a recorded login replays: the login page is the operator's credentials
// being typed, and a live picture of it is a picture of a secret.
//
// One frame per run, dropped when the run finishes or is evicted, so a forgotten crawl costs a ring of
// fifty URLs and nothing else.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/dash"
)

// crawlLiveRecent is how many completed fetches the view keeps.
const crawlLiveRecent = 50

// crawlLiveFrameEvery is the source-side throttle on frames.
const crawlLiveFrameEvery = time.Second

// The phases a running crawl reports.
const (
	livePhaseStarting  = "starting"
	livePhaseLoggingIn = "logging-in"
	livePhaseFetching  = "fetching"
	livePhaseRendering = "rendering"
	// livePhaseAuditing is the rendered-DOM audit after the crawl's own loop: still the crawl's task,
	// no longer the crawl's pages.
	livePhaseAuditing = "rendered-audit"
	livePhaseFinished = "finished"
)

type liveFetch struct {
	At            time.Time       `json:"at"`
	Method        string          `json:"method"`
	URL           string          `json:"url"`
	Status        int             `json:"status"`
	Depth         int             `json:"depth"`
	ExchangeID    core.ExchangeID `json:"exchange_id"`
	FoundByRender bool            `json:"found_by_render,omitempty"`
}

type liveCurrent struct {
	Method string    `json:"method,omitempty"`
	URL    string    `json:"url"`
	Since  time.Time `json:"since"`
}

type crawlLiveFrame struct {
	URL        string    `json:"url"`
	CapturedAt time.Time `json:"captured_at"`
	// Image is a data: URL, so the console shows it as an <img> and never as markup.
	Image string `json:"image"`
}

// crawlLive is one crawl's live state.
type crawlLive struct {
	mu        sync.Mutex
	browser   bool
	phase     string
	current   *liveCurrent
	recent    []liveFetch // newest last; reversed on the wire
	fetched   int
	frame     *crawlLiveFrame
	lastFrame time.Time
	finished  bool
}

func newCrawlLive(browser bool) *crawlLive {
	return &crawlLive{browser: browser, phase: livePhaseStarting}
}

// onSend is crawler.Config.OnSend.
func (l *crawlLive) onSend(method, url string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.phase = livePhaseFetching
	l.current = &liveCurrent{Method: method, URL: url, Since: time.Now()}
}

// onFetch records one completed fetch.
func (l *crawlLive) onFetch(f crawler.Fetch) {
	l.mu.Lock()
	defer l.mu.Unlock()
	row := liveFetch{
		At: time.Now(), Method: f.Method, URL: f.URL, Status: f.Status, Depth: f.Depth,
		ExchangeID: f.ExchangeID, FoundByRender: f.FoundByRender,
	}
	l.fetched++
	if len(l.recent) >= crawlLiveRecent {
		l.recent = append(l.recent[:0], l.recent[1:]...)
	}
	l.recent = append(l.recent, row)
}

// rendering marks the render pass's page as the one being looked at, and says whether this render
// should bring back a frame — the throttle lives here, at the source, so a fast crawl does not encode
// a JPEG per page only for all but one a second to be thrown away.
func (l *crawlLive) rendering(url string) (wantFrame bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.phase = livePhaseRendering
	l.current = &liveCurrent{URL: url, Since: time.Now()}
	if l.finished || time.Since(l.lastFrame) < crawlLiveFrameEvery {
		return false
	}
	l.lastFrame = time.Now()
	return true
}

func (l *crawlLive) setFrame(url string, jpeg []byte) {
	if len(jpeg) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return
	}
	l.frame = &crawlLiveFrame{URL: url, CapturedAt: time.Now(), Image: "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(jpeg)}
}

func (l *crawlLive) loggingIn(label string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.phase = livePhaseLoggingIn
	l.current = &liveCurrent{URL: "recorded login: " + label, Since: time.Now()}
}

// auditing marks the post-crawl rendered-DOM audit, so the view does not keep showing the last page the
// crawl rendered as if the crawler were still on it.
func (l *crawlLive) auditing() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.phase = livePhaseAuditing
	l.current = nil
}

// finish drops the frame: frames are kept only while a crawl runs.
func (l *crawlLive) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.finished = true
	l.phase = livePhaseFinished
	l.current = nil
	l.frame = nil
}

// liveLogin wraps a crawl's BrowserLogin so the view says the crawl is logging in (it takes no frame),
// and so each replay is in the task's event log — Burp's RECORDED_SEQUENCE_STARTED / _ERROR events.
// taskID is set once the task exists, before the crawl goroutine starts.
type liveLogin struct {
	inner  crawler.BrowserLogin
	live   *crawlLive
	events *dash.EventLog
	taskID uint64
}

func (w *liveLogin) Label() string { return w.inner.Label() }

func (w *liveLogin) Login(ctx context.Context) crawler.LoginAttempt {
	w.live.loggingIn(w.inner.Label())
	w.events.RecordFor(w.taskID, dash.EventCrawlLogin, dash.SeverityInfo,
		fmt.Sprintf("recorded login %q started", w.inner.Label()))
	a := w.inner.Login(ctx)
	switch {
	case !a.Succeeded:
		w.events.RecordFor(w.taskID, dash.EventCrawlLogin, dash.SeverityWarn,
			fmt.Sprintf("recorded login %q failed: %s", w.inner.Label(), a.Reason))
	case a.Verified:
		w.events.RecordFor(w.taskID, dash.EventCrawlLogin, dash.SeverityInfo,
			fmt.Sprintf("recorded login %q logged in; the status check confirmed it", w.inner.Label()))
	default:
		w.events.RecordFor(w.taskID, dash.EventCrawlLogin, dash.SeverityWarn,
			fmt.Sprintf("recorded login %q ran every step, but it has no status check, so nothing confirmed the login took", w.inner.Label()))
	}
	return a
}

// ---- GET /api/crawl/live?task=N ----------------------------------------------------------------

type crawlLiveView struct {
	TaskID  uint64       `json:"task_id"`
	State   string       `json:"state"`
	Phase   string       `json:"phase"`
	Current *liveCurrent `json:"current"`
	Fetched int          `json:"fetched"`
	// Recent is newest first.
	Recent []liveFetch `json:"recent"`
	// Browser is whether this crawl has a browser to render with at all.
	Browser bool            `json:"browser"`
	Frame   *crawlLiveFrame `json:"frame"`
	// FrameNote says why Frame is null, so an absent picture is never read as a blank page.
	FrameNote string `json:"frame_note,omitempty"`
	// LastPage is the most recent HTML location fetched, for the console's wire-HTML preview.
	LastPage *liveFetch `json:"last_page"`
}

func (l *crawlLive) view(taskID uint64, state string) crawlLiveView {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := crawlLiveView{
		TaskID: taskID, State: state, Phase: l.phase, Fetched: l.fetched, Browser: l.browser,
		Recent: make([]liveFetch, 0, len(l.recent)),
	}
	for i := len(l.recent) - 1; i >= 0; i-- {
		v.Recent = append(v.Recent, l.recent[i])
	}
	if l.current != nil {
		c := *l.current
		v.Current = &c
	}
	if l.frame != nil {
		f := *l.frame
		v.Frame = &f
	}
	switch {
	case v.Frame != nil:
	case l.finished:
		v.FrameNote = "the crawl has finished; frames are kept only while it runs"
	case !l.browser:
		v.FrameNote = "no browser is configured (-dom), so this crawl fetches over HTTP and renders nothing; the preview below is the last page's wire HTML with scripts and every load disabled, not what a browser would show"
	case l.phase == livePhaseLoggingIn:
		v.FrameNote = "the crawl is replaying its recorded login; no frame is taken of a login page"
	default:
		v.FrameNote = "no page has been rendered yet"
	}
	return v
}

func (s *Server) handleCrawlLive(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.URL.Query().Get("task"), 10, 64)
	if err != nil {
		http.Error(w, "task must be a whole number", http.StatusBadRequest)
		return
	}
	run, ok := s.crawls.get(id)
	live := s.crawls.liveFor(id)
	if !ok || live == nil {
		http.Error(w, fmt.Sprintf("No crawl %d is retained", id), http.StatusNotFound)
		return
	}
	v := live.view(id, run.State)
	v.LastPage = s.lastHTMLPage(v.Recent)
	writeJSON(w, http.StatusOK, v)
}

// lastHTMLPage is the newest 2xx HTML fetch among recent, read from the store at poll time rather
// than on the crawl goroutine: the crawl pays nothing for a view nobody is watching.
func (s *Server) lastHTMLPage(recent []liveFetch) *liveFetch {
	for i := range recent {
		f := recent[i]
		if f.Status < 200 || f.Status >= 300 || s.store == nil {
			continue
		}
		ex, err := s.store.GetExchange(f.ExchangeID)
		if err != nil || ex.Response == nil {
			continue
		}
		msg, err := s.store.Get(*ex.Response)
		if err != nil {
			continue
		}
		if ct := strings.ToLower(string(msg.Header("Content-Type"))); strings.Contains(ct, "html") {
			return &f
		}
	}
	return nil
}

// ---- wiring ------------------------------------------------------------------------------------

func (c *crawlRuns) attachLive(taskID uint64, l *crawlLive) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live == nil {
		c.live = map[uint64]*crawlLive{}
	}
	if _, ok := c.byID[taskID]; ok {
		c.live[taskID] = l
	}
}

func (c *crawlRuns) liveFor(taskID uint64) *crawlLive {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.live[taskID]
}

// liveFetchHook is the OnFetch link that feeds the view, then hands the fetch on.
func (l *crawlLive) hook(next func(crawler.Fetch)) func(crawler.Fetch) {
	return func(f crawler.Fetch) {
		l.onFetch(f)
		if next != nil {
			next(f)
		}
	}
}
