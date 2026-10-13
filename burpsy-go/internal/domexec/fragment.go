package domexec

// Rendering a response as a FRAGMENT, the way a page's own script does with a fetched answer.
//
// A large class of applications never let the browser load the endpoint that reflects input:
// the page fetches it (XHR/fetch) and assigns the body to an element's innerHTML. The response is
// often labelled text/plain, so nothing on the wire is "live markup", yet the page turns it into
// live markup. RenderFragment reproduces exactly that last step in isolation: an about:blank tab,
// every network request failed, the dialog functions replaced by recorders, and the fragment
// assigned to a div's innerHTML. It answers one question: when this text is inserted as HTML,
// which inline handlers run, and with what?
//
// It deliberately models innerHTML and nothing stronger. A <script> element inserted that way
// does not execute, which is the conservative reading: a page that inserts with jQuery's .html()
// would also run scripts, and missing that is a false negative, never a false positive.
//
// No request leaves the tab. The document is about:blank, and a Fetch-domain gate fails every
// request the fragment's elements try to make (an image, a stylesheet, a frame), so the target's
// markup cannot reach anything — the target included — and a resource element's error handler
// fires on the failure exactly as it would on a 404.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// FragmentCall is one call an inserted fragment's handlers made to a dialog function.
type FragmentCall struct {
	// Func is the dialog function called: alert, confirm, prompt or print; or "throw" for an
	// uncaught exception a handler raised, whose message is then in Args.
	Func string `json:"fn"`
	// Args is the call's arguments, each converted with String() and joined with a space. A tagged
	// template call (alert`x`) passes the strings array, whose String() is its text.
	Args string `json:"args"`
	// TargetID is the id of the element whose event was being dispatched when the call was made,
	// or "" when no event was in flight. It lets a payload whose handler takes no argument still
	// be tied to the element it injected.
	TargetID string `json:"target"`
	// Event is the type of that event (error, load, toggle, ...), or "".
	Event string `json:"event"`
}

// maxFragmentBytes bounds what one render inserts. A fragment endpoint that returns megabytes is
// not the shape this models, and the bound keeps one call's cost predictable.
const maxFragmentBytes = 1 << 20

// fragmentRecorderJS replaces the dialog functions with recorders. It runs before the fragment is
// inserted, in the page's main world, so every inline handler in the fragment sees the recorders.
const fragmentRecorderJS = `(() => {
  window.__burpsyFragment = [];
  const rec = (fn) => function () {
    try {
      const ev = window.event;
      const t = ev && ev.target;
      window.__burpsyFragment.push({
        fn: fn,
        args: Array.prototype.map.call(arguments, (a) => String(a)).join(" "),
        target: (t && typeof t.id === "string") ? t.id : (t && t.getAttribute ? (t.getAttribute("id") || "") : ""),
        event: (ev && ev.type) || "",
      });
    } catch (e) {}
  };
  // An inline handler that evaluates an undefined identifier throws, and the throw is reported
  // here: "zxss… is not defined" is the engine evaluating that name as code, which is execution
  // whether or not a dialog function was reached. Resource load failures are plain Events, not
  // ErrorEvents, and are not recorded.
  window.addEventListener("error", (e) => {
    try {
      if (!(e instanceof ErrorEvent)) return;
      window.__burpsyFragment.push({ fn: "throw", args: String(e.message || ""), target: "", event: "error" });
    } catch (x) {}
  }, true);
  window.alert = rec("alert");
  window.confirm = rec("confirm");
  window.prompt = rec("prompt");
  window.print = rec("print");
  return true;
})()`

// RenderFragment inserts fragment into an isolated, network-less about:blank document through
// innerHTML, waits settle for asynchronously dispatched events (an image's error, a details
// element's toggle), and returns every dialog-function call the inserted handlers made.
//
// A nil slice with a nil error means the fragment ran and called nothing. Any failure to drive
// the tab is an error, never an empty result: "nothing executed" and "could not look" are
// different facts.
func (b *Browser) RenderFragment(ctx context.Context, fragment string, settle time.Duration) ([]FragmentCall, error) {
	if len(fragment) > maxFragmentBytes {
		return nil, fmt.Errorf("domexec: fragment of %d bytes exceeds the %d-byte bound", len(fragment), maxFragmentBytes)
	}
	if settle <= 0 {
		settle = 750 * time.Millisecond
	}
	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Fail every request the tab makes. Paused at the request stage, so nothing is sent.
	chromedp.ListenTarget(tabCtx, func(ev any) {
		e, ok := ev.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		go func() {
			c := chromedp.FromContext(tabCtx)
			if c == nil || c.Target == nil {
				return
			}
			_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(cdp.WithExecutor(tabCtx, c.Target))
		}()
	})

	var installed bool
	var raw string
	err = chromedp.Run(tabCtx,
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}),
		chromedp.Navigate("about:blank"),
		chromedp.Evaluate(fragmentRecorderJS, &installed),
		chromedp.Evaluate(`(() => { const d = document.createElement("div"); document.body.appendChild(d); d.innerHTML = `+jsString(fragment)+`; return true; })()`, nil),
		chromedp.Sleep(settle),
		chromedp.Evaluate(`JSON.stringify(window.__burpsyFragment || null)`, &raw),
	)
	if err != nil {
		return nil, fmt.Errorf("domexec: render fragment: %w", err)
	}
	if !installed {
		return nil, errors.New("domexec: the dialog recorders were not installed")
	}
	if raw == "null" || raw == "" {
		return nil, errors.New("domexec: the recorder log was lost (the tab navigated away)")
	}
	var calls []FragmentCall
	if err := json.Unmarshal([]byte(raw), &calls); err != nil {
		return nil, fmt.Errorf("domexec: decode fragment calls: %w", err)
	}
	return calls, nil
}
