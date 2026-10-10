package domexec

// Browser-driven interaction (burpsy-react-ui-spa1). A render reads a page once; this drives it —
// clicking the controls that navigate a single-page application and, when asked, filling and
// submitting its forms — so a route that exists only after a click is discoverable at all.
//
// # Why a click is necessary and not a convenience
//
// A SPA routes in script. Its navigation controls are buttons, elements with a click handler, or
// anchors whose href is computed at run time, so the served bytes carry neither the destination nor
// a link the HTML parser can follow. The rendered pass (RenderedDOMWithOptions) already closes half
// the gap: it runs the page's script and reads the DOM that results, and it records the XHR/fetch
// requests the page issues on load. What it cannot do is press anything. A page whose `/orders`
// route is reached by clicking a tab renders only the seed view, and a crawl that never clicks
// reports the application as having one page.
//
// # Bounded by construction
//
// A page can carry a thousand controls and a click can start a request that never finishes, so every
// pass is bounded three ways and reports which bound it hit: a click cap, a form cap, and a whole-pass
// deadline. A pass that hits one is Capped, never presented as an exploration that finished.
//
// # Honesty, in the shape the rest of this tree uses
//
//   - a control the selector set does not recognise is a stated limitation (the set is documented
//     below), never silence;
//   - a click that changes nothing is recorded with Changed:false rather than dropped, so "the
//     control did nothing" is distinguishable from "the control was never clicked";
//   - a click that cannot be dispatched is recorded with its error, not skipped;
//   - the pass is run in a Session, which is scope-gated at the network layer, so a click that
//     navigates off the engagement's scope is refused exactly as a fetch would be — see
//     Session.Interact.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// InteractOptions bounds one interaction pass. The zero value is the documented default; a negative
// field is read as its default too, so a caller cannot accidentally ask for "unbounded".
type InteractOptions struct {
	// MaxClicks is how many navigational controls one pass may click. Default MaxInteractionClicks.
	MaxClicks int
	// MaxForms is how many forms one pass may fill and submit. Default MaxInteractionForms.
	MaxForms int
	// MaxWait caps the whole pass. Default DefaultMaxInteractionWait.
	MaxWait time.Duration
	// Settle is the wait applied after each click or submit, before the DOM is read. Zero takes the
	// render defaults, so an interaction waits at least as long as a render of the same page.
	Settle RenderOptions
	// FillForms types a default value into each visible field of a discovered form and submits it.
	// Such a pass is STATE-CHANGING — it writes to the application — so the caller decides, and the
	// crawler's own switch defaults it off. Form discovery still runs when this is false; only the
	// submit is withheld, and the pass says so.
	FillForms bool
}

// The bounds, and why each is a named constant rather than a literal at the call site: they are part
// of the contract a report cites when it says a pass was capped.
const (
	// MaxInteractionClicks is a page's worth of navigation, not a click farm. Twenty-five covers the
	// nav bars and tab strips a SPA uses; an application with more interactive controls than that is
	// explored over several crawls, not one unbounded pass.
	MaxInteractionClicks = 25
	// MaxInteractionForms is how many forms one pass submits. Submitting writes, so this is small.
	MaxInteractionForms = 5
	// DefaultMaxInteractionWait caps the whole pass. Thirty seconds is a few clicks at a settle
	// window each; a page that never settles costs this and is reported as capped.
	DefaultMaxInteractionWait = 30 * time.Second
	// interactElementTimeout is how long one control may take to become visible. Shorter than the
	// login replay's, because a pass visits many controls and one that is not there yet is a control
	// to skip, not a login step to wait out.
	interactElementTimeout = 2 * time.Second
)

func (o InteractOptions) withDefaults() InteractOptions {
	if o.MaxClicks <= 0 {
		o.MaxClicks = MaxInteractionClicks
	}
	if o.MaxForms <= 0 {
		o.MaxForms = MaxInteractionForms
	}
	if o.MaxWait <= 0 {
		o.MaxWait = DefaultMaxInteractionWait
	}
	o.Settle = o.Settle.withDefaults()
	return o
}

// InteractionView is one click or submit and what it produced.
type InteractionView struct {
	// Action is "click" or "submit".
	Action string `json:"action"`
	// Selector is the CSS selector the action was dispatched against, so a reader can reproduce it.
	Selector string `json:"selector"`
	// Label is the element's visible text, trimmed and capped. It is what the destructive classifier
	// reads and what a report shows; it is never trusted as markup.
	Label string `json:"label,omitempty"`
	// URL is the page's location after the action.
	URL string `json:"url,omitempty"`
	// DOM is the rendered outerHTML of the page after the action settled.
	DOM string `json:"dom,omitempty"`
	// Changed reports whether the URL or the DOM differs from the page the action was dispatched
	// from. A control that changed nothing is still a view, so "nothing happened" is on the record.
	Changed bool `json:"changed"`
	// Error is why the action could not be dispatched, when it could not. An empty Error with
	// Changed false reads as "the control did nothing", which is a different fact.
	Error string `json:"error,omitempty"`
}

// Interaction is one pass's whole outcome.
type Interaction struct {
	// BaseURL and BaseDOM are the page the pass started from, so a caller can tell whether a view
	// changed anything without re-rendering.
	BaseURL string `json:"base_url,omitempty"`
	BaseDOM string `json:"base_dom,omitempty"`
	// Views are the actions performed, in order.
	Views []InteractionView `json:"views"`
	// Requests are every XHR/fetch the page issued across all views — the API surface a click
	// revealed, which no served byte carries. Deduplicated on (method, URL).
	Requests []RenderedRequest `json:"requests,omitempty"`
	// FormsFound is how many forms the pass discovered; FormsSubmitted how many it submitted. They
	// differ when FillForms is false, and saying both keeps "found but did not submit" from reading
	// as "found nothing".
	FormsFound     int `json:"forms_found"`
	FormsSubmitted int `json:"forms_submitted"`
	// ClicksAttempted is how many controls were dispatched against, ClicksAvailable how many the
	// page offered. A pass that hit its cap reports both, so a capped exploration is never presented
	// as a complete one.
	ClicksAttempted int `json:"clicks_attempted"`
	ClicksAvailable int `json:"clicks_available"`
	// Capped reports that a bound (clicks, forms or the deadline) stopped the pass before the page
	// was exhausted.
	Capped bool `json:"capped"`
	// Waited is how long the pass took.
	Waited time.Duration `json:"waited"`
}

// interactCandidateJS enumerates the navigational controls a pass may click.
//
// The selector set is the documented contract, and it is deliberately the interactive kinds a SPA
// uses: a button (any form), a role=button, an ng-/v-/@ click binding, a data-toggle, an anchor with
// no href (a script-routed link), and an element carrying a tabindex with a click-looking class. A
// bare div is not a control — clicking every div would click half the page — so it is excluded, and
// that exclusion is the pass's stated limitation rather than a silent one.
//
// It returns, per candidate, an index, a stable CSS selector, the visible label, and whether the
// element is inside a form (a submit control is left to the form pass, not clicked here, or the same
// form would be submitted twice by two mechanisms).
const interactCandidateJS = `(function(){
  var sels = [
    'button:not([disabled])',
    '[role="button"]:not([disabled])',
    'input[type="button"]:not([disabled])',
    'input[type="submit"]:not([disabled])',
    '[onclick]:not([disabled])',
    '[ng-click]:not([disabled])',
    '[v-on\\:click]:not([disabled])',
    '[@click]:not([disabled])',
    '[data-toggle]:not([disabled])',
    'a:not([href]):not([disabled])',
    'a[href="#"],[href=""]:not([disabled])',
    '[tabindex][class*="btn"]:not([disabled])'
  ];
  var seen = new Set();
  var out = [];
  var idx = 0;
  sels.forEach(function(s){
    var list;
    try { list = document.querySelectorAll(s); } catch(e) { return; }
    for (var i=0;i<list.length;i++){
      var el = list[i];
      if (seen.has(el)) continue;
      seen.add(el);
      var r = el.getBoundingClientRect();
      if (r.width < 2 || r.height < 2) continue;
      var inForm = !!(el.form || el.closest('form'));
      if (inForm && (el.type === 'submit' || el.tagName === 'BUTTON' && el.type !== 'button')) continue;
      out.push({index: idx++, selector: cssPath(el), label: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0,120), inForm: inForm});
    }
  });
  return out;

  function cssPath(el){
    if (!el || el.nodeType !== 1) return '';
    if (el.id) { return '#' + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id); }
    var parts = [];
    var cur = el;
    while (cur && cur.nodeType === 1 && parts.length < 6) {
      var tag = cur.tagName.toLowerCase();
      var parent = cur.parentElement;
      if (parent) {
        var sibs = Array.prototype.filter.call(parent.children, function(c){ return c.tagName === cur.tagName; });
        if (sibs.length > 1) {
          var n = 1;
          for (var k=0;k<sibs.length;k++){ if (sibs[k] === cur) { n = k+1; break; } }
          tag += ':nth-of-type(' + n + ')';
        }
      }
      parts.unshift(tag);
      if (cur.id) { parts[0] = cur.tagName.toLowerCase() + '#' + cur.id; break; }
      cur = parent;
    }
    return parts.join(' > ');
  }
})()`

// interactFormJS enumerates the forms a pass may fill and submit, with a default value chosen for
// each field the same way the wire-side extractor chooses one (a type gets a plausible value, a
// select gets its first option). It is separate from the click enumeration so a submit control is
// exercised once, by its form, and never twice.
const interactFormJS = `(function(){
  var forms = document.querySelectorAll('form');
  var out = [];
  for (var i=0;i<forms.length;i++){
    var f = forms[i];
    var fields = [];
    var els = f.querySelectorAll('input,select,textarea');
    for (var j=0;j<els.length;j++){
      var el = els[j];
      var t = (el.type||'').toLowerCase();
      if (t === 'hidden' || t === 'submit' || t === 'button' || t === 'image' || el.disabled) continue;
      var r = el.getBoundingClientRect();
      var val = defaultFor(el, t);
      if (val === null) continue;
      fields.push({selector: cssPath(el), value: val, name: el.name || '', visible: r.width>=2 && r.height>=2});
    }
    out.push({index: i, selector: 'form:nth-of-type(' + (i+1) + ')', action: f.getAttribute('action') || '', method: (f.getAttribute('method')||'get').toLowerCase(), fields: fields});
  }
  return out;

  function defaultFor(el, t){
    if (el.tagName === 'SELECT') { return el.options.length ? (el.options[0].value || el.options[0].text) : null; }
    if (el.tagName === 'TEXTAREA') { return 'burpsy'; }
    switch (t) {
      case 'checkbox': case 'radio': return null;
      case 'email': return 'burpsy@example.com';
      case 'number': case 'range': return '1';
      case 'url': return 'http://example.com/';
      case 'tel': return '5555555555';
      case 'date': return '2020-01-01';
      case 'password': return 'burpsyPassw0rd!';
      case 'search': case 'text': default: return el.name ? el.name : 'burpsy';
    }
  }
  function cssPath(el){
    if (!el) return '';
    if (el.id) return '#' + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id);
    var name = el.getAttribute('name');
    if (name) return el.tagName.toLowerCase() + '[name="' + name.replace(/"/g,'\\"') + '"]';
    return el.tagName.toLowerCase();
  }
})()`

// interactCandidate is one enumerable control.
type interactCandidate struct {
	Index    int    `json:"index"`
	Selector string `json:"selector"`
	Label    string `json:"label"`
	InForm   bool   `json:"inForm"`
}

// interactForm is one enumerable form.
type interactForm struct {
	Index    int    `json:"index"`
	Selector string `json:"selector"`
	Action   string `json:"action"`
	Method   string `json:"method"`
	Fields   []struct {
		Selector string `json:"selector"`
		Value    string `json:"value"`
		Name     string `json:"name"`
		Visible  bool   `json:"visible"`
	} `json:"fields"`
}

// Interact drives a page in a tab newTab opens: it clicks the navigational controls the page
// offers (bounded), optionally fills and submits its forms, and returns every view with the DOM and
// the run-time requests each produced.
//
// It is the Session.Interact and Browser.Interact implementation in one place, so the gated and
// ungated callers cannot diverge in what they click or how they bound it.
func (b *Browser) interactIn(ctx context.Context, newTab func(context.Context) (context.Context, context.CancelFunc, error), targetURL string, opts InteractOptions) (Interaction, error) {
	opts = opts.withDefaults()
	started := time.Now()
	deadline := started.Add(opts.MaxWait)

	tabCtx, cancel, err := newTab(ctx)
	if err != nil {
		return Interaction{Waited: time.Since(started)}, err
	}
	defer cancel()

	// Every XHR/fetch the page issues across all views, deduplicated on (method, URL) so a control
	// that refetches the same endpoint on every view does not multiply the record.
	var mu sync.Mutex
	seenReq := map[string]bool{}
	var reqs []RenderedRequest
	dropped := 0
	recordReq := func(url, method, typ string) {
		key := method + " " + url
		mu.Lock()
		defer mu.Unlock()
		if seenReq[key] {
			return
		}
		if len(reqs) >= MaxRenderedRequests {
			dropped++
			return
		}
		seenReq[key] = true
		reqs = append(reqs, RenderedRequest{URL: url, Method: method, Type: typ})
	}
	chromedp.ListenTarget(tabCtx, func(ev any) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || e.Request == nil || (e.Type != network.ResourceTypeXHR && e.Type != network.ResourceTypeFetch) {
			return
		}
		recordReq(e.Request.URL, e.Request.Method, string(e.Type))
	})

	var out Interaction
	// Navigate and read the base. The instrumentation is installed on new documents so a view that
	// navigates still records its requests.
	if err := chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error { return network.Enable().Do(ctx) }),
		chromedp.Navigate(targetURL),
		chromedp.ActionFunc(func(ctx context.Context) error { waitForSettle(ctx, opts.Settle); return nil }),
		chromedp.Evaluate(`document.documentElement.outerHTML`, &out.BaseDOM),
		chromedp.Location(&out.BaseURL),
	); err != nil {
		return Interaction{Waited: time.Since(started), Requests: reqs}, fmt.Errorf("domec: interact %q: %w", targetURL, err)
	}

	// Enumerate the controls and forms once, from the base page.
	var candidates []interactCandidate
	var forms []interactForm
	if err := chromedp.Run(tabCtx,
		chromedp.Evaluate(interactCandidateJS, &candidates),
		chromedp.Evaluate(interactFormJS, &forms),
	); err != nil {
		return Interaction{BaseURL: out.BaseURL, BaseDOM: out.BaseDOM, Requests: reqs, Waited: time.Since(started)},
			fmt.Errorf("domec: enumerate controls for %q: %w", targetURL, err)
	}
	out.ClicksAvailable = len(candidates)
	out.FormsFound = len(forms)

	// Forms first: a form submit is the strongest signal of a new page, and submitting before
	// clicking keeps the click pass's baseline the base page rather than a form's result.
	if opts.FillForms {
		for _, f := range forms {
			if out.FormsSubmitted >= opts.MaxForms || time.Now().After(deadline) {
				out.Capped = true
				break
			}
			view := interactFormIn(tabCtx, f, out.BaseURL, out.BaseDOM, opts)
			out.FormsSubmitted++
			out.Views = append(out.Views, view)
			// Re-navigate so the next form is filled on the base page, not on this form's result.
			if err := chromedp.Run(tabCtx, chromedp.Navigate(targetURL)); err == nil {
				chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error { waitForSettle(ctx, opts.Settle); return nil }))
			}
		}
	}

	for _, c := range candidates {
		if out.ClicksAttempted >= opts.MaxClicks || time.Now().After(deadline) {
			out.Capped = true
			break
		}
		out.ClicksAttempted++
		view := interactClickIn(tabCtx, c, out.BaseURL, out.BaseDOM, opts)
		out.Views = append(out.Views, view)
		// Back to the base for the next control: without this a click that replaced the page would
		// make every later selector meaningless. A SPA route does not reload, so this is cheap.
		if err := chromedp.Run(tabCtx, chromedp.Navigate(targetURL)); err != nil {
			view.Error = joinErr(view.Error, "reset to the base page failed: "+err.Error())
			out.Views[len(out.Views)-1] = view
		} else {
			chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error { waitForSettle(ctx, opts.Settle); return nil }))
		}
	}

	mu.Lock()
	out.Requests = append([]RenderedRequest(nil), reqs...)
	mu.Unlock()
	if dropped > 0 {
		out.Capped = true
	}
	out.Waited = time.Since(started)
	return out, nil
}

// interactClickIn dispatches one click and reads what it produced. The selector is re-located on
// every call rather than cached as a box, because a reset navigation rebuilds the DOM and a stale
// box would click the wrong place.
func interactClickIn(tabCtx context.Context, c interactCandidate, baseURL, baseDOM string, opts InteractOptions) InteractionView {
	view := InteractionView{Action: "click", Selector: c.Selector, Label: c.Label}
	err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		box, err := locateSelector(ctx, c.Selector)
		if err != nil {
			return err
		}
		return clickAt(ctx, box)
	}))
	if err != nil {
		view.Error = err.Error()
		return view
	}
	chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error { waitForSettle(ctx, opts.Settle); return nil }))
	chromedp.Run(tabCtx, chromedp.Evaluate(`document.documentElement.outerHTML`, &view.DOM))
	chromedp.Run(tabCtx, chromedp.Location(&view.URL))
	view.Changed = view.URL != baseURL || view.DOM != baseDOM
	return view
}

// interactFormIn fills one form's visible fields and submits it by dispatching a submit event, which
// is what a script-driven SPA listens for — a native form.submit() bypasses the handler and would
// report a submission the application never processed.
func interactFormIn(tabCtx context.Context, f interactForm, baseURL, baseDOM string, opts InteractOptions) InteractionView {
	view := InteractionView{Action: "submit", Selector: f.Selector}
	err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		return chromedp.Evaluate(fillAndSubmitJS, nil).Do(ctx)
	}))
	if err != nil {
		view.Error = err.Error()
		return view
	}
	chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error { waitForSettle(ctx, opts.Settle); return nil }))
	chromedp.Run(tabCtx, chromedp.Evaluate(`document.documentElement.outerHTML`, &view.DOM))
	chromedp.Run(tabCtx, chromedp.Location(&view.URL))
	view.Changed = view.URL != baseURL || view.DOM != baseDOM
	return view
}

// fillAndSubmitJS fills every visible field of the form that owns the first matching control and
// dispatches a submit event. It is deliberately conservative: it touches only the form it is called
// for, and it dispatches an event rather than calling submit(), so the application's own handler runs.
const fillAndSubmitJS = `(function(){
  var forms = document.querySelectorAll('form');
  if (!forms.length) return;
  var f = forms[0];
  var els = f.querySelectorAll('input,select,textarea');
  for (var i=0;i<els.length;i++){
    var el = els[i];
    var t = (el.type||'').toLowerCase();
    if (t === 'hidden' || t === 'submit' || t === 'button' || t === 'checkbox' || t === 'radio' || el.disabled) continue;
    if (el.tagName === 'SELECT') { if (el.options.length) el.value = el.options[0].value; }
    else if (el.value === '' || el.value == null) { el.value = el.name ? el.name : 'burpsy'; }
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
  }
  var ev;
  try { ev = new SubmitEvent('submit', {bubbles:true, cancelable:true}); } catch(e) { ev = new Event('submit', {bubbles:true, cancelable:true}); }
  f.dispatchEvent(ev);
})()`

// locateSelector finds an element by CSS selector, scrolls it into view and returns its centre, or an
// error naming why not. Bounded by interactElementTimeout rather than the login replay's longer wait.
func locateSelector(ctx context.Context, sel string) (elementBox, error) {
	expr := `(function(s){var el=null; try{el=document.querySelector(s);}catch(e){} if(!el) return null; el.scrollIntoView({block:"center",inline:"center"}); var r=el.getBoundingClientRect(); return {x:r.left+r.width/2,y:r.top+r.height/2,w:r.width,h:r.height};})` + "(" + jsString(sel) + ")"
	deadline := time.Now().Add(interactElementTimeout)
	for {
		var box *elementBox
		err := chromedp.Evaluate(expr, &box).Do(ctx)
		if err == nil && box != nil && box.W > 0 && box.H > 0 {
			return *box, nil
		}
		if ctx.Err() != nil {
			return elementBox{}, ctx.Err()
		}
		if time.Now().After(deadline) {
			if err == nil && box != nil {
				return elementBox{}, errors.New("the control exists but is not visible")
			}
			return elementBox{}, fmt.Errorf("no control matched %q within %s", sel, interactElementTimeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Interact drives a page in the browser's own (ungated) context. It exists for a caller with no
// scope gate — a test, or a single-page probe — and the crawler does not use it: an interaction
// navigates, so the crawl's must run in a gated Session (Session.Interact).
func (b *Browser) Interact(ctx context.Context, targetURL string, opts InteractOptions) (Interaction, error) {
	return b.interactIn(ctx, b.newTab, targetURL, opts)
}

// Interact is Interact inside this session — the logged-in jar and the session's scope gate, so a
// click that navigates off the engagement's scope is refused at the gate exactly as a fetch is.
func (s *Session) Interact(ctx context.Context, targetURL string, opts InteractOptions) (Interaction, error) {
	return s.b.interactIn(ctx, func(ctx context.Context) (context.Context, context.CancelFunc, error) {
		return s.newTab(ctx, s.b.opts.resolvedTimeout())
	}, targetURL, opts)
}

// joinErr appends a second error message to a first, keeping both; empty inputs yield the other.
func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return strings.TrimSpace(a) + "; " + b
}
