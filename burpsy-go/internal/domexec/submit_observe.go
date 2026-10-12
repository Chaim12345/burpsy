package domexec

// Form-driven taint observation: type a canary into a page's own input, submit its own form, and
// report whether the page's script then fed the canary to a dangerous sink.
//
// # Why this is separate from ObserveTaint
//
// ObserveTaint plants the canary in a URL-borne source (location.hash, the query, the Referer) and
// loads the page. That answers "does this page's script route a URL-controlled value into a sink".
// It cannot answer the case this exists for: a page whose INPUT the user types into, whose script
// then sends it to an API and writes the response into the document with innerHTML. The canary never
// appears in the URL, so a source-planting harness has nothing to plant, and the API response that
// carries the payload back says text/plain — which is why the server-side reflected-XSS check
// correctly reports nothing while the page is genuinely exploitable. The only way to see it is to be
// the user: type, submit, and watch the sink.
//
// # What it is not
//
// It does not decide exploitability. It reports the sink calls whose argument carried the canary,
// exactly as ObserveTaint does, and the caller decides what that means for its row. A page that
// writes the canary into innerHTML as escaped text is not observed (the wrapper records the argument
// as given, and the caller compares against the markup it sent).

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// FormSubmitSpec describes the interaction: a page to load, an input to type into, and a control to
// submit with. Selectors are CSS; Submit may be empty, in which case the form is submitted by
// dispatching a submit event on the input's own form (the shape a script-driven SPA listens for).
type FormSubmitSpec struct {
	// PageURL is the document to load. It is the application's own page, so the script under test
	// is the one that runs.
	PageURL string
	// InputSelector locates the field to type into.
	InputSelector string
	// SubmitSelector locates the control to click. Empty dispatches a submit event instead.
	SubmitSelector string
	// ClickTrigger, when true, activates SubmitSelector with a plain click instead of dispatching a
	// submit event on its form. Some pages wire a control's own click handler rather than the form's
	// submit event (OWASP VulnerableApp's XSS levels do), and a submit event never reaches that
	// handler, while the click does.
	ClickTrigger bool
	// Payload is the text typed into the field.
	Payload string
	// Settle is how long to wait after submitting. Zero takes the render default.
	Settle RenderOptions
}

// SubmitAndObserve types spec.Payload into spec.InputSelector on spec.PageURL, submits, and returns
// every sink call whose argument carried canary — the same shape ObserveTaint returns, so a caller
// reasons about both identically.
//
// It reports an error only when the interaction could not be performed (no such input, no such
// submit control, a navigation failure). Zero observations with no error means the page ran and did
// not feed the canary to a sink; that is a result, not a failure.
func (b *Browser) SubmitAndObserve(ctx context.Context, spec FormSubmitSpec, canary string) ([]Observation, error) {
	if canary == "" {
		return nil, errors.New("domexec: canary must not be empty")
	}
	if spec.PageURL == "" || spec.InputSelector == "" {
		return nil, errors.New("domexec: SubmitAndObserve needs a page URL and an input selector")
	}
	opts := spec.Settle.withDefaults()

	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// The instrumentation must be installed before the page's own script runs, so it is added as a
	// new-document script — the same mechanism ObserveTaint uses.
	if err := chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error { return network.Enable().Do(ctx) }),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentationJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(spec.PageURL),
		chromedp.ActionFunc(func(ctx context.Context) error { waitForSettle(ctx, opts); return nil }),
	); err != nil {
		return nil, fmt.Errorf("domexec: load %q: %w", spec.PageURL, err)
	}
	obs, _, err := submitAndObserveIn(tabCtx, spec, canary)
	return obs, err
}

// SentRequest is one request the page sent while it was being driven, as the browser reported it.
// Body is the request body when the browser exposed it (it may omit a large one).
type SentRequest struct {
	Method string
	URL    string
	Body   string
}

// requestRecorder collects the requests a tab sends whose URL or body carries a token. It exists so a
// caller can tell WHICH request a typed value travelled in: a sink fed by the page's own script says
// that the page is exploitable, but only the request that carried the value says which endpoint and
// which parameter the exploit went through.
type requestRecorder struct {
	mu     sync.Mutex
	token  string
	open   bool
	report []SentRequest
}

func recordRequests(tabCtx context.Context, token string) *requestRecorder {
	rec := &requestRecorder{token: token, open: true}
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || e.Request == nil {
			return
		}
		body := ""
		for _, entry := range e.Request.PostDataEntries {
			if entry == nil {
				continue
			}
			if b, err := base64.StdEncoding.DecodeString(entry.Bytes); err == nil {
				body += string(b)
			} else {
				body += entry.Bytes
			}
		}
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if !rec.open || (!strings.Contains(e.Request.URL, rec.token) && !strings.Contains(body, rec.token)) {
			return
		}
		rec.report = append(rec.report, SentRequest{Method: e.Request.Method, URL: e.Request.URL, Body: body})
	})
	return rec
}

// close stops recording and returns what was recorded. A listener cannot be removed from a tab, so
// it is closed instead; later events are ignored.
func (r *requestRecorder) close() []SentRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.open = false
	return append([]SentRequest(nil), r.report...)
}

// submitAndObserveIn is the interaction half, against a tab already parked on the view. Split out so
// a SPA caller can navigate first (NavigateSPA) and then drive the reached view, and so the two
// failure modes — "never reached the form" and "the form fed no sink" — stay distinguishable.
//
// It also returns the requests the page sent, during the interaction, that carried the canary in their
// URL or body; see requestRecorder.
func submitAndObserveIn(tabCtx context.Context, spec FormSubmitSpec, canary string) ([]Observation, []SentRequest, error) {
	opts := spec.Settle.withDefaults()
	rec := recordRequests(tabCtx, canary)
	obs, err := driveAndObserve(tabCtx, spec, canary, opts)
	sent := rec.close()
	if err != nil {
		return nil, nil, err
	}
	return obs, sent, nil
}

func driveAndObserve(tabCtx context.Context, spec FormSubmitSpec, canary string, opts RenderOptions) ([]Observation, error) {
	// Type the payload the way a user would: set the value and fire the events a framework listens
	// for. Setting .value alone leaves a React/Vue-controlled input unchanged, because their own
	// state never sees the edit.
	typeJS := fmt.Sprintf(`(function(){
		var el = document.querySelector(%s);
		if (!el) return false;
		el.focus();
		el.value = %s;
		el.dispatchEvent(new Event('input', {bubbles:true}));
		el.dispatchEvent(new Event('change', {bubbles:true}));
		return true;
	})()`, jsString(spec.InputSelector), jsString(spec.Payload))
	var typed bool
	if err := chromedp.Run(tabCtx, chromedp.Evaluate(typeJS, &typed)); err != nil {
		return nil, fmt.Errorf("domexec: type into %q: %w", spec.InputSelector, err)
	}
	if !typed {
		return nil, fmt.Errorf("domexec: no input matched %q on %s", spec.InputSelector, spec.PageURL)
	}

	// Submit. The default path dispatches a `submit` event on the form the input belongs to, because
	// that is what every framework and every plain form agrees on. A `button.click()` is NOT
	// equivalent for a form: measured against a fixture with a `<button type=submit>` inside a form,
	// the click fired no request while the submit event did.
	//
	// ClickTrigger exists for the opposite page: one that wires the CONTROL's own click handler and
	// never listens for a form submit at all (OWASP VulnerableApp's XSS levels call an AJAX function
	// from the button's click listener). There the submit event reaches nothing and only the click
	// works. The caller says which shape its page has; neither is guessed, because guessing wrong
	// produces zero observations that look identical to a page with no vulnerability.
	if spec.ClickTrigger {
		clickJS := fmt.Sprintf(`(function(){
			var el = document.querySelector(%s);
			if (!el) return false;
			el.click();
			return true;
		})()`, jsString(spec.SubmitSelector))
		var clicked bool
		if err := chromedp.Run(tabCtx, chromedp.Evaluate(clickJS, &clicked)); err != nil {
			return nil, fmt.Errorf("domexec: click %q: %w", spec.SubmitSelector, err)
		}
		if !clicked {
			return nil, fmt.Errorf("domexec: no control matched %q on %s", spec.SubmitSelector, spec.PageURL)
		}
	} else {
		submitJS := fmt.Sprintf(`(function(){
			var el = document.querySelector(%s);
			if (!el) return false;
			var form = el.form;
			if (!form && %s) {
				var ctl = document.querySelector(%s);
				if (!ctl) return false;
				form = ctl.form || (ctl.closest ? ctl.closest('form') : null);
			}
			if (!form) return false;
			var ev;
			try { ev = new SubmitEvent('submit', {bubbles:true, cancelable:true}); }
			catch(e) { ev = new Event('submit', {bubbles:true, cancelable:true}); }
			form.dispatchEvent(ev);
			return true;
		})()`,
			jsString(spec.InputSelector),
			boolJS(spec.SubmitSelector != ""),
			jsString(spec.SubmitSelector))
		var submitted bool
		if err := chromedp.Run(tabCtx, chromedp.Evaluate(submitJS, &submitted)); err != nil {
			return nil, fmt.Errorf("domexec: submit the form owning %q: %w", spec.InputSelector, err)
		}
		if !submitted {
			return nil, fmt.Errorf("domexec: %q is not inside a form on %s", spec.InputSelector, spec.PageURL)
		}
	}

	// Wait for the page to finish reacting: the submission is asynchronous (an XHR, then a render).
	//
	// The wait is a POLL for the canary to appear in the document, bounded by MaxWait, rather than a
	// settle window. Settle can end in the gap between the fetch resolving and the .then() writing the
	// reply — the DOM is quiet exactly then — and a read there observes nothing, which is
	// indistinguishable from a page that never reacted. Waiting for the value to show up and only
	// then reading the taint is what makes "no observations" mean the page did not render the value.
	deadline := time.Now().Add(opts.MaxWait)
	for {
		var landed bool
		if err := chromedp.Run(tabCtx, chromedp.Evaluate(
			`document.documentElement.outerHTML.indexOf(`+jsString(canary)+`) !== -1`, &landed)); err == nil && landed {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// One more settle so a multi-step render (write, then a second update) is complete before the
	// taint dump.
	chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		waitForSettle(ctx, opts)
		return nil
	}))

	var raw string
	if err := chromedp.Run(tabCtx, chromedp.Evaluate(`JSON.stringify(window.__burpsyTaint || [])`, &raw)); err != nil {
		return nil, fmt.Errorf("domexec: read observations: %w", err)
	}
	// The source is not planted, so the decode uses SourceLocationHash purely as a label; the caller
	// reads Observation.Sink and Observation.Argument, which are what carry the meaning here.
	return decodeObservations(raw, SourceLocationHash, []string{canary})
}

// boolJS renders a Go bool as a JavaScript literal, for a condition spliced into an expression.
func boolJS(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
