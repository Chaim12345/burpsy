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
	"errors"
	"fmt"
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

	// Record the run-time requests too, so a caller can see the API call the submission made — the
	// second half of "this page posts the value and renders the reply".
	var reqs []RenderedRequest
	chromedp.ListenTarget(tabCtx, func(ev any) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || e.Request == nil || (e.Type != network.ResourceTypeXHR && e.Type != network.ResourceTypeFetch) {
			return
		}
		if len(reqs) < MaxRenderedRequests {
			reqs = append(reqs, RenderedRequest{URL: e.Request.URL, Method: e.Request.Method, Type: string(e.Type)})
		}
	})

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

	// Submit. Both branches end by dispatching a `submit` event on the form the input belongs to,
	// because that is the one activation every framework and every plain form agrees on: an
	// `onsubmit` handler runs, `event.preventDefault()` is honoured, and a script-driven SPA's own
	// handler sees it. A `button.click()` is NOT equivalent — measured against a fixture with a
	// `<button type=submit>` inside a form carrying `onsubmit`, the click fired no request at all,
	// while the submit event did.
	//
	// The SubmitSelector is still honoured as a way to find the form (a control outside the input's
	// own form, which some layouts use) and to confirm the control exists, so a caller naming a
	// selector that is not there gets an error rather than a silent submission of a different form.
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
