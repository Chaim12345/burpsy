package domexec

// Driving a single-page application's own navigation to reach the view under test.
//
// # Why a page URL is not enough
//
// A SPA serves ONE document for every route: the level URL a benchmark records (for example
// /VulnerableApp/XSSWithHtmlTagInjection/LEVEL_1) is answered with JSON, and the HTML the user
// actually types into is a template the SPA fetches only after it has built its navigation tree and
// been clicked through to that level. So loading the level URL in a browser renders the API answer,
// not a form, and a harness that only knows a URL cannot reach the page whose script it wants to
// observe. Measured against OWASP VulnerableApp: the level URL has no input element, while clicking
// its master item and then the level renders one.
//
// # What this does
//
// Load the application root, wait for the SPA to build its tree, click the navigation entry whose
// text contains a given label, then click the level entry whose text contains a given label, and
// wait for a selector to appear — the view is ready when the element the caller means to drive
// exists. Every step is a bounded poll that reports which step failed, so a page that never rendered
// its tree says so by name rather than returning an empty result that reads as "no vulnerability".

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// SPARoute describes a click path through a SPA's own navigation.
type SPARoute struct {
	// RootURL is the application root whose script builds the navigation.
	RootURL string
	// MasterSelector is the container of top-level entries; each is matched by its text.
	MasterSelector string
	// MasterText is the label of the top-level entry to click (substring match).
	MasterText string
	// LevelSelector is the container of second-level entries, present after the master click.
	LevelSelector string
	// LevelText is the label of the level entry to click (substring match), e.g. "LEVEL_3".
	LevelText string
	// ReadySelector is the element that proves the view is rendered, e.g. "#textInput".
	ReadySelector string
	// StepTimeout bounds each click's wait for its target. Zero takes a default.
	StepTimeout time.Duration
}

const defaultSPAStepTimeout = 15 * time.Second

// NavigateSPA loads route.RootURL and clicks through its navigation, returning a tab context parked
// on the reached view. The caller closes the tab with the returned cancel.
//
// It is separate from SubmitAndObserve because reaching the view and driving it are different
// failures: "the navigation did not reach the form" and "the form did not feed the sink" must be
// distinguishable, and a caller that saw only zero observations could not tell them apart.
func (b *Browser) NavigateSPA(ctx context.Context, route SPARoute) (context.Context, context.CancelFunc, error) {
	if route.RootURL == "" || route.MasterText == "" || route.ReadySelector == "" {
		return nil, nil, fmt.Errorf("domexec: NavigateSPA needs a root URL, a master label and a ready selector")
	}
	step := route.StepTimeout
	if step <= 0 {
		step = defaultSPAStepTimeout
	}
	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			cancel()
		}
	}()

	if err := chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error { return network.Enable().Do(ctx) }),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentationJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(route.RootURL),
	); err != nil {
		return nil, nil, fmt.Errorf("domexec: load %q: %w", route.RootURL, err)
	}

	// The SPA builds its tree from an XHR after load, so the first wait is for the master entries to
	// exist at all.
	if err := waitForSelector(tabCtx, route.MasterSelector, step); err != nil {
		return nil, nil, fmt.Errorf("domexec: the SPA never rendered %q on %s: %w", route.MasterSelector, route.RootURL, err)
	}
	if route.LevelSelector != "" && route.LevelText != "" {
		// The level list is REBUILT on each master click, and the PREVIOUS master's list is still in
		// the DOM while the new one loads — and on a page whose first master is auto-selected there is
		// always a list there from the start. So waiting for an entry carrying the level label can
		// pass instantly against the wrong family's list (measured: LEVEL_1 exists under master 0
		// before any click), and the click then selects a level of a family the caller never asked
		// for. The discriminator is that the list CHANGED: capture its signature before the master
		// click and wait for it to differ, which is what a rebuilt list does and a stale one does not.
		before := listSignature(tabCtx, route.LevelSelector)
		if err := clickByText(tabCtx, route.MasterSelector, route.MasterText, step); err != nil {
			return nil, nil, fmt.Errorf("domexec: no navigation entry matching %q: %w", route.MasterText, err)
		}
		if err := waitForListChange(tabCtx, route.LevelSelector, before, step); err != nil {
			return nil, nil, fmt.Errorf("domexec: the level list did not change after clicking %q: %w",
				route.MasterText, err)
		}
		// The list changing means the columns were REBUILT, but their click listeners are attached in
		// the same loop that builds them and the SPA auto-clicks the first one — so a click that lands
		// before that loop finishes hits an element with no handler and does nothing. A short settle
		// after the rebuild, then the text wait, is what makes the click land on a bound element.
		chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			waitForSettle(ctx, RenderOptions{}.withDefaults())
			return nil
		}))
		if err := waitForText(tabCtx, route.LevelSelector, route.LevelText, step); err != nil {
			return nil, nil, fmt.Errorf("domexec: no level entry matching %q appeared after clicking %q: %w",
				route.LevelText, route.MasterText, err)
		}
		if err := clickByText(tabCtx, route.LevelSelector, route.LevelText, step); err != nil {
			return nil, nil, fmt.Errorf("domexec: no level entry matching %q: %w", route.LevelText, err)
		}
	}
	// The view is ready when the element the caller means to drive EXISTS. Visibility is deliberately
	// not required: the SPA's detail pane is hidden by a CSS class until the operator opens it, and
	// its contents — the input the caller wants to type into — are present and drivable while the pane
	// is still collapsed. Requiring a box made NavigateSPA reject a view whose input was right there.
	// A selector that matches nothing at all still fails, which is the case worth reporting.
	if err := waitForSelector(tabCtx, route.ReadySelector, step); err != nil {
		return nil, nil, fmt.Errorf("domexec: %q never appeared on the view reached by %q/%q: %w",
			route.ReadySelector, route.MasterText, route.LevelText, err)
	}
	ok = true
	return tabCtx, cancel, nil
}

// waitForSelector polls until selector matches an element with a non-zero box, or the deadline.
//
// "Exists but is not visible" is accepted only when the element has children with a box, because a
// navigation container (`.master-item`) is sometimes laid out with zero height while its text child
// is visible — requiring the container itself to have a box made NavigateSPA report that a tree with
// 24 rendered entries had never rendered. A genuinely absent selector still fails, and so does one
// whose subtree is entirely zero-sized.
func waitForSelector(ctx context.Context, selector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	expr := `(function(){ var e = document.querySelector(` + jsString(selector) + `);
		if (!e) return false;
		var r = e.getBoundingClientRect();
		if (r.width > 1 && r.height > 1) return true;
		var kids = e.querySelectorAll('*');
		for (var i=0;i<kids.length;i++){ var kr = kids[i].getBoundingClientRect(); if (kr.width>1 && kr.height>1) return true; }
		if (e.innerText && e.innerText.trim().length > 0) return true;
		// An input/select/textarea has no innerText — its VALUE is what the caller drives — and it can
		// be present in a collapsed pane. Existence of a form control is the readiness the caller
		// means; requiring a box rejected a view whose input was right there.
		var tag = e.tagName;
		if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return true;
		return false; })()`
	for {
		var found bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &found)); err == nil && found {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not present within %s", timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// listSignature returns a cheap signature of the text a container currently holds, for detecting
// that a navigation rebuilt it. Empty when the container is absent.
func listSignature(ctx context.Context, container string) string {
	var sig string
	_ = chromedp.Run(ctx, chromedp.Evaluate(
		`(function(){ var n=document.querySelectorAll(`+jsString(container)+`); var s=''; for(var i=0;i<n.length;i++){ s += n[i].innerText; } return s; })()`, &sig))
	return sig
}

// waitForListChange polls until the container's signature differs from before.
func waitForListChange(ctx context.Context, container, before string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if listSignature(ctx, container) != before {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("unchanged within %s", timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForText polls until an element matching container carries label in its text.
func waitForText(ctx context.Context, container, label string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	expr := `(function(){
		var nodes = document.querySelectorAll(` + jsString(container) + `);
		for (var i=0;i<nodes.length;i++){
			if (nodes[i].innerText && nodes[i].innerText.indexOf(` + jsString(label) + `) !== -1) return true;
		}
		return false;
	})()`
	for {
		var found bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &found)); err == nil && found {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%q never appeared in %q within %s", label, container, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// clickByText clicks the first element matching container whose text contains label.
func clickByText(ctx context.Context, container, label string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	expr := `(function(){
		var nodes = document.querySelectorAll(` + jsString(container) + `);
		var target = null;
		for (var i=0;i<nodes.length;i++){
			if (nodes[i].innerText && nodes[i].innerText.indexOf(` + jsString(label) + `) !== -1) { target = nodes[i]; break; }
		}
		if (!target) return false;
		target.click();
		return true;
	})()`
	for {
		var clicked bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &clicked)); err == nil && clicked {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no element in %q carried %q within %s", container, label, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SubmitAndObserveIn drives the view already reached in tabCtx: type into the input, submit, and
// return the sink observations. It is SubmitAndObserve's second half, split out so a caller can park
// a tab on a view (NavigateSPA) and then drive it without re-navigating.
func (b *Browser) SubmitAndObserveIn(tabCtx context.Context, spec FormSubmitSpec, canary string) ([]Observation, error) {
	obs, _, err := submitAndObserveIn(tabCtx, spec, canary)
	return obs, err
}

// SubmitAndObserveRequestsIn is SubmitAndObserveIn that also returns the requests the page sent during
// the interaction whose URL or body carried the canary — the evidence of which endpoint and parameter
// the typed value actually travelled through. A caller that attributes a finding to one endpoint uses
// it to refuse a confirmation the page reached through some other request.
func (b *Browser) SubmitAndObserveRequestsIn(tabCtx context.Context, spec FormSubmitSpec, canary string) ([]Observation, []SentRequest, error) {
	return submitAndObserveIn(tabCtx, spec, canary)
}
