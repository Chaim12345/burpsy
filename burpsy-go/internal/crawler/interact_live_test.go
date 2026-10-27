package crawler

// End-to-end proof that the interaction capability is real, not just wired: a real headless Chrome
// driven by the real domexec engine, feeding the real crawler, reaching a route that exists only
// after a click. The other interaction tests stub the hook to test the WIRING; this one leaves the
// stub out, so a regression in the engine or in how the crawler calls it fails here.
//
// Untagged, matching internal/domexec's own tests, which launch Chrome in the normal suite. Chrome's
// absence (or a Chrome that cannot start) is a counted skip: the test says why, and TestMain fails
// the package unless BURPSY_ALLOW_NO_CHROME=1 — the same ledger every browser-driving package uses
// (internal/domexec/domexectest), because a silent skip here would report the SPA capability green
// while nothing about it was exercised. This helper used to name the escape hatch in its failure
// message without honouring it.

import (
	"context"
	"testing"

	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
)

func chromeForCrawl(t *testing.T) *domexec.Browser {
	t.Helper()
	if !domexectest.ChromeOnPath() {
		domexectest.Skip(t, "no Chrome binary on PATH: the SPA interaction capability is untested")
	}
	b, err := domexec.NewBrowser(context.Background(), domexec.Options{})
	if err != nil {
		domexectest.Skipf(t, "Chrome is on PATH but could not be launched: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// spaPages is a single-page app served for every path: the two views are built by script, and
// /orders/1 exists only in the DOM a click produces.
func spaPages() map[string]string {
	return map[string]string{
		"/app": `<html><body>
			<div id="app">Home</div>
			<button id="nav-orders" onclick="document.getElementById('app').innerHTML='<a href=&quot;/orders/1&quot;>Order 1</a>'; fetch('/api/orders');">Orders</button>
		</body></html>`,
		"/orders/1":   `<html><body>order one</body></html>`,
		"/api/orders": `<html><body>[]</body></html>`,
	}
}

// The claim: with the real engine wired, the crawler reaches a route that exists only after a click
// and would be invisible to a static parse and a one-shot render.
func TestTheRealInteractionEngineReachesAScriptRoutedPage(t *testing.T) {
	b := chromeForCrawl(t)
	tg := newTarget(t, spaPages())
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	cfg.Interact = func(ctx context.Context, url string, opts InteractionOptions) (Interaction, error) {
		got, err := b.Interact(ctx, url, domexec.InteractOptions{MaxClicks: opts.MaxClicks, MaxWait: opts.MaxWait})
		if err != nil {
			return Interaction{}, err
		}
		views := make([]InteractionView, 0, len(got.Views))
		for _, v := range got.Views {
			views = append(views, InteractionView{Action: v.Action, Selector: v.Selector, Label: v.Label,
				URL: v.URL, DOM: v.DOM, Changed: v.Changed, Error: v.Error})
		}
		reqs := make([]RenderedRequest, 0, len(got.Requests))
		for _, r := range got.Requests {
			reqs = append(reqs, RenderedRequest{URL: r.URL, Method: r.Method})
		}
		return Interaction{Views: views, Requests: reqs, FormsFound: got.FormsFound,
			ClicksAttempted: got.ClicksAttempted, ClicksAvailable: got.ClicksAvailable, Capped: got.Capped}, nil
	}

	rep := run(t, cfg)

	var sawOrders bool
	for _, f := range rep.Fetches {
		if f.URL == tg.URL+"/orders/1" {
			sawOrders = true
		}
	}
	if !sawOrders {
		t.Fatalf("the script-routed /orders/1 was not crawled; fetches: %+v", fetchURLs(rep))
	}
	if rep.InteractionsRun == 0 {
		t.Error("the interaction pass did not run")
	}
	if rep.EdgeKinds["clickable"] == 0 {
		t.Errorf("the clickable edge kind was not counted; edge kinds: %+v", rep.EdgeKinds)
	}
}
