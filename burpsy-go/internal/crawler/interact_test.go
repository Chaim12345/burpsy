package crawler

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// The interaction pass (burpsy-react-ui-spa1). The engine's job here is not to click — the browser
// package does that — but to fold a pass's outcome into the crawl honestly: a link a click revealed
// is a discovered location, a request the click issued is an API location, a capped pass is reported
// as capped, and a pass that could not run is a named skip rather than silence.

// interactionHarness runs with the interaction hook stubbed to a canned pass, so the wiring is what
// is under test, not the browser.
func interactionPass(views []InteractionView, reqs []RenderedRequest, capped bool) func(context.Context, string, InteractionOptions) (Interaction, error) {
	return func(context.Context, string, InteractionOptions) (Interaction, error) {
		return Interaction{Views: views, Requests: reqs, Capped: capped,
			ClicksAttempted: len(views), ClicksAvailable: len(views)}, nil
	}
}

// A link that a click revealed is admitted as a location, tagged as a clickable edge.
func TestALinkAClickRevealedIsAdmittedAsADiscoveredLocation(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/app":    `<html><body><button id="go">Go</button></body></html>`,
		"/orders": `<html><body>orders</body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	cfg.Interact = interactionPass([]InteractionView{{
		Action: "click", Selector: "#go", Label: "Go", Changed: true,
		URL: tg.URL + "/orders",
		DOM: `<html><body><a href="/orders">Orders</a></body></html>`,
	}}, nil, false)

	rep := run(t, cfg)

	var sawOrders bool
	for _, f := range rep.Fetches {
		if strings.HasSuffix(f.URL, "/orders") {
			sawOrders = true
		}
	}
	if !sawOrders {
		t.Fatalf("the link a click revealed was not crawled; fetches: %+v", fetchURLs(rep))
	}
	if rep.EdgeKinds["clickable"] == 0 {
		t.Errorf("the clickable edge kind was not counted; edge kinds: %+v", rep.EdgeKinds)
	}
	if rep.InteractionsRun < 1 {
		t.Errorf("the interaction pass ran on no page; InteractionsRun=%d", rep.InteractionsRun)
	}
	if rep.InteractionClicks == 0 {
		t.Error("no click was counted")
	}
}

// A request the click issued is admitted as an API location, like a rendered request.
func TestARequestAClickIssuedIsAdmittedAsAnAPILocation(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/app":        `<html><body><button id="go">Go</button></body></html>`,
		"/api/orders": `<html><body>[1,2]</body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	cfg.Interact = interactionPass(
		[]InteractionView{{Action: "click", Selector: "#go", Changed: true, URL: tg.URL + "/app"}},
		[]RenderedRequest{{URL: tg.URL + "/api/orders", Method: "GET"}}, false)

	rep := run(t, cfg)

	var sawAPI bool
	for _, f := range rep.Fetches {
		if strings.HasSuffix(f.URL, "/api/orders") {
			sawAPI = true
		}
	}
	if !sawAPI {
		t.Fatalf("the request the click issued was not crawled; fetches: %+v", fetchURLs(rep))
	}
}

// A pass that hit its bound is reported as capped, never as a complete exploration.
func TestACappedInteractionPassIsReportedAsCapped(t *testing.T) {
	tg := newTarget(t, map[string]string{"/app": `<html><body><button id="go">Go</button></body></html>`})
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	cfg.Interact = interactionPass(
		[]InteractionView{{Action: "click", Selector: "#go", Changed: true, DOM: `<html></html>`}},
		nil, true)

	rep := run(t, cfg)

	if rep.InteractionsCapped != 1 {
		t.Errorf("a capped pass did not set InteractionsCapped: %d", rep.InteractionsCapped)
	}
	if rep.Skips.Count(SkipInteractionUnavailable) == 0 {
		t.Error("a capped interaction pass recorded no skip; a truncated exploration must be visible")
	}
}

// A pass that could not run is a named skip, so a crawl that wanted interaction and did not get it
// is narrower than its counts say and the operator can see by how much.
func TestAFailedInteractionPassIsANamedSkipNotSilence(t *testing.T) {
	tg := newTarget(t, map[string]string{"/app": `<html><body><button id="go">Go</button></body></html>`})
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	cfg.Interact = func(context.Context, string, InteractionOptions) (Interaction, error) {
		return Interaction{}, fmt.Errorf("no browser")
	}

	rep := run(t, cfg)

	if got := rep.Skips.Count(SkipInteractionUnavailable); got != 1 {
		t.Fatalf("a failed interaction pass recorded %d skips, want 1: %+v", got, rep.Skips)
	}
	if rep.InteractionsRun != 0 {
		t.Errorf("a failed pass counted as a run: %d", rep.InteractionsRun)
	}
}

// A nil hook is the previous crawl to the byte: nothing runs, nothing is skipped, no counter moves.
func TestANilInteractionHookChangesNothing(t *testing.T) {
	tg := newTarget(t, map[string]string{"/app": `<html><body><a href="/x">x</a></body></html>`, "/x": `ok`})
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	// Interact left nil.

	rep := run(t, cfg)

	if rep.InteractionsRun != 0 || rep.InteractionsCapped != 0 || rep.InteractionClicks != 0 {
		t.Errorf("a nil hook moved interaction counters: %+v", rep)
	}
	if rep.Skips.Count(SkipInteractionUnavailable) != 0 {
		t.Error("a nil hook recorded a skip; nothing was declined")
	}
}

// A control that changed nothing is not a discovery and not a skip: an honest "it led nowhere".
func TestAClickThatChangedNothingIsNotADiscovery(t *testing.T) {
	tg := newTarget(t, map[string]string{"/app": `<html><body><button id="go">Go</button></body></html>`})
	h := newHarness()
	cfg := h.config(tg.URL + "/app")
	cfg.Interact = interactionPass([]InteractionView{{
		Action: "click", Selector: "#go", Changed: false, DOM: `<html><body><a href="/never">n</a></body></html>`,
	}}, nil, false)

	rep := run(t, cfg)

	for _, f := range rep.Fetches {
		if strings.HasSuffix(f.URL, "/never") {
			t.Fatalf("a link from an unchanged view was crawled; a control that did nothing is not a discovery")
		}
	}
}

func fetchURLs(rep Report) []string {
	out := make([]string, 0, len(rep.Fetches))
	for _, f := range rep.Fetches {
		out = append(out, f.URL)
	}
	return out
}
