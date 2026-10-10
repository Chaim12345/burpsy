package domexec

// The interaction pass against a real SPA fixture: a page whose second route exists only after a
// click, and whose form only submits through a script handler. These are the two things a static
// parse and a one-shot render cannot reach, so they are what proves the pass drives the page rather
// than reading it.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// spaFixture is a single-page app with no server-side routing: the root document is served for
// every path, and the two views are built by script. `/orders` is reachable only by clicking the
// button, and the form's submit handler is the only thing that reacts to a submit.
const spaFixture = `<!doctype html><html><body>
<div id="app"></div>
<button id="nav-orders" onclick="showOrders()">Orders</button>
<button role="button" id="nav-help" onclick="showHelp()">Help</button>
<form id="search" onsubmit="event.preventDefault(); search()">
  <input name="q" />
  <button type="submit">Search</button>
</form>
<script>
function showOrders(){
  document.getElementById('app').innerHTML = '<h1>Orders</h1><div id="order-list">ORD-1</div>';
  fetch('/api/orders?page=2');
}
function showHelp(){
  document.getElementById('app').innerHTML = '<h1>Help</h1>';
}
function search(){
  fetch('/api/search?q=' + encodeURIComponent(document.querySelector('[name=q]').value));
  document.getElementById('app').innerHTML = '<h1>Results</h1>';
}
</script>
</body></html>`

func interactCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 90*time.Second)
}

// The core claim: a route that exists only after a click is reached, and the click is on the record.
func TestClickingANavigationControlReachesARouteThePageNeverServed(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, spaFixture)
	ctx, cancel := interactCtx(t)
	defer cancel()

	got, err := b.Interact(ctx, url, InteractOptions{})
	if err != nil {
		t.Fatalf("interact: %v", err)
	}
	var orders *InteractionView
	for i := range got.Views {
		if got.Views[i].Action == "click" && strings.Contains(got.Views[i].Selector, "nav-orders") {
			orders = &got.Views[i]
		}
	}
	if orders == nil {
		t.Fatalf("the Orders button was never clicked; views: %+v", got.Views)
	}
	if !orders.Changed {
		t.Errorf("clicking Orders reported no change, but it renders a view the base page lacks")
	}
	if !strings.Contains(orders.DOM, "ORD-1") {
		t.Errorf("the Orders view was not captured; DOM: %.200s", orders.DOM)
	}
	// The API call the click caused is the SPA surface nothing else can see.
	var sawOrdersAPI bool
	for _, r := range got.Requests {
		if strings.Contains(r.URL, "/api/orders") {
			sawOrdersAPI = true
		}
	}
	if !sawOrdersAPI {
		t.Errorf("the fetch the click issued was not recorded; requests: %+v", got.Requests)
	}
}

// A control that changes nothing is recorded as such, not dropped: "nothing happened" and "never
// clicked" are different facts, and a report that conflated them would overstate coverage.
func TestEachDiscoveredControlIsAttemptedAndItsOutcomeRecorded(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, spaFixture)
	ctx, cancel := interactCtx(t)
	defer cancel()

	got, err := b.Interact(ctx, url, InteractOptions{})
	if err != nil {
		t.Fatalf("interact: %v", err)
	}
	if got.ClicksAvailable < 2 {
		t.Fatalf("the fixture has two navigation buttons; the pass found %d", got.ClicksAvailable)
	}
	if got.ClicksAttempted != got.ClicksAvailable {
		t.Errorf("attempted %d of %d available controls; a pass under its cap must attempt them all",
			got.ClicksAttempted, got.ClicksAvailable)
	}
	if len(got.Views) != got.ClicksAttempted {
		t.Errorf("%d views for %d attempts: an attempt without a view hides its outcome",
			len(got.Views), got.ClicksAttempted)
	}
}

// The click cap is honoured and reported: a truncated exploration must never read as a complete one.
func TestTheClickCapIsHonouredAndReported(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, spaFixture)
	ctx, cancel := interactCtx(t)
	defer cancel()

	got, err := b.Interact(ctx, url, InteractOptions{MaxClicks: 1})
	if err != nil {
		t.Fatalf("interact: %v", err)
	}
	if got.ClicksAttempted != 1 {
		t.Errorf("MaxClicks 1 attempted %d clicks", got.ClicksAttempted)
	}
	if !got.Capped {
		t.Error("a pass that stopped at its click cap did not report Capped: a truncated exploration " +
			"presented as complete is the confident wrong answer this bound exists to prevent")
	}
}

// A script-driven form submits through its handler, and the request it issues is recorded. Native
// form.submit() would bypass the handler, so this is what proves the pass dispatches an event.
func TestFillingAndSubmittingAFormRunsTheApplicationsOwnHandler(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, spaFixture)
	ctx, cancel := interactCtx(t)
	defer cancel()

	got, err := b.Interact(ctx, url, InteractOptions{FillForms: true})
	if err != nil {
		t.Fatalf("interact: %v", err)
	}
	if got.FormsFound == 0 {
		t.Fatal("the fixture's form was not discovered")
	}
	if got.FormsSubmitted == 0 {
		t.Fatal("FillForms was set but no form was submitted")
	}
	var sawSearch bool
	for _, r := range got.Requests {
		if strings.Contains(r.URL, "/api/search") {
			sawSearch = true
		}
	}
	if !sawSearch {
		t.Errorf("the form's onsubmit handler did not run — a native submit bypasses it; requests: %+v",
			got.Requests)
	}
}

// With FillForms off the form is still discovered, so "found but not submitted" cannot read as
// "found nothing".
func TestWithoutFillFormsTheFormIsFoundButNotSubmitted(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, spaFixture)
	ctx, cancel := interactCtx(t)
	defer cancel()

	got, err := b.Interact(ctx, url, InteractOptions{})
	if err != nil {
		t.Fatalf("interact: %v", err)
	}
	if got.FormsFound == 0 {
		t.Error("the form was not discovered with FillForms off")
	}
	if got.FormsSubmitted != 0 {
		t.Errorf("a form was submitted with FillForms off (%d)", got.FormsSubmitted)
	}
}

// A zero-valued options struct is the documented default, not "unbounded".
func TestZeroInteractOptionsTakesTheDocumentedBounds(t *testing.T) {
	t.Parallel()
	got := InteractOptions{}.withDefaults()
	if got.MaxClicks != MaxInteractionClicks || got.MaxForms != MaxInteractionForms || got.MaxWait != DefaultMaxInteractionWait {
		t.Fatalf("zero options resolved to %+v, want the named defaults", got)
	}
	if got.Settle.DOMQuiet <= 0 || got.Settle.MaxWait <= 0 {
		t.Fatalf("zero options left the settle windows unset: %+v", got.Settle)
	}
}
