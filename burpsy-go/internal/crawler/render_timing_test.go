package crawler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// burpsy-react-ui-efra: Burp navigates with idle/quiet thresholds (Zgjj.java:161-165,
// map_root.tsv:7393 "Network idle threshold (ms):") before it reads the DOM. burpsy's render seam
// had no options at all — whatever the browser had when it returned was the page — so a
// client-rendered route that populates after the load event contributed nothing, and the crawl then
// reported the application as having almost no locations: a confident wrong answer.

// The floor is not zero. The previous implementation slept a fixed 300 ms before reading the DOM,
// so that is the floor this feature may not go below: a crawl configured with nothing must wait at
// least as long as it always did, and no crawl may get slower.
func TestTheRenderDefaultsAreNonZeroAndAtLeastTheOldFixedSleep(t *testing.T) {
	o := RenderOptions{}.withDefaults()
	if o.DOMQuiet <= 0 || o.NetworkIdle <= 0 || o.MaxWait <= 0 {
		t.Errorf("defaults = %+v; a zero window means reading the DOM at the load event, which is the defect",
			o)
	}
	const oldFixedSleep = 300 * time.Millisecond
	if o.DOMQuiet < oldFixedSleep {
		t.Errorf("DOMQuiet = %v, below the %v the previous implementation slept unconditionally; a crawl "+
			"configured with nothing must not read the DOM EARLIER than it always did", o.DOMQuiet, oldFixedSleep)
	}
	// A cap is not optional: without one a page that never settles waits forever.
	if o.MaxWait <= o.DOMQuiet {
		t.Errorf("MaxWait %v does not exceed DOMQuiet %v, so the cap would fire before the window it caps",
			o.MaxWait, o.DOMQuiet)
	}
}

// An explicit value is honoured and an explicit zero means UNSET, not "do not wait at all". The
// distinction matters: zero here is "I did not configure this", because a crawl that reads the DOM at
// the load event is the defect this exists to fix.
func TestRenderOptionsResolveExplicitValuesAndTreatZeroAsUnset(t *testing.T) {
	got := RenderOptions{DOMQuiet: 2 * time.Second, NetworkIdle: 3 * time.Second, MaxWait: 4 * time.Second}.withDefaults()
	if got.DOMQuiet != 2*time.Second || got.NetworkIdle != 3*time.Second || got.MaxWait != 4*time.Second {
		t.Errorf("explicit options were overwritten: %+v", got)
	}
	if zero := (RenderOptions{}).withDefaults(); zero.DOMQuiet != DefaultRenderDOMQuiet {
		t.Errorf("an unset DOMQuiet resolved to %v, want the default %v", zero.DOMQuiet, DefaultRenderDOMQuiet)
	}
}

// A CAPPED render leaves a trace. A render that reached its cap was read while the page was still
// changing, so what it had not produced yet is MISSING rather than absent — and a crawl that
// presents a capped page as an empty one reports the application as smaller than it is.
//
// The cap has to be recorded AS a cap, because "the page never settled" and "the browser died" are
// two different answers with two different remedies and the queue has to tell them apart.
func TestACappedRenderIsRecordedAsIncompleteRatherThanAsAnEmptyPage(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":     `<html><body><a href="/slow">slow page</a></body></html>`,
		"/slow": `<html><body><p>still assembling</p></body></html>`,
		"/done": `<html><body><p>end</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RenderWithOutcome = cappedRenderStub{
		tg.URL + "/slow": {Doc: `<html><body><a href="/done">done</a></body></html>`, Capped: true},
	}.render
	rep := run(t, cfg)

	// The links the capped render DID produce are real and are still admitted: a cap is a caveat
	// about completeness, not a refusal of what was found.
	if f := fetchByPath(t, rep.Fetches, "/done"); f.URL == "" {
		t.Error("a capped render's links were dropped; they are real, and the cap says the page was " +
			"incomplete rather than that it had nothing")
	}

	// And the incompleteness is on the record, naming the window.
	var capDetail string
	for _, rec := range rep.Skips.Records {
		if rec.Reason == SkipRenderUnavailable && strings.Contains(rec.Detail, "cap") {
			capDetail = rec.Detail
		}
	}
	if capDetail == "" {
		var all []string
		for _, rec := range rep.Skips.Records {
			all = append(all, rec.Reason.String()+": "+rec.Detail)
		}
		t.Errorf("a capped render left no record; an operator reading this crawl cannot tell the page "+
			"was incomplete. Records: %v", all)
	}
	if !strings.Contains(capDetail, DefaultRenderMaxWait.String()) {
		t.Errorf("the cap record does not name the window it hit: %q; without it an operator cannot "+
			"tell whether to raise it", capDetail)
	}
}

// A render that SETTLED records nothing: a settled page is a complete reading, and a caveat on
// every settled page would train an operator to ignore the one that matters.
func TestASettledRenderRecordsNoIncompleteness(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":     `<html><body><a href="/page">page</a></body></html>`,
		"/page": `<html><body><p>settled</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RenderWithOutcome = cappedRenderStub{
		tg.URL + "/page": {Doc: `<html><body><p>settled</p></body></html>`, Settled: true},
	}.render
	rep := run(t, cfg)

	for _, rec := range rep.Skips.Records {
		if rec.Reason == SkipRenderUnavailable && strings.Contains(rec.Detail, "cap") {
			t.Errorf("a SETTLED render recorded a cap: %q; a caveat on every settled page trains an "+
				"operator to ignore the one that matters", rec.Detail)
		}
	}
}

// Settled and Capped are opposites, and a render that returned claims exactly one. A caller checking
// neither is assuming every page it rendered was complete.
func TestSettledAndCappedAreOpposites(t *testing.T) {
	if settled := (RenderOutcome{Settled: true}); settled.Settled == settled.Capped {
		t.Error("a settled render reported both states the same; exactly one must be true")
	}
	if capped := (RenderOutcome{Capped: true}); capped.Settled == capped.Capped {
		t.Error("a capped render reported both states the same")
	}
}

// A caller that wires only the PLAIN Render still gets a rendered pass, because the outcome form is
// preferred and not required. Making it required would break every existing Render wiring for no gain:
// a caller that has not told the engine it cares about settling gets no settle claim, which is exactly
// what it asked for.
func TestAPlainRenderIsStillHonoured(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":              `<html><body><a href="/wired">wired</a></body></html>`,
		"/wired":         `<html><body><p>no script links here</p></body></html>`,
		"/rendered-only": `<html><body><p>end</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.Render = renderedStub{
		tg.URL + "/wired": `<html><body><a href="/rendered-only">only after script</a></body></html>`,
	}.render
	rep := run(t, cfg)

	if f := fetchByPath(t, rep.Fetches, "/rendered-only"); f.URL == "" {
		t.Error("a plain Render was not honoured; the outcome form is preferred, not required")
	}
}

// cappedRenderStub is a render that reports an outcome, standing in for a browser the way
// renderedStub stands in for one in the sibling file.
type cappedRenderStub map[string]struct {
	Doc     string
	Settled bool
	Capped  bool
	Missing bool
}

func (c cappedRenderStub) render(_ context.Context, targetURL string) (string, RenderOutcome, error) {
	entry, ok := c[targetURL]
	if !ok || entry.Missing {
		return "", RenderOutcome{}, errors.New("no rendered document for " + targetURL)
	}
	return entry.Doc, RenderOutcome{Settled: entry.Settled, Capped: entry.Capped}, nil
}
