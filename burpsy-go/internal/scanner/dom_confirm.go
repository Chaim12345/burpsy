package scanner

// Dynamic confirmation for the static DOM pass's findings (burpsy-react-ui-m97j) — Phase 12,
// named in dom.go's header since the pass shipped and never built.
//
// # What this decides, and why a real browser is the arbiter
//
// The static DOM pass is a lexical tracer: it establishes that a source-to-sink PATH EXISTS IN
// THE SOURCE, and it says so in every finding's evidence. "Exists in the source" is not
// "reachable at runtime" — the statement may sit in a dead branch, behind a guard the lexical
// pass cannot evaluate, or after an early return — and the pass's own header names over-report
// as one of its documented failure modes. Confirmation answers the reachability question the
// only honest way it can be answered: plant a canary in the flow's source, load the page in a
// real browser, and see whether the page's own script feeds it to a dangerous sink.
//
// The scout's recommendation is the design: reuse domexec's ObserveTaint (the outside-the-page
// CDP taint harness) rather than porting Burp's in-page Zp7 library. ObserveTaint answers
// exactly this source-to-sink question with a simpler trust model — the page cannot see or
// subvert an observer that never injected script.
//
// # The three verdicts, and why retire is not delete
//
//	Promoted — the canary reached a dangerous sink. The finding's confidence becomes "firm":
//	        a browser watched it happen, which is the strongest evidence this scanner ever has.
//	Retired — the canary never reached ANY instrumented sink. The finding's confidence becomes
//	        "suppressed-negative": the static candidate stays named (the finding is not deleted)
//	        because "we loaded it once and nothing fired" is evidence, not proof — an event-driven
//	        sink the harness did not trigger, a guard that needed a different canary shape, and a
//	        DOM state the single load never built are all real ways a true flow stays quiet.
//	        Deleting the finding would convert an unknown into a silent negative; recording the
//	        verdict keeps the finding and names the basis.
//	Unchanged — no browser is attached, or the observation errored. The finding stays
//	        "tentative" exactly as before, and the evidence gains a line SAYING the dynamic
//	        tier did not run, because a caveat that exists only in the operator's memory is
//	        the failure dom.Caveat exists to prevent.
//
// # The mapping, and its honesty limits
//
// Only URL-kind flows can be confirmed: a canary is planted in location.hash/search, and the
// page is loaded. Stored flows read data the page itself persisted earlier — the harness has
// nothing to plant at load time — and message flows arrive from another document the harness
// does not control; both are counted, reported as not dynamically confirmable rather than
// silently skipped, and stay tentative. The URL-kind flow that CONFIRMS elevates the whole
// finding (its Issue is a DOM-based variant of one flow) — a confirmed flow is the finding's
// own path proven.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// DOMConfirmState is the dynamic tier's verdict for one finding.
type DOMConfirmState string

const (
	// DOMConfirmNone means the dynamic tier has not run for this finding.
	DOMConfirmNone DOMConfirmState = ""
	// DOMConfirmPromoted means the canary reached a dangerous sink in a real browser.
	DOMConfirmPromoted DOMConfirmState = "promoted"
	// DOMConfirmRetired means the canary was planted and reached no instrumented sink.
	DOMConfirmRetired DOMConfirmState = "retired"
	// DOMConfirmUnavailable means no browser was attached, so the finding stays tentative.
	DOMConfirmUnavailable DOMConfirmState = "unavailable"
	// DOMConfirmUnsupported means the flow's source kind cannot be planted by this harness.
	DOMConfirmUnsupported DOMConfirmState = "unsupported-source"
)

// ConfirmDOMFindings runs the dynamic confirmation tier over one exchange's tentative DOM
// findings, in place. It is the Phase 12 pass: promote what a real browser confirms, retire
// what it does not, and say so in each finding's evidence either way.
//
// Findings are matched back to their flows by Issue name, because the finding carries the
// flow's identity in that one field; a finding whose Issue does not map to a flow in this
// exchange's analysis is left untouched (it is some other tier's finding, and renaming it
// would corrupt that tier's own accounting).
//
// The URL for the browser to load is rebuilt from the exchange exactly as the active DOM
// checks rebuild it (exchangeURL), because the confirmation must observe the SAME page the
// static pass analysed — a confirmation against a different URL is evidence about something
// else.
func (s *ActiveScanner) ConfirmDOMFindings(ctx context.Context, ex *core.Exchange, analysis DOMAnalysis) []*Finding {
	if s == nil || ex == nil {
		return nil
	}
	if len(analysis.Flows) == 0 {
		return nil // nothing to confirm; not an error and not a claim
	}
	// The findings slice this pass confirms and returns. DOMAnalysis.Findings() builds a
	// FRESH []*Finding on every call, so a caller that reads findings after confirming would
	// see unconfirmed copies — the confirmed slice has to travel out of this function.
	confirmed := analysis.Findings()

	flowsByIssue := make(map[string]DOMFlow, len(analysis.Flows))
	for _, f := range analysis.Flows {
		flowsByIssue[f.Issue] = f
	}

	// Without a browser provider the whole tier is unavailable, and every finding says so —
	// AC4: the caveat must be ON the finding, not in a log the operator never opens.
	if !s.DOMCapabilityConfigured() {
		for _, f := range confirmed {
			if _, isDOM := flowsByIssue[f.Name]; isDOM {
				f.Confirm = DOMConfirmUnavailable
				f.Confidence = "tentative"
				f.Evidence += " Dynamic confirmation did not run: no DOM execution capability is attached to this scan, so this stays a static-analysis candidate."
			}
		}
		return confirmed
	}

	browser, err := s.browsers.Browser(ctx)
	if err != nil {
		for _, f := range confirmed {
			if _, isDOM := flowsByIssue[f.Name]; isDOM {
				f.Confirm = DOMConfirmUnavailable
				f.Confidence = "tentative"
				f.Evidence += fmt.Sprintf(" Dynamic confirmation did not run: %v.", err)
			}
		}
		return confirmed
	}

	target := exchangeURL(ex)
	for _, f := range confirmed {
		flow, isDOM := flowsByIssue[f.Name]
		if !isDOM {
			continue
		}
		kind, supported := domexecSourceFor(flow)
		if !supported {
			f.Confirm = DOMConfirmUnsupported
			f.Confidence = "tentative"
			f.Evidence += " Dynamic confirmation is not available for this flow's source kind: the harness can plant a canary in a URL, not in client-side storage or an inbound message. This stays a static-analysis candidate."
			continue
		}
		// The canary is per-flow so two flows on one page cannot confirm each other's path.
		// ObserveTaint is called directly rather than through the active checks' cached helper:
		// that helper mints its own canary internally and caches one observation per
		// (exchange, source) pair, while confirmation needs ITS OWN canary — a shared one lets
		// two flows on one page confirm each other's path.
		canary := domCanary("confirm")
		obs, obsErr := domConfirmObserve(ctx, browser, target, kind, canary)
		if obsErr != nil {
			// An observation that errored is not a negative. Retiring on an error would say
			// "we looked and saw nothing" about a page that never loaded.
			f.Confirm = DOMConfirmUnavailable
			f.Confidence = "tentative"
			f.Evidence += fmt.Sprintf(" Dynamic confirmation did not run: %v.", obsErr)
			continue
		}
		if domObservationConfirms(obs, canary) {
			f.Confirm = DOMConfirmPromoted
			f.Confidence = "firm"
			f.Evidence += " Dynamic confirmation: a browser loaded the page with a canary planted in the flow's source, and the page's own script delivered it to a dangerous sink. The path is proven reachable, not only present in the source."
			continue
		}
		f.Confirm = DOMConfirmRetired
		f.Confidence = "suppressed-negative"
		f.Evidence += " Dynamic confirmation: a browser loaded the page with a canary planted in the flow's source, and no instrumented sink received it. The flow stays named — one load observing nothing is evidence against reachability, not proof of safety (an untriggered event path or a guard needing a different canary shape would stay silent too)."
	}
	return confirmed
}

// domObservationConfirms says whether any observation carries this canary into a sink. Every
// instrumented sink is a dangerous one (the instrumentation records only the dangerous-sink
// table), so presence of the canary in ANY argument is a confirmation.
func domObservationConfirms(obs []domexec.Observation, canary string) bool {
	for _, o := range obs {
		if strings.Contains(o.Argument, canary) {
			return true
		}
	}
	return false
}

// domexecSourceFor maps a static flow's source kind to the domexec planting kind. Only URL
// sources are plantable at load time; the mapping is total so the unsupported arm stays honest.
func domexecSourceFor(f DOMFlow) (domexec.SourceKind, bool) {
	switch f.Source.Kind {
	case DOMSourceURL:
		return domexec.SourceLocationHash, true
	case DOMSourceStored:
		return domexec.SourceStored, false
	case DOMSourceMessage:
		return domexec.SourcePostMessage, false
	}
	return domexec.SourceStored, false
}

// The audit's entry into this tier is javascriptAnalysisFor (js_analysis.go), which runs the same
// static pass the passive path runs (AnalyzeDOMDocument is free-standing so the two cannot drift),
// applies the run's javascript_analysis keys and issue selection, and hands the candidates a browser
// may confirm to ConfirmDOMFindings.

// domConfirmObserve is the confirm pass's observation seam. Production always uses the real
// browser.ObserveTaint; the var exists because ObserveTaint is a concrete method on a concrete
// type and the confirm tests must drive each verdict without Chrome — the same seam style the
// tool runner uses. Swapped only by dom_confirm_test.go.
var domConfirmObserve = func(ctx context.Context, browser *domexec.Browser, target string, source domexec.SourceKind, canary string) ([]domexec.Observation, error) {
	if browser == nil {
		return nil, errors.New("browser: no DOM execution capability is configured for this scan")
	}
	return browser.ObserveTaint(ctx, target, source, canary)
}
