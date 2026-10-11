package scanner

// Browser confirmation of a reflected-XSS point (j1mk.38).
//
// # The gap this closes
//
// The server-side reflected-XSS check reports a breakout only when markup survives unescaped in a
// response the browser will PARSE as markup. Some applications answer a probe with text/plain and let
// the PAGE's own script write that answer into the document — measured on OWASP VulnerableApp, whose
// XSS levels do exactly this. The server-side refusal is correct on the wire: the response body
// carries no live markup. It is wrong about the application: the payload executes. Nothing on the wire
// can settle it, so the check asks the browser.
//
// # How it is driven
//
// The application's own page is the thing under test, so the confirmation drives IT rather than
// re-sending the probe: navigate its single-page tree to the view that renders the reflected value
// (domexec.NavigateSPA), type the payload into the field that produces the reflection, activate the
// control, and watch the pages's sinks (domexec.SubmitAndObserveIn). A sink call whose argument
// carries the payload is the confirmation the wire refused to give.
//
// # Why the routes are data
//
// The page URL, the field and the control are properties of the TARGET, not of this scanner. A caller
// that knows them — the benchmark does — supplies them through Config.XSSBrowserTargets; a target
// this build has no route for is DECLINED with that reason, never reported clean. A default route
// guessed from the response would be a fabricated finding the moment it was wrong.

import (
	"context"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// XSSBrowserTarget names one application's reflected-XSS page: how to reach the view that renders a
// reflected value and how to make it reflect one.
type XSSBrowserTarget struct {
	// Match is the host (and optionally a path prefix) this route applies to. Empty matches any host.
	Match string
	// RootURL is the application root whose script builds the navigation.
	RootURL string
	// MasterText and LevelText select the navigation path to the view.
	MasterText string
	LevelText  string
	// InputSelector is the field that produces the reflection; SubmitSelector activates it.
	InputSelector  string
	SubmitSelector string
	// ClickTrigger activates SubmitSelector with a click rather than a form submit. See
	// domexec.FormSubmitSpec.ClickTrigger for why a caller states this rather than the harness guessing.
	ClickTrigger bool
	// Sink is the domexec sink the page's script is expected to feed the payload to. Zero means any
	// innerHTML-family sink, which is what "reflected XSS" means in practice.
	Sink domexec.SinkKind
}

// confirmReflectedXSSInBrowser drives the target's own page and returns a finding when the page's
// script fed the payload to a sink, or nil when it did not or the confirmation could not run.
//
// A nil return is never a clean verdict on its own: the caller has already decided the wire showed a
// reflection, and this function's silence means only that the browser did not confirm it. The reason
// silence happened (no route, no browser, navigation failed) is recorded as a decline so a report can
// distinguish "we looked in a browser" from "we could not".
func confirmReflectedXSSInBrowser(ctx context.Context, cc *CheckContext, point bcheck.InsertionPoint, bank []xssPayload) *Finding {
	target, ok := xssBrowserTargetFor(cc)
	if !ok {
		recordXSSBrowserDecline(cc, point, "no browser route is configured for this host, so the reflected value was not driven into a page")
		return nil
	}
	browser, err := cc.Scanner.BrowserForRender(ctx)
	if err != nil {
		recordXSSBrowserDecline(cc, point, "no browser available: "+err.Error())
		return nil
	}
	// One payload: the bank's first is the most specific attempt the point's context chose, and the
	// browser confirmation is about the CONTEXT the value lands in, not about trying every spelling.
	payload := ""
	for _, p := range bank {
		payload = p.build(newXSSCanary())
		break
	}
	if payload == "" {
		return nil
	}
	// The canary is embedded in the payload, so scanning the observed sink arguments for it is the
	// same test the wire-side confirmation does.
	canary := ""
	if c := xssCanaryIn(payload); c != "" {
		canary = c
	}
	if canary == "" {
		return nil
	}

	tab, cancel, err := browser.NavigateSPA(ctx, domexec.SPARoute{
		RootURL:        target.RootURL,
		MasterSelector: ".master-item",
		MasterText:     target.MasterText,
		LevelSelector:  ".inner-master-item",
		LevelText:      target.LevelText,
		ReadySelector:  target.InputSelector,
	})
	if err != nil {
		recordXSSBrowserDecline(cc, point, "the browser could not reach the view: "+err.Error())
		return nil
	}
	defer cancel()

	obs, err := browser.SubmitAndObserveIn(tab, domexec.FormSubmitSpec{
		InputSelector:  target.InputSelector,
		SubmitSelector: target.SubmitSelector,
		ClickTrigger:   target.ClickTrigger,
		Payload:        payload,
	}, canary)
	if err != nil {
		recordXSSBrowserDecline(cc, point, "the browser could not drive the view: "+err.Error())
		return nil
	}
	sinks := []domexec.SinkKind{domexec.SinkInnerHTML, domexec.SinkDocumentWrite, domexec.SinkJQueryHtml, domexec.SinkScriptSrc}
	if target.Sink != 0 {
		sinks = []domexec.SinkKind{target.Sink}
	}
	for _, sink := range sinks {
		for _, o := range domexec.ObservationsForSink(obs, sink) {
			if !strings.Contains(o.Argument, canary) {
				continue
			}
			return &Finding{
				Name:        xssReflectedIssue,
				Severity:    "high",
				Confidence:  "firm",
				Description: fmt.Sprintf("reflected XSS confirmed in a browser: the page's own script wrote the payload into %s (the response was text/plain, so no wire-side breakout exists)", sink),
				URL:         cc.Exchange.Path,
				Method:      cc.Exchange.Method,
				Evidence:    fmt.Sprintf("browser-confirmed: %s %q landed in %s", point.Kind, point.Name, sink),
			}
		}
	}
	return nil
}

// xssBrowserTargetFor finds the route configured for this exchange's host.
func xssBrowserTargetFor(cc *CheckContext) (XSSBrowserTarget, bool) {
	if cc == nil || cc.Scanner == nil || cc.Scanner.config == nil {
		return XSSBrowserTarget{}, false
	}
	host := ""
	if cc.Exchange != nil {
		host = cc.Exchange.Host
	}
	path := ""
	if cc.Exchange != nil {
		path = cc.Exchange.Path
	}
	for _, t := range cc.Scanner.config.XSSBrowserTargets {
		if t.Match == "" {
			return t, true
		}
		if host == t.Match || strings.HasPrefix(host, t.Match) || strings.HasPrefix(path, t.Match) {
			return t, true
		}
	}
	return XSSBrowserTarget{}, false
}

// recordXSSBrowserDecline notes that a browser confirmation could not run, so a point whose probe was
// reflected is not read as clean.
func recordXSSBrowserDecline(cc *CheckContext, point bcheck.InsertionPoint, reason string) {
	if cc == nil || cc.MethodDeclines == nil {
		return
	}
	cc.MethodDeclines.Record(MethodDecline{
		TypeIndex: 0x00200300, // Cross-site scripting (reflected)
		Issue:     xssReflectedIssue,
		Method:    MethodClientSide,
		Reason:    reason,
	})
}

// xssCanaryIn returns the canary embedded in a built payload, or "". Every xssPayload builder takes
// the canary as its argument and splices it verbatim, and newXSSCanary always prefixes "zxss", so the
// last such run is the token the sink argument must carry.
func xssCanaryIn(payload string) string {
	i := strings.LastIndex(payload, "zxss")
	if i < 0 {
		return ""
	}
	j := i
	for j < len(payload) && isAlnum(payload[j]) {
		j++
	}
	return payload[i:j]
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
