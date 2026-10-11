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
	// MasterText and LevelText select the navigation path to the view. LevelText may be left
	// empty when the level is already in the exchange's own path (VulnerableApp's levels are
	// /XSSWithHtmlTagInjection/LEVEL_2); the confirmation then takes the level from the path so
	// an audit of LEVEL_2 drives LEVEL_2's view rather than a fixed one. Leaving it empty and
	// NOT deriving it would drive another level's field, and the sink would never carry this
	// point's payload — a silent miss on every level but the one the default happened to name.
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

	sinks := []domexec.SinkKind{domexec.SinkInnerHTML, domexec.SinkDocumentWrite, domexec.SinkJQueryHtml, domexec.SinkScriptSrc}
	if target.Sink != 0 {
		sinks = []domexec.SinkKind{target.Sink}
	}

	// A filter that strips the first spelling leaves the sink un-fed for a reason that has nothing to do
	// with the application being safe, so the confirmation walks a short ladder of spellings rather than
	// sending exactly one. Measured on OWASP VulnerableApp's XSS levels: the whole family answers
	// text/plain and renders it with innerHTML, but LEVEL_2 deletes any tag whose name begins with the
	// letters its regex names — which includes the bank's `<svg onload=…>` — and LEVEL_3 additionally
	// rejects the literal substrings `alert` and `javascript`. One payload reported that level as clean
	// while a browser plainly executed a reflection; a `<details ontoggle=confirm(…)>` survives both
	// filters, keeps the canary in the response (so the sink argument still carries it), and is the
	// second rung. The ladder is bounded, leads with the context-specific payload, and stops at the first
	// confirmation.
	for _, p := range xssBrowserConfirmLadder(bank, maxXSSBrowserConfirmAttempts) {
		payload := p.build(newXSSCanary())
		// The canary is embedded in the payload, so scanning the observed sink arguments for it is the
		// same test the wire-side confirmation does.
		canary := xssCanaryIn(payload)
		if canary == "" {
			continue
		}
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
		for _, sink := range sinks {
			for _, o := range domexec.ObservationsForSink(obs, sink) {
				// The confirmation is the payload's OWN evidence test against the sink argument, not a
				// substring search for the canary. A canary-only test fires on a page that HTML-escaped the
				// value (VulnerableApp LEVEL_4/5 render `&lt;details…&gt;`), so it reported a secure level as
				// exploited — the exact false positive this project treats as its worst failure. confirm
				// asks the parser whether the crafted element survived AS markup; the escaped form has no
				// such element and is correctly not a hit.
				if !xssSinkCarriesBreakout(o.Argument, canary, p) {
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
					// The occurrence must cite the audited exchange. It is how the issues API attributes the
					// finding to a host and path, and how a consumer (the live benchmark among them) tells
					// which exchange a finding belongs to. Leaving it zero resolved to the store's first
					// exchange, so every browser-confirmed hit was attributed to the wrong row and read as a
					// miss — the finding existed but pointed at nothing the audit was about.
					ExchangeID: cc.Exchange.ID,
				}
			}
		}
	}
	return nil
}

// xssSinkCarriesBreakout reports whether a sink argument is evidence that the payload broke out.
//
// It uses the rung's own confirm predicate when it has one — the same test the wire-side check uses, so
// the browser and the wire agree on what a breakout looks like — and falls back to a canary substring
// test only for a rung that states no predicate. The substring fallback is deliberately the weaker one:
// it is correct for a payload whose evidence IS its literal bytes, and wrong for one that opens markup,
// which is why every ladder rung that opens a tag states a predicate.
func xssSinkCarriesBreakout(arg, canary string, p xssPayload) bool {
	if !strings.Contains(arg, canary) {
		return false
	}
	if p.confirm == nil {
		return true
	}
	return p.confirm(arg, canary)
}

// confirmElementHandler is the evidence for a tag breakout whose proof is a specific element carrying a
// specific event-handler attribute set to exactly the injected expression. It generalises
// confirmAltHandlerBreakout to the ladder's confirmation-handler spellings.
func confirmElementHandler(tag, attr, want string) xssConfirm {
	return func(body, canary string) bool {
		return anyAttr(body, func(t, name, value string) bool {
			return t == tag && name == attr && strings.TrimSpace(value) == want
		})
	}
}

// maxXSSBrowserConfirmAttempts bounds the payload ladder the browser confirmation walks. Four rungs is
// the context-specific payload plus three filter-evasion spellings: enough for the naive tag-name and
// keyword filters a deliberately-vulnerable target ships, and deliberately not an unbounded payload
// fuzzer — each rung is a real browser interaction against the target.
const maxXSSBrowserConfirmAttempts = 4

// xssBrowserConfirmLadder is the ordered spellings the browser confirmation tries. It leads with the
// bank's context-specific payloads (the most precise attempts) and then adds spellings that keep the
// breakout and the canary while evading a filter the first spelling trips.
//
// Every rung keeps the canary LITERAL in the response, because the confirmation is a substring test on
// the sink's argument: a payload that hides the canary inside a base64 blob would decode to an exploit
// yet never match, which reads as a clean page. That is why the escapes here are tag-name and keyword
// choices rather than encodings.
func xssBrowserConfirmLadder(bank []xssPayload, max int) []xssPayload {
	var out []xssPayload
	seen := map[string]bool{}
	add := func(p xssPayload) {
		if seen[p.note] {
			return
		}
		seen[p.note] = true
		out = append(out, p)
	}
	// Lead with the bank's PRIMARY payload only. The bank is ordered most-specific-first and its later
	// entries are the same question asked in other syntaxes; the browser confirmation is about the
	// CONTEXT the value lands in, so one context-specific spelling plus the evasion rungs below is the
	// right budget — carrying the whole bank would spend the cap before any evasion rung ran.
	if len(bank) > 0 {
		add(bank[0])
	} else {
		add(genericXSSPayloads()[0])
	}
	add(xssPayload{build: textNodeAltHandlerPayload, confirm: confirmAltHandlerBreakout, note: "tag injection with a handler outside the usual blocklist"})
	add(xssPayload{
		build: func(c string) string { return `<details open ontoggle=confirm(` + c + `)>` },
		note:  "tag injection using a confirmation handler and no blocklisted keyword",
		confirm: func(body, canary string) bool {
			return confirmElementHandler("details", "ontoggle", "confirm("+canary+")")(body, canary)
		},
	})
	add(xssPayload{
		build: func(c string) string { return `<object data=x onerror=confirm(` + c + `)>` },
		note:  "object tag using a confirmation handler",
		confirm: func(body, canary string) bool {
			return confirmElementHandler("object", "onerror", "confirm("+canary+")")(body, canary)
		},
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
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
		if t.Match != "" && host != t.Match && !strings.HasPrefix(host, t.Match) && !strings.HasPrefix(path, t.Match) {
			continue
		}
		// A route that names no level is generic over levels, and the level is the last path
		// segment of the exchange the audit is walking (VulnerableApp: .../XSSWithHtmlTagInjection
		// /LEVEL_3). Deriving it here — rather than at the call site — keeps the one place that
		// already reads the exchange's path the one place that decides the view.
		if t.LevelText == "" {
			if lvl := xssLevelFromPath(path); lvl != "" {
				t.LevelText = lvl
			}
		}
		return t, true
	}
	return XSSBrowserTarget{}, false
}

// xssLevelFromPath returns the final non-empty element of a request path, query stripped. It is the
// level a per-level application puts in the URL (…/LEVEL_3); "%2F"-style escapes are left alone
// because the app's own routing does not decode them into separators.
func xssLevelFromPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimRight(path, "/")
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	return path
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
