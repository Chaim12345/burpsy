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
// that knows them supplies them through ScanConfig.XSSBrowserTargets. This build ships NO route: a
// route is one application's page, field and control, and a default naming one application would make
// the scanner's result depend on which application it happened to be pointed at. A target no route
// covers is DECLINED with that reason, never reported clean.
//
// # What a confirmation is allowed to claim
//
// The page's own script decides which request the typed value travels in. A confirmation therefore
// credits the audited exchange only when the browser recorded a request, during the interaction, to
// that exchange's origin and path carrying the payload in the audited parameter. A sink fed through any
// other request proves the PAGE is exploitable but says nothing about THIS endpoint and parameter, and
// is declined rather than attributed.
//
// # Scope
//
// The browser navigates only to a route whose RootURL is on the audited exchange's own origin, and only
// after RequireEgress has authorised active traffic to that exchange. A route pointing anywhere else is
// declined without a navigation.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// XSSBrowserTarget names one application's reflected-XSS page: how to reach the view that renders a
// reflected value and how to make it reflect one.
type XSSBrowserTarget struct {
	// Match is the host (and optionally a path prefix) this route applies to. Empty matches any host.
	Match string
	// RootURL is the application root whose script builds the navigation. It must be on the audited
	// exchange's own origin; a route elsewhere is declined.
	RootURL string
	// MasterSelector and LevelSelector are the CSS containers of the SPA's first- and second-level
	// navigation entries; MasterText and LevelText pick the entry within each by its text. They are
	// the application's markup, so the caller states them: nothing here assumes any one SPA's class
	// names. LevelSelector may be empty for a one-level tree.
	MasterSelector string
	MasterText     string
	LevelSelector  string
	LevelText      string
	// LevelFromPath, when LevelText is empty, takes the level label from the last segment of the
	// audited exchange's path. It is for an application that serves one URL per level and labels the
	// level's navigation entry with that same segment, so an audit of …/LEVEL_2 drives LEVEL_2's view
	// rather than a fixed one. Off unless the caller says its application has that shape.
	LevelFromPath bool
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
	if err := cc.RequireEgress(); err != nil {
		recordXSSBrowserDecline(cc, point, "the browser was not driven: "+err.Error())
		return nil
	}
	if reason := xssBrowserRouteOutOfScope(cc.Exchange, target); reason != "" {
		recordXSSBrowserDecline(cc, point, reason)
		return nil
	}
	if target.MasterSelector == "" || target.MasterText == "" || target.InputSelector == "" {
		recordXSSBrowserDecline(cc, point, "the configured browser route names no navigation selector, entry or input, so there is no view to drive")
		return nil
	}
	if !xssBrowserAttributable(point) {
		recordXSSBrowserDecline(cc, point, fmt.Sprintf("a %s point cannot be matched to the request a page sends, so a browser confirmation could not be attributed to it", point.Kind))
		return nil
	}
	browser, err := cc.Scanner.BrowserForRender(ctx)
	if err != nil {
		recordXSSBrowserDecline(cc, point, "no browser available: "+err.Error())
		return nil
	}
	tab, cancel, err := browser.NavigateSPA(ctx, domexec.SPARoute{
		RootURL:        target.RootURL,
		MasterSelector: target.MasterSelector,
		MasterText:     target.MasterText,
		LevelSelector:  target.LevelSelector,
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
	// with the application being safe, so the confirmation walks a short, bounded ladder of spellings
	// (a tag-name filter and a keyword filter are the common naive ones) and stops at the first
	// confirmation.
	unattributed := ""
	for _, p := range xssBrowserConfirmLadder(bank, maxXSSBrowserConfirmAttempts) {
		payload := p.build(newXSSCanary())
		// The canary is embedded in the payload, so scanning the observed sink arguments for it is the
		// same test the wire-side confirmation does.
		canary := xssCanaryIn(payload)
		if canary == "" {
			continue
		}
		obs, sent, err := browser.SubmitAndObserveRequestsIn(tab, domexec.FormSubmitSpec{
			InputSelector:  target.InputSelector,
			SubmitSelector: target.SubmitSelector,
			ClickTrigger:   target.ClickTrigger,
			Payload:        payload,
		}, canary)
		if err != nil {
			recordXSSBrowserDecline(cc, point, "the browser could not drive the view: "+err.Error())
			return nil
		}
		sink, hit := xssBrowserSinkHit(obs, sinks, canary, p)
		if !hit {
			continue
		}
		// The sink confirms the PAGE. Only a request to this exchange's endpoint carrying the payload in
		// this point's parameter confirms THIS point.
		via, drove := xssBrowserDroveThisPoint(cc.Exchange, point, sent, canary)
		if !drove {
			if len(sent) > 0 {
				unattributed = sent[0].Method + " " + sent[0].URL
			} else {
				unattributed = "no request the browser recorded"
			}
			continue
		}
		return &Finding{
			Name:        xssReflectedIssue,
			Severity:    "high",
			Confidence:  "firm",
			Description: fmt.Sprintf("reflected XSS confirmed in a browser: the page's own script wrote the payload into %s (the response was text/plain, so no wire-side breakout exists)", sink),
			URL:         cc.Exchange.Path,
			Method:      cc.Exchange.Method,
			Evidence:    fmt.Sprintf("browser-confirmed: %s %q travelled in %s and landed in %s", point.Kind, point.Name, via, sink),
			// The occurrence cites the audited exchange, which the request check above has tied to the
			// interaction.
			ExchangeID: cc.Exchange.ID,
		}
	}
	if unattributed != "" {
		recordXSSBrowserDecline(cc, point, fmt.Sprintf("the page fed a sink, but the value travelled in %s, not in this exchange's %s %q, so the confirmation is not attributed to it", unattributed, point.Kind, point.Name))
	}
	return nil
}

// xssBrowserSinkHit reports the first sink whose argument carries the rung's breakout.
//
// The confirmation is the payload's OWN evidence test against the sink argument, not a substring search
// for the canary: a page that HTML-escaped the value still writes the canary into innerHTML, and a
// canary-only test would report that safe page as exploited.
func xssBrowserSinkHit(obs []domexec.Observation, sinks []domexec.SinkKind, canary string, p xssPayload) (domexec.SinkKind, bool) {
	for _, sink := range sinks {
		for _, o := range domexec.ObservationsForSink(obs, sink) {
			if xssSinkCarriesBreakout(o.Argument, canary, p) {
				return sink, true
			}
		}
	}
	return 0, false
}

// xssBrowserAttributable reports whether a point's value can be recognised in a request a page sends:
// a query parameter or a body parameter. A header, cookie or path point cannot be matched to a page's
// own request by name, so a confirmation through one could never be attributed.
func xssBrowserAttributable(point bcheck.InsertionPoint) bool {
	return (point.Kind == bcheck.IpQuery || point.Kind == bcheck.IpBody) && point.Name != ""
}

// xssBrowserRouteOutOfScope returns a decline reason when the route's RootURL is not on the audited
// exchange's own origin, or "" when it is.
func xssBrowserRouteOutOfScope(ex *core.Exchange, t XSSBrowserTarget) string {
	if ex == nil {
		return "no audited exchange, so the browser route cannot be checked against scope"
	}
	u, err := url.Parse(t.RootURL)
	if err != nil || u.Host == "" {
		return fmt.Sprintf("the browser route's root %q is not an absolute URL, so it was not navigated", t.RootURL)
	}
	if !xssSameOrigin(ex, u) {
		return fmt.Sprintf("the browser route's root %q is not on the audited exchange's origin, so it was not navigated", t.RootURL)
	}
	return ""
}

// xssSameOrigin reports whether u is on the exchange's scheme, host and port.
func xssSameOrigin(ex *core.Exchange, u *url.URL) bool {
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	if !strings.EqualFold(u.Scheme, scheme) || !strings.EqualFold(u.Hostname(), ex.Host) {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	return port == strconv.Itoa(int(ex.Port))
}

// xssBrowserDroveThisPoint reports whether one of the requests the browser recorded went to the audited
// exchange's origin and path and carried the canary in the audited parameter, and names it.
func xssBrowserDroveThisPoint(ex *core.Exchange, point bcheck.InsertionPoint, sent []domexec.SentRequest, canary string) (string, bool) {
	if ex == nil {
		return "", false
	}
	wantPath := ex.Path
	if i := strings.IndexByte(wantPath, '?'); i >= 0 {
		wantPath = wantPath[:i]
	}
	for _, r := range sent {
		u, err := url.Parse(r.URL)
		if err != nil || !xssSameOrigin(ex, u) || u.Path != wantPath {
			continue
		}
		switch point.Kind {
		case bcheck.IpQuery:
			for _, v := range u.Query()[point.Name] {
				if strings.Contains(v, canary) {
					return r.Method + " " + r.URL, true
				}
			}
		case bcheck.IpBody:
			if form, err := url.ParseQuery(r.Body); err == nil {
				for _, v := range form[point.Name] {
					if strings.Contains(v, canary) {
						return r.Method + " " + r.URL, true
					}
				}
			}
			var obj map[string]any
			if json.Unmarshal([]byte(r.Body), &obj) == nil {
				if v, ok := obj[point.Name].(string); ok && strings.Contains(v, canary) {
					return r.Method + " " + r.URL, true
				}
			}
		}
	}
	return "", false
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

// xssBrowserTargetFor finds the route configured for this exchange's host. It reads the routes from a
// config snapshot taken under the scanner's lock, never by writing to the shared config.
func xssBrowserTargetFor(cc *CheckContext) (XSSBrowserTarget, bool) {
	if cc == nil || cc.Scanner == nil {
		return XSSBrowserTarget{}, false
	}
	targets := cc.Scanner.ConfigSnapshot().XSSBrowserTargets
	host := ""
	if cc.Exchange != nil {
		host = cc.Exchange.Host
	}
	path := ""
	if cc.Exchange != nil {
		path = cc.Exchange.Path
	}
	for _, t := range targets {
		if t.Match != "" && host != t.Match && !strings.HasPrefix(host, t.Match) && !strings.HasPrefix(path, t.Match) {
			continue
		}
		// A route that asks for it takes the level from the last path segment of the exchange the
		// audit is walking, so each level's audit drives its own view.
		if t.LevelText == "" && t.LevelFromPath {
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
