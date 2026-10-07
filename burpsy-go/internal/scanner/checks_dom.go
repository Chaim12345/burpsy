package scanner

// Wired DOM-based evaluators, driven by internal/domexec.
//
// # Which rows are here, and which are deliberately not
//
// A row is wired here only when one of domexec's instrumented sinks is the sink its family is
// defined by. That list has since grown to cover every family below — WebSQL executeSql,
// document.evaluate, JSON.parse, FileReader, the RegExp constructor and anchor href were all added
// for exactly that reason, and this comment used to say those families stay declined, which stopped
// being true when they were instrumented.
//
// That restraint is the point. Wiring a row whose sink is not instrumented produces a check
// that can never fire, and a permanently silent check is worse than an honest decline: it
// looks like coverage in every report that counts runnable checks.
//
// # DOM clobbering: the one DOM Invader attack type with no row here, on purpose
//
// DOM Invader's set (dom-invader/settings/attack-types.html) is covered by the families below
// except clobbering, and clobbering has no row for a structural reason, not an oversight: its
// observable is a NAMED PROPERTY READ (window.someId resolving to an injected element), which
// is identifier resolution the ES engine cannot model — named access is a DOM behaviour — and
// is not one of domexec's instrumented sinks either. Burp places the detection in the DOM
// Invader browser extension, not the scanner (no catalog row, no issue-descriptions page, zero
// clobber strings in the binary). The disposition is stated in docs/SCANNER-COVERAGE.md so the
// catalog's coverage numbers are never read as including it.
//
// # Why a missing browser is an error
//
// ObserveTaint on no browser observes nothing, and nothing is indistinguishable from a clean
// page. Every runner here returns the capability error instead, so the audit engine counts a
// refusal rather than recording a page as safe that was never loaded.

import (
	"context"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

func domChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckDOM }

// domFamily binds one catalog row family to the sinks that define it.
type domFamily struct {
	// Row is the "(DOM-based)" catalog name; variants are derived from it.
	Row   string
	Sinks []domexec.SinkKind
	// Severity for the reflected/DOM-based variants.
	Severity string
	// Note is appended to the finding when the instrumented sink is an approximation of
	// the family's true sink, so a reader is told rather than left to assume.
	Note string
}

// domFamilies is the mapping. Every sink named here exists in domexec's sinkTags (or is
// SinkLocationAssign, which domexec observes through frame navigation instead).
var domFamilies = []domFamily{
	{
		Row:      "Cross-site scripting (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkInnerHTML, domexec.SinkDocumentWrite, domexec.SinkJQueryHtml, domexec.SinkScriptSrc},
		Severity: "high",
	},
	{
		Row:      "JavaScript injection (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkEval, domexec.SinkFunctionCtor, domexec.SinkSetTimeoutString},
		Severity: "high",
	},
	{
		Row:      "Open redirection (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkLocationAssign},
		Severity: "low",
	},
	{
		Row:      "WebSocket URL poisoning (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkWebSocketURL},
		Severity: "medium",
	},
	{
		Row:      "HTML5 storage manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkLocalStorage, domexec.SinkSessionStorage},
		Severity: "low",
	},
	{
		Row:      "HTML5 web message manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkPostMessage},
		Severity: "low",
	},
	{
		Row:      "Cookie manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkCookie},
		Severity: "low",
	},
	{
		Row:      "Document domain manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkDocumentDomain},
		Severity: "medium",
	},
	{
		Row:      "Ajax request header manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkAjaxHeader, domexec.SinkXHROpen},
		Severity: "low",
		Note:     "observed at XMLHttpRequest.setRequestHeader, the family's own sink; XHROpen is kept as a second signal because a tainted URL built alongside a tainted header is the same code path, but a header-only flow no longer goes unreported",
	},
	{
		Row:      "DOM data manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkXHROpen, domexec.SinkPostMessage},
		Severity: "low",
	},
	// Families below became expressible once their sinks were instrumented; before that
	// they were declined rather than wired, because a row whose sink is unwrapped can never
	// fire and would score as coverage anyway.
	{
		Row:      "Client-side SQL injection (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkWebSQL},
		Severity: "medium",
		Note:     "observed at SQLTransaction.executeSql; WebSQL is deprecated in Chrome, so a page reaching this sink is unusual and worth confirming by hand",
	},
	{
		Row:      "Client-side XPath injection (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkXPathEvaluate},
		Severity: "medium",
	},
	{
		Row:      "Client-side JSON injection (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkJSONParse},
		Severity: "low",
	},
	{
		Row:      "Link manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkAnchorHref},
		Severity: "low",
	},
	{
		Row:      "Denial of service (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkRegExpCtor},
		Severity: "low",
		Note:     "observed as a RegExp built from tainted input, the catastrophic-backtracking vector; a tainted pattern is the precondition, not a demonstrated hang",
	},
	{
		Row:      "Local file path manipulation (DOM-based)",
		Sinks:    []domexec.SinkKind{domexec.SinkFileRead},
		Severity: "medium",
	},
}

// domVariant is which of the three catalog spellings a finding belongs to, decided by where
// the tainted value came from rather than by the sink.
type domVariant int

const (
	// domVariantDOM is taint the attacker places in the URL directly: the server never
	// sees it, which is what makes the row "(DOM-based)".
	domVariantDOM domVariant = iota
	// domVariantReflected is taint the server echoed into the page before script read it.
	domVariantReflected
	// domVariantStored is taint the application persisted and later rendered.
	domVariantStored
)

// rowFor turns a family's base row name into the variant spelling used by the catalog.
func (f domFamily) rowFor(v domVariant) string {
	switch v {
	case domVariantReflected:
		return strings.Replace(f.Row, "(DOM-based)", "(reflected DOM-based)", 1)
	case domVariantStored:
		return strings.Replace(f.Row, "(DOM-based)", "(stored DOM-based)", 1)
	}
	return f.Row
}

// domSourcesForVariant is the source set that establishes each variant.
//
// The URL-borne sources prove a "(DOM-based)" flow because the payload never reaches the
// server. document.referrer and window.name are the cross-page carriers Burp uses for the
// reflected variant. The stored variant is not established by a source at all — it needs a
// canary planted in an earlier exchange, which is why it is driven separately.
func domSourcesForVariant(v domVariant) []domexec.SourceKind {
	switch v {
	case domVariantDOM:
		return []domexec.SourceKind{domexec.SourceLocationHash, domexec.SourceLocationSearch}
	case domVariantReflected:
		return []domexec.SourceKind{domexec.SourceReferrer, domexec.SourceWindowName, domexec.SourcePostMessage}
	}
	return nil
}

// domCanary mints the marker planted in a source. Alphanumeric so nothing re-encodes it, and
// per-call random so a marker stored by an earlier scan cannot poison a later baseline.
func domCanary(prefix string) string {
	return "bsydom" + prefix + newProbeCanary("")
}

// observeDOM loads the page once per source and returns every observation, caching per
// (exchange, source) so the sixteen families sharing a source share one page load.
func observeDOM(ctx context.Context, cc *CheckContext, sources []domexec.SourceKind) ([]domexec.Observation, error) {
	browser, err := cc.Browser(ctx)
	if err != nil {
		return nil, err
	}
	target := exchangeURL(cc.Exchange)
	var all []domexec.Observation
	for i, source := range sources {
		obs, err := cc.Scanner.observeTaintCached(ctx, browser, cc.Exchange.ID, target, source, i)
		if err != nil {
			return all, fmt.Errorf("observing %s: %w", source, err)
		}
		all = append(all, obs...)
	}
	return all, nil
}

func (s *ActiveScanner) observeTaintCached(ctx context.Context, browser *domexec.Browser,
	id core.ExchangeID, target string, source domexec.SourceKind, idx int) ([]domexec.Observation, error) {

	key := fmt.Sprintf("%d|%s", id, source)
	s.domObsMu.Lock()
	if obs, ok := s.domObs[key]; ok {
		s.domObsMu.Unlock()
		return obs, nil
	}
	s.domObsMu.Unlock()

	obs, err := browser.ObserveTaint(ctx, target, source, domCanary(fmt.Sprintf("%d", idx)))
	if err != nil {
		return obs, err
	}
	s.domObsMu.Lock()
	if s.domObs == nil {
		s.domObs = map[string][]domexec.Observation{}
	}
	s.domObs[key] = obs
	s.domObsMu.Unlock()
	return obs, nil
}

// domCheck builds a runner for one family/variant pair.
func domCheck(f domFamily, v domVariant) CheckRunner {
	row := f.rowFor(v)
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Exchange == nil {
			return nil, nil
		}
		sources := domSourcesForVariant(v)
		if len(sources) == 0 {
			// The stored variant has no URL-borne source; it is driven by the ledger.
			return domStoredCheck(ctx, cc, f, row)
		}
		obs, err := observeDOM(ctx, cc, sources)
		if err != nil {
			return nil, err
		}
		for _, sink := range f.Sinks {
			hits := domexec.ObservationsForSink(obs, sink)
			if len(hits) == 0 {
				continue
			}
			return []*Finding{buildDOMFinding(cc, row, f, hits[0])}, nil
		}
		return nil, nil
	}
}

// domStoredCheck confirms a stored DOM flow: a value this exchange persisted that a page's own
// script later fed to one of this family's sinks.
//
// # Why it plants, and why it cannot answer immediately
//
// The check owns both halves of the lifecycle, exactly as the non-DOM stored rows do. It plants
// into this exchange's own inputs (once, however many stored rows audit it), and the sighting can
// only exist afterwards, on some other page, after a browser has run that page's script. So it
// defers: FinishScan's render pass produces the evidence and the pending claim is asked again.
//
// # What was wrong before
//
// The previous implementation asked whether the rendered DOM merely CONTAINED an outstanding
// canary, ignoring f.Sinks entirely. Every one of the sixteen families shares that condition, so a
// single stored value displayed anywhere on a page would have fired all sixteen rows at once - and
// fired them just as readily against a page that escapes the value into text, which is the safe
// behaviour these rows exist to distinguish from. It also read SecondOrderObservations(), which
// only the raw-HTTP pass ever filled, so in practice it could not fire at all. Both halves are
// replaced here: the ledger's own sink sightings decide the row, and each family sees only its own
// sinks.
func domStoredCheck(ctx context.Context, cc *CheckContext, f domFamily, row string) ([]*Finding, error) {
	ledger, err := cc.StoredLedger()
	if err != nil {
		return nil, err
	}
	// Asked for up front rather than at resolution time. A scan with no browser will never render
	// anything, and a claim deferred into that scan would retire as outstanding with no reason
	// attached; the capability error names the reason now.
	if _, err := cc.Browser(ctx); err != nil {
		return nil, err
	}
	if ledger.ClaimPlanting(cc.Exchange.ID) {
		if _, err := PlantStoredCanaries(ctx, cc); err != nil {
			return nil, err
		}
	}
	if finding := domStoredFinding(cc, f, row); finding != nil {
		// A render pass has already run in this scan - the live-proxy ordering, where planting and
		// rendering happened during an earlier audit.
		return []*Finding{finding}, nil
	}
	return nil, deferDOMStoredClaim(cc, f, row)
}

// domStoredFinding looks for a sink sighting belonging to THIS exchange's plantings and to this
// family's sinks.
//
// Both filters are load-bearing. Without the origin filter the scan-wide sighting list would let
// one vulnerable page's flow satisfy every later stored-DOM audit, safe endpoints included - the
// same ledger bleed deferStoredClaim documents. Without the sink filter every family would report
// every flow.
func domStoredFinding(cc *CheckContext, f domFamily, row string) *Finding {
	for _, sighting := range cc.Scanner.domStoredSightings() {
		if sighting.Canary.Origin != cc.Exchange.ID {
			continue
		}
		if !domFamilyOwnsSink(f, sighting.Observation.Sink) {
			continue
		}
		detail := fmt.Sprintf("a value submitted to %s (parameter %q) in exchange %d is fetched by script on %s "+
			"and passed to the %s sink", sighting.Canary.OriginPath, sighting.Canary.InsertionPoint,
			sighting.Canary.Origin, sighting.SeenPath, sighting.Observation.Sink)
		if f.Note != "" {
			detail += ". " + f.Note
		}
		if frame := firstStackFrame(sighting.Observation.StackTrace); frame != "" {
			detail += fmt.Sprintf(" (stack: %s)", frame)
		}
		return buildHeaderFinding(cc, row, f.Severity, "firm",
			fmt.Sprintf("%s -> %s: %s", sighting.Canary.Token, sighting.Observation.Sink,
				sighting.Observation.Argument), detail)
	}
	return nil
}

func domFamilyOwnsSink(f domFamily, sink domexec.SinkKind) bool {
	for _, s := range f.Sinks {
		if s == sink {
			return true
		}
	}
	return false
}

// deferDOMStoredClaim hands the row to the pending registry, to be asked again once the browser
// has rendered the pages that might carry this exchange's canaries into a sink.
func deferDOMStoredClaim(cc *CheckContext, f domFamily, row string) error {
	planted := cc.Scanner.stored.CanariesFrom(cc.Exchange.ID)
	if len(planted) == 0 {
		// Nothing was planted here - no inputs to plant into. Nothing was suppressed, so a clean
		// result is the truth rather than an unanswered claim.
		return nil
	}
	deadline := nowUTC().Add(DefaultPendingDeadline)
	if cc.Config != nil && cc.Config.PendingDeadline > 0 {
		deadline = nowUTC().Add(cc.Config.PendingDeadline)
	}
	err := cc.Scanner.Pending().Register(PendingItem{
		Row:      row,
		Exchange: cc.Exchange.ID,
		Deadline: deadline,
		What: fmt.Sprintf("%d canary(ies) planted in %s, awaiting a page whose script carries one into a %s sink",
			len(planted), cc.Exchange.Path, f.Row),
	}, func(context.Context) (*Finding, bool, error) {
		if finding := domStoredFinding(cc, f, row); finding != nil {
			return finding, true, nil
		}
		return nil, false, nil
	})
	if err != nil {
		return err
	}
	return fmt.Errorf("%s: canaries planted, no rendered sink sighting yet: %w", row, errCheckInconclusive)
}

func buildDOMFinding(cc *CheckContext, row string, f domFamily, o domexec.Observation) *Finding {
	detail := fmt.Sprintf("data from %s reached the %s sink", o.Source, o.Sink)
	if f.Note != "" {
		detail += ". " + f.Note
	}
	if o.StackTrace != "" {
		detail += fmt.Sprintf(" (stack: %s)", firstStackFrame(o.StackTrace))
	}
	return buildHeaderFinding(cc, row, f.Severity, "firm",
		fmt.Sprintf("%s -> %s: %s", o.Source, o.Sink, o.Argument), detail)
}

// firstStackFrame trims a JS stack to its first frame, which is where the sink was called.
func firstStackFrame(stack string) string {
	for _, line := range strings.Split(stack, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Error") {
			return line
		}
	}
	return ""
}

// DOMCheckDescriptors returns the wired DOM checks: every family above in its DOM-based,
// reflected and stored spellings.
func DOMCheckDescriptors() []CheckDescriptor {
	var out []CheckDescriptor
	for _, f := range domFamilies {
		for _, v := range []domVariant{domVariantDOM, domVariantReflected, domVariantStored} {
			row := f.rowFor(v)
			if _, ok := ByName(row); !ok {
				// The catalog has no such spelling for this family; skip rather than
				// panic, so a family with only two variants is expressible.
				continue
			}
			scope := DispatchScopePerUrl
			if v == domVariantStored {
				scope = DispatchScopeStoredPerInsertionPoint
			}
			out = append(out, nativeDescriptor(row, scope, domChecksEnabled, domCheck(f, v)))
		}
	}
	return out
}
