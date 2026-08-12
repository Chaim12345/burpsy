// Static DOM taint analysis: trace JavaScript in a captured response from a controllable source to
// a dangerous sink, and report the catalogued DOM-based issue that sink implies.
//
// This closes roadmap Phase 11 (DOM-01, DOM-02, DOM-03). It is new work, not a port — the Rust
// original has no DOM analysis either.
//
// # What this is, stated before what it finds
//
// This is a lexical pass with one-variable-deep taint propagation. It is not a JavaScript parser,
// has no scope analysis, no control flow, and no type information. That choice is deliberate — a
// real parser is a module dependency this repo does not carry and a project of its own — but it
// means the honest framing has to come first, because **an analysis that looks exhaustive and is
// not would be worse than no analysis at all**. Every finding it raises is therefore reported at
// `tentative` confidence, and Phase 12 (dynamic confirmation) exists precisely to promote or
// retire those candidates against a real browser.
//
// ## What it will miss
//
//   - **Computed property access.** `el["inner"+"HTML"] = t` is a sink write this pass cannot see.
//     When it can tell that the property was computed it says so — DOMUnresolvedComputedAccess —
//     but a computed access it cannot even recognise as one is simply invisible.
//   - **Aliasing it cannot track.** Taint moves through direct `x = <expr>` assignments only.
//     Through an object property (`o.v = location.hash`), an array element, a function return
//     value, a parameter, a closure, a promise, or an event-handler argument, it is lost.
//   - **`eval` and the Function constructor.** Code built at runtime is not analysed. Their
//     *presence* is recorded (DOMUnresolvedDynamicCode) so a caller knows the pass went blind, but
//     nothing inside the constructed string is examined.
//   - **Minified and obfuscated code.** Minification is survivable — `a=location.hash;b(a)` traces
//     fine — and is flagged (DOMUnresolvedMinified) because everything else about such a script is
//     less legible. Genuine obfuscation (string-table indirection, packed payloads) defeats it
//     entirely and silently.
//   - **Template literals.** A `${...}` substitution is not evaluated; the literal is treated as
//     opaque text, so taint entering through one is lost.
//   - **Flow order and reassignment.** Taint is propagated without regard to statement order, and
//     is never cleared. `x = location.hash; x = "safe"; el.innerHTML = x` is over-reported, and a
//     sink textually above the assignment that taints its input is still reported.
//   - **Framework sinks.** React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrustHtml`,
//     Vue `v-html` and every templating engine's raw-output directive are not in the tables.
//   - **External scripts.** A `<script src=...>` has no body in this response. It is recorded as a
//     script that was not analysed (DOMScriptSkipExternalSrc), never counted as clean.
//   - **Regular expression literals.** The splitter distinguishes a regex literal from a division
//     with the conventional preceding-token heuristic. It is a heuristic; a regex it misreads can
//     swallow or split a statement, which loses flows rather than inventing them.
//
// ## Three outcomes, never two
//
// The reason this pass is worth having despite the list above is that it does not collapse
// "no problem" and "no idea" into one answer, which is the same defect CoverageTracker exists to
// fix for the passive check set. Every source/sink pair it examines lands in exactly one of:
//
//	Flows       — reported. A catalogued issue, with the source, the sink and the hops named.
//	Suppressed  — deliberately not reported, and recorded anyway: a recognised sanitizer accepted
//	              for this sink class (DOM-02), or a sink that cannot execute or navigate.
//	Unresolved  — no verdict either way. The pass found a sink and could not trace its input.
//	              This is *not* a safe flow and is never presented as one.
//
// A recognised operation that is *not* accepted for this sink class — HTML-escaping a value on its
// way to a navigation sink, `escape()`, a hand-rolled `.replace()` — is reported as a finding with
// the operation and the reason named in its evidence. Failing towards reporting is the right
// direction there: the code's author evidently believed they had a defence, and the scanner
// disagreeing needs to say why rather than going quiet.
//
// # The budget, and why it cannot be hit silently (DOM-03)
//
// DOMBudget bounds script bytes, script count, statements scanned, propagation rounds, and the size
// of each result list. Every bound that is hit appends a DOMBudgetStop to DOMBudgetReport.Stops, and
// DOMBudgetReport.Truncated is *derived from that slice* rather than being a separate flag — so
// there is no way to stop early without saying which bound stopped you. DOMAnalysis.Complete() is
// false and DOMAnalysis.Caveat() returns a non-empty line whenever any stop fired, so a truncated
// analysis can never be rendered as a clean "no findings". This mirrors DiffResult.Truncated in
// internal/tools/comparer.go: a capped result must SAY it was capped.
package scanner

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- budget --------------------------------------------------------------------------------

// DOMBudget bounds one item's analysis. Zero fields are replaced with the defaults by normalise, so
// a caller can override one bound without restating the rest.
type DOMBudget struct {
	// MaxScriptBytes caps the total script text examined for the whole item.
	MaxScriptBytes int
	// MaxScripts caps how many script bodies are examined.
	MaxScripts int
	// MaxStatements caps statements scanned, summed across every round and every script. This is
	// the bound that actually governs cost: work is O(statements x rounds x table size).
	MaxStatements int
	// MaxPropagationRounds caps how many times taint is folded forward.
	//
	// One round already resolves any chain written in order, because a round walks the statements
	// in order and each link sees the previous one's result. What extra rounds buy is chains that
	// read *backwards* — a sink or an assignment textually above the statement that taints its
	// input, which is ordinary in code organised as helpers-after-use. So this caps how far
	// backwards a chain can be followed, not its total length.
	MaxPropagationRounds int
	// MaxFlows, MaxSuppressed and MaxUnresolved cap each result list. Overflow is dropped and
	// counted, never appended past the cap and never dropped without a stop.
	MaxFlows      int
	MaxSuppressed int
	MaxUnresolved int
}

// DefaultDOMBudget is the bound used when a caller does not supply one.
//
// 512 KiB of script text and 20 000 statements is a few tens of milliseconds and comfortably covers
// an ordinary page including its bundled framework; four propagation rounds covers the assignment
// chains that appear in hand-written code without letting a generated file iterate for free.
func DefaultDOMBudget() DOMBudget {
	return DOMBudget{
		MaxScriptBytes:       512 * 1024,
		MaxScripts:           64,
		MaxStatements:        20_000,
		MaxPropagationRounds: 4,
		MaxFlows:             100,
		MaxSuppressed:        200,
		MaxUnresolved:        200,
	}
}

func (b DOMBudget) normalise() DOMBudget {
	d := DefaultDOMBudget()
	if b.MaxScriptBytes <= 0 {
		b.MaxScriptBytes = d.MaxScriptBytes
	}
	if b.MaxScripts <= 0 {
		b.MaxScripts = d.MaxScripts
	}
	if b.MaxStatements <= 0 {
		b.MaxStatements = d.MaxStatements
	}
	if b.MaxPropagationRounds <= 0 {
		b.MaxPropagationRounds = d.MaxPropagationRounds
	}
	if b.MaxFlows <= 0 {
		b.MaxFlows = d.MaxFlows
	}
	if b.MaxSuppressed <= 0 {
		b.MaxSuppressed = d.MaxSuppressed
	}
	if b.MaxUnresolved <= 0 {
		b.MaxUnresolved = d.MaxUnresolved
	}
	return b
}

// DOMBudgetStop names one bound that was hit. Every value here is a reason an analysis is
// incomplete, and each carries the one line an operator can act on.
type DOMBudgetStop int

const (
	// DOMStopScriptBytes means the item carried more script text than the byte cap allows.
	DOMStopScriptBytes DOMBudgetStop = iota
	// DOMStopScripts means the item carried more script bodies than the script cap allows.
	DOMStopScripts
	// DOMStopStatements means scanning ran out of statement budget.
	DOMStopStatements
	// DOMStopPropagationRounds means the final permitted round was still discovering new tainted
	// variables, so the assignment chain continued past where tracing stopped. It does *not* fire
	// when propagation reached a fixpoint inside the budget — a converged analysis is complete.
	DOMStopPropagationRounds
	// DOMStopFlows means more flows were found than the flow cap allows.
	DOMStopFlows
	// DOMStopSuppressed means more suppressed flows were found than that cap allows.
	DOMStopSuppressed
	// DOMStopUnresolved means more unresolved sinks were found than that cap allows.
	DOMStopUnresolved
)

// DOMBudgetStopAll is every stop, so a caller can render a legend without hard-coding the set.
var DOMBudgetStopAll = [7]DOMBudgetStop{
	DOMStopScriptBytes,
	DOMStopScripts,
	DOMStopStatements,
	DOMStopPropagationRounds,
	DOMStopFlows,
	DOMStopSuppressed,
	DOMStopUnresolved,
}

// Explanation is one line an operator can act on.
func (s DOMBudgetStop) Explanation() string {
	switch s {
	case DOMStopScriptBytes:
		return "the item carries more script text than the per-item byte budget; the remainder was not analysed"
	case DOMStopScripts:
		return "the item carries more script bodies than the per-item script budget; the remainder was not analysed"
	case DOMStopStatements:
		return "the statement budget ran out; the remaining statements were not scanned"
	case DOMStopPropagationRounds:
		return "taint was still spreading when the propagation-round budget ran out; longer assignment chains were not followed"
	case DOMStopFlows:
		return "more source-to-sink flows were found than the flow budget reports; the excess was dropped"
	case DOMStopSuppressed:
		return "more sanitized or safe-sink flows were found than the budget reports; the excess was dropped"
	case DOMStopUnresolved:
		return "more untraceable sinks were found than the budget reports; the excess was dropped"
	}
	return "unknown budget stop"
}

func (s DOMBudgetStop) String() string {
	switch s {
	case DOMStopScriptBytes:
		return "script-bytes"
	case DOMStopScripts:
		return "scripts"
	case DOMStopStatements:
		return "statements"
	case DOMStopPropagationRounds:
		return "propagation-rounds"
	case DOMStopFlows:
		return "flows"
	case DOMStopSuppressed:
		return "suppressed"
	case DOMStopUnresolved:
		return "unresolved"
	}
	return "unknown"
}

// DOMBudgetReport is what the budget allowed, what was consumed, and which bounds stopped the pass.
type DOMBudgetReport struct {
	// Budget is the effective budget after defaults were filled in.
	Budget DOMBudget `json:"budget"`
	// ScriptBytes, Scripts, Statements and Rounds are what was actually consumed.
	ScriptBytes int `json:"script_bytes"`
	Scripts     int `json:"scripts"`
	Statements  int `json:"statements"`
	Rounds      int `json:"rounds"`
	// Stops names every bound that was hit, in the order first hit, each at most once. Truncated
	// is derived from this slice, so a stop can never be recorded without surfacing, and the pass
	// can never stop early without recording one.
	Stops []DOMBudgetStop `json:"stops,omitempty"`
	// FlowsDropped, SuppressedDropped and UnresolvedDropped count results discarded at a list cap.
	// Honest counting: a dropped result is counted, never silently absent.
	FlowsDropped      int `json:"flows_dropped"`
	SuppressedDropped int `json:"suppressed_dropped"`
	UnresolvedDropped int `json:"unresolved_dropped"`
}

// Truncated reports whether any bound was hit. Derived, never stored.
func (r DOMBudgetReport) Truncated() bool { return len(r.Stops) > 0 }

// Hit reports whether one specific bound was hit.
func (r DOMBudgetReport) Hit(stop DOMBudgetStop) bool {
	for _, s := range r.Stops {
		if s == stop {
			return true
		}
	}
	return false
}

func (r *DOMBudgetReport) record(stop DOMBudgetStop) {
	if r.Hit(stop) {
		return
	}
	r.Stops = append(r.Stops, stop)
}

// ---- results -------------------------------------------------------------------------------

// DOMScriptRef identifies one script body inside the item, for evidence.
type DOMScriptRef struct {
	// Origin says where the body came from: the response body itself, an inline <script>, or an
	// inline event-handler attribute.
	Origin string `json:"origin"`
	// Line is the 1-based line in the response body where the body starts.
	Line int `json:"line"`
}

// DOMScriptSkipReason says why a script body present in the item was not analysed. These are
// coverage gaps, kept apart from DOMUnresolved (which is about a sink whose input could not be
// traced) because "did not look" and "looked and could not tell" are different claims.
type DOMScriptSkipReason int

const (
	// DOMScriptSkipExternalSrc means the <script> references an external URL, so its body is not
	// in this response at all.
	DOMScriptSkipExternalSrc DOMScriptSkipReason = iota
	// DOMScriptSkipNonExecutableType means the <script> carries a type the browser will not
	// execute as JavaScript (a JSON island, a client-side template).
	DOMScriptSkipNonExecutableType
	// DOMScriptSkipOverBudget means the byte or script budget was already exhausted.
	DOMScriptSkipOverBudget
)

func (r DOMScriptSkipReason) Explanation() string {
	switch r {
	case DOMScriptSkipExternalSrc:
		return "the script is loaded from an external URL, so its body is not in this response"
	case DOMScriptSkipNonExecutableType:
		return "the script element carries a type the browser does not execute as JavaScript"
	case DOMScriptSkipOverBudget:
		return "the per-item script budget was already exhausted"
	}
	return "unknown script skip"
}

// DOMScriptSkip is one script body present in the item and not analysed.
type DOMScriptSkip struct {
	Script DOMScriptRef        `json:"script"`
	Reason DOMScriptSkipReason `json:"reason"`
	// Detail is the concrete particular — the src URL, the type attribute — or empty.
	Detail string `json:"detail,omitempty"`
}

// unreadScriptReason renders the unread-script half of a Caveat.
//
// It names the reasons rather than only counting, because "3 scripts were not read" does not tell an
// operator whether to care: an external src means the page's logic is elsewhere and this pass could
// never see it, while a non-executable type means there was nothing to read. Those call for different
// responses, so the caveat distinguishes them.
func unreadScriptReason(n int, skipped []DOMScriptSkip) string {
	seen := make(map[DOMScriptSkipReason]int, 2)
	for _, sk := range skipped {
		seen[sk.Reason]++
	}
	parts := make([]string, 0, len(seen))
	for _, r := range []DOMScriptSkipReason{DOMScriptSkipExternalSrc, DOMScriptSkipNonExecutableType} {
		if c, ok := seen[r]; ok {
			parts = append(parts, strconv.Itoa(c)+" "+r.Explanation())
		}
	}
	// Any reason added later without being listed above still gets counted rather than vanishing.
	counted := 0
	for _, c := range seen {
		counted += c
	}
	if counted < n {
		parts = append(parts, strconv.Itoa(n-counted)+" for an unnamed reason")
	}
	return strconv.Itoa(n) + " script(s) present in this item were not read (" + strings.Join(parts, ", ") + ")"
}

// DOMFlow is one traced source-to-sink flow that is reported as a finding.
type DOMFlow struct {
	// Issue is the full catalogued issue name, base plus variant.
	Issue string `json:"issue"`
	// IssueBase is the name without the variant suffix, as it appears in the sink table.
	IssueBase string `json:"issue_base"`
	// Source is the table entry matched; SourceExpr is the text matched in the script.
	Source     DOMSource `json:"source"`
	SourceExpr string    `json:"source_expr"`
	// Sink is the table entry matched.
	Sink DOMSink `json:"sink"`
	// Via names the intermediate variables taint moved through, source-order. Empty for a flow
	// where source and sink share one statement.
	Via []string `json:"via,omitempty"`
	// Script and Line locate the sink statement.
	Script DOMScriptRef `json:"script"`
	Line   int          `json:"line"`
	// Statement is the sink statement text, clipped.
	Statement string `json:"statement"`
	// Caveats names recognised operations on this path that were *not* accepted as a defence for
	// this sink class, each with the reason. Non-empty means the flow was reported despite an
	// apparent defence, and the report must say why.
	Caveats []string `json:"caveats,omitempty"`
}

// DOMSuppressReason says why a traced flow was deliberately not reported.
type DOMSuppressReason int

const (
	// DOMSuppressReasonSanitizer means every recognised operation needed was present: a sanitizer
	// accepted for this sink class sits on the path. This is DOM-02.
	DOMSuppressReasonSanitizer DOMSuppressReason = iota
	// DOMSuppressReasonSafeSink means the value was written somewhere that cannot execute or
	// navigate — textContent and friends.
	DOMSuppressReasonSafeSink
)

func (r DOMSuppressReason) String() string {
	switch r {
	case DOMSuppressReasonSanitizer:
		return "sanitized"
	case DOMSuppressReasonSafeSink:
		return "safe sink"
	}
	return "unknown suppression"
}

// DOMSuppressed is a flow the pass traced and decided not to report. Recorded rather than dropped:
// "we looked, we found a real dataflow, and here is the operation we accepted as a defence" is a
// different and more useful statement than silence.
type DOMSuppressed struct {
	Reason DOMSuppressReason `json:"reason"`
	// Issue is the catalogued issue this flow would have been reported as, when the suppression is
	// a sanitizer. Empty for a safe sink, which has no sink-table entry and therefore no issue.
	Issue      string    `json:"issue,omitempty"`
	Source     DOMSource `json:"source"`
	SourceExpr string    `json:"source_expr"`
	// Sink is the matched property or callee text.
	Sink string `json:"sink"`
	// By is the sanitizer or safe sink accepted, and Why is its recorded justification.
	By        string       `json:"by"`
	Why       string       `json:"why"`
	Via       []string     `json:"via,omitempty"`
	Script    DOMScriptRef `json:"script"`
	Line      int          `json:"line"`
	Statement string       `json:"statement"`
}

// DOMUnresolvedReason says what the pass could not resolve.
type DOMUnresolvedReason int

const (
	// DOMUnresolvedUntracedValue means a sink is fed by an expression carrying at least one
	// identifier whose origin this pass could not trace. It is neither a finding nor a clean
	// result: the input may or may not be attacker-controlled.
	DOMUnresolvedUntracedValue DOMUnresolvedReason = iota
	// DOMUnresolvedComputedAccess means the assignment target was computed, so which property is
	// written is not statically known — and a tainted value reaches it.
	DOMUnresolvedComputedAccess
	// DOMUnresolvedDynamicCode means the script builds code at runtime (eval, the Function
	// constructor, with), so anything downstream of that construct is outside this pass.
	DOMUnresolvedDynamicCode
	// DOMUnresolvedMinified means the script looks minified, so an absence of findings in it
	// carries less weight than it would in legible source.
	DOMUnresolvedMinified
)

func (r DOMUnresolvedReason) Explanation() string {
	switch r {
	case DOMUnresolvedUntracedValue:
		return "a sink is fed by a value this pass could not trace to its origin; it is not known to be safe"
	case DOMUnresolvedComputedAccess:
		return "a tainted value is written to a computed property, so the sink that receives it is not statically known"
	case DOMUnresolvedDynamicCode:
		return "the script builds code at runtime, so this pass is blind past that construct"
	case DOMUnresolvedMinified:
		return "the script looks minified, so an absence of findings in it is weaker evidence than in legible source"
	}
	return "unknown unresolved reason"
}

// DOMUnresolved is one thing the pass could not decide. Never a finding, never counted as clean.
type DOMUnresolved struct {
	Reason DOMUnresolvedReason `json:"reason"`
	// Sink is the matched property or callee text, when the entry is about a specific sink.
	Sink string `json:"sink,omitempty"`
	// Detail is the concrete particular: the untraced expression, the construct found.
	Detail    string       `json:"detail,omitempty"`
	Script    DOMScriptRef `json:"script"`
	Line      int          `json:"line"`
	Statement string       `json:"statement,omitempty"`
}

// DOMSkip is why the pass never ran on an item at all. Same discipline as ScanSkip in coverage.go:
// each of these once collapsed into an empty result, indistinguishable from "analysed and clean".
type DOMSkip int

const (
	// DOMSkipExchangeNotFound means there was no exchange to analyse.
	DOMSkipExchangeNotFound DOMSkip = iota
	// DOMSkipOutOfScope means the exchange falls outside the engagement scope.
	DOMSkipOutOfScope
	// DOMSkipResponseNotFound means the exchange has no stored response.
	DOMSkipResponseNotFound
	// DOMSkipEmptyBody means the response has no body.
	DOMSkipEmptyBody
	// DOMSkipNotScriptBearing means the body is neither HTML nor JavaScript and carries no
	// recognisable script, so there was nothing for this pass to read.
	DOMSkipNotScriptBearing
)

// DOMSkipAll is every skip, in the order ScanDOM tests them.
var DOMSkipAll = [5]DOMSkip{
	DOMSkipExchangeNotFound,
	DOMSkipOutOfScope,
	DOMSkipResponseNotFound,
	DOMSkipEmptyBody,
	DOMSkipNotScriptBearing,
}

// Explanation is one line an operator can act on.
func (s DOMSkip) Explanation() string {
	switch s {
	case DOMSkipExchangeNotFound:
		return "there is no exchange to analyse"
	case DOMSkipOutOfScope:
		return "the host is outside the engagement scope"
	case DOMSkipResponseNotFound:
		return "the exchange has no stored response"
	case DOMSkipEmptyBody:
		return "the response has no body"
	case DOMSkipNotScriptBearing:
		return "the response body is neither HTML nor JavaScript and carries no recognisable script"
	}
	return "unknown skip"
}

// DOMAnalysis is the whole outcome of one static DOM pass over one item.
//
// Findings are only reachable through this value's Findings method, so a caller holding findings is
// necessarily also holding Budget and can see whether the pass finished. That is the structural
// half of DOM-03: there is no path that yields findings while hiding truncation.
type DOMAnalysis struct {
	// Skip is non-nil exactly when the pass never ran, and then every other field is zero. A nil
	// Skip with no Flows means analysed and nothing reportable found — the distinction this type
	// exists to preserve.
	Skip *DOMSkip `json:"skip,omitempty"`
	// ExchangeID, URL and Method identify the item, for the findings this analysis produces. Zero
	// when the analysis was run directly on a body rather than on a stored exchange.
	ExchangeID core.ExchangeID `json:"exchange_id,omitempty"`
	URL        string          `json:"url,omitempty"`
	Method     string          `json:"method,omitempty"`
	// Scripts are the bodies actually analysed; SkippedScripts are the bodies present and not
	// analysed. The two together account for every script found.
	Scripts        []DOMScriptRef  `json:"scripts,omitempty"`
	SkippedScripts []DOMScriptSkip `json:"skipped_scripts,omitempty"`
	// Flows, Suppressed and Unresolved are the three-way partition documented in the package
	// comment. Only Flows becomes findings.
	Flows      []DOMFlow       `json:"flows,omitempty"`
	Suppressed []DOMSuppressed `json:"suppressed,omitempty"`
	Unresolved []DOMUnresolved `json:"unresolved,omitempty"`
	Budget     DOMBudgetReport `json:"budget"`
}

// Complete reports whether the pass covered the whole item within its budget. False whenever any
// bound was hit — see Caveat for the line to print alongside the findings.
// A script that was present and not read makes the pass incomplete just as surely as a budget stop
// does. This used to consult only the budget, so a page whose every <script> was external — which is
// every modern single-page app — analysed zero bytes of JavaScript and reported Complete() == true
// with an empty Caveat(). That output is byte-identical to "analysed it all, found nothing", which is
// the one claim this type exists to make impossible. SkippedScripts is the evidence and it was being
// collected and then ignored.
func (a DOMAnalysis) Complete() bool {
	return !a.Budget.Truncated() && len(a.SkippedScripts) == 0
}

// Caveat is the line a report must print next to this analysis's findings, or "" when the pass
// finished inside its budget and nothing about it needs qualifying.
//
// Non-empty means the findings are a floor, not a total: there may be more in the part that was not
// reached. A caller rendering findings without consulting this is presenting a truncated result as
// a complete one, which is the exact failure DOM-03 forbids.
func (a DOMAnalysis) Caveat() string {
	if a.Skip != nil {
		return "static DOM analysis did not run: " + a.Skip.Explanation()
	}
	if a.Complete() {
		return ""
	}
	reasons := make([]string, 0, len(a.Budget.Stops)+1)
	for _, s := range a.Budget.Stops {
		reasons = append(reasons, s.Explanation())
	}
	// Unread scripts are named separately from budget stops because they are a different kind of
	// incompleteness and call for a different response: a budget stop means "raise the bound", an
	// unread external script means "this page's logic lives somewhere this pass cannot follow".
	if n := len(a.SkippedScripts); n > 0 {
		reasons = append(reasons, unreadScriptReason(n, a.SkippedScripts))
	}
	return "static DOM analysis is INCOMPLETE for this item, so these findings are a floor and not a total: " +
		strings.Join(reasons, "; ")
}

// Summary formats the analysis for reports and logs. It always states completeness, so the shape of
// the sentence itself carries the DOM-03 answer.
func (a DOMAnalysis) Summary() string {
	if a.Skip != nil {
		return "static DOM analysis skipped: " + a.Skip.Explanation()
	}
	state := "complete"
	if a.Budget.Truncated() {
		state = "INCOMPLETE"
	}
	return fmt.Sprintf(
		"static DOM analysis (%s): %d scripts analysed, %d not analysed, %d statements, %d rounds; %d reported, %d suppressed, %d unresolved",
		state,
		len(a.Scripts), len(a.SkippedScripts),
		a.Budget.Statements, a.Budget.Rounds,
		len(a.Flows), len(a.Suppressed), len(a.Unresolved),
	)
}

// Findings turns the reported flows into scanner findings, drawing the issue name, background and
// remediation from Burp's shipped catalog.
//
// Confidence is always tentative. Static analysis establishes that a path exists in the source, not
// that it is reachable or exploitable — the shipped catalog text for these issues says as much
// itself — and Phase 12's dynamic confirmation is what promotes a candidate. Severity comes from
// the catalog's typical severity for the issue class; when a name does not resolve in the catalog,
// severity is left empty and the evidence says so, rather than this pass inventing one.
func (a DOMAnalysis) Findings() []*Finding {
	out := make([]*Finding, 0, len(a.Flows))
	for _, f := range a.Flows {
		def, known := ByName(f.Issue)
		fin := &Finding{
			Name:       f.Issue,
			Confidence: "tentative",
			Param:      f.SourceExpr,
			URL:        a.URL,
			Method:     a.Method,
			ExchangeID: a.ExchangeID,
			Evidence:   f.evidence(known),
			Timestamp:  time.Now(),
		}
		if known {
			fin.Severity = def.TypicalSeverity
			fin.Description = def.Description
		}
		// EnrichFinding fills Solution from the catalog's shipped remediation. This pass never
		// writes remediation text of its own: invented remediation is invented security advice
		// presented to an operator as authoritative.
		EnrichFinding(fin)
		out = append(out, fin)
	}
	return out
}

// evidence is the trace, written so an operator can find the code without re-running the tool.
func (f DOMFlow) evidence(known bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s) reaches %s", f.SourceExpr, f.Source.Kind, f.Sink.Match)
	if len(f.Via) > 0 {
		fmt.Fprintf(&b, " via %s", strings.Join(f.Via, " -> "))
	}
	fmt.Fprintf(&b, " at %s line %d: %s", f.Script.Origin, f.Line, f.Statement)
	b.WriteString(". Found by static analysis only: the path exists in the source, which is not the same as being reachable or exploitable.")
	for _, c := range f.Caveats {
		b.WriteString(" Reported despite an apparent defence: ")
		b.WriteString(c)
		b.WriteString(".")
	}
	if !known {
		b.WriteString(" This issue name is absent from the shipped catalog, so no typical severity, background or remediation is available for it.")
	}
	return b.String()
}

// ---- entry points --------------------------------------------------------------------------

// ScanDOM runs the static DOM pass over one stored exchange's response.
//
// A method on PassiveScanner so the analysis lives on the scanner a caller already holds, reusing
// its store and its scope judgement exactly as scanBChecks does. It deliberately does not touch
// the passive CoverageTracker: that table is index-aligned with the loaded BCheck set, and folding
// a different check's outcome into it would corrupt the identities coverage.go exists to preserve.
// DOMAnalysis carries its own skip vocabulary instead.
func (s *PassiveScanner) ScanDOM(exchange *core.Exchange) DOMAnalysis {
	if exchange == nil {
		return domSkipped(DOMSkipExchangeNotFound)
	}
	if s.scope != nil && !s.scope.Contains(exchange.Host, exchange.Port, exchange.Path, exchange.TLS) {
		return domSkipped(DOMSkipOutOfScope)
	}
	if exchange.Response == nil {
		return domSkipped(DOMSkipResponseNotFound)
	}
	if s.store == nil {
		return domSkipped(DOMSkipResponseNotFound)
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return domSkipped(DOMSkipResponseNotFound)
	}
	a := AnalyzeDOMDocument(msg.Body(), string(msg.Header("Content-Type")), DOMBudget{})
	a.ExchangeID = exchange.ID
	a.Method = exchange.Method
	a.URL = domURL(exchange)
	return a
}

func domURL(ex *core.Exchange) string {
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, ex.Host, ex.Port, ex.Path)
}

func domSkipped(why DOMSkip) DOMAnalysis {
	return DOMAnalysis{Skip: &why, Budget: DOMBudgetReport{Budget: DefaultDOMBudget()}}
}

// AnalyzeDOMDocument runs the pass over one response body, extracting script bodies from HTML or
// treating the whole body as one script when the content type says JavaScript.
//
// Exported and free of the store so the analysis is testable and reusable on a body from anywhere —
// a crawler, a plugin, a file on disk — not only on a stored exchange.
func AnalyzeDOMDocument(body []byte, contentType string, budget DOMBudget) DOMAnalysis {
	budget = budget.normalise()
	a := DOMAnalysis{Budget: DOMBudgetReport{Budget: budget}}
	if len(body) == 0 {
		return domSkipped(DOMSkipEmptyBody)
	}
	scripts, skips, found := domExtractScripts(body, contentType)
	if !found {
		return domSkipped(DOMSkipNotScriptBearing)
	}
	a.SkippedScripts = skips
	e := &domEngine{budget: budget, res: &a}
	for _, sc := range scripts {
		if !e.admit(sc) {
			continue
		}
		e.analyse(sc)
	}
	return a
}

// AnalyzeDOMScript runs the pass over one script body directly, for callers that already have
// JavaScript in hand.
func AnalyzeDOMScript(src string, budget DOMBudget) DOMAnalysis {
	budget = budget.normalise()
	a := DOMAnalysis{Budget: DOMBudgetReport{Budget: budget}}
	e := &domEngine{budget: budget, res: &a}
	sc := domScriptSrc{ref: DOMScriptRef{Origin: "script", Line: 1}, text: src}
	if e.admit(sc) {
		e.analyse(sc)
	}
	return a
}

// ---- engine --------------------------------------------------------------------------------

type domScriptSrc struct {
	ref  DOMScriptRef
	text string
}

// domEngine holds the per-item mutable state: the budget counters and the taint table.
type domEngine struct {
	budget DOMBudget
	res    *DOMAnalysis
	// taint maps a variable name to what reached it. taintOrder keeps insertion order so lookups
	// and therefore evidence are deterministic; ranging over a Go map would make the reported
	// intermediate variable vary between runs on the same input.
	taint      map[string]domTaint
	taintOrder []string
	// seen deduplicates reported flows: the same source, sink and line found in two propagation
	// rounds is one flow, not two.
	seen map[string]bool
}

// domTaint is what reached a variable, and what happened to it on the way.
type domTaint struct {
	source     DOMSource
	sourceExpr string
	via        []string
	accepted   []DOMSanitizer
	weak       []DOMWeakEncoder
}

// admit charges a script against the byte and script budgets, recording a skip and a stop when
// either is exhausted. Returns false when the script must not be analysed.
func (e *domEngine) admit(sc domScriptSrc) bool {
	if len(e.res.Scripts) >= e.budget.MaxScripts {
		e.res.Budget.record(DOMStopScripts)
		e.res.SkippedScripts = append(e.res.SkippedScripts, DOMScriptSkip{
			Script: sc.ref, Reason: DOMScriptSkipOverBudget,
		})
		return false
	}
	if e.res.Budget.ScriptBytes+len(sc.text) > e.budget.MaxScriptBytes {
		e.res.Budget.record(DOMStopScriptBytes)
		e.res.SkippedScripts = append(e.res.SkippedScripts, DOMScriptSkip{
			Script: sc.ref, Reason: DOMScriptSkipOverBudget,
			Detail: fmt.Sprintf("%d bytes would exceed the %d byte per-item budget", len(sc.text), e.budget.MaxScriptBytes),
		})
		return false
	}
	e.res.Budget.ScriptBytes += len(sc.text)
	e.res.Budget.Scripts++
	e.res.Scripts = append(e.res.Scripts, sc.ref)
	return true
}

// spend charges n statements against the statement budget, returning false once it is exhausted.
func (e *domEngine) spend(n int) bool {
	if e.res.Budget.Statements+n > e.budget.MaxStatements {
		e.res.Budget.record(DOMStopStatements)
		return false
	}
	e.res.Budget.Statements += n
	return true
}

func (e *domEngine) analyse(sc domScriptSrc) {
	if e.taint == nil {
		e.taint = map[string]domTaint{}
		e.seen = map[string]bool{}
	}
	stmts := domSplitStatements(sc.text)
	e.noteScriptShape(sc)

	// Propagation first, then sinks. Doing taint to a fixpoint before looking for sinks makes the
	// pass insensitive to statement order, which over-reports a sink placed above the assignment
	// that taints its input and is the honest trade for having no control flow at all: the
	// alternative, a single forward pass, silently misses every flow into a function declared
	// before its caller.
	//
	// Propagation may spend at most half the statement budget. Without that reserve a script with
	// an expensive taint table would consume the whole budget before a single sink was looked at,
	// and the analysis would come back empty and truncated — technically honest, practically
	// useless. Statements are charged one at a time so a phase cut short still keeps the work it
	// did, rather than discarding a partial pass as if it had never run.
	propCap := e.budget.MaxStatements / 2
	if propCap < 1 {
		propCap = 1
	}
	propSpent := 0
propagation:
	for round := 1; round <= e.budget.MaxPropagationRounds; round++ {
		e.res.Budget.Rounds = round
		added := 0
		for _, st := range stmts {
			if propSpent >= propCap {
				e.res.Budget.record(DOMStopStatements)
				break propagation
			}
			if !e.spend(1) {
				break propagation
			}
			propSpent++
			if e.propagate(st) {
				added++
			}
		}
		if added == 0 {
			break
		}
		if round == e.budget.MaxPropagationRounds {
			// Still discovering taint with no rounds left: the chain continues past here.
			e.res.Budget.record(DOMStopPropagationRounds)
		}
	}

	for _, st := range stmts {
		if !e.spend(1) {
			return
		}
		e.checkSinks(sc, st)
	}
}

// noteScriptShape records the properties of a script that weaken any conclusion drawn from it.
func (e *domEngine) noteScriptShape(sc domScriptSrc) {
	if domLooksMinified(sc.text) {
		e.addUnresolved(DOMUnresolved{
			Reason: DOMUnresolvedMinified, Script: sc.ref, Line: sc.ref.Line,
			Detail: fmt.Sprintf("%d bytes over %d source lines", len(sc.text), strings.Count(sc.text, "\n")+1),
		})
	}
	for _, construct := range []string{"eval(", "new Function(", "with ("} {
		if strings.Contains(sc.text, construct) {
			e.addUnresolved(DOMUnresolved{
				Reason: DOMUnresolvedDynamicCode, Script: sc.ref, Line: sc.ref.Line,
				Detail: construct,
			})
		}
	}
}

// propagate records taint for a plain `name = <tainted expr>` assignment. Returns true when it
// tainted a variable that was not already tainted — the signal the fixpoint loop counts.
func (e *domEngine) propagate(st domStatement) bool {
	lhs, rhs, ok := domSplitAssign(st.text)
	if !ok {
		return false
	}
	name := domStripDeclaration(lhs)
	if !domIsPlainIdent(name) {
		return false
	}
	if _, already := e.taint[name]; already {
		return false
	}
	t, tainted := e.evalTaint(rhs)
	if !tainted {
		return false
	}
	t.via = append(append([]string{}, t.via...), name)
	e.taint[name] = t
	e.taintOrder = append(e.taintOrder, name)
	return true
}

// evalTaint decides whether an expression carries taint, and what happened to it on the way.
//
// A source expression matched directly wins over a tainted variable: `f(location.hash)` is
// attributed to the source it names, not to whatever variable also appears in the argument list.
func (e *domEngine) evalTaint(expr string) (domTaint, bool) {
	var t domTaint
	found := false
	for _, src := range domSources {
		if domContainsToken(expr, src.Expr) {
			t = domTaint{source: src, sourceExpr: src.Expr}
			found = true
			break
		}
	}
	if !found {
		for _, name := range e.taintOrder {
			if domContainsToken(expr, name) {
				prev := e.taint[name]
				t = domTaint{
					source:     prev.source,
					sourceExpr: prev.sourceExpr,
					via:        append([]string{}, prev.via...),
					accepted:   append([]DOMSanitizer{}, prev.accepted...),
					weak:       append([]DOMWeakEncoder{}, prev.weak...),
				}
				found = true
				break
			}
		}
	}
	if !found {
		return domTaint{}, false
	}
	for _, s := range domSanitizers {
		if domContainsToken(expr, s.Call) {
			t.accepted = append(t.accepted, s)
		}
	}
	for _, w := range domWeakEncoders {
		if domContainsToken(expr, w.Call) {
			t.weak = append(t.weak, w)
		}
	}
	return t, true
}

// checkSinks evaluates one statement against every sink form.
func (e *domEngine) checkSinks(sc domScriptSrc, st domStatement) {
	e.checkAssignSink(sc, st)
	e.checkCallSinks(sc, st)
}

func (e *domEngine) checkAssignSink(sc domScriptSrc, st domStatement) {
	lhs, rhs, ok := domSplitAssign(st.text)
	if !ok {
		return
	}
	target := strings.TrimSpace(domStripDeclaration(lhs))
	if domIsPlainIdent(target) {
		return // a plain variable assignment, handled by propagate
	}
	t, tainted := e.evalTaint(rhs)

	// A computed target with a tainted value: the property written is not statically known, so
	// neither "safe" nor a named issue can be claimed. Recorded, never dropped.
	if strings.HasSuffix(target, "]") {
		if tainted {
			e.addUnresolved(DOMUnresolved{
				Reason: DOMUnresolvedComputedAccess, Sink: target,
				Detail: t.sourceExpr, Script: sc.ref, Line: e.absLine(sc, st), Statement: domClip(st.text),
			})
		}
		return
	}

	for _, safe := range domSafeSinks {
		if !domTargets(target, safe) {
			continue
		}
		if tainted {
			e.addSuppressed(DOMSuppressed{
				Reason: DOMSuppressReasonSafeSink,
				Source: t.source, SourceExpr: t.sourceExpr, Sink: safe, Via: t.via,
				By:        safe,
				Why:       "writing to " + safe + " inserts text, so the value cannot execute or navigate; Burp would catalogue this as info-level DOM data manipulation",
				Script:    sc.ref,
				Line:      e.absLine(sc, st),
				Statement: domClip(st.text),
			})
		}
		return
	}

	for _, sink := range domSinks {
		if sink.Form != DOMSinkAssign || !domTargets(target, sink.Match) {
			continue
		}
		if tainted {
			e.decide(sc, st, sink, t)
		} else {
			e.noteUntraced(sc, st, sink.Match, rhs)
		}
		return
	}
}

func (e *domEngine) checkCallSinks(sc domScriptSrc, st domStatement) {
	for _, sink := range domSinks {
		if sink.Form == DOMSinkAssign {
			continue
		}
		// Every occurrence, not just the first: one statement can call the same sink twice, and
		// stopping at the first would silently drop the second.
		for at := domFindToken(st.text, sink.Match, 0); at >= 0; at = domFindToken(st.text, sink.Match, at+1) {
			args, ok := domCallArgs(st.text, at+len(sink.Match))
			if !ok {
				continue
			}
			if sink.Form == DOMSinkCallString && domFirstArgIsFunction(args) {
				// setTimeout(function(){...}) is the safe, ordinary use. Not a sink, and not an
				// unresolved case either: the pass knows exactly what this is.
				continue
			}
			if t, tainted := e.evalTaint(args); tainted {
				e.decide(sc, st, sink, t)
			} else {
				e.noteUntraced(sc, st, sink.Match, args)
			}
		}
	}
}

// decide is the DOM-02 judgement: suppress the flow when a recognised sanitizer is accepted for
// this sink class, and otherwise report it with any non-accepted operation named as a caveat.
func (e *domEngine) decide(sc domScriptSrc, st domStatement, sink DOMSink, t domTaint) {
	line := e.absLine(sc, st)
	for _, s := range t.accepted {
		if s.covers(sink.Issue) {
			e.addSuppressed(DOMSuppressed{
				Reason: DOMSuppressReasonSanitizer,
				Issue:  domIssueName(sink.Issue, t.source.Kind),
				Source: t.source, SourceExpr: t.sourceExpr, Sink: sink.Match, Via: t.via,
				By: s.Call, Why: s.Why,
				Script: sc.ref, Line: line, Statement: domClip(st.text),
			})
			return
		}
	}
	var caveats []string
	for _, s := range t.accepted {
		caveats = append(caveats, fmt.Sprintf("%s is recognised but is not accepted for %s — %s",
			s.Call, sink.Issue, s.Why))
	}
	for _, w := range t.weak {
		caveats = append(caveats, fmt.Sprintf("%s is not accepted as a defence — %s", w.Call, w.Why))
	}
	e.addFlow(DOMFlow{
		Issue:     domIssueName(sink.Issue, t.source.Kind),
		IssueBase: sink.Issue,
		Source:    t.source, SourceExpr: t.sourceExpr,
		Sink: sink, Via: t.via,
		Script: sc.ref, Line: line, Statement: domClip(st.text),
		Caveats: caveats,
	})
}

// noteUntraced records a sink whose input carries at least one identifier this pass could not trace.
// Not a finding and emphatically not a clean result: this is the "couldn't tell" bucket.
func (e *domEngine) noteUntraced(sc domScriptSrc, st domStatement, sink, expr string) {
	idents := domUntracedIdents(expr, e.taint)
	if len(idents) == 0 {
		return // the input is literal, so the pass genuinely knows it is not attacker-controlled
	}
	e.addUnresolved(DOMUnresolved{
		Reason: DOMUnresolvedUntracedValue, Sink: sink,
		Detail:    strings.Join(idents, ", "),
		Script:    sc.ref,
		Line:      e.absLine(sc, st),
		Statement: domClip(st.text),
	})
}

func (e *domEngine) absLine(sc domScriptSrc, st domStatement) int {
	return sc.ref.Line + st.line - 1
}

func (e *domEngine) addFlow(f DOMFlow) {
	// Script.Origin and Statement matter as much as Line: two statements on the same line — the
	// normal case in a minified bundle, where every statement in the file is line 1 — are two
	// different flows, not one seen twice. Without them, fifty distinct `x.innerHTML=location.hash`
	// sinks in a minified file collapsed to one flow and FlowsDropped stayed at 0, which reads
	// identically to "checked and found one" rather than "found forty-nine more and threw them away".
	key := fmt.Sprintf("%s|%s|%s|%s|%d|%s", f.Issue, f.SourceExpr, f.Sink.Match, f.Script.Origin, f.Line, f.Statement)
	if e.seen[key] {
		// A key this specific repeating is a genuine duplicate — the same statement reached twice —
		// and it is still a drop: the caller asked to record a flow and this pass silently declined.
		e.res.Budget.FlowsDropped++
		return
	}
	e.seen[key] = true
	if len(e.res.Flows) >= e.budget.MaxFlows {
		e.res.Budget.record(DOMStopFlows)
		e.res.Budget.FlowsDropped++
		return
	}
	e.res.Flows = append(e.res.Flows, f)
}

func (e *domEngine) addSuppressed(s DOMSuppressed) {
	if len(e.res.Suppressed) >= e.budget.MaxSuppressed {
		e.res.Budget.record(DOMStopSuppressed)
		e.res.Budget.SuppressedDropped++
		return
	}
	e.res.Suppressed = append(e.res.Suppressed, s)
}

func (e *domEngine) addUnresolved(u DOMUnresolved) {
	if len(e.res.Unresolved) >= e.budget.MaxUnresolved {
		e.res.Budget.record(DOMStopUnresolved)
		e.res.Budget.UnresolvedDropped++
		return
	}
	e.res.Unresolved = append(e.res.Unresolved, u)
}

// ---- lexing --------------------------------------------------------------------------------

// domStatement is one statement-ish fragment of a script, with the line it started on.
type domStatement struct {
	text string
	line int
	// unbalanced is the open-paren/bracket depth this fragment leaves behind; the merge step joins
	// a fragment forward while it is positive, which is what puts a multi-line call back together.
	unbalanced int
}

// domSplitStatements cuts a script into statement-ish fragments, stripping comments and preserving
// line numbers.
//
// Cuts at `;` and at newlines (JavaScript's automatic semicolon insertion makes a line break a real
// statement boundary) and at braces outside any parenthesis. It is not a parser: a fragment left
// with unbalanced parentheses is merged forward, which recovers multi-line calls and object
// literals, and anything the regex-literal heuristic misreads can cut in the wrong place. Those
// mistakes lose flows; they do not invent them.
func domSplitStatements(src string) []domStatement {
	var raw []domStatement
	var buf strings.Builder
	line, startLine := 1, 1
	depth, fragDepth := 0, 0
	var lastSig byte

	flush := func() {
		t := strings.TrimSpace(buf.String())
		if t != "" {
			raw = append(raw, domStatement{text: t, line: startLine, unbalanced: fragDepth})
		}
		buf.Reset()
		startLine = line
		fragDepth = 0
	}

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			flush()
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i < len(src) && !(src[i] == '*' && i+1 < len(src) && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
			buf.WriteByte(' ')
		case c == '\'' || c == '"' || c == '`' || (c == '/' && domRegexAllowed(lastSig)):
			end, nl, ok := domScanLiteral(src, i)
			if !ok {
				// Unterminated: either a genuinely broken literal or, far more likely, a `/`
				// the regex heuristic misread as one. Treat the character as ordinary code and
				// carry on, so one misread division cannot swallow the rest of the file.
				buf.WriteByte(c)
				lastSig = c
				i++
				break
			}
			buf.WriteString(src[i:end])
			line += nl
			lastSig = src[end-1]
			i = end
		case c == '(' || c == '[':
			depth++
			fragDepth++
			buf.WriteByte(c)
			lastSig = c
			i++
		case c == ')' || c == ']':
			if depth > 0 {
				depth--
			}
			fragDepth--
			buf.WriteByte(c)
			lastSig = c
			i++
		case c == ';' && depth == 0:
			flush()
			i++
		case (c == '{' || c == '}') && depth == 0:
			flush()
			lastSig = c
			i++
		default:
			buf.WriteByte(c)
			if c != ' ' && c != '\t' && c != '\r' {
				lastSig = c
			}
			i++
		}
	}
	flush()

	// Merge a fragment forward while it has parentheses still open, which is what puts a call or an
	// expression split across lines back together.
	//
	// A fragment that already contains an opening brace is never merged. An open paren with a brace
	// inside it is a function body or a block starting mid-expression — `(function () {`,
	// `forEach(function (x) {` — and its statements are separate statements. Merging those would
	// fold an entire IIFE into one blob, which then has no top-level assignment operator at all and
	// loses every assignment sink inside it. The cost of the rule is a multi-line object literal
	// passed to a sink, whose argument list is then not reassembled; that loses a flow rather than
	// inventing one, and it is far rarer than an IIFE.
	const maxMerges = 8
	out := make([]domStatement, 0, len(raw))
	for i := 0; i < len(raw); {
		cur := raw[i]
		j := i + 1
		for merges := 0; cur.unbalanced > 0 && j < len(raw) && merges < maxMerges; merges++ {
			if strings.ContainsRune(cur.text, '{') {
				break
			}
			cur.text += " " + raw[j].text
			cur.unbalanced += raw[j].unbalanced
			j++
		}
		out = append(out, cur)
		i = j
	}
	return out
}

// domRegexAllowed reports whether a `/` following this significant character starts a regex literal
// rather than a division. The conventional heuristic: a regex can only begin where a value is
// expected, so only punctuation can precede one.
//
// It follows that `return /re/.test(x)` is misread as a division, because the preceding significant
// character is an identifier letter. Widening the rule to cover keyword lookback would also let
// every `a / b` where `a` ends in a keyword letter be misread as a regex, which is the worse
// direction: a misread division is recovered by the unterminated-literal fallback in the splitter,
// while a misread regex can eat a statement.
func domRegexAllowed(lastSig byte) bool {
	switch lastSig {
	case 0, '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^':
		return true
	}
	return false
}

// domScanLiteral consumes a string, template or regex literal starting at i, returning the index
// just past it, how many newlines it spanned, and whether it terminated. An unterminated literal is
// reported rather than assumed, so a misread regex cannot silently swallow the rest of the file.
func domScanLiteral(src string, i int) (end, newlines int, ok bool) {
	quote := src[i]
	inClass := false
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '\n':
			newlines++
			if quote != '`' {
				return j, newlines, false // strings and regexes do not span lines
			}
		case '[':
			if quote == '/' {
				inClass = true
			}
		case ']':
			if quote == '/' {
				inClass = false
			}
		case quote:
			if quote == '/' && inClass {
				continue
			}
			j++
			if quote == '/' { // consume regex flags
				for j < len(src) && domIdentByte(src[j]) {
					j++
				}
			}
			return j, newlines, true
		}
	}
	return len(src), newlines, false
}

// domSplitAssign splits a statement at its top-level assignment operator, returning the target and
// the assigned expression. `+=` counts: appending to innerHTML is the same sink as setting it.
// Comparisons, arrow functions and compound arithmetic operators do not.
func domSplitAssign(stmt string) (lhs, rhs string, ok bool) {
	depth := 0
	for i := 0; i < len(stmt); i++ {
		c := stmt[i]
		switch c {
		case '\'', '"', '`':
			end, _, term := domScanLiteral(stmt, i)
			if !term {
				return "", "", false
			}
			i = end - 1
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(stmt) && (stmt[i+1] == '=' || stmt[i+1] == '>') {
				continue
			}
			if i == 0 {
				continue
			}
			switch stmt[i-1] {
			case '=', '!', '<', '>':
				continue
			case '+':
				return strings.TrimSpace(stmt[:i-1]), strings.TrimSpace(stmt[i+1:]), true
			case '-', '*', '/', '%', '&', '|', '^':
				continue
			}
			return strings.TrimSpace(stmt[:i]), strings.TrimSpace(stmt[i+1:]), true
		}
	}
	return "", "", false
}

// domCallArgs returns the argument text of a call whose callee ends at from, or ok == false when
// there is no argument list there or it does not close within this statement.
func domCallArgs(stmt string, from int) (string, bool) {
	i := from
	for i < len(stmt) && (stmt[i] == ' ' || stmt[i] == '\t') {
		i++
	}
	if i >= len(stmt) || stmt[i] != '(' {
		return "", false
	}
	depth := 0
	start := i + 1
	for ; i < len(stmt); i++ {
		switch stmt[i] {
		case '\'', '"', '`':
			end, _, term := domScanLiteral(stmt, i)
			if !term {
				return "", false
			}
			i = end - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return stmt[start:i], true
			}
		}
	}
	return "", false
}

// domFirstArgIsFunction reports whether a call's first argument is a function rather than a string —
// the difference between `setTimeout(tainted, 0)`, which executes the value, and
// `setTimeout(function(){}, 0)`, which does not.
func domFirstArgIsFunction(args string) bool {
	a := strings.TrimSpace(args)
	switch {
	case strings.HasPrefix(a, "function"),
		strings.HasPrefix(a, "async"),
		strings.HasPrefix(a, "("),
		strings.HasPrefix(a, "()"):
		return true
	}
	// A bare `x => ...` or `x=>...` arrow before the first comma.
	if cut := strings.IndexByte(a, ','); cut >= 0 {
		a = a[:cut]
	}
	return strings.Contains(a, "=>")
}

// domTargets reports whether an assignment target ends in this property, as a whole token, so
// `el.innerHTML` matches `innerHTML` while `location.href` does not match a bare `href` — the
// longest-first table order in dom_data.go is what makes that precedence hold.
func domTargets(target, property string) bool {
	if !strings.HasSuffix(target, property) {
		return false
	}
	at := len(target) - len(property)
	if at > 0 && domIdentByte(target[at-1]) {
		return false
	}
	if at > 0 && target[at-1] != '.' && property[0] != '.' {
		return false
	}
	return true
}

func domStripDeclaration(lhs string) string {
	l := strings.TrimSpace(lhs)
	for _, kw := range []string{"var ", "let ", "const "} {
		if strings.HasPrefix(l, kw) {
			return strings.TrimSpace(l[len(kw):])
		}
	}
	return l
}

func domIsPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !domIdentByte(s[i]) {
			return false
		}
	}
	return !domKeywords[s]
}

// domKeywords are the words that look like identifiers and are not variables a value can be
// assigned to or traced through.
var domKeywords = map[string]bool{
	"true": true, "false": true, "null": true, "undefined": true, "this": true,
	"new": true, "typeof": true, "void": true, "delete": true, "function": true,
	"return": true, "if": true, "else": true, "for": true, "while": true, "do": true,
	"switch": true, "case": true, "break": true, "continue": true, "in": true, "of": true,
	"instanceof": true, "var": true, "let": true, "const": true, "NaN": true,
	"Infinity": true, "try": true, "catch": true, "finally": true, "throw": true,
	"class": true, "extends": true, "super": true, "yield": true, "await": true, "async": true,
}

// domUntracedIdents returns the identifiers in an expression whose origin this pass cannot account
// for: not a literal, not a keyword, not a member name, not a tainted variable it already tracks.
// A non-empty result is what turns "no flow found" into "could not tell".
func domUntracedIdents(expr string, taint map[string]domTaint) []string {
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(expr); {
		c := expr[i]
		if c == '\'' || c == '"' || c == '`' {
			end, _, ok := domScanLiteral(expr, i)
			if !ok {
				break
			}
			i = end
			continue
		}
		if !domIdentByte(c) || (c >= '0' && c <= '9') {
			i++
			continue
		}
		start := i
		for i < len(expr) && domIdentByte(expr[i]) {
			i++
		}
		name := expr[start:i]
		if start > 0 && expr[start-1] == '.' {
			continue // a member name, not a free variable
		}
		if i < len(expr) && expr[i] == '(' {
			continue // a callee: the value is its return, reported through its arguments instead
		}
		if domKeywords[name] || seen[name] {
			continue
		}
		if _, tracked := taint[name]; tracked {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// domLooksMinified reports whether a script's line geometry says it was machine-packed. Not a
// refusal to analyse — minified code still traces — but a caveat on any conclusion drawn from it.
func domLooksMinified(src string) bool {
	if len(src) < 2048 {
		return false
	}
	lines := strings.Count(src, "\n") + 1
	return len(src)/lines > 300
}

func domClip(s string) string {
	const max = 200
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ---- script extraction ---------------------------------------------------------------------

// domExtractScripts pulls every script body out of a response.
//
// found is false when the body is neither HTML nor JavaScript and contains no `<script`, which is
// the DOMSkipNotScriptBearing case: nothing to read is a different answer from nothing found.
func domExtractScripts(body []byte, contentType string) (scripts []domScriptSrc, skips []DOMScriptSkip, found bool) {
	ct := strings.ToLower(contentType)
	text := string(body)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return []domScriptSrc{{
			ref:  DOMScriptRef{Origin: "response body (javascript)", Line: 1},
			text: text,
		}}, nil, true
	}
	lower := strings.ToLower(text)
	isHTML := strings.Contains(ct, "html") || strings.Contains(lower, "<script")
	if !isHTML {
		return nil, nil, false
	}

	n := 0
	for i := 0; ; {
		open := strings.Index(lower[i:], "<script")
		if open < 0 {
			break
		}
		open += i
		tagEnd := strings.IndexByte(lower[open:], '>')
		if tagEnd < 0 {
			break
		}
		tagEnd += open
		tag := lower[open : tagEnd+1]
		closeAt := strings.Index(lower[tagEnd:], "</script")
		bodyStart := tagEnd + 1
		bodyEnd := len(text)
		if closeAt >= 0 {
			bodyEnd = tagEnd + closeAt
		}
		n++
		ref := DOMScriptRef{
			Origin: fmt.Sprintf("inline <script> #%d", n),
			Line:   domLineOf(text, bodyStart),
		}
		src, hasSrc := domTagAttr(tag, "src")
		typ, hasType := domTagAttr(tag, "type")
		switch {
		case hasSrc:
			skips = append(skips, DOMScriptSkip{
				Script: ref, Reason: DOMScriptSkipExternalSrc, Detail: domClip(src),
			})
		case hasType && !domExecutableScriptType(typ):
			skips = append(skips, DOMScriptSkip{
				Script: ref, Reason: DOMScriptSkipNonExecutableType, Detail: domClip(typ),
			})
		default:
			scripts = append(scripts, domScriptSrc{ref: ref, text: text[bodyStart:bodyEnd]})
		}
		if closeAt < 0 {
			break
		}
		i = bodyEnd + 1
	}

	scripts = append(scripts, domExtractHandlers(text)...)
	return scripts, skips, true
}

// domExecutableScriptType reports whether a script tag's declared type is one the browser runs as
// JavaScript. An empty value counts as JavaScript, matching the browser.
func domExecutableScriptType(typ string) bool {
	switch strings.TrimSpace(typ) {
	case "", "text/javascript", "application/javascript", "module", "text/ecmascript",
		"application/ecmascript", "text/babel", "text/jsx":
		return true
	}
	return false
}

// domTagAttr reads one attribute out of a lower-cased tag.
//
// The attribute name must be preceded by whitespace or the tag name, so `data-src=` is not read as
// `src=`. Reading it as src would classify an inline script with a data attribute as external and
// silently skip a body that is right there in the response.
func domTagAttr(tag, attr string) (string, bool) {
	for i := 0; ; {
		at := strings.Index(tag[i:], attr+"=")
		if at < 0 {
			return "", false
		}
		at += i
		i = at + len(attr) + 1
		if at == 0 || !domTagAttrBoundary(tag[at-1]) {
			continue
		}
		rest := tag[i:]
		if rest == "" {
			return "", true
		}
		if q := rest[0]; q == '"' || q == '\'' {
			if end := strings.IndexByte(rest[1:], q); end >= 0 {
				return rest[1 : 1+end], true
			}
			return "", true
		}
		if cut := strings.IndexAny(rest, " \t\r\n>"); cut >= 0 {
			return rest[:cut], true
		}
		return rest, true
	}
}

func domTagAttrBoundary(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// domHandlerAttrs is the inline event-handler attributes whose value is executable JavaScript.
//
// An explicit list rather than a general `on[a-z]+=` match: the general form collides with ordinary
// data attributes and with framework bindings whose value is not JavaScript at all, and treating
// those as script would manufacture flows out of markup.
var domHandlerAttrs = []string{
	"onclick", "onload", "onerror", "onmouseover", "onmouseout", "onsubmit", "onfocus",
	"onblur", "onchange", "oninput", "onkeyup", "onkeydown", "onkeypress", "onmessage",
	"onhashchange", "onpopstate", "ondblclick", "onunload", "onbeforeunload",
}

// domExtractHandlers pulls inline event-handler attribute values out of markup as script bodies.
// Only double- and single-quoted values are read; an unquoted handler value is not extracted, and
// that omission is why this is a supplement to the <script> scan rather than a replacement for it.
func domExtractHandlers(text string) []domScriptSrc {
	lower := strings.ToLower(text)
	var out []domScriptSrc
	for _, attr := range domHandlerAttrs {
		for i := 0; ; {
			at := strings.Index(lower[i:], attr+"=")
			if at < 0 {
				break
			}
			at += i
			i = at + len(attr) + 1
			if at > 0 && domIdentByte(lower[at-1]) {
				continue
			}
			if i >= len(text) {
				break
			}
			quote := text[i]
			if quote != '"' && quote != '\'' {
				continue
			}
			end := strings.IndexByte(text[i+1:], quote)
			if end < 0 {
				continue
			}
			end += i + 1
			out = append(out, domScriptSrc{
				ref:  DOMScriptRef{Origin: attr + " attribute", Line: domLineOf(text, i)},
				text: text[i+1 : end],
			})
			i = end + 1
		}
	}
	return out
}

func domLineOf(text string, idx int) int {
	if idx > len(text) {
		idx = len(text)
	}
	return strings.Count(text[:idx], "\n") + 1
}
