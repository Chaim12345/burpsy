package scanner

// Burp's javascript_analysis keys (burpsy-react-ui-9mti): use_static_analysis,
// use_dynamic_analysis, max_static_time_per_item and max_dynamic_time_per_item, applied to the run
// that carries them.
//
// # What "static" and "dynamic" are in this engine
//
// Burp's own split (Zxc3.java:27-31, build 51467; documented under "JavaScript analysis" in
// scanner/scan-configurations/audit-settings.html) is between analysing a page's script as text and
// executing it. burpsy has exactly one of each:
//
//   - static: AnalyzeDOMDocument, the lexical source-to-sink tracer over an item's own response. In an
//     audit it runs at the end of every item (javascriptAnalysisFor) and seeds the confirmation tier.
//   - dynamic: everything that drives the headless browser — the DOM check families
//     (checks_dom.go, checks_dom_extra.go; their gate is domChecksEnabled) and the confirmation of
//     static candidates (dom_confirm.go).
//
// # Units
//
// Both limits are SECONDS. Burp's settings panel labels both fields "seconds" (Zrde.java:204,230) and
// reads them as ints bound 1..MAX_VALUE (:36-37); its documentation says "zero or a blank value"
// means no limit, which is the reading here — a zero cannot mean "time out at once", which no
// operator would configure on purpose. The panel's lower bound of 1 and the documentation's zero
// disagree; burpsy accepts both, and zero is unlimited.
//
// # What a limit does when it is reached
//
// Burp "truncates analysis" and "shows an alert identifying the item affected". burpsy keeps what
// the pass found before the limit, marks the static analysis incomplete (DOMStopTime, so its caveat
// says so), and records one JSAnalysisSkip per pass on the item's outcome — the alert's
// counterpart, counted, with the reason. A browser-driven check the dynamic limit stopped, or never
// started because the item's dynamic time was already spent, is counted Skipped: not clean, and not
// a send failure, because the limit is ours and must not trip the item's failure breaker.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// domNow is the static pass's clock. A var only so a test can make a one-second limit expire on a
// script that takes microseconds; production always reads the wall clock.
var domNow = time.Now

// staticJavaScriptOn reports whether the run's static DOM pass runs. Unset is on.
func (cfg AuditConfig) staticJavaScriptOn() bool {
	return !cfg.JavaScriptStaticAnalysis.Set || cfg.JavaScriptStaticAnalysis.Value != 0
}

// dynamicJavaScriptOn reports whether the run drives the browser. Unset is on.
func (cfg AuditConfig) dynamicJavaScriptOn() bool {
	return !cfg.JavaScriptDynamicAnalysis.Set || cfg.JavaScriptDynamicAnalysis.Value != 0
}

func secondsLimit(v OptUint32) time.Duration {
	if !v.Set || v.Value == 0 {
		return 0
	}
	return time.Duration(v.Value) * time.Second
}

// JSAnalysisSkip is one pass of one item that a javascript_analysis limit stopped. Pass is "static"
// or "dynamic"; Check names the DOM check or tier that was stopped (empty for the static pass, which
// is one pass over the whole item).
type JSAnalysisSkip struct {
	Pass   string `json:"pass"`
	Check  string `json:"check,omitempty"`
	Reason string `json:"reason"`
}

// JSAnalysisSkips marshals as [] when empty, never null: "no pass was cut short" must not read as a
// list nobody filled in.
type JSAnalysisSkips []JSAnalysisSkip

// MarshalJSON keeps an empty list an empty list.
func (s JSAnalysisSkips) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]JSAnalysisSkip(s))
}

// errDynamicTimeLimit marks a DOM check the item's dynamic time limit stopped.
var errDynamicTimeLimit = errors.New("the item's max_dynamic_time_per_item was reached")

// domTimeBudget is one item's dynamic-analysis clock. It starts at the item's first browser use, not
// at the item's start — DOM checks run late in an item's plan, and a clock started earlier would spend
// their time on the injection checks ahead of them — and it is shared by every DOM check and the
// confirmation tier, because Burp's limit is per item, not per check: sixteen families times their
// variants times the limit would be no bound at all.
type domTimeBudget struct {
	limit time.Duration

	mu       sync.Mutex
	deadline time.Time
	skips    JSAnalysisSkips
}

// newDOMTimeBudget returns the item's dynamic clock, or nil when the run sets no limit.
func newDOMTimeBudget(cfg AuditConfig) *domTimeBudget {
	limit := secondsLimit(cfg.MaxDynamicTimePerItem)
	if limit <= 0 {
		return &domTimeBudget{}
	}
	return &domTimeBudget{limit: limit}
}

// ctx returns parent bounded by the item's dynamic deadline, starting the clock on first use. With no
// limit it is parent itself.
func (b *domTimeBudget) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	if b == nil || b.limit <= 0 {
		return parent, func() {}
	}
	b.mu.Lock()
	if b.deadline.IsZero() {
		b.deadline = time.Now().Add(b.limit)
	}
	deadline := b.deadline
	b.mu.Unlock()
	return context.WithDeadline(parent, deadline)
}

// spent reports whether the item's dynamic time has run out.
func (b *domTimeBudget) spent() bool {
	if b == nil || b.limit <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.deadline.IsZero() && !time.Now().Before(b.deadline)
}

// skip records one dynamic pass the limit stopped.
func (b *domTimeBudget) skip(check, why string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.skips = append(b.skips, JSAnalysisSkip{Pass: "dynamic", Check: check, Reason: why})
}

// staticSkip records the static pass's own stop.
func (b *domTimeBudget) staticSkip(why string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.skips = append(b.skips, JSAnalysisSkip{Pass: "static", Reason: why})
}

// list returns the item's skips, never nil.
func (b *domTimeBudget) list() JSAnalysisSkips {
	out := JSAnalysisSkips{}
	if b == nil {
		return out
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append(out, b.skips...)
}

// dynamicLimitReason is the sentence a stopped or never-started browser pass carries.
func (b *domTimeBudget) dynamicLimitReason(started bool) string {
	if started {
		return fmt.Sprintf("max_dynamic_time_per_item (%s) ran out while this ran; it stopped without a verdict", b.limit)
	}
	return fmt.Sprintf("max_dynamic_time_per_item (%s) was already spent on this item's earlier browser work, so this did not start", b.limit)
}

// isDynamicJavaScriptCheck reports whether a check drives the browser: the DOM families, identified by
// their gate function, so a descriptor added under that gate is dynamic automatically.
func isDynamicJavaScriptCheck(enabled func(*ScanConfig) bool) bool {
	return enabled != nil && funcPtr(enabled) == funcPtr(domChecksEnabled)
}

// javascriptAnalysisFor is an audit item's JavaScript analysis tail: the static DOM pass over the
// item's own response, the browser confirmation of what it found, and the run's javascript_analysis
// keys and issue selection applied to both. It replaces the unconditional Phase 12 call, which ran the
// static pass and the browser whatever the run's configuration said.
//
// What it returns is what the audit reports: candidates a browser confirmed (as before), and — when
// the browser cannot be used for a candidate's type because the run switched dynamic analysis off or
// disabled Javascript dynamic analysis for that issue — the static candidate itself, tentative, with
// its evidence saying why it was not confirmed. A run that had both techniques reports nothing new
// for an unconfirmed candidate, exactly as before: the passive path already carries it.
func (s *ActiveScanner) javascriptAnalysisFor(ctx context.Context, ex *core.Exchange, cfg AuditConfig, clock *domTimeBudget) []*Finding {
	if s == nil || ex == nil || ex.Response == nil || !cfg.staticJavaScriptOn() {
		return nil
	}
	msg, err := s.store.Get(*ex.Response)
	if err != nil || msg == nil {
		return nil
	}
	var budget DOMBudget
	if limit := secondsLimit(cfg.MaxStaticTimePerItem); limit > 0 {
		budget.Deadline = domNow().Add(limit)
	}
	a := AnalyzeDOMDocument(readableBody(msg), string(msg.Header("Content-Type")), budget)
	a.ExchangeID = ex.ID
	a.Method = ex.Method
	a.URL = domURL(ex)
	if a.Budget.Hit(DOMStopTime) {
		clock.staticSkip(fmt.Sprintf("max_static_time_per_item (%s) ran out after %d statements in %d script(s); "+
			"the findings are what was reached before it", secondsLimit(cfg.MaxStaticTimePerItem), a.Budget.Statements, a.Budget.Scripts))
	}

	scanWide := s.ConfigSnapshot().IssueTypes
	var confirmable, staticOnly []DOMFlow
	notConfirmed := map[string]string{}
	for _, f := range a.Flows {
		def, ok := ByName(f.Issue)
		if !ok || !cfg.admitsIssue(def.TypeIndex, scanWide) {
			continue
		}
		disabled := cfg.disabledMethodsFor(def.TypeIndex)
		if disabled[MethodJavaScriptStatic] {
			continue // this static candidate is a method the run turned off for its type
		}
		switch {
		case !cfg.dynamicJavaScriptOn():
			notConfirmed[f.Issue] = "use_dynamic_analysis is false in this run's configuration"
			staticOnly = append(staticOnly, f)
		case disabled[MethodJavaScriptDynamic]:
			notConfirmed[f.Issue] = "Javascript dynamic analysis is disabled for this issue type by the run's configuration"
			staticOnly = append(staticOnly, f)
		case s.DOMCapabilityConfigured():
			confirmable = append(confirmable, f)
		}
	}

	var out []*Finding
	if len(staticOnly) > 0 {
		sa := a
		sa.Flows = staticOnly
		for _, f := range sa.Findings() {
			f.Evidence += " Dynamic analysis did not run for this candidate: " + notConfirmed[f.Name] +
				", so this is a static-analysis finding — a path that exists in the source, not one a browser watched fire."
			if caveat := a.Caveat(); caveat != "" {
				f.Evidence += " " + caveat + "."
			}
			out = append(out, f)
		}
	}
	if len(confirmable) == 0 {
		return out
	}
	if clock.spent() {
		clock.skip("DOM confirmation", clock.dynamicLimitReason(false))
		return out
	}
	ca := a
	ca.Flows = confirmable
	cctx, cancel := clock.ctx(ctx)
	confirmed := s.ConfirmDOMFindings(cctx, ex, ca)
	cancel()
	stopped := 0
	for _, f := range confirmed {
		switch {
		case f.Confirm == DOMConfirmPromoted:
			// Only what a browser confirmed is an audit finding when both techniques ran. A retired
			// candidate is dropped, not because the verdict is useless, but because this tier's job in
			// an audit is to add evidence, and a negative about a flow the passive path never reported
			// would itself be a finding nobody asked for: the safe-counterpart suite is the exact case, a
			// page whose script carries a path a real load never fires. Retire semantics belong where the
			// tentative finding already exists (the passive path's own findings).
			out = append(out, f)
		case f.Confirm == DOMConfirmUnavailable && clock.spent() && ctx.Err() == nil:
			stopped++
		}
	}
	if stopped > 0 {
		clock.skip("DOM confirmation", fmt.Sprintf("%s (%d candidate(s) left unconfirmed)", clock.dynamicLimitReason(true), stopped))
	}
	return out
}

// javascriptTailRuns reports whether an item's JavaScript analysis tail runs under this run: the DOM
// families are on for the scanner, the run did not set scan_type_javascript_analysis false, and the
// static pass the tail starts from is on.
func (s *ActiveScanner) javascriptTailRuns(cfg AuditConfig) bool {
	if s == nil || !cfg.staticJavaScriptOn() || (cfg.JavaScriptAnalysis.Set && cfg.JavaScriptAnalysis.Value == 0) {
		return false
	}
	snap := s.ConfigSnapshot()
	return snap.CheckDOM
}

// admitsIssue reports whether the run's issue selection lets a finding of this type be reported: the
// scanner's own whitelist and the run's (filterByIssueTypes' rule — empty restricts nothing), then the
// run's per-type deny list. It is the selection filterBySelection applies to the check set, asked of a
// finding a pass produced outside any descriptor.
func (cfg AuditConfig) admitsIssue(typeIndex uint32, scanWide []uint32) bool {
	inList := func(list []uint32) bool {
		if len(list) == 0 {
			return true
		}
		for _, t := range list {
			if t == typeIndex {
				return true
			}
		}
		return false
	}
	return inList(scanWide) && inList(cfg.IssueTypes) && !cfg.issueTypeDisabled(typeIndex)
}
