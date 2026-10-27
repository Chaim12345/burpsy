package scanner

// burpsy-react-ui-9mti: the javascript_analysis keys — use_static_analysis, use_dynamic_analysis,
// max_static_time_per_item, max_dynamic_time_per_item — imported through ApplyBurpConfigFile and run
// through AuditSession against vulnapp.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"go.uber.org/zap"
)

// countingBrowserProvider answers every Browser call with an error and counts the calls, so "the run
// never started a browser" is a number rather than an absence of symptoms.
type countingBrowserProvider struct{ calls atomic.Int64 }

func (p *countingBrowserProvider) Browser(context.Context) (*domexec.Browser, error) {
	p.calls.Add(1)
	return nil, errors.New("stub provider: no browser in this test")
}

func (p *countingBrowserProvider) Close() error { return nil }

// domOnlyScanner audits with the DOM families alone (WithBrowserProvider switches them on).
func domOnlyScanner(store *core.TrafficStore, provider BrowserProvider) *ActiveScanner {
	return NewActiveScanner(store, zap.NewNop()).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 2 * time.Minute}).
		WithSender(runtimeSender()).
		WithBrowserProvider(provider)
}

func TestAStaticOnlyRunStartsNoBrowserAndReportsTheStaticCandidate(t *testing.T) {
	ot := startOverrideTarget(t)
	id := ot.seed(t, "/dom/innerhtml")
	stub := &countingBrowserProvider{}
	scan := domOnlyScanner(ot.store, stub)

	staticOnly := importOverride(t, `{"scanner":{"javascript_analysis":{"use_static_analysis":true,"use_dynamic_analysis":false}}}`)
	outcome, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, staticOnly)
	if n := stub.calls.Load(); n != 0 {
		t.Fatalf("use_dynamic_analysis false: the browser was asked for %d times", n)
	}
	var static *Finding
	for _, f := range findings {
		if strings.Contains(f.Name, "DOM-based") {
			static = f
		}
	}
	if static == nil {
		t.Fatalf("a static-only run reported no DOM finding for a page whose script writes location.hash into innerHTML (outcome %+v)",
			outcome.Items[0].Outcome)
	}
	if static.Confidence != "tentative" || !strings.Contains(static.Evidence, "use_dynamic_analysis is false") {
		t.Errorf("the static candidate does not say it was not confirmed: confidence %q, evidence %q", static.Confidence, static.Evidence)
	}
	raw, _ := json.Marshal(outcome.Items[0].Outcome)
	if !strings.Contains(string(raw), `"javascript_analysis_skips":[]`) {
		t.Errorf("an item no limit stopped does not report an empty skip list: %s", raw)
	}

	// Control: the same scanner with dynamic analysis on asks for the browser, so the zero above is
	// the switch and not a stub that is never consulted.
	scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	if stub.calls.Load() == 0 {
		t.Fatal("control: a run with dynamic analysis on never asked for the browser — the count above proves nothing")
	}
}

func TestStaticAnalysisOffRunsNoStaticPassAndSoConfirmsNothing(t *testing.T) {
	ot := startOverrideTarget(t)
	id := ot.seed(t, "/dom/innerhtml")
	ex, _ := ot.store.GetExchange(id)
	scan := NewActiveScanner(ot.store, zap.NewNop()).WithBrowserProvider(&confirmStubProvider{})

	var observed atomic.Int64
	old := domConfirmObserve
	domConfirmObserve = func(_ context.Context, _ *domexec.Browser, _ string, _ domexec.SourceKind, canary string) ([]domexec.Observation, error) {
		observed.Add(1)
		return []domexec.Observation{{Argument: canary}}, nil
	}
	defer func() { domConfirmObserve = old }()

	off := importOverride(t, `{"scanner":{"javascript_analysis":{"use_static_analysis":false}}}`)
	if got := scan.javascriptAnalysisFor(context.Background(), ex, off, newDOMTimeBudget(off)); len(got) != 0 || observed.Load() != 0 {
		t.Fatalf("use_static_analysis false: %d finding(s) and %d confirmation load(s), want none", len(got), observed.Load())
	}
	on := DefaultAuditConfig()
	if got := scan.javascriptAnalysisFor(context.Background(), ex, on, newDOMTimeBudget(on)); len(got) == 0 || observed.Load() == 0 {
		t.Fatalf("control: with static analysis on the candidate was not confirmed (%d finding(s), %d load(s))", len(got), observed.Load())
	}
}

func TestMaxStaticTimePerItemStopsThePassAndCountsTheSkip(t *testing.T) {
	ot := startOverrideTarget(t)
	id := ot.seed(t, "/dom/innerhtml")
	scan := domOnlyScanner(ot.store, &countingBrowserProvider{})

	// The pass over this page takes microseconds, so the clock is made to jump: the first read sets the
	// deadline, every later read is an hour on.
	start := time.Now()
	var reads atomic.Int64
	old := domNow
	domNow = func() time.Time {
		if reads.Add(1) == 1 {
			return start
		}
		return start.Add(time.Hour)
	}
	defer func() { domNow = old }()

	limited := importOverride(t, `{"scanner":{"javascript_analysis":{"use_dynamic_analysis":false,"max_static_time_per_item":1}}}`)
	if v := limited.MaxStaticTimePerItem; !v.Set || v.Value != 1 {
		t.Fatalf("max_static_time_per_item 1 parsed as %+v", v)
	}
	outcome, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, limited)
	skips := outcome.Items[0].Outcome.JavaScriptAnalysisSkips
	if len(skips) != 1 || skips[0].Pass != "static" || !strings.Contains(skips[0].Reason, "max_static_time_per_item") {
		t.Fatalf("a static pass the limit stopped was not counted with its reason: %+v", skips)
	}
	for _, f := range findings {
		if strings.Contains(f.Name, "DOM-based") {
			t.Errorf("the pass stopped before its first statement and still reported %q", f.Name)
		}
	}

	domNow = old
	unlimited := importOverride(t, `{"scanner":{"javascript_analysis":{"use_dynamic_analysis":false}}}`)
	outcome, findings = scan.AuditSession(context.Background(), []core.ExchangeID{id}, unlimited)
	if n := len(outcome.Items[0].Outcome.JavaScriptAnalysisSkips); n != 0 {
		t.Errorf("control: an unlimited pass recorded %d skip(s)", n)
	}
	found := false
	for _, f := range findings {
		found = found || strings.Contains(f.Name, "DOM-based")
	}
	if !found {
		t.Error("control: the unlimited static pass found nothing, so the limited run's silence proves nothing")
	}
}

func TestMaxDynamicTimePerItemIsACountedSkipNotACleanResultOrABreakerTrip(t *testing.T) {
	if !chromeOnPath() {
		domexectest.Skip(t, "no Chrome on PATH: the dynamic limit needs a real browser load")
	}
	ot := startOverrideTarget(t)
	// /slow answers after 1.5 s, so a browser load of it cannot finish inside a 1 s item limit.
	id := ot.seed(t, "/slow")
	scan := domOnlyScanner(ot.store, sharedBrowserProvider())

	limited := importOverride(t, `{"scanner":{"javascript_analysis":{"max_dynamic_time_per_item":1}}}`)
	begin := time.Now()
	outcome, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, limited)
	took := time.Since(begin)
	o := outcome.Items[0].Outcome
	if len(o.JavaScriptAnalysisSkips) == 0 {
		t.Fatalf("no dynamic skip was recorded for an item whose page cannot load inside the limit (outcome %+v)", o)
	}
	for _, s := range o.JavaScriptAnalysisSkips {
		if s.Pass != "dynamic" || s.Check == "" || !strings.Contains(s.Reason, "max_dynamic_time_per_item") {
			t.Errorf("skip without its pass, check or reason: %+v", s)
		}
	}
	if o.Skipped < len(o.JavaScriptAnalysisSkips) {
		t.Errorf("%d checks named as stopped but only %d counted skipped", len(o.JavaScriptAnalysisSkips), o.Skipped)
	}
	if o.SendFailures != 0 || o.UnitAbandoned != 0 {
		t.Errorf("the run's own limit was counted against the target: %d send failures, %d abandoned", o.SendFailures, o.UnitAbandoned)
	}
	if len(findings) != 0 {
		t.Errorf("a run whose browser work was all stopped reported %d finding(s)", len(findings))
	}
	// One clock per item: every DOM check after the first is refused at once, so the whole item costs
	// about the limit, not the limit per check.
	if took > 10*time.Second {
		t.Errorf("the item took %s under a 1 s per-item limit — the clock is per check, not per item", took)
	}

	// Control: with no limit the same checks wait out the page and run.
	outcome, _ = scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	if c := outcome.Items[0].Outcome; c.Ran == 0 || len(c.JavaScriptAnalysisSkips) != 0 {
		t.Fatalf("control: with no limit the DOM checks did not run cleanly (ran %d, skips %+v)", c.Ran, c.JavaScriptAnalysisSkips)
	}
}

func TestShippedConfigurationsCarryTheJavaScriptKeysAsBurpWroteThem(t *testing.T) {
	maximum := loadShippedConfig(t, "Audit coverage - maximum.json")
	if v := maximum.JSMaxStaticSecondsPerItem; !v.Set || v.Value != 600 {
		t.Errorf("maximum: max_static_time_per_item 600 parsed as %+v (a boolean read of 600 is 1)", v)
	}
	if v := maximum.JSMaxDynamicSecondsPerItem; !v.Set || v.Value != 600 {
		t.Errorf("maximum: max_dynamic_time_per_item 600 parsed as %+v", v)
	}
	if v := maximum.JSUseStaticAnalysis; !v.Set || v.Value != 1 {
		t.Errorf("maximum: use_static_analysis true parsed as %+v", v)
	}
	fast := loadShippedConfig(t, "Crawl and Audit - Fast.json")
	cfg, unapplied := fast.ApplyWithReport(DefaultAuditConfig())
	if cfg.MaxStaticTimePerItem.Value != 10 {
		t.Errorf("Fast: the run carries max_static_time_per_item %+v, want 10", cfg.MaxStaticTimePerItem)
	}
	for _, k := range unapplied {
		if strings.Contains(k, "static_time") {
			t.Errorf("Fast: %s is still reported unapplied", k)
		}
	}
	// Burp's pre-split spelling max_time_per_item (Zxc3.java:30) is in none of the 29 shipped files, so
	// it has no row: a file carrying it is told the key did nothing rather than silently aliased.
	legacy, err := ParseBurpConfig([]byte(`{"scanner":{"javascript_analysis":{"max_time_per_item":5}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, un := legacy.ApplyWithReport(DefaultAuditConfig()); len(un) != 1 || !strings.HasSuffix(un[0], "max_time_per_item") {
		t.Errorf("max_time_per_item was not reported unapplied: %v", un)
	}
}

// An enabled "Javascript static analysis" for a DOM type is a method the audit now runs, so a
// configuration naming it must not be told it never runs here.
func TestAnEnabledJavaScriptStaticMethodIsNoLongerDeclinedAsUnimplemented(t *testing.T) {
	cfg := importOverride(t, `{"scanner":{"issues_reported":{"select_individual_issues":true,"selected_issues":[
		{"type_index":"0x00200310","enabled":true,"detection_methods":[
			{"name":"Javascript static analysis","enabled":true},{"name":"Javascript dynamic analysis","enabled":true}]}]}}}`)
	for _, d := range cfg.DeclinedDetectionMethods {
		if d.Method == MethodJavaScriptStatic || d.Method == MethodJavaScriptDynamic {
			t.Errorf("an implemented DOM method was declined: %+v", d)
		}
	}
}
