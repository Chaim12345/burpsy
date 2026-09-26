package scanner

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- helpers -------------------------------------------------------------------------------

func domFlowFor(t *testing.T, a DOMAnalysis, issue string) DOMFlow {
	t.Helper()
	for _, f := range a.Flows {
		if f.Issue == issue {
			return f
		}
	}
	t.Fatalf("no flow reported for %q; got %s (flows: %v)", issue, a.Summary(), domFlowNames(a))
	return DOMFlow{}
}

func domFlowNames(a DOMAnalysis) []string {
	out := make([]string, 0, len(a.Flows))
	for _, f := range a.Flows {
		out = append(out, f.Issue)
	}
	return out
}

func domHasUnresolved(a DOMAnalysis, reason DOMUnresolvedReason) bool {
	for _, u := range a.Unresolved {
		if u.Reason == reason {
			return true
		}
	}
	return false
}

func domSuppressedFor(a DOMAnalysis, reason DOMSuppressReason) (DOMSuppressed, bool) {
	for _, s := range a.Suppressed {
		if s.Reason == reason {
			return s, true
		}
	}
	return DOMSuppressed{}, false
}

// ---- DOM-01: a source reaches a sink and the catalogued issue is reported -------------------

func Test_a_url_source_reaching_inner_html_is_reported_as_the_catalogued_dom_based_xss_issue(t *testing.T) {
	a := AnalyzeDOMScript(`document.getElementById("out").innerHTML = location.hash;`, DOMBudget{})

	if len(a.Flows) != 1 {
		t.Fatalf("flows = %d, want 1: %s", len(a.Flows), a.Summary())
	}
	f := a.Flows[0]
	if f.Issue != "Cross-site scripting (DOM-based)" {
		t.Errorf("issue = %q, want Cross-site scripting (DOM-based)", f.Issue)
	}
	if _, ok := ByName(f.Issue); !ok {
		t.Errorf("issue %q is not a name in the shipped catalog", f.Issue)
	}
	if f.SourceExpr != "location.hash" {
		t.Errorf("source expr = %q, want location.hash", f.SourceExpr)
	}
	if f.Sink.Match != "innerHTML" {
		t.Errorf("sink = %q, want innerHTML", f.Sink.Match)
	}
	if len(f.Caveats) != 0 {
		t.Errorf("caveats = %v, want none on an undefended flow", f.Caveats)
	}
	if !a.Complete() {
		t.Errorf("Complete() = false, want true: %s", a.Caveat())
	}
}

func Test_taint_propagated_through_a_variable_reaches_the_sink_and_names_the_hop(t *testing.T) {
	a := AnalyzeDOMScript(`
var raw = location.search;
var msg = "Hello " + raw;
document.write(msg);
`, DOMBudget{})

	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if f.Sink.Match != "document.write" {
		t.Errorf("sink = %q, want document.write", f.Sink.Match)
	}
	if got := strings.Join(f.Via, ","); got != "raw,msg" {
		t.Errorf("via = %q, want raw,msg", got)
	}
	if !strings.Contains(f.evidence(true), "raw -> msg") {
		t.Errorf("evidence does not name the hops: %s", f.evidence(true))
	}
}

func Test_a_stored_source_is_reported_under_the_stored_dom_based_catalog_variant(t *testing.T) {
	a := AnalyzeDOMScript(`var v = localStorage.getItem("k"); el.innerHTML = v;`, DOMBudget{})

	f := domFlowFor(t, a, "Cross-site scripting (stored DOM-based)")
	if f.Source.Kind != DOMSourceStored {
		t.Errorf("source kind = %v, want stored", f.Source.Kind)
	}
	if _, ok := ByName(f.Issue); !ok {
		t.Errorf("issue %q is not a name in the shipped catalog", f.Issue)
	}
}

func Test_each_sink_class_reports_its_own_catalogued_issue_rather_than_one_generic_name(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{"eval", `eval(location.hash);`, "JavaScript injection (DOM-based)"},
		{"string setTimeout", `setTimeout(location.hash, 10);`, "JavaScript injection (DOM-based)"},
		{"navigation", `window.location = document.referrer;`, "Open redirection (DOM-based)"},
		{"document domain", `document.domain = location.search;`, "Document domain manipulation (DOM-based)"},
		{"cookie write", `document.cookie = "p=" + location.hash;`, "Cookie manipulation (DOM-based)"},
		{"web message", `frames[0].postMessage(location.hash, "*");`, "HTML5 web message manipulation (DOM-based)"},
		{"websocket", `var s = new WebSocket(location.hash);`, "WebSocket URL poisoning (DOM-based)"},
		{"storage write", `localStorage.setItem("k", location.hash);`, "HTML5 storage manipulation (DOM-based)"},
		{"link", `a.href = location.hash;`, "Link manipulation (DOM-based)"},
		{"client json", `var o = JSON.parse(location.hash);`, "Client-side JSON injection (DOM-based)"},
		{"client xpath", `document.evaluate(location.hash, doc, null, 0, null);`, "Client-side XPath injection (DOM-based)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := AnalyzeDOMScript(tc.script, DOMBudget{})
			domFlowFor(t, a, tc.want)
		})
	}
}

func Test_every_sink_and_source_kind_pair_resolves_to_a_name_in_the_shipped_catalog(t *testing.T) {
	kinds := []DOMSourceKind{DOMSourceURL, DOMSourceStored, DOMSourceMessage}
	for _, sink := range domSinks {
		for _, kind := range kinds {
			name := domIssueName(sink.Issue, kind)
			if _, ok := ByName(name); !ok {
				t.Errorf("sink %q with a %v source yields %q, which is not in the shipped catalog",
					sink.Match, kind, name)
			}
		}
	}
}

func Test_a_finding_takes_its_severity_background_and_remediation_from_the_catalog(t *testing.T) {
	a := AnalyzeDOMScript(`el.innerHTML = location.hash;`, DOMBudget{})
	findings := a.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	def, ok := ByName("Cross-site scripting (DOM-based)")
	if !ok {
		t.Fatal("the catalog has no Cross-site scripting (DOM-based) entry")
	}
	if f.Severity != def.TypicalSeverity {
		t.Errorf("severity = %q, want the catalogued %q", f.Severity, def.TypicalSeverity)
	}
	if f.Description != def.Description {
		t.Error("description is not the catalogued background text")
	}
	if def.HasRemediation() && f.Solution != def.Remediation {
		t.Error("solution is not the catalogued remediation text")
	}
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative for a static-only finding", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "location.hash") || !strings.Contains(f.Evidence, "innerHTML") {
		t.Errorf("evidence does not name the source and sink: %q", f.Evidence)
	}
}

func Test_an_inline_event_handler_attribute_is_analysed_as_a_script_body(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(`<html><body>`+
		`<a href="#" onclick="document.write(location.hash)">go</a>`+
		`</body></html>`), "text/html", DOMBudget{})

	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if f.Script.Origin != "onclick attribute" {
		t.Errorf("origin = %q, want onclick attribute", f.Script.Origin)
	}
}

func Test_an_inline_script_element_in_an_html_body_is_analysed(t *testing.T) {
	a := AnalyzeDOMDocument([]byte("<html>\n<head>\n<script>\nvar t = location.hash;\neval(t);\n</script>\n</html>"),
		"text/html; charset=utf-8", DOMBudget{})

	f := domFlowFor(t, a, "JavaScript injection (DOM-based)")
	if f.Script.Origin != "inline <script> #1" {
		t.Errorf("origin = %q, want inline <script> #1", f.Script.Origin)
	}
	if f.Line != 5 {
		t.Errorf("line = %d, want 5 (the eval statement in the document)", f.Line)
	}
}

// ---- DOM-02: a flow through a recognised sanitizer is not reported --------------------------

func Test_a_flow_through_encode_uri_component_is_suppressed_and_not_reported(t *testing.T) {
	unsafe := AnalyzeDOMScript(`el.innerHTML = location.hash;`, DOMBudget{})
	if len(unsafe.Flows) != 1 {
		t.Fatalf("control case: flows = %d, want 1", len(unsafe.Flows))
	}

	a := AnalyzeDOMScript(`el.innerHTML = encodeURIComponent(location.hash);`, DOMBudget{})
	if len(a.Flows) != 0 {
		t.Fatalf("flows = %d, want 0 for a sanitized flow: %v", len(a.Flows), domFlowNames(a))
	}
	s, ok := domSuppressedFor(a, DOMSuppressReasonSanitizer)
	if !ok {
		t.Fatalf("the sanitized flow was not recorded as suppressed: %s", a.Summary())
	}
	if s.By != "encodeURIComponent" {
		t.Errorf("suppressed by = %q, want encodeURIComponent", s.By)
	}
	if s.Why == "" {
		t.Error("a suppression must carry the recorded justification, not just the operation name")
	}
	if s.Issue != "Cross-site scripting (DOM-based)" {
		t.Errorf("suppressed issue = %q, want the issue it would have been reported as", s.Issue)
	}
	if len(a.Findings()) != 0 {
		t.Error("a suppressed flow must not become a finding")
	}
}

func Test_a_sanitizer_through_a_variable_hop_is_still_recognised(t *testing.T) {
	a := AnalyzeDOMScript(`
var raw = location.hash;
var safe = encodeURIComponent(raw);
document.write(safe);
`, DOMBudget{})
	if len(a.Flows) != 0 {
		t.Fatalf("flows = %d, want 0: %v", len(a.Flows), domFlowNames(a))
	}
	if _, ok := domSuppressedFor(a, DOMSuppressReasonSanitizer); !ok {
		t.Fatalf("the sanitizer was lost across the variable hop: %s", a.Summary())
	}
}

func Test_a_sanitizer_that_does_not_cover_this_sink_class_is_reported_with_the_reason_named(t *testing.T) {
	// escapeHtml stops the value becoming markup and does nothing about a javascript: URL, so a
	// navigation sink defended with it is still reported — and the finding has to say why.
	a := AnalyzeDOMScript(`window.location = escapeHtml(location.hash);`, DOMBudget{})

	f := domFlowFor(t, a, "Open redirection (DOM-based)")
	if len(f.Caveats) == 0 {
		t.Fatal("a flow reported despite an apparent defence must carry a caveat naming it")
	}
	if !strings.Contains(f.Caveats[0], "escapeHtml") {
		t.Errorf("caveat does not name the operation: %q", f.Caveats[0])
	}
	if _, ok := domSuppressedFor(a, DOMSuppressReasonSanitizer); ok {
		t.Error("a defence not accepted for this sink class must not suppress the flow")
	}
	// The same operation on the sink class it does cover is accepted.
	covered := AnalyzeDOMScript(`el.innerHTML = escapeHtml(location.hash);`, DOMBudget{})
	if len(covered.Flows) != 0 {
		t.Errorf("escapeHtml is accepted for XSS; flows = %v", domFlowNames(covered))
	}
}

func Test_a_weak_encoder_is_reported_rather_than_accepted_as_a_defence(t *testing.T) {
	for _, script := range []string{
		`document.write(escape(location.hash));`,
		`window.location = encodeURI(location.hash);`,
		`el.innerHTML = location.hash.replace("<", "");`,
	} {
		a := AnalyzeDOMScript(script, DOMBudget{})
		if len(a.Flows) == 0 {
			t.Fatalf("%s: flows = 0, want the flow reported despite the weak encoder", script)
		}
		if len(a.Flows[0].Caveats) == 0 {
			t.Errorf("%s: the weak encoder was not named in the finding's caveats", script)
		}
		if _, ok := domSuppressedFor(a, DOMSuppressReasonSanitizer); ok {
			t.Errorf("%s: a weak encoder must never suppress a flow", script)
		}
	}
}

func Test_writing_a_tainted_value_to_text_content_is_suppressed_as_a_safe_sink_and_still_recorded(t *testing.T) {
	a := AnalyzeDOMScript(`el.textContent = location.hash;`, DOMBudget{})

	if len(a.Flows) != 0 {
		t.Fatalf("flows = %d, want 0 for a text sink: %v", len(a.Flows), domFlowNames(a))
	}
	s, ok := domSuppressedFor(a, DOMSuppressReasonSafeSink)
	if !ok {
		t.Fatalf("a safe-sink flow must be recorded, not dropped: %s", a.Summary())
	}
	if s.By != "textContent" {
		t.Errorf("suppressed by = %q, want textContent", s.By)
	}
	if s.SourceExpr != "location.hash" {
		t.Errorf("source expr = %q, want location.hash", s.SourceExpr)
	}
}

// ---- couldn't tell is not the same as safe --------------------------------------------------

func Test_a_sink_fed_by_an_untraceable_value_is_unresolved_and_never_counted_as_safe(t *testing.T) {
	a := AnalyzeDOMScript(`function render(v) { document.getElementById("o").innerHTML = v; }`, DOMBudget{})

	if len(a.Flows) != 0 {
		t.Fatalf("flows = %d, want 0: an untraced value is not a finding", len(a.Flows))
	}
	if len(a.Suppressed) != 0 {
		t.Fatalf("suppressed = %d, want 0: an untraced value is not a sanitized flow", len(a.Suppressed))
	}
	if !domHasUnresolved(a, DOMUnresolvedUntracedValue) {
		t.Fatalf("the untraceable sink input was not recorded as unresolved: %s", a.Summary())
	}
	var u DOMUnresolved
	for _, cand := range a.Unresolved {
		if cand.Reason == DOMUnresolvedUntracedValue {
			u = cand
		}
	}
	if u.Sink != "innerHTML" {
		t.Errorf("unresolved sink = %q, want innerHTML", u.Sink)
	}
	if !strings.Contains(u.Detail, "v") {
		t.Errorf("unresolved detail does not name the untraced identifier: %q", u.Detail)
	}
	if u.Reason.Explanation() == "" {
		t.Error("an unresolved reason must carry an explanation an operator can act on")
	}
}

func Test_a_computed_assignment_target_carrying_taint_is_unresolved_not_silent(t *testing.T) {
	a := AnalyzeDOMScript(`var p = "inner" + "HTML"; el[p] = location.hash;`, DOMBudget{})

	if len(a.Flows) != 0 {
		t.Errorf("flows = %v, want none: the sink written is not statically known", domFlowNames(a))
	}
	if !domHasUnresolved(a, DOMUnresolvedComputedAccess) {
		t.Fatalf("a computed sink target with a tainted value was not recorded: %s", a.Summary())
	}
}

func Test_a_sink_written_only_from_literals_is_neither_a_finding_nor_unresolved(t *testing.T) {
	a := AnalyzeDOMScript(`document.getElementById("o").innerHTML = "<b>static</b>";`, DOMBudget{})

	if len(a.Flows) != 0 || len(a.Suppressed) != 0 {
		t.Errorf("flows = %d, suppressed = %d, want 0 and 0", len(a.Flows), len(a.Suppressed))
	}
	if domHasUnresolved(a, DOMUnresolvedUntracedValue) {
		t.Error("a literal sink write is fully resolved; it must not be reported as unresolved")
	}
}

func Test_a_script_that_builds_code_at_runtime_records_that_the_pass_went_blind(t *testing.T) {
	a := AnalyzeDOMScript(`var f = new Function("return 1"); f();`, DOMBudget{})

	if !domHasUnresolved(a, DOMUnresolvedDynamicCode) {
		t.Fatalf("runtime code construction was not recorded as a blind spot: %s", a.Summary())
	}
}

func Test_a_minified_script_is_analysed_and_flagged_as_weaker_evidence(t *testing.T) {
	packed := "var a=1;" + strings.Repeat("b(a);", 800) + "c.innerHTML=location.hash;"
	a := AnalyzeDOMScript(packed, DOMBudget{})

	if !domHasUnresolved(a, DOMUnresolvedMinified) {
		t.Errorf("a minified script was not flagged: %s", a.Summary())
	}
	// Flagged is not the same as refused: minified code still traces.
	domFlowFor(t, a, "Cross-site scripting (DOM-based)")
}

// ---- DOM-03: bounded, and the bound is reported ---------------------------------------------

func Test_exceeding_the_statement_budget_names_the_bound_and_marks_the_analysis_incomplete(t *testing.T) {
	// A long script whose sink sits at the very end: with a statement budget too small to reach
	// it, the pass must say so rather than return an empty, clean-looking result.
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString("var x = 1;\n")
	}
	b.WriteString("el.innerHTML = location.hash;\n")

	a := AnalyzeDOMScript(b.String(), DOMBudget{MaxStatements: 10})

	if !a.Budget.Truncated() {
		t.Fatal("Truncated() = false after the statement budget was exhausted")
	}
	if !a.Budget.Hit(DOMStopStatements) {
		t.Errorf("stops = %v, want the statement bound named", a.Budget.Stops)
	}
	if a.Complete() {
		t.Error("Complete() = true on a truncated analysis")
	}
	if a.Caveat() == "" {
		t.Fatal("a truncated analysis must carry a non-empty caveat")
	}
	if !strings.Contains(a.Caveat(), "INCOMPLETE") {
		t.Errorf("caveat does not say the analysis is incomplete: %q", a.Caveat())
	}
	if !strings.Contains(a.Summary(), "INCOMPLETE") {
		t.Errorf("summary does not say the analysis is incomplete: %q", a.Summary())
	}
	if len(a.Flows) != 0 {
		t.Errorf("flows = %v: the sink is past the budget, so it must not appear", domFlowNames(a))
	}
}

func Test_a_truncated_analysis_still_carries_the_findings_it_did_reach_and_says_they_are_a_floor(t *testing.T) {
	// The sink is first, so it is found; the budget then runs out. Findings are real *and*
	// incomplete, which is exactly the pair a caller must be able to see at once.
	var b strings.Builder
	b.WriteString("el.innerHTML = location.hash;\n")
	for i := 0; i < 500; i++ {
		b.WriteString("var x" + string(rune('a'+i%26)) + " = 1;\n")
	}

	a := AnalyzeDOMScript(b.String(), DOMBudget{MaxStatements: 600, MaxPropagationRounds: 1})

	if len(a.Findings()) == 0 {
		t.Fatalf("findings = 0, want the flow that was reached: %s", a.Summary())
	}
	if !a.Budget.Truncated() {
		t.Fatalf("Truncated() = false, want true: %s", a.Summary())
	}
	if a.Complete() {
		t.Error("Complete() = true while holding a truncated result")
	}
	if !strings.Contains(a.Caveat(), "floor") {
		t.Errorf("caveat does not tell the caller the findings are a floor: %q", a.Caveat())
	}
}

func Test_the_flow_cap_drops_and_counts_the_excess_rather_than_appending_past_it(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteString("el" + string(rune('a'+i)) + ".innerHTML = location.hash;\n")
	}

	a := AnalyzeDOMScript(b.String(), DOMBudget{MaxFlows: 3})

	if len(a.Flows) != 3 {
		t.Fatalf("flows = %d, want exactly the cap of 3", len(a.Flows))
	}
	if a.Budget.FlowsDropped != 9 {
		t.Errorf("FlowsDropped = %d, want 9 — a dropped result must be counted", a.Budget.FlowsDropped)
	}
	if !a.Budget.Hit(DOMStopFlows) {
		t.Errorf("stops = %v, want the flow bound named", a.Budget.Stops)
	}
	if a.Complete() {
		t.Error("Complete() = true although 9 flows were dropped")
	}
}

func Test_the_unresolved_cap_drops_and_counts_the_excess(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("el" + string(rune('a'+i)) + ".innerHTML = untraced" + string(rune('a'+i)) + ";\n")
	}

	a := AnalyzeDOMScript(b.String(), DOMBudget{MaxUnresolved: 2})

	if len(a.Unresolved) != 2 {
		t.Fatalf("unresolved = %d, want exactly the cap of 2", len(a.Unresolved))
	}
	if a.Budget.UnresolvedDropped != 8 {
		t.Errorf("UnresolvedDropped = %d, want 8", a.Budget.UnresolvedDropped)
	}
	if !a.Budget.Hit(DOMStopUnresolved) {
		t.Errorf("stops = %v, want the unresolved bound named", a.Budget.Stops)
	}
}

// domBackwardChain is a taint chain written in reverse — each assignment reads a variable defined
// on a later line, and the sink comes first. One propagation round resolves one link, so this is
// the shape that exercises the round budget; a chain written in order resolves in a single round
// however long it is.
const domBackwardChain = `
el.innerHTML = a5;
var a5 = a4;
var a4 = a3;
var a3 = a2;
var a2 = a1;
var a1 = location.hash;
`

func Test_a_propagation_that_converges_inside_its_round_budget_is_not_reported_as_truncated(t *testing.T) {
	a := AnalyzeDOMScript(domBackwardChain, DOMBudget{MaxPropagationRounds: 8})

	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if got := strings.Join(f.Via, ","); got != "a1,a2,a3,a4,a5" {
		t.Errorf("via = %q, want the whole chain a1,a2,a3,a4,a5", got)
	}
	if a.Budget.Hit(DOMStopPropagationRounds) {
		t.Error("a converged propagation must not record a round-budget stop")
	}
	if !a.Complete() {
		t.Errorf("Complete() = false on a converged analysis: %s", a.Caveat())
	}
}

func Test_a_taint_chain_longer_than_the_round_budget_records_the_round_bound(t *testing.T) {
	a := AnalyzeDOMScript(domBackwardChain, DOMBudget{MaxPropagationRounds: 2})

	if !a.Budget.Hit(DOMStopPropagationRounds) {
		t.Fatalf("a chain longer than the round budget did not record the bound: %s", a.Summary())
	}
	if a.Complete() {
		t.Error("Complete() = true although the assignment chain was not followed to its end")
	}
	if len(a.Flows) != 0 {
		t.Errorf("flows = %v: taint never reached the sink, so nothing should be reported",
			domFlowNames(a))
	}
}

func Test_the_script_byte_budget_records_both_a_stop_and_the_script_it_did_not_analyse(t *testing.T) {
	body := "<html><script>" + strings.Repeat("var pad = 1;\n", 200) +
		"</script><script>el.innerHTML = location.hash;</script></html>"

	a := AnalyzeDOMDocument([]byte(body), "text/html", DOMBudget{MaxScriptBytes: 100})

	if !a.Budget.Hit(DOMStopScriptBytes) {
		t.Fatalf("stops = %v, want the script-byte bound named", a.Budget.Stops)
	}
	if len(a.SkippedScripts) == 0 {
		t.Fatal("a script rejected by the byte budget must be recorded as not analysed")
	}
	found := false
	for _, s := range a.SkippedScripts {
		if s.Reason == DOMScriptSkipOverBudget {
			found = true
		}
	}
	if !found {
		t.Error("the over-budget script was not recorded with the over-budget reason")
	}
	if a.Complete() {
		t.Error("Complete() = true although a script body was never read")
	}
}

func Test_the_script_count_budget_records_a_stop_and_the_scripts_it_did_not_analyse(t *testing.T) {
	body := "<html>" + strings.Repeat("<script>var a = 1;</script>", 6) + "</html>"

	a := AnalyzeDOMDocument([]byte(body), "text/html", DOMBudget{MaxScripts: 2})

	if len(a.Scripts) != 2 {
		t.Fatalf("scripts analysed = %d, want the cap of 2", len(a.Scripts))
	}
	if !a.Budget.Hit(DOMStopScripts) {
		t.Errorf("stops = %v, want the script-count bound named", a.Budget.Stops)
	}
	if len(a.SkippedScripts) != 4 {
		t.Errorf("skipped scripts = %d, want the 4 that were never read", len(a.SkippedScripts))
	}
}

func Test_truncation_is_derived_from_the_stop_list_so_it_cannot_be_set_without_a_reason(t *testing.T) {
	var r DOMBudgetReport
	if r.Truncated() {
		t.Fatal("a zero budget report must not read as truncated")
	}
	for _, stop := range DOMBudgetStopAll {
		var one DOMBudgetReport
		one.record(stop)
		if !one.Truncated() {
			t.Errorf("recording %v did not mark the report truncated", stop)
		}
		if !one.Hit(stop) {
			t.Errorf("recording %v did not register as hit", stop)
		}
		if stop.Explanation() == "" || stop.Explanation() == "unknown budget stop" {
			t.Errorf("%v has no operator-actionable explanation", stop)
		}
	}
}

func Test_recording_the_same_bound_twice_keeps_one_entry(t *testing.T) {
	var r DOMBudgetReport
	r.record(DOMStopFlows)
	r.record(DOMStopFlows)
	if len(r.Stops) != 1 {
		t.Errorf("stops = %v, want one entry per bound", r.Stops)
	}
}

func Test_the_default_budget_fills_in_only_the_bounds_a_caller_left_unset(t *testing.T) {
	got := DOMBudget{MaxStatements: 7}.normalise()
	def := DefaultDOMBudget()
	if got.MaxStatements != 7 {
		t.Errorf("MaxStatements = %d, want the caller's 7", got.MaxStatements)
	}
	if got.MaxFlows != def.MaxFlows || got.MaxScriptBytes != def.MaxScriptBytes {
		t.Error("normalise did not fill the unset bounds from the default budget")
	}
}

// ---- skips: never looked is not the same as looked and found nothing -----------------------

func Test_a_body_that_is_neither_html_nor_javascript_is_skipped_rather_than_reported_clean(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(`{"a":"location.hash"}`), "application/json", DOMBudget{})

	if a.Skip == nil {
		t.Fatal("Skip = nil: a non-script body must be a skip, not a clean analysis")
	}
	if *a.Skip != DOMSkipNotScriptBearing {
		t.Errorf("skip = %v, want not-script-bearing", *a.Skip)
	}
	if a.Complete() {
		// Nothing was analysed at all, so "complete" would be a lie of a different kind: the
		// caveat is what a caller must render.
		if a.Caveat() == "" {
			t.Error("a skipped analysis must still carry a caveat saying it did not run")
		}
	}
}

func Test_an_empty_body_is_skipped_and_says_why(t *testing.T) {
	a := AnalyzeDOMDocument(nil, "text/html", DOMBudget{})
	if a.Skip == nil || *a.Skip != DOMSkipEmptyBody {
		t.Fatalf("skip = %v, want empty-body", a.Skip)
	}
	if !strings.Contains(a.Summary(), "skipped") {
		t.Errorf("summary does not say the pass was skipped: %q", a.Summary())
	}
}

func Test_an_external_script_src_is_recorded_as_not_analysed_rather_than_as_clean(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(`<html><script src="/app.js"></script></html>`), "text/html", DOMBudget{})

	if len(a.Scripts) != 0 {
		t.Errorf("scripts analysed = %d, want 0: the body is not in this response", len(a.Scripts))
	}
	if len(a.SkippedScripts) != 1 {
		t.Fatalf("skipped scripts = %d, want 1", len(a.SkippedScripts))
	}
	if a.SkippedScripts[0].Reason != DOMScriptSkipExternalSrc {
		t.Errorf("reason = %v, want external src", a.SkippedScripts[0].Reason)
	}
	if a.SkippedScripts[0].Detail != "/app.js" {
		t.Errorf("detail = %q, want the src URL", a.SkippedScripts[0].Detail)
	}
}

func Test_a_data_src_attribute_does_not_make_an_inline_script_look_external(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(`<html><script data-src="x">el.innerHTML = location.hash;</script></html>`),
		"text/html", DOMBudget{})

	if len(a.SkippedScripts) != 0 {
		t.Errorf("skipped = %v, want none: the body is inline", a.SkippedScripts)
	}
	domFlowFor(t, a, "Cross-site scripting (DOM-based)")
}

func Test_a_non_executable_script_type_is_recorded_as_not_analysed(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(`<html><script type="text/template">`+
		`el.innerHTML = location.hash;</script></html>`), "text/html", DOMBudget{})

	if len(a.Flows) != 0 {
		t.Errorf("flows = %v, want none: the browser will not execute this element", domFlowNames(a))
	}
	if len(a.SkippedScripts) != 1 || a.SkippedScripts[0].Reason != DOMScriptSkipNonExecutableType {
		t.Fatalf("skipped = %v, want one non-executable-type entry", a.SkippedScripts)
	}
	if a.SkippedScripts[0].Reason.Explanation() == "" {
		t.Error("a script skip reason must carry an explanation")
	}
}

func Test_a_javascript_content_type_is_analysed_as_one_whole_script(t *testing.T) {
	a := AnalyzeDOMDocument([]byte("var t = document.referrer;\neval(t);\n"),
		"application/javascript", DOMBudget{})

	f := domFlowFor(t, a, "JavaScript injection (DOM-based)")
	if f.Script.Origin != "response body (javascript)" {
		t.Errorf("origin = %q, want response body (javascript)", f.Script.Origin)
	}
}

func Test_every_dom_skip_carries_an_operator_actionable_explanation(t *testing.T) {
	for _, s := range DOMSkipAll {
		if e := s.Explanation(); e == "" || e == "unknown skip" {
			t.Errorf("%d has no explanation", int(s))
		}
	}
	for _, r := range []DOMUnresolvedReason{
		DOMUnresolvedUntracedValue, DOMUnresolvedComputedAccess,
		DOMUnresolvedDynamicCode, DOMUnresolvedMinified,
	} {
		if e := r.Explanation(); e == "" || e == "unknown unresolved reason" {
			t.Errorf("unresolved reason %d has no explanation", int(r))
		}
	}
	for _, r := range []DOMScriptSkipReason{
		DOMScriptSkipExternalSrc, DOMScriptSkipNonExecutableType, DOMScriptSkipOverBudget,
	} {
		if e := r.Explanation(); e == "" || e == "unknown script skip" {
			t.Errorf("script skip reason %d has no explanation", int(r))
		}
	}
}

// ---- the scanner entry point ---------------------------------------------------------------

func domExchangeWithBody(t *testing.T, store *core.TrafficStore, host, contentType, body string) *core.Exchange {
	t.Helper()
	reqID, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	raw := "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\n\r\n" + body
	respID, err := store.Put([]byte(raw), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: host, Port: 443, TLS: true, Method: "GET", Path: "/", Status: &status,
	}
	store.AddExchange(ex)
	return ex
}

func Test_scan_dom_reports_a_catalogued_finding_from_a_stored_exchange_response(t *testing.T) {
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("*")
	ps := NewPassiveScanner(store, zap.NewNop())
	ps.scope = scope

	ex := domExchangeWithBody(t, store, "app.test", "text/html",
		"<html><script>document.write(location.hash);</script></html>")

	a := ps.ScanDOM(ex)
	if a.Skip != nil {
		t.Fatalf("skip = %v, want the pass to run", *a.Skip)
	}
	findings := a.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %s", len(findings), a.Summary())
	}
	if findings[0].Name != "Cross-site scripting (DOM-based)" {
		t.Errorf("name = %q", findings[0].Name)
	}
	if findings[0].URL != "https://app.test:443/" {
		t.Errorf("url = %q, want the exchange URL", findings[0].URL)
	}
	if findings[0].ExchangeID != ex.ID {
		t.Errorf("exchange id = %d, want %d", findings[0].ExchangeID, ex.ID)
	}
	if findings[0].Method != "GET" {
		t.Errorf("method = %q, want GET", findings[0].Method)
	}
}

func Test_scan_dom_skips_an_out_of_scope_exchange_and_says_so(t *testing.T) {
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("in.test")
	ps := NewPassiveScanner(store, zap.NewNop())
	ps.scope = scope

	ex := domExchangeWithBody(t, store, "out.test", "text/html",
		"<html><script>document.write(location.hash);</script></html>")

	a := ps.ScanDOM(ex)
	if a.Skip == nil || *a.Skip != DOMSkipOutOfScope {
		t.Fatalf("skip = %v, want out-of-scope", a.Skip)
	}
	if len(a.Findings()) != 0 {
		t.Error("a skipped analysis must produce no findings")
	}
	if a.Caveat() == "" {
		t.Error("a skipped analysis must carry a caveat saying it did not run")
	}
}

func Test_scan_dom_skips_a_nil_exchange_and_an_exchange_with_no_response(t *testing.T) {
	store := core.NewTrafficStore()
	ps := NewPassiveScanner(store, zap.NewNop())

	if a := ps.ScanDOM(nil); a.Skip == nil || *a.Skip != DOMSkipExchangeNotFound {
		t.Errorf("nil exchange: skip = %v, want exchange-not-found", a.Skip)
	}
	if a := ps.ScanDOM(&core.Exchange{Host: "x.test"}); a.Skip == nil || *a.Skip != DOMSkipResponseNotFound {
		t.Errorf("no response: skip = %v, want response-not-found", a.Skip)
	}
}

func Test_scan_dom_does_not_disturb_the_passive_check_coverage_table(t *testing.T) {
	// The coverage table is index-aligned with the loaded BCheck set; folding a DOM outcome into
	// it would corrupt exactly the identities coverage.go exists to preserve.
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("*")
	ps := buildPassiveScanner(store, scope, zap.NewNop(), nil, LoadReport{})

	ex := domExchangeWithBody(t, store, "app.test", "text/html",
		"<html><script>document.write(location.hash);</script></html>")

	before := ps.Coverage()
	if len(ps.ScanDOM(ex).Flows) != 1 {
		t.Fatal("the DOM pass did not run over the stored response")
	}
	after := ps.Coverage()
	for i := range after.Skips {
		if after.Skips[i].Count != before.Skips[i].Count {
			t.Errorf("ScanDOM changed the passive skip counter %q", after.Skips[i].Reason)
		}
	}
}

// ---- lexing ---------------------------------------------------------------------------------

func Test_a_comment_containing_a_source_and_a_sink_is_not_reported(t *testing.T) {
	for _, script := range []string{
		"// el.innerHTML = location.hash;\nvar ok = 1;",
		"/* el.innerHTML = location.hash; */\nvar ok = 1;",
	} {
		a := AnalyzeDOMScript(script, DOMBudget{})
		if len(a.Flows) != 0 {
			t.Errorf("%q: flows = %v, want none — the code is commented out", script, domFlowNames(a))
		}
	}
}

func Test_a_source_name_that_is_only_a_prefix_of_an_identifier_is_not_a_source(t *testing.T) {
	a := AnalyzeDOMScript(`var locationCount = 1; el.innerHTML = locationCount;`, DOMBudget{})
	if len(a.Flows) != 0 {
		t.Errorf("flows = %v, want none: locationCount is not location", domFlowNames(a))
	}
}

func Test_a_sink_name_that_is_only_a_prefix_of_an_identifier_is_not_a_sink(t *testing.T) {
	a := AnalyzeDOMScript(`myEvaluator(location.hash);`, DOMBudget{})
	if len(a.Flows) != 0 {
		t.Errorf("flows = %v, want none: myEvaluator is not eval", domFlowNames(a))
	}
}

func Test_set_timeout_with_a_function_argument_is_not_treated_as_a_sink(t *testing.T) {
	for _, script := range []string{
		`setTimeout(function () { render(location.hash); }, 10);`,
		`setTimeout(() => render(location.hash), 10);`,
	} {
		a := AnalyzeDOMScript(script, DOMBudget{})
		for _, f := range a.Flows {
			if f.Sink.Match == "setTimeout" {
				t.Errorf("%q: setTimeout with a function argument was reported as a string sink", script)
			}
		}
	}
}

func Test_a_multi_line_call_is_rejoined_before_its_arguments_are_read(t *testing.T) {
	a := AnalyzeDOMScript("document.write(\n  \"<b>\" + location.hash + \"</b>\"\n);", DOMBudget{})
	domFlowFor(t, a, "Cross-site scripting (DOM-based)")
}

func Test_a_longer_source_expression_wins_over_the_prefix_it_contains(t *testing.T) {
	a := AnalyzeDOMScript(`el.innerHTML = location.search;`, DOMBudget{})
	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if f.SourceExpr != "location.search" {
		t.Errorf("source expr = %q, want the specific location.search, not the bare location", f.SourceExpr)
	}
}

func Test_a_navigation_assignment_is_open_redirection_and_an_anchor_href_is_link_manipulation(t *testing.T) {
	nav := AnalyzeDOMScript(`location.href = location.hash;`, DOMBudget{})
	domFlowFor(t, nav, "Open redirection (DOM-based)")

	link := AnalyzeDOMScript(`anchor.href = location.hash;`, DOMBudget{})
	domFlowFor(t, link, "Link manipulation (DOM-based)")
}

func Test_appending_to_inner_html_is_the_same_sink_as_setting_it(t *testing.T) {
	a := AnalyzeDOMScript(`el.innerHTML += location.hash;`, DOMBudget{})
	domFlowFor(t, a, "Cross-site scripting (DOM-based)")
}

func Test_an_equality_comparison_is_not_read_as_an_assignment(t *testing.T) {
	a := AnalyzeDOMScript(`if (el.innerHTML === location.hash) { ok(); }`, DOMBudget{})
	if len(a.Flows) != 0 {
		t.Errorf("flows = %v, want none: a comparison writes nothing", domFlowNames(a))
	}
}

// domRealisticPage is written the way page scripts actually are — an IIFE, nested callbacks, a
// regex literal, a division, a CDN script, a JSON island, framework-shaped jQuery — because the
// failure mode this test exists to catch is not a missed pattern but a lexing collapse: an earlier
// draft folded the whole IIFE into one statement, which silently lost every assignment sink inside
// it while still reporting "complete".
const domRealisticPage = `<!doctype html>
<html><head>
<script src="https://cdn.example/jquery.min.js"></script>
<script type="application/json" id="cfg">{"a":1}</script>
</head>
<body>
<div id="out"></div>
<script>
(function () {
  "use strict";
  var params = {};
  location.search.substring(1).split("&").forEach(function (pair) {
    var kv = pair.split("=");
    params[kv[0]] = decodeURIComponent(kv[1] || "");
  });
  var name = params.name || "guest";
  document.getElementById("out").textContent = "Hi " + name;
  var target = location.hash.slice(1);
  if (target) {
    document.getElementById("out").innerHTML = "<a href='" + target + "'>go</a>";
  }
  $("#banner").html(escapeHtml(params.msg));
  window.addEventListener("message", function (event) {
    if (event.origin !== "https://trusted.example") { return; }
    eval(event.data);
  });
  setTimeout(function () { render(); }, 50);
  var re = /^[a-z]+$/;
  if (!re.test(name)) { console.log("bad " + name / 2); }
})();
</script>
</body></html>`

func Test_a_realistic_page_is_traced_without_the_lexer_collapsing_its_function_bodies(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(domRealisticPage), "text/html; charset=utf-8", DOMBudget{})

	// This page carries an external CDN script and a non-executable <script type>, so the pass did
	// NOT read every script in it and must not claim to have. This assertion used to be
	// `if !a.Complete()` — it asserted the opposite, and passed, because Complete() consulted only the
	// budget and ignored SkippedScripts entirely. That made a page whose every script is external —
	// i.e. any modern single-page app — report a clean complete pass over zero bytes of JavaScript.
	// The assertion was pinning the bug, so it is inverted here rather than the fix being relaxed.
	if a.Complete() {
		t.Error("Complete() = true although this page has scripts the pass never read; " +
			"an unread script makes the analysis a floor, not a total")
	}
	if len(a.SkippedScripts) != 2 {
		t.Errorf("SkippedScripts = %d, want 2 (the external src and the non-executable type)", len(a.SkippedScripts))
	}
	// And the caveat has to say so, since that is what a report prints next to the findings.
	if cav := a.Caveat(); !strings.Contains(cav, "were not read") {
		t.Errorf("Caveat() = %q, want it to name the scripts that were not read", cav)
	}
	// The guard: a collapsed lexer yields a handful of mega-statements. This script has dozens.
	if a.Budget.Statements < 40 {
		t.Errorf("statements = %d, want dozens — a low count means function bodies were merged",
			a.Budget.Statements)
	}

	xss := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if xss.Sink.Match != "innerHTML" || strings.Join(xss.Via, ",") != "target" {
		t.Errorf("xss flow = %s via %v, want innerHTML via target", xss.Sink.Match, xss.Via)
	}
	if !strings.Contains(xss.Statement, "innerHTML") {
		t.Errorf("statement is not the sink line: %q", xss.Statement)
	}
	inj := domFlowFor(t, a, "JavaScript injection (DOM-based)")
	if inj.SourceExpr != "event.data" {
		t.Errorf("injection source = %q, want event.data", inj.SourceExpr)
	}
	if len(a.Flows) != 2 {
		t.Errorf("flows = %v, want exactly the two real ones", domFlowNames(a))
	}

	// The textContent write of an untraced value is neither reported nor unresolved: a text sink is
	// safe whatever reaches it. The jQuery .html() of an object property this pass cannot follow is
	// unresolved — the aliasing limit, surfaced rather than passed off as clean.
	sawHTMLUnresolved := false
	for _, u := range a.Unresolved {
		if u.Reason == DOMUnresolvedUntracedValue && u.Sink == ".html" {
			sawHTMLUnresolved = true
		}
	}
	if !sawHTMLUnresolved {
		t.Errorf("the jQuery .html() sink fed by an untracked object was not recorded: %v", a.Unresolved)
	}
	if len(a.SkippedScripts) != 2 {
		t.Errorf("skipped scripts = %v, want the CDN script and the JSON island", a.SkippedScripts)
	}
}

func Test_the_source_and_sink_tables_are_held_longest_match_first(t *testing.T) {
	for i := 1; i < len(domSources); i++ {
		if len(domSources[i-1].Expr) < len(domSources[i].Expr) {
			t.Fatalf("domSources is not longest-first at %d: %q before %q",
				i, domSources[i-1].Expr, domSources[i].Expr)
		}
	}
	for i := 1; i < len(domSinks); i++ {
		if len(domSinks[i-1].Match) < len(domSinks[i].Match) {
			t.Fatalf("domSinks is not longest-first at %d: %q before %q",
				i, domSinks[i-1].Match, domSinks[i].Match)
		}
	}
}

func Test_a_sanitizer_declares_which_issue_classes_it_is_accepted_for(t *testing.T) {
	for _, s := range domSanitizers {
		if s.Why == "" {
			t.Errorf("sanitizer %q has no recorded justification", s.Call)
		}
		for _, n := range s.Neutralises {
			if _, ok := ByName(domIssueName(n, DOMSourceURL)); !ok {
				t.Errorf("sanitizer %q claims to neutralise %q, which is not a catalogued issue base",
					s.Call, n)
			}
		}
	}
	for _, w := range domWeakEncoders {
		if w.Why == "" {
			t.Errorf("weak encoder %q has no recorded reason for not being accepted", w.Call)
		}
	}
}

// The SPA case, stated as its own test because it is the common one and the old behaviour was
// indistinguishable from a clean result. A page whose only script is external gives the pass nothing
// to read: Scripts is empty, no flow is possible, and the budget is untouched — so before
// SkippedScripts was consulted this returned Complete() == true with an empty Caveat(), byte-identical
// to "analysed it all, found nothing".
func Test_a_page_whose_scripts_are_all_external_is_not_a_clean_pass(t *testing.T) {
	a := AnalyzeDOMDocument(
		[]byte(`<html><head><script src="/static/app.bundle.js"></script></head><body></body></html>`),
		"text/html", DOMBudget{})

	if a.Skip != nil {
		t.Fatalf("the pass declined to run entirely (%s); it should run and report what it could not read",
			a.Skip.Explanation())
	}
	if len(a.Scripts) != 0 {
		t.Errorf("Scripts = %d, want 0 — there is no inline script here", len(a.Scripts))
	}
	if len(a.SkippedScripts) != 1 {
		t.Fatalf("SkippedScripts = %d, want 1", len(a.SkippedScripts))
	}
	if a.Complete() {
		t.Error("Complete() = true after reading zero bytes of JavaScript; that is the exact claim " +
			"this type exists to make impossible")
	}
	cav := a.Caveat()
	if cav == "" {
		t.Fatal("Caveat() is empty, so a report would print these (zero) findings as a complete result")
	}
	if !strings.Contains(cav, "external URL") {
		t.Errorf("Caveat() = %q, want it to name the external script as the reason", cav)
	}
}

// A page with no scripts at all is genuinely complete — there was nothing to miss. Without this the
// fix above could be satisfied by making every analysis report incomplete, which would be useless.
func Test_a_page_with_no_scripts_at_all_is_a_complete_pass(t *testing.T) {
	a := AnalyzeDOMDocument([]byte(`<html><body><p>static content</p></body></html>`), "text/html", DOMBudget{})
	if !a.Complete() {
		t.Errorf("Complete() = false on a page with no scripts: %s", a.Caveat())
	}
	if cav := a.Caveat(); cav != "" {
		t.Errorf("Caveat() = %q, want empty — nothing about this pass needs qualifying", cav)
	}
}
