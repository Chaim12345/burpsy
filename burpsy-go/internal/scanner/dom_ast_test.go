package scanner

import (
	"strings"
	"testing"
)

// r996: capabilities the AST pass (goja/parser) adds over the lexical pass. These tests are the
// bead's acceptance seam: they must go red on the lexical pass and green on the AST pass, without
// any of the behaviours dom_test.go pins changing.

// A function argument carries taint into a sink: the call site binds the callee's parameter.
func Test_a_function_argument_carries_taint_into_a_sink(t *testing.T) {
	a := AnalyzeDOMScript(`
function set(html) { document.getElementById("m").innerHTML = html; }
set(location.hash);
`, DOMBudget{})

	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if f.Sink.Match != "innerHTML" {
		t.Errorf("sink = %q, want innerHTML", f.Sink.Match)
	}
	if f.SourceExpr != "location.hash" {
		t.Errorf("source = %q, want location.hash", f.SourceExpr)
	}
	if got := strings.Join(f.Via, ","); !strings.Contains(got, "html") {
		t.Errorf("via = %q, want the callee's parameter named", got)
	}
}

// An object property alias carries taint to a sink: o.v = <tainted>; el.innerHTML = o.v.
func Test_an_object_property_alias_carries_taint_to_a_sink(t *testing.T) {
	a := AnalyzeDOMScript(`
var o = {};
o.v = location.hash;
document.getElementById("m").innerHTML = o.v;
`, DOMBudget{})

	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if f.Sink.Match != "innerHTML" {
		t.Errorf("sink = %q, want innerHTML", f.Sink.Match)
	}
}

// Pinned both ways: a parameter no call ever feeds is untraced, unresolved, never a flow.
func Test_the_ast_path_keeps_an_uncalled_parameter_untraced(t *testing.T) {
	a := AnalyzeDOMScript(`function render(v) { document.getElementById("o").innerHTML = v; }`, DOMBudget{})

	if len(a.Flows) != 0 {
		t.Fatalf("flows = %d, want 0: an uncalled parameter is not attacker-controlled", len(a.Flows))
	}
	if !domHasUnresolved(a, DOMUnresolvedUntracedValue) {
		t.Fatalf("the untraceable sink input was not recorded as unresolved: %s", a.Summary())
	}
}

// A script goja's parser rejects is not dropped: the lexical pass still reads it.
func Test_an_unparseable_script_falls_back_to_the_lexical_pass(t *testing.T) {
	a := AnalyzeDOMScript("el.innerHTML = location.hash;\nreturn;\n", DOMBudget{})
	f := domFlowFor(t, a, "Cross-site scripting (DOM-based)")
	if f.Sink.Match != "innerHTML" {
		t.Errorf("sink = %q, want innerHTML", f.Sink.Match)
	}
}
