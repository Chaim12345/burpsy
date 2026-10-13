package scanner

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

// TestXSSIsMarkupFragment pins which non-markup answers are treated as an HTML fragment. A plain
// echo, JSON, and a body whose first tag is not an HTML element are not; those are the shapes the
// content-type gate exists for and must stay gated.
func TestXSSIsMarkupFragment(t *testing.T) {
	const c = "zxss0011aabbcc"
	cases := []struct {
		name, body string
		want       bool
	}{
		{"element with the value in an attribute", `<img src=` + c + ` width="400"/>`, true},
		{"element list with the value in text", `<div id="comments">x</div><div id="comments">` + c + `</div>`, true},
		{"leading whitespace", "\n  <p>" + c + "</p>", true},
		{"plain echo", "you said " + c, false},
		{"echo that ends in markup", c + " <b>", false},
		{"json", `{"v":"` + c + `"}`, false},
		{"unknown first tag", `<zzfoo>` + c + `</zzfoo>`, false},
		{"comment first", `<!-- x --><p>` + c + `</p>`, false},
		{"canary absent", `<p>other</p>`, false},
	}
	for _, tc := range cases {
		if got := xssIsMarkupFragment(tc.body, c); got != tc.want {
			t.Errorf("%s: xssIsMarkupFragment = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestXSSFragmentExecuted pins the evidence rule: a dialog call carrying the canary, an event on the
// element the canary names, or the engine evaluating the canary as a name. Another probe's canary,
// a throw about some other name, and a call with no canary are not evidence.
func TestXSSFragmentExecuted(t *testing.T) {
	const c = "zxss0011aabbcc"
	yes := [][]domexec.FragmentCall{
		{{Func: "alert", Args: c}},
		{{Func: "alert", Args: "1", TargetID: c, Event: "toggle"}},
		{{Func: "throw", Args: "Uncaught ReferenceError: " + c + " is not defined"}},
	}
	no := [][]domexec.FragmentCall{
		nil,
		{{Func: "alert", Args: "zxss99"}},
		{{Func: "alert", Args: "1"}},
		{{Func: "throw", Args: "Uncaught ReferenceError: other is not defined"}},
		{{Func: "throw", Args: "Uncaught SyntaxError: " + c}},
	}
	for i, calls := range yes {
		if _, ok := xssFragmentExecuted(calls, c); !ok {
			t.Errorf("yes[%d] %+v: not counted as execution", i, calls)
		}
	}
	for i, calls := range no {
		if how, ok := xssFragmentExecuted(calls, c); ok {
			t.Errorf("no[%d] %+v: counted as execution (%s)", i, calls, how)
		}
	}
}

// TestURLAttributeIsStillAnAttribute pins the classifier fix: a value in <img src> gets the
// attribute breakouts, not only a javascript: URL (which no browser runs from an image source), and
// a resource-loading element gets an error-handler injection, since onfocus never fires on it.
func TestURLAttributeIsStillAnAttribute(t *testing.T) {
	notes := func(ctx xssContext) string {
		var out []string
		for _, p := range xssPayloadsForContexts([]xssContext{ctx}) {
			out = append(out, p.note)
		}
		return strings.Join(out, " | ")
	}
	unquoted := notes(xssContext{Kind: xssCtxAttrValue, TagName: "img", AttrName: "src"})
	for _, want := range []string{"javascript: scheme", "error-handler injection into an unquoted value", "(backtick call)", "attribute injection into an unquoted value"} {
		if !strings.Contains(unquoted, want) {
			t.Errorf("img src unquoted: bank %q lacks %q", unquoted, want)
		}
	}
	quoted := notes(xssContext{Kind: xssCtxAttrValue, TagName: "img", AttrName: "src", Quote: '"'})
	for _, want := range []string{"error-handler injection into a quoted value", "tag breakout from a quoted attribute value"} {
		if !strings.Contains(quoted, want) {
			t.Errorf("img src quoted: bank %q lacks %q", quoted, want)
		}
	}
	// A non-resource element keeps its old bank: no error handler is offered where none fires.
	if a := notes(xssContext{Kind: xssCtxAttrValue, TagName: "a", AttrName: "href", Quote: '"'}); strings.Contains(a, "error-handler") {
		t.Errorf("a href: bank %q offers an error handler", a)
	}
	// The payloads confirm against their own reflection.
	const c = "zxss0011aabbcc"
	body := `<img src=` + unquotedAttrErrorPayload(c) + ` width="4"/>`
	if !confirmEventAttrInjection(body, c) {
		t.Errorf("unquotedAttrErrorPayload does not confirm in %q", body)
	}
	body = `<img src=` + unquotedAttrErrorBacktickPayload(c) + ` width="4"/>`
	if !confirmEventAttrInjectionBacktick(body, c) {
		t.Errorf("unquotedAttrErrorBacktickPayload does not confirm in %q", body)
	}
	body = `<img src="` + quotedAttrErrorPayload('"', c) + `" width="4"/>`
	if !confirmEventAttrInjection(body, c) {
		t.Errorf("quotedAttrErrorPayload does not confirm in %q", body)
	}
}
