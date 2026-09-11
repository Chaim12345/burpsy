package proxy

import "testing"

// The two attribute-deleting rules must not reach inside a quoted attribute VALUE
// (burpsy-react-ui-q1cm).
//
// `[^>]*?` as the prefix could stop anywhere, including part-way through a value, so a page that
// merely mentioned the word had it deleted:
//
//	<input type="text" title="temporarily disabled sorry">  ->  ...title="temporarily sorry">
//
// Silent corruption of a response the operator was reading, from a rule enabled for an unrelated
// reason. The existing tests covered the word as the WHOLE value of an unrelated attribute
// (data-x="disabled"), which is the safe case — a quote sits immediately before the word, so the
// required leading whitespace never matched. Mid-value is the case that broke, and was untested.
func TestAttributeRulesDoNotReachInsideQuotedValues(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		want string // unchanged unless the rule has a real attribute to delete
	}{
		// The regression, in each rule and each control the rules cover.
		{"disabled mid-sentence in a title", `<input type="text" title="temporarily disabled sorry">`, ""},
		{"maxlength mid-sentence in a placeholder", `<input type="text" placeholder="a maxlength of 10 applies">`, ""},
		{"maxlength mid-sentence in a textarea title", `<textarea title="the maxlength rule">x</textarea>`, ""},
		{"disabled mid-sentence in a button title", `<button title="temporarily disabled sorry">Go</button>`, ""},
		{"disabled in a single-quoted value", `<input type='text' title='is disabled now'>`, ""},
		// Already safe before the fix, kept so the fix cannot regress them: a quote immediately
		// precedes the word, so there is no whitespace for the rule to anchor on.
		{"the word as an entire quoted value", `<input type="text" data-x="disabled">`, ""},
		{"a longer word starting with the attribute name", `<input type="text" disabledx>`, ""},

		// The rules must still do their job.
		{"a bare disabled attribute", `<input type="text" disabled>`, `<input type="text">`},
		{"disabled=\"disabled\"", `<input type="text" disabled="disabled">`, `<input type="text">`},
		{"disabled with spaces around =", `<input type="text" disabled = 'disabled'>`, `<input type="text">`},
		{"a bare maxlength attribute", `<input type="text" maxlength="10">`, `<input type="text">`},
		// The one that proves the prefix still crosses a quoted value to reach a real attribute
		// beyond it — a fix that simply refused to look past any quote would fail here.
		{"a real attribute after a value that mentions the word", `<input title="disabled maybe" disabled>`, `<input title="disabled maybe">`},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := c.want
			if want == "" {
				want = c.in
			}
			got := string(removeInputFieldLengthLimits(enableDisabledFormFields([]byte(c.in))))
			if got != want {
				t.Errorf("in:   %s\ngot:  %s\nwant: %s", c.in, got, want)
			}
		})
	}
}
