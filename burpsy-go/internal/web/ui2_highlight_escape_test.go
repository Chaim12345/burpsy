package web

import (
	"strings"
	"testing"
)

// A lone backslash as the last byte of a quoted run must never push the scanner's
// slice bound past the end of the input. Before the clamp, inputs like "\"\\"
// panicked with "slice bounds out of range" in every string scanner here, and a
// hostile captured body reached the panic per request through renderMessagePane.

func TestHighlightJSONLoneBackslash(t *testing.T) {
	inputs := []string{
		`"\`,             // quote, lone backslash, end
		`"ab\`,           // backslash after content
		`{"key\": "val\`, // nested in an object
		`["a", "b\`,      // nested in an array
		"\"\\\"\\\"\"",   // escaped backslash then escaped quote, unterminated
		`"\\`,            // escaped backslash only, unterminated
	}
	for _, in := range inputs {
		out := string(highlightJSON(in)) // must not panic
		if out == "" {
			t.Errorf("highlightJSON(%q) produced no output", in)
		}
	}
	// The trailing backslash is content: it renders, escaped, inside the string token.
	if got, want := string(highlightJSON(`"\`)), span("str", `"\"`[:2]); got != want {
		t.Errorf("highlightJSON lone-backslash token = %q, want %q", got, want)
	}
	// In-bounds escapes are unchanged: an escaped quote stays inside the string token.
	// html escaping turns the quote into &#34;; the escape backslash must survive in front of it.
	if got := string(highlightJSON(`"a\"b"`)); !strings.Contains(got, "\\&#34;") {
		t.Errorf("highlightJSON escaped-quote token lost the escape: %q", got)
	}
}

func TestHighlightJSLoneBackslash(t *testing.T) {
	inputs := []string{
		`'\`,
		`"\`,
		"`\\",
		"let s = \"ab\\",
		"`a${b}c\\",
		"'a\\\\' + 'b\\",
	}
	for _, in := range inputs {
		out := string(highlightJS(in)) // must not panic
		if out == "" {
			t.Errorf("highlightJS(%q) produced no output", in)
		}
	}
	if got, want := string(highlightJS(`'\`)), span("str", `'\`); got != want {
		t.Errorf("highlightJS lone-backslash token = %q, want %q", got, want)
	}
	if got := string(highlightJS(`'a\'b'`)); !strings.Contains(got, "\\&#39;") {
		t.Errorf("highlightJS escaped-quote token lost the escape: %q", got)
	}
}

func TestHighlightCSSLoneBackslash(t *testing.T) {
	inputs := []string{
		`'\`,
		`a { content: "\`,
		`a::before { content: '\`,
	}
	for _, in := range inputs {
		out := string(highlightCSS(in)) // must not panic
		if out == "" {
			t.Errorf("highlightCSS(%q) produced no output", in)
		}
	}
}

func TestFormatCSSLoneBackslash(t *testing.T) {
	inputs := []string{
		`a { content: '\`,
		`a { content: "\`,
	}
	for _, in := range inputs {
		_ = formatCSS(in) // must not panic
	}
}

// The reachable path: a captured response with a JSON content type whose invalid body
// ends in a lone backslash. Pretty mode formats nothing (invalid JSON falls back to
// raw with a note) but the raw body is STILL highlighted - that is where the panic was.
func TestRenderMessagePaneMalformedJSONBody(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\": \"\\"
	for _, pretty := range []bool{true, false} {
		view := renderMessagePane(raw, false, pretty) // must not panic
		if !strings.Contains(string(view.Highlighted), "\\") {
			t.Errorf("pretty=%v: trailing backslash missing from pane", pretty)
		}
		if view.Kind != "JSON" {
			t.Errorf("pretty=%v: Kind = %q, want JSON", pretty, view.Kind)
		}
	}
	prettyView := renderMessagePane(raw, false, true)
	if prettyView.Note == "" || !strings.Contains(prettyView.Note, "not valid JSON") {
		t.Errorf("pretty pane note = %q, want the invalid-JSON fallback note", prettyView.Note)
	}
}

// Every body syntax with a string scanner gets the trailing-backslash body through the
// full pane path, request and response, pretty and raw.
func TestRenderMessagePaneTrailingBackslashBodies(t *testing.T) {
	kinds := []struct {
		ct   string
		body string
	}{
		{"application/json", "{\"a\": \"\\"},
		{"text/javascript", "var s = '\\"},
		{"text/css", "a { content: '\\"},
		{"text/css", "a { content: \"\\"},
	}
	for _, k := range kinds {
		raw := "HTTP/1.1 200 OK\r\nContent-Type: " + k.ct + "\r\n\r\n" + k.body
		for _, pretty := range []bool{true, false} {
			renderMessagePane(raw, false, pretty) // must not panic
			renderMessagePane(raw, true, pretty)
		}
	}
}
