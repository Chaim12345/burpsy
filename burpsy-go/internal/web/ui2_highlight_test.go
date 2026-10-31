package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// The contract for every highlighter: any byte sequence in, escaped text out. Hostile
// captured content must be inert — no span boundary can be broken by what it colors.
func TestHighlightingNeverRendersHostileInput(t *testing.T) {
	hostile := `</span><script>alert(1)</script><img src=x onerror=alert(1)>`
	outs := []string{
		string(highlightHTTPHead("GET /"+hostile+" HTTP/1.1\r\nX-Evil: "+hostile, true)),
		string(highlightJSON(`{"k":"` + hostile + `"}`)),
		string(highlightMarkup("<div title=\"" + hostile + "\">" + hostile + "</div>")),
		string(highlightCSS("a{color:\"" + hostile + "\"}")),
		string(highlightJS("// " + hostile + "\nvar x = '" + hostile + "';")),
		string(highlightForm("a=" + hostile)),
	}
	for i, out := range outs {
		if strings.Contains(out, "<script>") || strings.Contains(out, "<img") {
			t.Errorf("output %d renders hostile input as live markup: %s", i, out[:ui2Min(300, len(out))])
		}
		if !strings.Contains(out, "&lt;") {
			t.Errorf("output %d does not escape the hostile input: %s", i, out[:ui2Min(300, len(out))])
		}
	}
}

func TestHighlightJSONColorsTokens(t *testing.T) {
	out := string(highlightJSON(`{"name":"burp","n":42,"ok":true,"none":null}`))
	for _, want := range []string{`hl-key">&#34;name&#34;`, `hl-str">&#34;burp&#34;`, `hl-num">42`, `hl-kw">true`, `hl-kw">null`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %s: %s", want, out)
		}
	}
}

func TestHighlightJSONInvalidStillRenders(t *testing.T) {
	out := string(highlightJSON(`{"broken": `))
	if !strings.Contains(out, `&#34;broken&#34;`) {
		t.Errorf("invalid JSON did not render: %s", out)
	}
}

func TestHighlightHTTPHeadRequestAndResponse(t *testing.T) {
	req := string(highlightHTTPHead("POST /a?b=1 HTTP/1.1\r\nHost: x.test\r\nCookie: sid=1", true))
	for _, want := range []string{`hl-method">POST`, `hl-path">/a?b=1`, `hl-ver">HTTP/1.1`, `hl-hdr">Host:`} {
		if !strings.Contains(req, want) {
			t.Errorf("request head missing %s: %s", want, req)
		}
	}
	resp := string(highlightHTTPHead("HTTP/1.1 200 OK\r\nContent-Type: text/html", false))
	if !strings.Contains(resp, `hl-status">200`) {
		t.Errorf("response head missing status coloring: %s", resp)
	}
}

func TestFormatBodyJSONAndFallback(t *testing.T) {
	pretty, ok := formatBody(bodyJSON, `{"a":{"b":1}}`)
	if !ok || !strings.Contains(pretty, "\n  ") {
		t.Errorf("valid JSON not indented: ok=%v %q", ok, pretty)
	}
	if _, ok := formatBody(bodyJSON, `{"a":`); ok {
		t.Errorf("invalid JSON must report ok=false so the caller can say so")
	}
	if _, ok := formatBody(bodyPlain, "hello"); ok {
		t.Errorf("plain text has no formatter claim")
	}
	f, ok := formatBody(bodyForm, "a=1&b=2")
	if !ok || f != "a=1\nb=2" {
		t.Errorf("form not split one-pair-per-line: %q", f)
	}
}

func TestDetectBodyKind(t *testing.T) {
	jsonHead := "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8"
	if detectBodyKind(jsonHead, `{"a":1}`) != bodyJSON {
		t.Errorf("content-type json not detected")
	}
	if detectBodyKind("", `{"a":1}`) != bodyJSON {
		t.Errorf("sniffed valid json not detected")
	}
	if detectBodyKind("", `{"a":`) == bodyJSON {
		t.Errorf("invalid json must not be claimed as JSON")
	}
	if detectBodyKind("", "<!doctype html><p>x</p>") != bodyMarkup {
		t.Errorf("markup sniff failed")
	}
	formHead := "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded"
	if detectBodyKind(formHead, "a=1") != bodyForm {
		t.Errorf("form content-type not detected")
	}
	if detectBodyKind("", "hello world") != bodyPlain {
		t.Errorf("plain text misdetected")
	}
}

func TestRenderMessagePanePrettyRawAndLimits(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"a\":1,\"b\":[2,3]}"
	pretty := renderMessagePane(raw, true, true)
	if pretty.Kind != "JSON" {
		t.Errorf("pretty pane does not label the JSON body: %+v", pretty)
	}
	out := string(pretty.Highlighted)
	if !strings.Contains(out, "\n") || !strings.Contains(out, `hl-key`) {
		t.Errorf("pretty JSON pane neither formatted nor colored: %s", out[:300])
	}
	rawView := renderMessagePane(raw, true, false)
	if !strings.Contains(html.UnescapeString(stripTags(string(rawView.Highlighted))), `{"a":1,"b":[2,3]}`) {
		t.Errorf("raw pane does not show the compact recorded body")
	}
	// Text content of the raw pane is the recorded message BYTE FOR BYTE for ordinary
	// text captures: CR bytes and the CRLFCRLF separator survive highlighting.
	// (This assertion covers ASCII/UTF-8; arbitrary binary is replacement text in any
	// HTML rendering, not a byte channel, and no fidelity claim is made for it.)
	if got := html.UnescapeString(stripTags(string(rawView.Highlighted))); got != raw {
		t.Errorf("raw pane text is not the recorded message:\ngot:  %q\nwant: %q", got, raw)
	}
	// CR bytes sit adjacent to their LF, never split across a span boundary: the HTML
	// parser's CR->LF normalization would otherwise surface each header line as TWO
	// line breaks in the pane.
	if strings.Contains(string(rawView.Highlighted), "\r</span>") {
		t.Errorf("CR split from its LF by a span boundary - would double line breaks")
	}

	bad := renderMessagePane("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":", false, true)
	if bad.Note == "" || !strings.Contains(bad.Note, "not valid JSON") {
		t.Errorf("invalid JSON pretty view lacks the explicit fallback note: %+v", bad)
	}
}

func TestRenderMessagePaneSizeBound(t *testing.T) {
	big := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + strings.Repeat("x", highlightMaxBytes+10)
	p := renderMessagePane(big, false, true)
	if p.Note == "" || !strings.Contains(p.Note, "raw") {
		t.Errorf("oversize body lacks the explicit raw note: %+v", p.Note)
	}
	// Past the cap there is NO tokenizer/formatting work: the body region is escaped
	// raw text with zero spans.
	out := string(p.Highlighted)
	idx := strings.Index(out, "xxxx")
	if idx < 0 {
		t.Fatalf("oversize raw body missing from pane")
	}
	if strings.Contains(out[idx:], "<span") {
		t.Errorf("oversize body was tokenized; must be escaped raw only")
	}
	if !strings.HasPrefix(out, `<span class="hl-`) {
		t.Errorf("head should still be highlighted")
	}
}

// stripTags removes the span markup a pane adds, proving the text underneath is the
// recorded message.
func stripTags(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '<' {
			j := strings.IndexByte(s[i:], '>')
			if j < 0 {
				break
			}
			i += j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestUI2HistoryDetailPanesAndToggle(t *testing.T) {
	s := newTestServer()
	id := seedUI2Exchange(t, s,
		"GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"hello\":\"world\"}")

	// Default: pretty reading, colored and labeled.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/history/"+strconv.FormatUint(uint64(id), 10), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `hl-key">&#34;hello&#34;`) || !strings.Contains(body, ">JSON<") {
		t.Errorf("default detail view is not the pretty colored one: %s", body[:ui2Min(600, len(body))])
	}
	if !strings.Contains(body, `pt-on">Pretty`) {
		t.Errorf("toggle does not show Pretty as the active reading")
	}

	// Raw reading: exact recorded body, toggle flips.
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/history/"+strconv.FormatUint(uint64(id), 10)+"?view_resp=raw", nil))
	body = rec.Body.String()
	if !strings.Contains(html.UnescapeString(stripTags(body)), `{"hello":"world"}`) {
		t.Errorf("raw view does not show the compact recorded body")
	}
	if !strings.Contains(body, `pt-on">Raw`) {
		t.Errorf("toggle does not show Raw as the active reading")
	}
	// The toggle link preserves the other pane's state.
	if !strings.Contains(body, "view_resp=pretty") {
		t.Errorf("toggle does not offer the way back to Pretty")
	}
}

func TestFormatJSFormattingApplies(t *testing.T) {
	pretty, ok := formatJS(`function f(){return {a:1};}`)
	if !ok || !strings.Contains(pretty, "\n  ") {
		t.Errorf("no indentation produced: %q ok=%v", pretty, ok)
	}
	// Keyword-context regex formats; division refuses rather than guesses.
	if _, ok := formatJS("function q(){return /x+/g;}"); !ok {
		t.Errorf("proven regex after return refused")
	}
	if _, ok := formatJS("a = b / c / d;"); ok {
		t.Errorf("ambiguous division must refuse formatting")
	}
}

// TestFormatJSParserVerified covers the ASI hazard list: the formatter must either
// refuse outright or produce a candidate a real ASI-aware parser/minifier proves
// equivalent to the input. Whitespace-stripped string equality is NOT accepted as
// evidence — the check is minified canonical form equality, enforced at runtime by
// formatJS itself and re-asserted here.
func TestFormatJSParserVerified(t *testing.T) {
	mustFormat := []string{
		"function f(){return {a:1,b:2};}var x=f();",
		"if(a){b();}else{c();}\ntry{d();}catch(e){throw e;}",
		"var re = /a{1,2};x/; var s = 'str{ing}'; var t = `tpl ${a?b:c}`; // c{;",
		"function q(){return /x+/g;}",
		"var cls = /[/*]/; var n=1e5;",
		"for(var i=0;i<10;i++){f(i);}",
		// Restricted productions: original newlines carry meaning and must survive.
		"function f(){return\n{a:1};}", // ASI: returns undefined, NOT the object
		"a\n[1].forEach(b);",           // member access continues the expression
		"i++\nj++;",                    // postfix ++ at line end
		"i--\n--j;",                    // postfix/prefix mix
		"var t = `l1\n${x +\n1}`;",     // template interpolation across lines
		"do{x++;}while(x<3);",
		"var o={get x(){return 1;},set x(v){this._x=v;}};",
	}
	for _, src := range mustFormat {
		out, ok := formatJS(src)
		if !ok {
			t.Errorf("refused parseable JS: %q", src)
			continue
		}
		if _, err := jsParseForTest(out); err != nil {
			t.Errorf("output does not parse: %q -> %q: %v", src, out, err)
		}
		if !jsSemanticallyEqual(src, out) {
			t.Errorf("formatting changed semantics:\nin:  %q\nout: %q", src, out)
		}
	}
	// Refusal is mandatory for unparseable input, including subtle ASI traps.
	mustRefuse := []string{
		"function {",
		"function g(){throw\nnew E();}", // throw + LineTerminator is a syntax error
		"x = y\n/z/.test(y);",           // division cannot take .test as operand: invalid
		"a = b / c / d;",                // division: never guess regex vs divide
	}
	for _, src := range mustRefuse {
		if _, ok := formatJS(src); ok {
			t.Errorf("must refuse: %q", src)
		}
	}
}
func TestFormatMarkupReflowSafety(t *testing.T) {
	// Mixed content, inline tags and even whitespace-only runs between tags REFUSE the
	// reflow: re-indenting them could move or drop whitespace that changes what the
	// captured document says.
	for _, src := range []string{
		`<p>Hello <b>world</b>!</p>`,
		`<i>a</i> <b>b</b>`,
		`<ul><li><span></span></li></ul>`,
		"<div>\n  <p></p></div>",
		`<script>var a=1;</script>`,
	} {
		if _, ok := formatMarkup(src); ok {
			t.Errorf("unsafe markup must refuse re-indent: %q", src)
		}
	}
	// Pure structural markup re-indents, and the concatenated tags are untouched.
	out, ok := formatMarkup(`<div><p></p><p></p></div>`)
	if !ok || !strings.Contains(out, "\n  <p>") {
		t.Errorf("structural markup not indented: %q ok=%v", out, ok)
	}
	if strings.Join(strings.Fields(out), "") != `<div><p></p><p></p></div>` {
		t.Errorf("re-indent changed the tag stream: %q", out)
	}
	// The pane falls back to highlighted raw with an explicit note.
	p := renderMessagePane("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+`<p>Hello <b>world</b>!</p>`, false, true)
	if !strings.Contains(p.Note, "never re-flowed") {
		t.Errorf("mixed-content pretty view lacks the refusal note: %+v", p.Note)
	}
	if !strings.Contains(string(p.Highlighted), "Hello") {
		t.Errorf("fallback lost the body text")
	}
}

func TestRenderMessagePaneJSFormats(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfunction f(){return 1;}"
	p := renderMessagePane(raw, false, true)
	if p.Kind != "JavaScript" {
		t.Errorf("kind = %q", p.Kind)
	}
	if !strings.Contains(string(p.Highlighted), "\n") {
		t.Errorf("JS pretty view not re-indented")
	}
}

func TestHighlightJSRegexAndNumbers(t *testing.T) {
	src := "var re = /[/*]/g; var n = 1e5; var h = 0x1F; var f = 1.5e-10; var d = a / b; return /x/;"
	out := string(highlightJS(src))
	for _, want := range []string{
		`hl-str">/[/*]/g`, // regex with class: NOT eaten as a comment
		`hl-num">1e5`,     // exponent is part of the number
		`hl-num">0x1F`,
		`hl-num">1.5e-10`,
		`hl-str">/x/`, // keyword context: return /x/ is a regex
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	// The division slash stayed plain and did not swallow the rest as regex/comment.
	if !strings.Contains(out, "a / b") {
		t.Errorf("division mangled: %s", out)
	}
	// Text content is the input, untouched.
	if html.UnescapeString(stripTags(out)) != src {
		t.Errorf("highlighting changed the JS text")
	}
}

// jsParseForTest parses src with the same parser formatJS relies on.
func jsParseForTest(src string) (interface{}, error) {
	return js.Parse(parse.NewInputString(src), js.Options{})
}
