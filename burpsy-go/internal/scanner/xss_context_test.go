package scanner

import "testing"

// The classifier is tested directly rather than only through the check, because its whole purpose
// is to make a distinction the check's caller cannot otherwise see. A test that only asserted the
// check's verdict would pass for the wrong reason as soon as two contexts happened to agree.

func TestClassifyPlacesEachContext(t *testing.T) {
	const c = "ZCAN"
	cases := []struct {
		name     string
		body     string
		wantKind xssContextKind
		wantTag  string
		wantAttr string
		wantQ    byte
	}{
		{"text node", `<p>hi ZCAN</p>`, xssCtxText, "p", "", 0},
		{"double-quoted attr", `<input value="ZCAN">`, xssCtxAttrValue, "input", "value", '"'},
		{"single-quoted attr", `<input value='ZCAN'>`, xssCtxAttrValue, "input", "value", '\''},
		{"unquoted attr", `<input value=ZCAN>`, xssCtxAttrValue, "input", "value", 0},
		{"comment", `<!-- ZCAN -->`, xssCtxComment, "", "", 0},
		{"rcdata textarea", `<textarea>ZCAN</textarea>`, xssCtxRCDATA, "textarea", "", 0},
		{"rcdata title", `<title>ZCAN</title>`, xssCtxRCDATA, "title", "", 0},
		// Script contexts carry the enclosing JS string quote, resolved by the lexer rather than
		// guessed, because it decides which breakout payload can work here at all.
		{"script single-quoted host", `<script>var a='ZCAN';</script>`, xssCtxScript, "script", "", '\''},
		{"script double-quoted host", `<script>var a="ZCAN";</script>`, xssCtxScript, "script", "", '"'},
		// Not inside any literal: no quote to report, and the caller then tries both styles.
		{"script code position", `<script>var a=ZCAN;</script>`, xssCtxScript, "script", "", 0},
		{"href url attr", `<a href="javascript:ZCAN">x</a>`, xssCtxAttrValue, "a", "href", '"'},
		{"srcdoc html attr", `<iframe srcdoc="ZCAN"></iframe>`, xssCtxAttrValue, "iframe", "srcdoc", '"'},
		{"event attr", `<div onclick="ZCAN"></div>`, xssCtxAttrValue, "div", "onclick", '"'},
		// <style> is raw text but not an execution context on its own; claiming it would be a
		// finding no browser honours.
		{"style is not executable", `<style>a{x:ZCAN}</style>`, xssCtxUnknown, "style", "", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyXSSContexts(tc.body, c)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 context, got %d: %+v", len(got), got)
			}
			g := got[0]
			if g.Kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", g.Kind, tc.wantKind)
			}
			if g.TagName != tc.wantTag {
				t.Errorf("tag = %q, want %q", g.TagName, tc.wantTag)
			}
			if g.AttrName != tc.wantAttr {
				t.Errorf("attr = %q, want %q", g.AttrName, tc.wantAttr)
			}
			if g.Quote != tc.wantQ {
				t.Errorf("quote = %q, want %q", g.Quote, tc.wantQ)
			}
			// The offset must actually point at the canary, or every downstream decision is
			// reading the wrong bytes.
			if g.Offset < 0 || g.Offset+len(c) > len(tc.body) || tc.body[g.Offset:g.Offset+len(c)] != c {
				t.Errorf("offset %d does not land on the canary in %q", g.Offset, tc.body)
			}
		})
	}
}

func TestClassifyFindsEveryOccurrence(t *testing.T) {
	const c = "ZCAN"
	body := `<p>ZCAN</p><input value=ZCAN><script>x='ZCAN'</script>`
	got := classifyXSSContexts(body, c)
	if len(got) != 3 {
		t.Fatalf("want 3 occurrences, got %d: %+v", len(got), got)
	}
	want := []xssContextKind{xssCtxText, xssCtxAttrValue, xssCtxScript}
	for i, w := range want {
		if got[i].Kind != w {
			t.Errorf("occurrence %d kind = %v, want %v", i, got[i].Kind, w)
		}
		if body[got[i].Offset:got[i].Offset+len(c)] != c {
			t.Errorf("occurrence %d offset %d does not land on the canary", i, got[i].Offset)
		}
	}
}

func TestClassifyAbsentCanaryIsNil(t *testing.T) {
	if got := classifyXSSContexts(`<p>nothing here</p>`, "ZCAN"); got != nil {
		t.Fatalf("want nil for an absent canary, got %+v", got)
	}
	if got := classifyXSSContexts(`<p>ZCAN</p>`, ""); got != nil {
		t.Fatalf("want nil for an empty canary, got %+v", got)
	}
}

// The tokenizer reports script and RCDATA content as ordinary Text tokens, so without the
// open-element stack a canary inside <script> would be classified as injectable markup. That is
// the dangerous direction — it claims a tag injection the browser will never perform — so it gets
// its own test rather than riding on the table above.
func TestScriptAndRCDATAAreNotTextNodes(t *testing.T) {
	for _, tc := range []struct {
		body string
		want xssContextKind
	}{
		{`<script>ZCAN</script>`, xssCtxScript},
		{`<textarea>ZCAN</textarea>`, xssCtxRCDATA},
		{`<div>ZCAN</div>`, xssCtxText},
	} {
		got := classifyXSSContexts(tc.body, "ZCAN")
		if len(got) != 1 || got[0].Kind != tc.want {
			t.Errorf("%s -> %+v, want kind %v", tc.body, got, tc.want)
		}
	}
}

// After an element closes, following text belongs to the parent again. A stack that never popped
// would keep reporting the last element opened.
func TestOpenElementStackPopsOnEndTag(t *testing.T) {
	body := `<script>a</script><p>ZCAN</p>`
	got := classifyXSSContexts(body, "ZCAN")
	if len(got) != 1 || got[0].Kind != xssCtxText {
		t.Fatalf("after </script> the canary is ordinary text, got %+v", got)
	}
}

// Void elements take no end tag. Pushing them would make everything after the first <input> look
// like it lived inside it.
func TestVoidElementsDoNotNest(t *testing.T) {
	body := `<input value=a><p>ZCAN</p>`
	got := classifyXSSContexts(body, "ZCAN")
	if len(got) != 1 || got[0].TagName != "p" {
		t.Fatalf("want the canary attributed to <p>, got %+v", got)
	}
}

// Unbalanced markup is the norm in the wild. A stray end tag must not misattribute everything
// after it.
func TestStrayEndTagDoesNotCorruptTheStack(t *testing.T) {
	body := `</div><p>ZCAN</p>`
	got := classifyXSSContexts(body, "ZCAN")
	if len(got) != 1 || got[0].TagName != "p" {
		t.Fatalf("want <p>, got %+v", got)
	}
}

func TestAttributeClassificationHelpers(t *testing.T) {
	url := classifyXSSContexts(`<a href="ZCAN">x</a>`, "ZCAN")[0]
	if !url.IsURLAttr() || url.IsHTMLAttr() || url.IsEventAttr() {
		t.Errorf("href should be URL-valued only, got %+v", url)
	}
	doc := classifyXSSContexts(`<iframe srcdoc="ZCAN"></iframe>`, "ZCAN")[0]
	if !doc.IsHTMLAttr() || doc.IsURLAttr() {
		t.Errorf("srcdoc should be HTML-valued only, got %+v", doc)
	}
	ev := classifyXSSContexts(`<div onerror="ZCAN"></div>`, "ZCAN")[0]
	if !ev.IsEventAttr() || ev.IsURLAttr() {
		t.Errorf("onerror should be an event handler only, got %+v", ev)
	}
	plain := classifyXSSContexts(`<input value="ZCAN">`, "ZCAN")[0]
	if plain.IsURLAttr() || plain.IsHTMLAttr() || plain.IsEventAttr() {
		t.Errorf("value is an ordinary attribute, got %+v", plain)
	}
}

// Multiple attributes on one tag, so the scanner has to keep attribute boundaries straight rather
// than finding the canary and guessing which name preceded it.
func TestMultipleAttributesOnOneTag(t *testing.T) {
	body := `<img src="a.png" alt=ZCAN title='t' onload="f()">`
	got := classifyXSSContexts(body, "ZCAN")
	if len(got) != 1 {
		t.Fatalf("want 1, got %+v", got)
	}
	if got[0].AttrName != "alt" || got[0].Quote != 0 {
		t.Fatalf("want unquoted alt, got attr=%q quote=%q", got[0].AttrName, got[0].Quote)
	}
}
