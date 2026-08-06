package advisory

import (
	"strings"
	"testing"
)

// ---- SanitisedHTML -------------------------------------------------------------------------------
//
// The catalogue is trusted today, so these are not about the corpus that ships — they are about the
// two ways it stops being trusted without anyone revisiting the renderers: an operator-supplied
// definitions directory, and a definition nobody audited. A report is a file that gets mailed around
// and opened outside the tool, so the guarantee has to hold at the seam, not in an assumption.

// The structure that makes remediation advice readable is the entire reason for not just escaping.
func TestParagraphsAndListsSurviveBecauseTheyAreWhyThisIsNotJustEscaping(t *testing.T) {
	got := SanitisedHTML("<p>First para.</p>\n<p>Second with <b>bold</b> and <code>code</code>.</p><ul><li>one</li><li>two</li></ul>")
	for _, want := range []string{"<p>", "</p>", "<b>bold</b>", "<code>code</code>", "<ul>", "<li>one</li>"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q from the sanitised output:\n%s", want, got)
		}
	}
}

// A script tag is the whole point. Its text is kept (so no sentence silently vanishes) but it is no
// longer an element, so nothing executes.
func TestAScriptElementIsStrippedWhileItsTextRemainsVisible(t *testing.T) {
	got := SanitisedHTML("<p>before</p><script>alert(1)</script><p>after</p>")
	if strings.Contains(strings.ToLower(got), "<script") {
		t.Errorf("script element survived: %s", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("surrounding prose was lost: %s", got)
	}
}

// Attributes are dropped wholesale, so no event handler and no javascript: target can ride in on an
// otherwise allow-listed element.
func TestEveryAttributeIsDroppedIncludingEventHandlersAndHrefs(t *testing.T) {
	got := SanitisedHTML(`<p onclick="steal()" class="x">text</p><a href="javascript:alert(1)">link text</a>`)
	for _, banned := range []string{"onclick", "javascript:", "href", "class="} {
		if strings.Contains(strings.ToLower(got), banned) {
			t.Errorf("%q survived sanitisation: %s", banned, got)
		}
	}
	// The anchor is not allow-listed, so it is dropped as an element — but its text is prose.
	if !strings.Contains(got, "link text") {
		t.Errorf("anchor text was lost with its tag: %s", got)
	}
}

// An img with an onerror is the classic payload that survives naive tag-name blocklists.
func TestAnImageWithAnErrorHandlerDoesNotSurvive(t *testing.T) {
	got := SanitisedHTML(`<img src=x onerror="alert(1)">`)
	if strings.Contains(strings.ToLower(got), "<img") || strings.Contains(strings.ToLower(got), "onerror") {
		t.Errorf("img/onerror survived: %s", got)
	}
}

// Text is escaped, so a fragment that is not valid markup degrades to something visible and inert
// rather than to markup the renderer then trusts.
func TestBareTextIsEscapedRatherThanPassedThrough(t *testing.T) {
	got := SanitisedHTML("5 < 6 && 7 > 2")
	if strings.Contains(got, "<") && !strings.Contains(got, "&lt;") {
		t.Errorf("a bare < was not escaped: %s", got)
	}
}

// br is a void element: emitting a closing tag for it would be invalid markup.
func TestBrIsEmittedWithoutAClosingTag(t *testing.T) {
	got := SanitisedHTML("a<br>b")
	if strings.Contains(got, "</br>") {
		t.Errorf("br was given a closing tag: %s", got)
	}
	if !strings.Contains(got, "<br>") {
		t.Errorf("br was dropped entirely: %s", got)
	}
}

func TestEmptyInputProducesEmptyOutput(t *testing.T) {
	if got := SanitisedHTML("   \n "); got != "" {
		t.Errorf("SanitisedHTML(whitespace) = %q, want empty", got)
	}
}

// The real corpus must survive sanitisation with its structure intact — if this function stripped
// the whole catalogue to plain text, every test above would still pass and the reports would be
// walls of text.
func TestTheRealCatalogueKeepsItsParagraphs(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	withParagraphs := 0
	for _, d := range c.All() {
		if strings.Contains(SanitisedHTML(d.Description), "<p>") {
			withParagraphs++
		}
	}
	if withParagraphs < 100 {
		t.Errorf("only %d of %d definitions kept a paragraph; sanitisation is eating the catalogue's structure", withParagraphs, c.Len())
	}
}
