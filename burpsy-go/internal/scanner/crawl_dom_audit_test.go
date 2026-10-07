package scanner

// The rendered-DOM audit's comparison half (burpsy-react-ui-xuim): what counts as
// script-created content. The browser half is driven live (the web package's crawl test, which
// has a real crawl and a real Chrome); what is worth pinning without a browser is the DECISION —
// which rendered pages are "content the wire never carried" and which are browser chrome, moved
// text, or code.

import "testing"

func TestScriptOnlyContentFiresOnlyOnCreatedText(t *testing.T) {
	// The SPA fixture's shape: the wire body's visible text is "Shell", and the script creates
	// a link whose label exists nowhere in the wire bytes.
	wire := []byte("<!DOCTYPE html><html><body><h1>Shell</h1><div id=" + "`" + "app" + "`" + "></div><script>" +
		"var app = document.getElementById('app'); var route = document.createElement('a');" +
		"route.href = '/items/42'; route.textContent = 'client-rendered route item the wire never carried';" +
		"app.appendChild(route);</script></body></html>")
	rendered := []byte("<!DOCTYPE html><html><head></head><body><h1>Shell</h1>" +
		"<div id=" + "`" + "app" + "`" + "><a href=\"/items/42\">client-rendered route item the wire never carried</a></div>" +
		"<script>var app = document.getElementById('app');</script></body></html>")

	if !scriptOnlyContent(wire, rendered) {
		t.Error("a rendered DOM carrying link text the wire response never contained must count " +
			"as script-created content — this is the whole finding")
	}
}

func TestScriptOnlyContentStaysSilentOnMovedAndBorrowedText(t *testing.T) {
	wire := []byte("<html><body><p>this text is in the wire response</p><script>var x = 1;</script></body></html>")
	// Browser chrome (html/head/body added), attribute noise, and the SAME text — silent.
	rendered := []byte("<html><head></head><body><p>this text is in the wire response</p><script>var x = 1;</script></body></html>")
	if scriptOnlyContent(wire, rendered) {
		t.Error("a rendered DOM whose visible text the wire body also carries is not new content — " +
			"the browser only added its own chrome, and firing here would be a false positive on every page")
	}

	// Text that moved position but not origin: silent.
	rendered = []byte("<html><head></head><body><div><span>this text is in the wire response</span></div></body></html>")
	if scriptOnlyContent(wire, rendered) {
		t.Error("wire text moved to another element is still wire text — position is not content")
	}
}

func TestScriptOnlyContentIgnoresCodeAndShortChunks(t *testing.T) {
	wire := []byte("<html><body><script>var x = 1;</script></body></html>")
	// Script source that exists only in the rendered document is code, not visible content.
	rendered := []byte("<html><head></head><body><script>var x = 1; var y = 2;</script></body></html>")
	if scriptOnlyContent(wire, rendered) {
		t.Error("script source is stripped before the comparison — code that exists only rendered " +
			"is the render pass's business, not a content finding")
	}

	// Short stray chunks (whitespace, single characters) are browser chrome.
	rendered = []byte("<html><head></head><body>a</body></html>")
	if scriptOnlyContent(wire, rendered) {
		t.Error("a one-character text node is browser chrome noise, not content — the length " +
			"floor exists precisely so this stays silent")
	}
}

func TestHasScriptBoundsTheRenderCost(t *testing.T) {
	if hasScript([]byte("<html><body>no scripts here</body></html>")) {
		t.Error("a page with no script element must be reported script-free: it renders to what " +
			"it already was, so a browser could not reveal anything the wire pass saw")
	}
	if !hasScript([]byte("<html><body><SCRIPT src=\"/app.js\"></SCRIPT></body></html>")) {
		t.Error("a page with an external script element carries script and must be rendered")
	}
}
