package vulnapp

// DOM-based rows driven through a headless browser.
//
// One file per check family, holding that family's vulnerable endpoints, their safe counterparts and
// the routes serving both. The manifest entries returned here are appended to Vulnerabilities() by
// familyEndpoints in vulnapp.go; the routes are registered by registerDOMFamily.
//
// The contract every entry has to meet:
//
//   - Row must match a catalog row name in internal/scanner exactly. The runtime test resolves every
//     Row against the shipped registry before auditing anything, so a typo fails loudly rather than
//     exempting the endpoint from its own assertion.
//   - A vulnerable endpoint needs a safe twin: same Row, Safe: true, reflecting or echoing the same
//     input WITHOUT the defect. That twin is what catches a detector firing on reflection alone.
//   - Handlers must be the real mechanism, not a payload matcher.
//
// Corresponding scanner descriptors: DOMCheckDescriptors / DOMExtraCheckDescriptors.
//
// # What this file does and does not cover
//
// Every endpoint below drives a genuinely instrumented sink (see internal/domexec/taint.go). The
// (DOM-based) variant reads the taint from location.hash; the (reflected DOM-based) variant reads it
// from window.name, one of the three cross-page carriers Burp's reflected variant plants
// (document.referrer, window.name, postMessage) — so no server echo is involved. The safe twins read
// the SAME source but assign it to textContent (or otherwise avoid the sink), which is the only thing
// that proves the detector keys on the sink rather than on "the page read untrusted input".
//
// The (stored DOM-based) spellings live in vulnapp_stored_dom.go, not here, because they need a
// plant/render pair rather than a single page. Three of the sixteen are built; the rest are still
// absent. The two defects that made all sixteen impossible are fixed: domStoredCheck now plants,
// defers and decides on the ledger's own sink sightings (it used to fire on the mere presence of any
// canary in the rendered DOM, which every family shares and no safe page could avoid), and
// ActiveScanner.RenderStoredTargets now loads pages in a browser so a canary that only script ever
// puts in the document is observed at all.
//
// The (reflected DOM-based) spellings of the HTML5 web message manipulation and DOM data manipulation
// families are also absent. The reflected variant's postMessage source is planted by the harness
// through an actual window.postMessage(canary, '*') call, which the SinkPostMessage wrapper records —
// so any reflected endpoint of a postMessage-sink family trips the sink during source planting and can
// never keep a safe twin quiet. That, too, is a scanner defect (the source and sink are the same API),
// and is reported separately rather than faked with a SafeTwinNotApplicable.

import (
	"fmt"
	"net/http"
)

// dmPageHash serves a page whose script reads location.hash into `taint` and then runs script.
// location.hash is the (DOM-based) source the scanner plants its canary in.
func dmPageHash(w http.ResponseWriter, script string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>dm</title></head>
<body><div id="out"></div><script>
var taint = decodeURIComponent(location.hash.slice(1));
%s
</script></body></html>`, script)
}

// dmPageReflected serves a page whose script reads window.name into `taint` and then runs script.
// The reflected-variant scanner plants its canary in window.name (a cross-page carrier) before
// navigating, so reading it feeds tainted data to the sink with no server echo.
func dmPageReflected(w http.ResponseWriter, script string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>dm</title></head>
<body><div id="out"></div><script>
var taint = window.name;
%s
</script></body></html>`, script)
}

// dmHandler binds a page-rendering helper to a fixed script.
func dmHandler(page func(http.ResponseWriter, string), script string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		page(w, script)
	}
}

// dmTemplatePage evaluates a {{a*b}} expression read from the URL, proving client-side template
// evaluation by rendering the product rather than the marker.
func dmTemplatePage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>dm</title></head>
<body><div id="out"></div><script>
var taint = decodeURIComponent(location.hash.slice(1));
var m = taint.match(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/);
var out = document.getElementById('out');
if (m) { out.textContent = String(Number(m[1]) * Number(m[2])); }
</script></body></html>`)
}

// dmSafeTemplatePage reflects the marker verbatim, so a template engine that only echoed it would
// show the marker — exactly what the check must not report as evaluated.
func dmSafeTemplatePage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>dm</title></head>
<body><div id="out"></div><script>
var taint = decodeURIComponent(location.hash.slice(1));
document.getElementById('out').textContent = taint;
</script></body></html>`)
}

// dmPRSSI serves a page that imports a stylesheet by a path-relative URL — the PRSSI precondition.
func dmPRSSI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><link rel="stylesheet" href="theme.css"></head>
<body>dm</body></html>`)
}

// dmSafePRSSI imports the same stylesheet by a root-relative URL, which resolves independently of the
// page path and therefore carries no defect.
func dmSafePRSSI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><link rel="stylesheet" href="/static/theme.css"></head>
<body>dm</body></html>`)
}

// domFamilyEndpoints returns this family's manifest entries.
func domFamilyEndpoints() []Endpoint {
	return []Endpoint{
		// ---- WebSocket URL poisoning ----
		{Path: "/dm/websocket", Row: "WebSocket URL poisoning (DOM-based)", DOM: true,
			Note: "location.hash passed to the WebSocket constructor"},
		{Path: "/dm/websocket-reflected", Row: "WebSocket URL poisoning (reflected DOM-based)", DOM: true,
			Note: "window.name (planted by the reflected variant) passed to the WebSocket constructor"},
		{Path: "/dm/safe/websocket", Row: "WebSocket URL poisoning (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to a WebSocket URL"},
		{Path: "/dm/safe/websocket-reflected", Row: "WebSocket URL poisoning (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to a WebSocket URL"},

		// ---- HTML5 web message manipulation (reflected variant omitted; see file note) ----
		{Path: "/dm/webmsg", Row: "HTML5 web message manipulation (DOM-based)", DOM: true,
			Note: "location.hash posted via window.postMessage"},
		{Path: "/dm/safe/webmsg", Row: "HTML5 web message manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never posted"},

		// ---- Document domain manipulation ----
		{Path: "/dm/docdomain", Row: "Document domain manipulation (DOM-based)", DOM: true,
			Note: "location.hash assigned to document.domain"},
		{Path: "/dm/docdomain-reflected", Row: "Document domain manipulation (reflected DOM-based)", DOM: true,
			Note: "window.name assigned to document.domain"},
		{Path: "/dm/safe/docdomain", Row: "Document domain manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to document.domain"},
		{Path: "/dm/safe/docdomain-reflected", Row: "Document domain manipulation (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to document.domain"},

		// ---- Ajax request header manipulation ----
		{Path: "/dm/ajax", Row: "Ajax request header manipulation (DOM-based)", DOM: true,
			Note: "location.hash passed to XMLHttpRequest.open (observed at the open call, not setRequestHeader)"},
		{Path: "/dm/ajax-reflected", Row: "Ajax request header manipulation (reflected DOM-based)", DOM: true,
			Note: "window.name passed to XMLHttpRequest.open"},
		{Path: "/dm/safe/ajax", Row: "Ajax request header manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to an XHR open call"},
		{Path: "/dm/safe/ajax-reflected", Row: "Ajax request header manipulation (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to an XHR open call"},

		// ---- DOM data manipulation (reflected variant omitted; see file note) ----
		{Path: "/dm/domdata", Row: "DOM data manipulation (DOM-based)", DOM: true,
			Note: "location.hash passed to XMLHttpRequest.open / window.postMessage"},
		{Path: "/dm/safe/domdata", Row: "DOM data manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to an XHR open call"},

		// ---- Client-side XPath injection ----
		{Path: "/dm/xpath", Row: "Client-side XPath injection (DOM-based)", DOM: true,
			Note: "location.hash passed to document.evaluate"},
		{Path: "/dm/xpath-reflected", Row: "Client-side XPath injection (reflected DOM-based)", DOM: true,
			Note: "window.name passed to document.evaluate"},
		{Path: "/dm/safe/xpath", Row: "Client-side XPath injection (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to document.evaluate"},
		{Path: "/dm/safe/xpath-reflected", Row: "Client-side XPath injection (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to document.evaluate"},

		// ---- Client-side JSON injection ----
		{Path: "/dm/json", Row: "Client-side JSON injection (DOM-based)", DOM: true,
			Note: "location.hash passed to JSON.parse"},
		{Path: "/dm/json-reflected", Row: "Client-side JSON injection (reflected DOM-based)", DOM: true,
			Note: "window.name passed to JSON.parse"},
		{Path: "/dm/safe/json", Row: "Client-side JSON injection (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never parsed as JSON"},
		{Path: "/dm/safe/json-reflected", Row: "Client-side JSON injection (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never parsed as JSON"},

		// ---- Link manipulation ----
		{Path: "/dm/link", Row: "Link manipulation (DOM-based)", DOM: true,
			Note: "location.hash assigned to an anchor's href"},
		{Path: "/dm/link-reflected", Row: "Link manipulation (reflected DOM-based)", DOM: true,
			Note: "window.name assigned to an anchor's href"},
		{Path: "/dm/safe/link", Row: "Link manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to an anchor href"},
		{Path: "/dm/safe/link-reflected", Row: "Link manipulation (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never to an anchor href"},

		// ---- Denial of service ----
		{Path: "/dm/dos", Row: "Denial of service (DOM-based)", DOM: true,
			Note: "location.hash compiled into a RegExp (catastrophic-backtracking precondition)"},
		{Path: "/dm/dos-reflected", Row: "Denial of service (reflected DOM-based)", DOM: true,
			Note: "window.name compiled into a RegExp"},
		{Path: "/dm/safe/dos", Row: "Denial of service (DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never compiled into a RegExp"},
		{Path: "/dm/safe/dos-reflected", Row: "Denial of service (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never compiled into a RegExp"},

		// ---- Reflected variants of the five families already demonstrated in their (DOM-based) form ----
		{Path: "/dm/xss-reflected", Row: "Cross-site scripting (reflected DOM-based)", DOM: true,
			Note: "window.name written into innerHTML"},
		{Path: "/dm/safe/xss-reflected", Row: "Cross-site scripting (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source written into textContent, never innerHTML"},
		{Path: "/dm/js-reflected", Row: "JavaScript injection (reflected DOM-based)", DOM: true,
			Note: "window.name passed to eval"},
		{Path: "/dm/safe/js-reflected", Row: "JavaScript injection (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source written into textContent, never evaluated"},
		{Path: "/dm/redirect-reflected", Row: "Open redirection (reflected DOM-based)", DOM: true,
			Note: "window.name passed to location.assign"},
		{Path: "/dm/safe/redirect-reflected", Row: "Open redirection (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source written into textContent, never used as a navigation target"},
		{Path: "/dm/storage-reflected", Row: "HTML5 storage manipulation (reflected DOM-based)", DOM: true,
			Note: "window.name written to localStorage"},
		{Path: "/dm/safe/storage-reflected", Row: "HTML5 storage manipulation (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source written into textContent, never to storage"},
		{Path: "/dm/cookie-reflected", Row: "Cookie manipulation (reflected DOM-based)", DOM: true,
			Note: "window.name written to document.cookie"},
		{Path: "/dm/safe/cookie-reflected", Row: "Cookie manipulation (reflected DOM-based)", DOM: true, Safe: true,
			Note: "same source written into textContent, never to a cookie"},

		// ---- DOM-extra rows (not a source-to-sink flow of the domFamilies shape) ----
		{Path: "/dm/proto", Row: "Client-side prototype pollution", DOM: true,
			Note: "location.hash used as a property name written onto Object.prototype"},
		{Path: "/dm/safe/proto", Row: "Client-side prototype pollution", DOM: true, Safe: true,
			Note: "same source assigned to textContent, never written to Object.prototype"},
		{Path: "/dm/template", Row: "Client-side template injection", DOM: true,
			Note: "a {{a*b}} expression from the URL is evaluated and rendered as its product"},
		{Path: "/dm/safe/template", Row: "Client-side template injection", DOM: true, Safe: true,
			Note: "the expression is reflected as text, never evaluated"},
		{Path: "/dm/prssi", Row: "Path-relative style sheet import", DOM: true,
			Note: "serves a stylesheet by a path-relative href"},
		{Path: "/dm/safe/prssi", Row: "Path-relative style sheet import", DOM: true, Safe: true,
			Note: "serves the same stylesheet by a root-relative href"},
	}
}

// registerDOMFamily serves this family's routes.
func registerDOMFamily(mux *http.ServeMux) {
	// WebSocket URL poisoning.
	mux.HandleFunc("/dm/websocket", dmHandler(dmPageHash, `try { new WebSocket(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/websocket-reflected", dmHandler(dmPageReflected, `try { new WebSocket(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/websocket", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/websocket-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// HTML5 web message manipulation (DOM-based only — reflected variant omitted; see file note).
	mux.HandleFunc("/dm/webmsg", dmHandler(dmPageHash, `try { window.postMessage(taint, '*'); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/webmsg", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))

	// Document domain manipulation.
	mux.HandleFunc("/dm/docdomain", dmHandler(dmPageHash, `try { document.domain = taint; } catch (e) {}`))
	mux.HandleFunc("/dm/docdomain-reflected", dmHandler(dmPageReflected, `try { document.domain = taint; } catch (e) {}`))
	mux.HandleFunc("/dm/safe/docdomain", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/docdomain-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// Ajax request header manipulation.
	mux.HandleFunc("/dm/ajax", dmHandler(dmPageHash, `try { var x = new XMLHttpRequest(); x.open('GET', taint, true); } catch (e) {}`))
	mux.HandleFunc("/dm/ajax-reflected", dmHandler(dmPageReflected, `try { var x = new XMLHttpRequest(); x.open('GET', taint, true); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/ajax", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/ajax-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// DOM data manipulation (DOM-based only — reflected variant omitted; see file note).
	mux.HandleFunc("/dm/domdata", dmHandler(dmPageHash, `try { var x = new XMLHttpRequest(); x.open('GET', taint, true); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/domdata", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))

	// Client-side XPath injection.
	mux.HandleFunc("/dm/xpath", dmHandler(dmPageHash, `try { document.evaluate(taint, document, null, XPathResult.ANY_TYPE, null); } catch (e) {}`))
	mux.HandleFunc("/dm/xpath-reflected", dmHandler(dmPageReflected, `try { document.evaluate(taint, document, null, XPathResult.ANY_TYPE, null); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/xpath", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/xpath-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// Client-side JSON injection.
	mux.HandleFunc("/dm/json", dmHandler(dmPageHash, `try { JSON.parse(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/json-reflected", dmHandler(dmPageReflected, `try { JSON.parse(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/json", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/json-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// Link manipulation.
	mux.HandleFunc("/dm/link", dmHandler(dmPageHash, `try { var a = document.createElement('a'); a.href = taint; document.body.appendChild(a); } catch (e) {}`))
	mux.HandleFunc("/dm/link-reflected", dmHandler(dmPageReflected, `try { var a = document.createElement('a'); a.href = taint; document.body.appendChild(a); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/link", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/link-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// Denial of service.
	mux.HandleFunc("/dm/dos", dmHandler(dmPageHash, `try { new RegExp(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/dos-reflected", dmHandler(dmPageReflected, `try { new RegExp(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/dos", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/safe/dos-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// Reflected variants of the five already-demonstrated (DOM-based) families.
	mux.HandleFunc("/dm/xss-reflected", dmHandler(dmPageReflected, `document.getElementById('out').innerHTML = taint;`))
	mux.HandleFunc("/dm/safe/xss-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/js-reflected", dmHandler(dmPageReflected, `try { eval(taint); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/js-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/redirect-reflected", dmHandler(dmPageReflected, `if (taint) { try { location.assign(taint); } catch (e) {} }`))
	mux.HandleFunc("/dm/safe/redirect-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/storage-reflected", dmHandler(dmPageReflected, `try { localStorage.setItem('k', taint); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/storage-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/cookie-reflected", dmHandler(dmPageReflected, `try { document.cookie = 'k=' + taint; } catch (e) {}`))
	mux.HandleFunc("/dm/safe/cookie-reflected", dmHandler(dmPageReflected, `document.getElementById('out').textContent = taint;`))

	// DOM-extra rows.
	mux.HandleFunc("/dm/proto", dmHandler(dmPageHash, `try { Object.defineProperty(Object.prototype, taint, {value: 1, configurable: true}); } catch (e) {}`))
	mux.HandleFunc("/dm/safe/proto", dmHandler(dmPageHash, `document.getElementById('out').textContent = taint;`))
	mux.HandleFunc("/dm/template", dmTemplatePage)
	mux.HandleFunc("/dm/safe/template", dmSafeTemplatePage)
	mux.HandleFunc("/dm/prssi", dmPRSSI)
	mux.HandleFunc("/dm/safe/prssi", dmSafePRSSI)
}
