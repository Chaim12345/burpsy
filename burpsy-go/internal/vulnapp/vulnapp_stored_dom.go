package vulnapp

// stored DOM-based rows: a value the server persists, that only ever reaches a dangerous sink
// through the page's own script.
//
// One file per check family, holding that family's vulnerable endpoints, their safe counterparts and
// the routes serving both. The manifest entries returned here are appended to Vulnerabilities() by
// familyEndpoints in vulnapp.go; the routes are registered by familyRegistrars.
//
// # What makes these different from both neighbours
//
// vulnapp_stored.go's rows put the stored value in the RESPONSE BODY, so an HTTP re-fetch sees it.
// vulnapp_dom.go's rows put attacker data in the URL, so the server never sees it at all. The rows
// here are the intersection nobody could previously demonstrate: the value is persisted by one
// request, and the page that uses it does not contain it - a script fetches it from an API and
// writes it into the sink after load. Every byte of the render page's HTTP response is constant.
//
// That is deliberate, and it is what the fixture is for. If the data endpoint were part of the
// declared manifest the HTTP re-fetch would capture the canary from its JSON and the flow would be
// provable without a browser, which would not exercise the thing being demonstrated. It is served
// but never declared, so the ONLY way the canary is ever observed is
// ActiveScanner.RenderStoredTargets loading the page in a real browser.
//
// # The safe twins deliberately still show the value
//
// Each safe page fetches the same stored value and writes it to textContent. The canary therefore
// appears in the safe page's rendered DOM exactly as it does in the vulnerable one, which is the
// strongest form of the pairing available here: silence on the safe twin cannot be explained by the
// value not having arrived, only by the sink not having been reached.
//
// # The three rows this file deliberately does NOT cover
//
// Each is undemonstrable for a reason that is a property of the platform or the sink, not of effort,
// and a green row for any of them would assert something untrue:
//
//   - Client-side SQL injection (stored DOM-based). The sink is SQLTransaction.executeSql. WebSQL
//     was removed from Chromium, so no page loaded by this harness can reach it. The scanner's
//     wrapper stays instrumented for hosts that still expose it.
//   - Local file path manipulation (stored DOM-based). The sink is FileReader.read*, whose argument
//     is a File object; it stringifies to "[object File]" and never carries a path, so a canary
//     cannot survive into the observation. Reaching it also needs a real file chooser.
//   - Open redirection (stored DOM-based). Its sink is an actual navigation, which is terminal - one
//     per page load - so a page cannot walk a stored history and try each value, and whichever value
//     happens to be last decides the whole result. On a shared fixture that is not under this
//     family's control (every other scanner in the suite also probes these endpoints, and their
//     payloads land in the same history) "last value" is not a property a fixture can rely on.
//     Link manipulation below is the same stored-value-becomes-a-navigation-target defect with a
//     sink that can be reached once per stored value.
//
// Corresponding scanner descriptors: DOMCheckDescriptors, the domVariantStored branch.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// storedDOMStore is one case's persisted history. Each case owns two - one per half of the pair - so
// a canary planted at one endpoint can never be fetched by another endpoint's page.
type storedDOMStore struct {
	mu  sync.Mutex
	log []string
}

// storedDOMCase is one row's pair: a vulnerable page whose script drives the stored value into the
// row's own sink, and a safe page whose script displays the same value without reaching any sink.
//
// use and safeUse are JS statements evaluated once per stored value, with that value bound to
// `value`. They are the entire difference between the two halves.
type storedDOMCase struct {
	prefix   string // path prefix owning six routes, e.g. "/sdm/json"
	param    string // query parameter the plant endpoint persists
	row      string // catalog row name, exactly
	use      string // the vulnerable statement
	safeUse  string // the safe statement; textContent unless a row needs otherwise
	note     string // why the vulnerable endpoint is vulnerable
	safeNote string // why the safe endpoint is not
	vuln     storedDOMStore
	safe     storedDOMStore
}

// safeShow is the safe statement every case uses: the value reaches the document, and no sink.
const safeShow = `document.getElementById('out').textContent += value;`

// storedDOMCases is the whole family. Adding a row is one entry here; the manifest entries and the
// six routes are both derived from it, so the two cannot drift apart.
var storedDOMCases = []*storedDOMCase{
	{
		prefix: "/sdm/xss", param: "text", row: "Cross-site scripting (stored DOM-based)",
		use:     `document.getElementById('out').innerHTML += value;`,
		safeUse: safeShow,
		note: "a note submitted here is fetched from the page's own data endpoint and written into " +
			"innerHTML, which parses it as markup; no HTTP response ever contains the value",
		safeNote: "the same submission, displayed with textContent - it still appears in the rendered " +
			"document, it just never reaches an HTML-parsing sink",
	},
	{
		prefix: "/sdm/domdata", param: "report", row: "DOM data manipulation (stored DOM-based)",
		use:     `var x = new XMLHttpRequest(); x.open('GET', '/sdm/_target?id=' + value, true); x.send();`,
		safeUse: safeShow,
		note: "a report id submitted here is fetched back by the page's script and concatenated into " +
			"the URL of an XMLHttpRequest it then opens",
		safeNote: "the same submission, displayed with textContent - never used to build a request URL",
	},
	{
		prefix: "/sdm/link", param: "destination", row: "Link manipulation (stored DOM-based)",
		use: `var a = document.createElement('a'); a.href = value; a.textContent = 'saved link'; ` +
			`document.body.appendChild(a);`,
		safeUse: safeShow,
		note: "a destination submitted here is fetched back and assigned to an anchor's href, so a " +
			"stored value decides where a link on the page points",
		safeNote: "the same submission, displayed with textContent - never assigned to an href",
	},
	{
		prefix: "/sdm/js", param: "expr", row: "JavaScript injection (stored DOM-based)",
		use:     `eval('var _stored = "' + value + '";');`,
		safeUse: safeShow,
		note: "a value submitted here is fetched back and spliced into a string the page passes to " +
			"eval, so stored data becomes executed code",
		safeNote: "the same submission, displayed with textContent - never passed to eval",
	},
	{
		prefix: "/sdm/json", param: "payload", row: "Client-side JSON injection (stored DOM-based)",
		use:     `JSON.parse('{"stored":"' + value + '"}');`,
		safeUse: safeShow,
		note: "a value submitted here is fetched back and concatenated into a JSON document the page " +
			"then parses, so a stored value decides that document's structure",
		safeNote: "the same submission, displayed with textContent - never concatenated into JSON",
	},
	{
		prefix: "/sdm/xpath", param: "name", row: "Client-side XPath injection (stored DOM-based)",
		use:     `document.evaluate("//user[@name='" + value + "']", document, null, 0, null);`,
		safeUse: safeShow,
		note: "a name submitted here is fetched back and spliced into an XPath expression the page " +
			"evaluates against its own document",
		safeNote: "the same submission, displayed with textContent - never part of an expression",
	},
	{
		prefix: "/sdm/cookie", param: "pref", row: "Cookie manipulation (stored DOM-based)",
		use:     `document.cookie = 'pref=' + value + '; path=/';`,
		safeUse: safeShow,
		note: "a preference submitted here is fetched back and written into document.cookie, so a " +
			"stored value decides a cookie the browser then sends",
		safeNote: "the same submission, displayed with textContent - never written to document.cookie",
	},
	{
		prefix: "/sdm/storage", param: "pref", row: "HTML5 storage manipulation (stored DOM-based)",
		use:     `localStorage.setItem('sdmPref', value);`,
		safeUse: safeShow,
		note: "a preference submitted here is fetched back and written into localStorage, where the " +
			"page trusts it on later visits",
		safeNote: "the same submission, displayed with textContent - never written to localStorage",
	},
	{
		prefix: "/sdm/message", param: "body", row: "HTML5 web message manipulation (stored DOM-based)",
		use:     `window.postMessage(value, '*');`,
		safeUse: safeShow,
		note: "a message submitted here is fetched back and posted as a web message with a wildcard " +
			"target origin, so a stored value reaches any listener",
		safeNote: "the same submission, displayed with textContent - never posted as a message",
	},
	{
		prefix: "/sdm/domain", param: "host", row: "Document domain manipulation (stored DOM-based)",
		use:     `document.domain = value;`,
		safeUse: safeShow,
		note: "a host submitted here is fetched back and assigned to document.domain, which widens " +
			"the origin the page will accept scripting from. The browser rejects a value that is not " +
			"a suffix of the real host, and the assignment is the defect either way: the page hands " +
			"its origin policy to stored data",
		safeNote: "the same submission, displayed with textContent - never assigned to document.domain",
	},
	{
		prefix: "/sdm/ws", param: "channel", row: "WebSocket URL poisoning (stored DOM-based)",
		use:     `new WebSocket('ws://' + location.host + '/sdm/_ws/' + value);`,
		safeUse: safeShow,
		note: "a channel submitted here is fetched back and built into the URL of a WebSocket the " +
			"page opens, so a stored value decides where the socket connects",
		safeNote: "the same submission, displayed with textContent - never built into a socket URL",
	},
	{
		prefix: "/sdm/dos", param: "pattern", row: "Denial of service (stored DOM-based)",
		use:     `new RegExp(value);`,
		safeUse: safeShow,
		note: "a pattern submitted here is fetched back and compiled with the RegExp constructor. A " +
			"tainted pattern is the catastrophic-backtracking precondition; the finding is that " +
			"stored data reaches the compiler, not that a hang was measured",
		safeNote: "the same submission, displayed with textContent - never compiled as a pattern",
	},
	{
		prefix: "/sdm/ajax", param: "trace", row: "Ajax request header manipulation (stored DOM-based)",
		use: `var x = new XMLHttpRequest(); x.open('GET', '/sdm/_target', true); ` +
			`x.setRequestHeader('X-Trace', value); x.send();`,
		safeUse: safeShow,
		note: "a trace id submitted here is fetched back and passed to setRequestHeader. The request " +
			"URL is a constant on purpose: only the header carries the stored value, which is what " +
			"this row is named for and what observing XMLHttpRequest.open alone would miss",
		safeNote: "the same submission, displayed with textContent - never passed to setRequestHeader",
	},
}

// storedDOMPage serves a render page whose script fetches dataPath and runs use(value) on every
// stored value it gets back. The response body itself never contains a stored value.
func storedDOMPage(w http.ResponseWriter, dataPath, use string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>sdm</title></head>
<body><div id="out"></div><script>
fetch(%q).then(function (r) { return r.json(); }).then(function (values) {
  for (var i = 0; i < values.length; i++) {
    var value = values[i];
    try { %s } catch (e) {}
  }
}).catch(function () {});
</script></body></html>`, dataPath, use)
}

// storedDOMData serves a history as JSON, which is what the render pages fetch.
func storedDOMData(w http.ResponseWriter, mu *sync.Mutex, log *[]string) {
	body, err := json.Marshal(storedSnapshot(mu, log))
	if err != nil {
		http.Error(w, "cannot encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// storedDOMSubmit persists one query parameter and says so, mirroring vulnapp_stored.go's submit
// handlers: storing untrusted input is not the defect, the later use is.
func storedDOMSubmit(mu *sync.Mutex, log *[]string, param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		storedAppend(mu, log, r.URL.Query().Get(param))
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "saved\n")
	}
}

// storedDOMFamilyEndpoints returns this family's manifest entries, four per case.
//
// The data endpoints are absent on purpose; see the file comment. The render pages are declared so
// the deferred phase knows to look at them, exactly as /st/notes and friends are.
func storedDOMFamilyEndpoints() []Endpoint {
	out := make([]Endpoint, 0, len(storedDOMCases)*4)
	for _, c := range storedDOMCases {
		out = append(out,
			Endpoint{
				Path: c.prefix + "/plant?" + c.param + "=seed", Row: c.row,
				Stored: true, DOM: true, Note: c.note,
			},
			Endpoint{
				Path: c.prefix,
				Note: "fetches this family's stored values and drives each into the row's sink; " +
					"rendered by the deferred phase",
			},
			Endpoint{
				Path: c.prefix + "/safe/plant?" + c.param + "=seed", Row: c.row,
				Safe: true, Stored: true, DOM: true, Note: c.safeNote,
			},
			Endpoint{
				Path: c.prefix + "/safe",
				Note: "fetches the same stored values and writes them into textContent; rendered by " +
					"the deferred phase",
			},
		)
	}
	return out
}

// registerStoredDOMFamily serves this family's routes: six per case, plus the two shared endpoints
// the sinks aim at.
func registerStoredDOMFamily(mux *http.ServeMux) {
	for _, c := range storedDOMCases {
		c := c
		mux.HandleFunc(c.prefix+"/plant", storedDOMSubmit(&c.vuln.mu, &c.vuln.log, c.param))
		mux.HandleFunc(c.prefix+"/data", func(w http.ResponseWriter, _ *http.Request) {
			storedDOMData(w, &c.vuln.mu, &c.vuln.log)
		})
		mux.HandleFunc(c.prefix, func(w http.ResponseWriter, _ *http.Request) {
			storedDOMPage(w, c.prefix+"/data", c.use)
		})

		mux.HandleFunc(c.prefix+"/safe/plant", storedDOMSubmit(&c.safe.mu, &c.safe.log, c.param))
		mux.HandleFunc(c.prefix+"/safe/data", func(w http.ResponseWriter, _ *http.Request) {
			storedDOMData(w, &c.safe.mu, &c.safe.log)
		})
		mux.HandleFunc(c.prefix+"/safe", func(w http.ResponseWriter, _ *http.Request) {
			storedDOMPage(w, c.prefix+"/safe/data", c.safeUse)
		})
	}

	// The target the XHR cases aim at. It exists so the request the page issues actually completes;
	// what it returns is irrelevant, the sink observation happens before the send.
	mux.HandleFunc("/sdm/_target", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok\n")
	})
}
