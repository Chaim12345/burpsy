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
// Corresponding scanner descriptors: DOMCheckDescriptors, the domVariantStored branch.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

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

// storedDOMFamilyEndpoints returns this family's manifest entries.
//
// The data endpoints are absent on purpose; see the file comment. The render pages are declared so
// the deferred phase knows to look at them, exactly as /st/notes and friends are.
func storedDOMFamilyEndpoints() []Endpoint {
	return []Endpoint{
		// ---- innerHTML: Cross-site scripting (stored DOM-based) ----
		{Path: "/sdm/xss/plant?text=seed", Row: "Cross-site scripting (stored DOM-based)", Stored: true, DOM: true,
			Note: "a note submitted here is fetched from /sdm/xss/data by /sdm/xss's own script and written " +
				"into innerHTML; no HTTP response ever contains the value, so only a rendered page shows the flow"},
		{Path: "/sdm/xss", Note: "fetches the stored notes and writes them into innerHTML; rendered by the deferred phase"},
		{Path: "/sdm/xss/safe/plant?text=seed", Row: "Cross-site scripting (stored DOM-based)", Safe: true, Stored: true, DOM: true,
			Note: "the same submission, fetched and displayed by /sdm/xss/safe with textContent - the value still " +
				"appears in the rendered document, it just never reaches an HTML-parsing sink"},
		{Path: "/sdm/xss/safe", Note: "fetches the stored notes and writes them into textContent; rendered by the deferred phase"},

		// ---- XMLHttpRequest.open: DOM data manipulation (stored DOM-based) ----
		{Path: "/sdm/domdata/plant?report=seed", Row: "DOM data manipulation (stored DOM-based)", Stored: true, DOM: true,
			Note: "a report id submitted here is fetched from /sdm/domdata/data by /sdm/domdata's own script and " +
				"concatenated into the URL of an XMLHttpRequest it then opens"},
		{Path: "/sdm/domdata", Note: "fetches the stored report ids and opens an XHR against each; rendered by the deferred phase"},
		{Path: "/sdm/domdata/safe/plant?report=seed", Row: "DOM data manipulation (stored DOM-based)", Safe: true, Stored: true, DOM: true,
			Note: "the same submission, fetched and displayed by /sdm/domdata/safe with textContent - never used to " +
				"build a request URL"},
		{Path: "/sdm/domdata/safe", Note: "fetches the stored report ids and writes them into textContent; rendered by the deferred phase"},

		// ---- anchor.href: Link manipulation (stored DOM-based) ----
		//
		// This is the navigation-target family in its loop-safe form. Open redirection (stored
		// DOM-based) shares the shape but not the mechanism: its sink is an actual navigation,
		// which is terminal - one per page load - so a page cannot walk a stored history and try
		// each value, and whichever value happens to be last decides the whole result. On a shared
		// fixture that is not under this family's control (every other scanner in the suite also
		// probes this endpoint and its payloads land in the same history), "last value" is not a
		// property a fixture can rely on. Writing the value into an anchor's href is the same
		// stored-value-becomes-a-link defect with a sink that can be reached once per stored value.
		{Path: "/sdm/link/plant?destination=seed", Row: "Link manipulation (stored DOM-based)", Stored: true, DOM: true,
			Note: "a destination submitted here is fetched from /sdm/link/data by /sdm/link's own script and assigned " +
				"to an anchor's href, so a stored value decides where a link on the page points"},
		{Path: "/sdm/link", Note: "fetches the stored destinations and assigns each to an anchor href; rendered by the deferred phase"},
		{Path: "/sdm/link/safe/plant?destination=seed", Row: "Link manipulation (stored DOM-based)", Safe: true, Stored: true, DOM: true,
			Note: "the same submission, fetched and displayed by /sdm/link/safe with textContent - never assigned to an href"},
		{Path: "/sdm/link/safe", Note: "fetches the stored destinations and writes them into textContent; rendered by the deferred phase"},
	}
}

var (
	storedDOMNoteMu  sync.Mutex
	storedDOMNoteLog []string

	storedDOMSafeNoteMu  sync.Mutex
	storedDOMSafeNoteLog []string

	storedDOMReportMu  sync.Mutex
	storedDOMReportLog []string

	storedDOMSafeReportMu  sync.Mutex
	storedDOMSafeReportLog []string

	storedDOMDestMu  sync.Mutex
	storedDOMDestLog []string

	storedDOMSafeDestMu  sync.Mutex
	storedDOMSafeDestLog []string
)

// registerStoredDOMFamily serves this family's routes.
func registerStoredDOMFamily(mux *http.ServeMux) {
	// Cross-site scripting (stored DOM-based). innerHTML parses what it is given as markup, which
	// is the defect; the safe twin's textContent does not.
	mux.HandleFunc("/sdm/xss/plant", storedDOMSubmit(&storedDOMNoteMu, &storedDOMNoteLog, "text"))
	mux.HandleFunc("/sdm/xss/data", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMData(w, &storedDOMNoteMu, &storedDOMNoteLog)
	})
	mux.HandleFunc("/sdm/xss", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMPage(w, "/sdm/xss/data", `document.getElementById('out').innerHTML += value;`)
	})
	mux.HandleFunc("/sdm/xss/safe/plant", storedDOMSubmit(&storedDOMSafeNoteMu, &storedDOMSafeNoteLog, "text"))
	mux.HandleFunc("/sdm/xss/safe/data", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMData(w, &storedDOMSafeNoteMu, &storedDOMSafeNoteLog)
	})
	mux.HandleFunc("/sdm/xss/safe", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMPage(w, "/sdm/xss/safe/data", `document.getElementById('out').textContent += value;`)
	})

	// DOM data manipulation (stored DOM-based). The stored value becomes part of a request URL the
	// page issues on the visitor's behalf.
	mux.HandleFunc("/sdm/domdata/plant", storedDOMSubmit(&storedDOMReportMu, &storedDOMReportLog, "report"))
	mux.HandleFunc("/sdm/domdata/data", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMData(w, &storedDOMReportMu, &storedDOMReportLog)
	})
	mux.HandleFunc("/sdm/domdata", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMPage(w, "/sdm/domdata/data",
			`var x = new XMLHttpRequest(); x.open('GET', '/sdm/domdata/report?id=' + value, true); x.send();`)
	})
	mux.HandleFunc("/sdm/domdata/report", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "report\n")
	})
	mux.HandleFunc("/sdm/domdata/safe/plant", storedDOMSubmit(&storedDOMSafeReportMu, &storedDOMSafeReportLog, "report"))
	mux.HandleFunc("/sdm/domdata/safe/data", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMData(w, &storedDOMSafeReportMu, &storedDOMSafeReportLog)
	})
	mux.HandleFunc("/sdm/domdata/safe", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMPage(w, "/sdm/domdata/safe/data", `document.getElementById('out').textContent += value;`)
	})

	// Link manipulation (stored DOM-based). A stored value decides where a link points.
	mux.HandleFunc("/sdm/link/plant", storedDOMSubmit(&storedDOMDestMu, &storedDOMDestLog, "destination"))
	mux.HandleFunc("/sdm/link/data", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMData(w, &storedDOMDestMu, &storedDOMDestLog)
	})
	mux.HandleFunc("/sdm/link", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMPage(w, "/sdm/link/data",
			`var a = document.createElement('a'); a.href = value; a.textContent = 'saved link'; document.body.appendChild(a);`)
	})
	mux.HandleFunc("/sdm/link/safe/plant", storedDOMSubmit(&storedDOMSafeDestMu, &storedDOMSafeDestLog, "destination"))
	mux.HandleFunc("/sdm/link/safe/data", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMData(w, &storedDOMSafeDestMu, &storedDOMSafeDestLog)
	})
	mux.HandleFunc("/sdm/link/safe", func(w http.ResponseWriter, _ *http.Request) {
		storedDOMPage(w, "/sdm/link/safe/data", `document.getElementById('out').textContent += value;`)
	})
}
