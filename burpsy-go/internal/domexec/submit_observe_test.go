package domexec

// Form-driven taint observation: the harness types a canary into a page's own input, submits its own
// form, and reports whether the page's script then fed the canary to a dangerous sink.
//
// The fixture is the shape that motivates the harness: the server answers text/plain with the value
// echoed, and the PAGE's script writes the reply into the document with innerHTML. Nothing in the
// HTTP exchange is evidence of a breakout, and the server-side reflected-XSS check is right to stay
// silent; the vulnerability exists only once a browser has run the page's script.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// spaFormPage is served for the page path: an input, a submit handler, and an API the handler calls
// whose answer is written into the document with innerHTML.
const spaFormPage = `<!doctype html><html><body>
<div id="out"></div>
<form id="f">
  <input id="q" name="q" />
  <button id="go" type="submit">Go</button>
</form>
<script>
document.getElementById('f').addEventListener('submit', function(e){ e.preventDefault(); go(); });
function go(){
  fetch('/api/search?q=' + encodeURIComponent(document.getElementById('q').value))
    .then(function(r){ return r.text(); })
    .then(function(t){ document.getElementById('out').innerHTML = t; });
}
</script>
</body></html>`

// spaFormSite serves the page and an API that echoes the query back as text/plain — the exact shape
// that defeats a server-side check. escape=true makes the API escape the value, the safe twin.
func spaFormSite(t *testing.T, escape bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/search" {
			w.Header().Set("Content-Type", "text/plain")
			q := r.URL.Query().Get("q")
			if escape {
				q = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(q)
			}
			_, _ = w.Write([]byte("<div>" + q + "</div>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(spaFormPage))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// The claim: a page that writes the API reply into innerHTML is observed at that sink, even though
// the reply arrived as text/plain and the URL never carried the payload.
func TestTypingAndSubmittingObservesTheSinkThePageWritesTo(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	base := spaFormSite(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const canary = "bsycanaryform1"
	payload := "<svg id=" + canary + " onload=1>"
	obs, err := b.SubmitAndObserve(ctx, FormSubmitSpec{
		PageURL:        base + "/",
		InputSelector:  "#q",
		SubmitSelector: "#go",
		Payload:        payload,
	}, canary)
	if err != nil {
		t.Fatalf("SubmitAndObserve: %v", err)
	}
	if len(ObservationsForSink(obs, SinkInnerHTML)) == 0 {
		t.Fatalf("the page's innerHTML write was not observed; observations: %+v", obs)
	}
}

// The safe twin: the API escapes the value, so the script writes ESCAPED text. The sink is still
// called — with markup that cannot execute — so this pins that the harness reports what reached the
// sink rather than deciding exploitability, and that a caller comparing the argument against the
// markup it sent can tell the two apart.
func TestAnEscapedReplyReachesTheSinkButNotAsMarkup(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	base := spaFormSite(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const canary = "bsycanaryform2"
	payload := "<svg id=" + canary + " onload=1>"
	obs, err := b.SubmitAndObserve(ctx, FormSubmitSpec{
		PageURL:        base + "/",
		InputSelector:  "#q",
		SubmitSelector: "#go",
		Payload:        payload,
	}, canary)
	if err != nil {
		t.Fatalf("SubmitAndObserve: %v", err)
	}
	for _, o := range ObservationsForSink(obs, SinkInnerHTML) {
		if strings.Contains(o.Argument, payload) {
			t.Fatalf("an escaped reply was reported carrying the raw markup %q; the sink saw %q",
				payload, o.Argument)
		}
	}
}

// A missing input is an error naming the selector, not a silent zero-observation "clean" result —
// the honest-failure contract the rest of the package follows.
func TestAMissingInputIsAnErrorNotASilentCleanResult(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	base := spaFormSite(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := b.SubmitAndObserve(ctx, FormSubmitSpec{
		PageURL:       base + "/",
		InputSelector: "#no-such-field",
		Payload:       "x",
	}, "canary")
	if err == nil {
		t.Fatal("a missing input returned no error; zero observations from a page that was never " +
			"interacted with is indistinguishable from a page that ran and was clean")
	}
}
