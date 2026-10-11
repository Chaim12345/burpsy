package domexec

// Driving a SPA's own navigation to reach the view under test.
//
// The fixture is the shape that motivates it: ONE document is served for every path, and the page
// whose script matters is rendered only after the navigation tree is clicked through. A harness that
// knows only a URL loads the API answer, never the form.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// spaNavPage serves a two-level navigation tree built by script, exactly as a real SPA does: the
// master entries appear after the initial XHR, clicking one rebuilds the level list, and clicking a
// level renders the level's own form. The form posts its input to /api/echo and writes the reply
// into the document with innerHTML.
const spaNavPage = `<!doctype html><html><body>
<div class="master"></div><div class="inner-master"></div><div id="formHost"></div>
<input id="textInput"><button id="submit">Go</button><div id="result"></div>
<script>
function api(path, cb){ fetch(path).then(function(r){return r.text();}).then(cb); }
api('/nav', function(json){
  var data = JSON.parse(json);
  var m = document.querySelector('.master');
  data.masters.forEach(function(name){
    var el = document.createElement('div'); el.className = 'master-item'; el.innerText = name;
    el.addEventListener('click', function(){ levels(name); });
    m.appendChild(el);
  });
});
function levels(name){
  var inner = document.querySelector('.inner-master');
  inner.innerHTML = '';
  ['LEVEL_1','LEVEL_2'].forEach(function(lv){
    var el = document.createElement('div'); el.className = 'inner-master-item'; el.innerText = lv;
    el.addEventListener('click', function(){ render(name, lv); });
    inner.appendChild(el);
  });
}
function render(name, lv){
  // The form and its listener are bound ONCE at load, as the app's template does; the navigation
  // only reveals it. Binding inside render() re-added a listener on every level click and, worse,
  // rebuilt the input through formHost.innerHTML, which is the very sink under test.
  document.getElementById('formHost').textContent = name + ' ' + lv;
}
document.getElementById('submit').addEventListener('click', function(){
  api('/api/echo?value=' + encodeURIComponent(document.getElementById('textInput').value),
      function(t){ document.getElementById('result').innerHTML = t; });
});
</script></body></html>`

func spaNavSite(t *testing.T, escape bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nav":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"masters":["Alpha","Beta"]}`))
		case "/api/echo":
			w.Header().Set("Content-Type", "text/plain")
			v := r.URL.Query().Get("value")
			if escape {
				v = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(v)
			}
			_, _ = w.Write([]byte("<div>" + v + "</div>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(spaNavPage))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// The claim: a view that exists only after the SPA's tree is clicked through is reached, and its
// script's sink is then observed carrying the payload.
func TestNavigatingASPATreeReachesAViewOnlyAClickRenders(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	base := spaNavSite(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tab, tcancel, err := b.NavigateSPA(ctx, SPARoute{
		RootURL:        base + "/",
		MasterSelector: ".master-item",
		MasterText:     "Beta",
		LevelSelector:  ".inner-master-item",
		LevelText:      "LEVEL_2",
		ReadySelector:  "#textInput",
	})
	if err != nil {
		t.Fatalf("NavigateSPA: %v", err)
	}
	defer tcancel()

	const canary = "bsyspacanary1"
	payload := "<svg id=" + canary + " onload=1>"
	obs, err := b.SubmitAndObserveIn(tab, FormSubmitSpec{
		InputSelector:  "#textInput",
		SubmitSelector: "#submit",
		ClickTrigger:   true,
		Payload:        payload,
	}, canary)
	if err != nil {
		t.Fatalf("SubmitAndObserveIn: %v", err)
	}
	if len(ObservationsForSink(obs, SinkInnerHTML)) == 0 {
		t.Fatalf("the reached view's innerHTML write was not observed; observations: %+v", obs)
	}
}

// A navigation that cannot reach its target is an error naming the step, not a silent success with
// nothing to drive — the honest-failure contract the rest of the package follows.
func TestANavigationThatCannotReachItsViewIsAnErrorNamingTheStep(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	base := spaNavSite(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, _, err := b.NavigateSPA(ctx, SPARoute{
		RootURL:        base + "/",
		MasterSelector: ".master-item",
		MasterText:     "NoSuchFamily",
		LevelSelector:  ".inner-master-item",
		LevelText:      "LEVEL_1",
		ReadySelector:  "#textInput",
		StepTimeout:    3 * time.Second,
	})
	if err == nil {
		t.Fatal("a navigation to a non-existent family returned no error")
	}
	if !strings.Contains(err.Error(), "NoSuchFamily") {
		t.Fatalf("the error does not name the step that failed: %v", err)
	}
}
