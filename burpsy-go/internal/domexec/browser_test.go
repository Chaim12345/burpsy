package domexec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// This package's tests share one headless Chrome process instead of launching one per test.
//
// Launching Chrome ~14 times (once per test needing a browser) dominated this package's wall
// clock: NewBrowser blocks on a real process start plus a warm-up round trip, so a sub-second
// fixture cost was paid once per test rather than once per package. Browser already hands out
// an isolated tab per call (see newTab) specifically so "concurrent or sequential
// ObserveTaint/RenderedDOM calls never see each other's instrumentation state" - that contract,
// already relied on by real scans running many DOM checks through one shared browser, is exactly
// what makes sharing one Browser across every test in this package safe: each test still gets
// its own tab, its own navigation, its own DOM, and (per that same contract) may run concurrently
// with the others.
//
// TestMain, not t.Cleanup, owns teardown. t.Cleanup on the first test to request the browser
// would close it the moment that ONE test finished, and every later test would then either error
// on a dead browser or - the failure this package's own tests exist to catch - silently observe
// nothing and be misread as a passing negative case.
var (
	sharedBrowserOnce sync.Once
	sharedBrowser     *Browser
	sharedBrowserErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedBrowser != nil {
		_ = sharedBrowser.Close()
	}
	os.Exit(code)
}

// newTestBrowser returns the package's shared Browser, launching it on first use, or skips. Chrome
// is present on the development box, so these tests do run here; the skip exists so the suite
// stays green on a host without a browser rather than reporting a missing prerequisite as a code
// failure.
func newTestBrowser(t *testing.T) *Browser {
	t.Helper()
	sharedBrowserOnce.Do(func() {
		// BURPSY_DOM_REMOTE points the whole suite at a running CDP server
		// (obscura serve / lightpanda serve) instead of launching Chrome —
		// this is how alternative engines get benchmarked against the same
		// sink-by-sink assertions with zero test changes.
		if remote := os.Getenv("BURPSY_DOM_REMOTE"); remote != "" {
			sharedBrowser, sharedBrowserErr = NewBrowser(context.Background(), Options{RemoteURL: remote})
		} else {
			sharedBrowser, sharedBrowserErr = NewBrowser(context.Background(), Options{Timeout: 30 * time.Second})
		}
	})
	if sharedBrowserErr != nil {
		t.Skipf("no browser available, skipping: %v", sharedBrowserErr)
	}
	return sharedBrowser
}

// servePage serves one HTML document at / and returns its URL.
func servePage(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func observe(t *testing.T, b *Browser, url string, canary string) []Observation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	obs, err := b.ObserveTaint(ctx, url, SourceLocationHash, canary)
	if err != nil {
		t.Fatalf("ObserveTaint failed: %v", err)
	}
	return obs
}

func TestAHashSourceFlowingIntoEvalIsObservedAtTheEvalSink(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><script>
		try { eval(decodeURIComponent(location.hash.slice(1))); } catch (e) {}
	</script></body></html>`)
	obs := observe(t, b, url, "burpsyCanary1")
	if len(ObservationsForSink(obs, SinkEval)) == 0 {
		t.Fatalf("a hash value reaching eval is the canonical DOM-XSS flow and must be observed; got %d observations: %+v", len(obs), obs)
	}
}

func TestAHashSourceAssignedToInnerHTMLIsObservedAtTheInnerHTMLSink(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><div id="x"></div><script>
		document.getElementById('x').innerHTML = location.hash.slice(1);
	</script></body></html>`)
	obs := observe(t, b, url, "burpsyCanary2")
	if len(ObservationsForSink(obs, SinkInnerHTML)) == 0 {
		t.Fatalf("an innerHTML write fed from location.hash must be observed; got %+v", obs)
	}
}

func TestAHashSourceDrivingANavigationIsObservedAtTheLocationSink(t *testing.T) {
	// This is the DOM-based open-redirection family, which is why the location sink is
	// tracked separately from the HTML-writing sinks.
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><script>
		var t = location.hash.slice(1);
		if (t) { location.href = t; }
	</script></body></html>`)
	obs := observe(t, b, url, "burpsyCanary3")
	if len(ObservationsForSink(obs, SinkLocationAssign)) == 0 {
		t.Fatalf("assigning location.href from location.hash must be observed as a navigation sink; got %+v", obs)
	}
}

func TestAHashSourceWrittenToLocalStorageIsObservedAtTheStorageSink(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><script>
		localStorage.setItem('k', location.hash.slice(1));
	</script></body></html>`)
	obs := observe(t, b, url, "burpsyCanary4")
	if len(ObservationsForSink(obs, SinkLocalStorage)) == 0 {
		t.Fatalf("a localStorage write fed from location.hash must be observed; got %+v", obs)
	}
}

func TestAPageThatNeverReadsASourceYieldsNoObservations(t *testing.T) {
	// The negative case that proves the harness reports flows rather than merely reporting
	// that sinks were called. Without this, every page using innerHTML at all would look
	// vulnerable.
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><div id="x"></div><script>
		document.getElementById('x').innerHTML = "<b>static content</b>";
		eval("var unused = 1;");
	</script></body></html>`)
	obs := observe(t, b, url, "burpsyCanary5")
	if len(obs) != 0 {
		t.Fatalf("sinks called with data unrelated to the canary must not be reported as flows; got %+v", obs)
	}
}

func TestInstrumentedSinksStillCallThroughSoThePageKeepsWorking(t *testing.T) {
	// An instrumentation wrapper that swallowed the call would observe nothing on any real
	// page, and would do so silently. Proving call-through is what makes the whole harness
	// trustworthy.
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><div id="x"></div><script>
		document.getElementById('x').innerHTML = "<span id=proof>" + location.hash.slice(1) + "</span>";
	</script></body></html>`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	obs, err := b.ObserveTaint(ctx, url, SourceLocationHash, "burpsyCanary6")
	if err != nil {
		t.Fatalf("ObserveTaint failed: %v", err)
	}
	if len(ObservationsForSink(obs, SinkInnerHTML)) == 0 {
		t.Fatalf("expected the innerHTML flow to be observed; got %+v", obs)
	}
	dom, err := b.RenderedDOM(ctx, url+"#burpsyCanary6")
	if err != nil {
		t.Fatalf("RenderedDOM failed: %v", err)
	}
	if !strings.Contains(dom, "burpsyCanary6") {
		t.Error("the wrapped innerHTML setter did not actually write to the document; instrumentation that swallows the call would observe nothing on a real page")
	}
}

func TestRenderedDOMSeesMarkupThatOnlyExistsAfterScriptRuns(t *testing.T) {
	// The other half of what the DOM rows need: content the HTTP-only scanner cannot see at
	// all, because it is created by script rather than served.
	t.Parallel()
	b := newTestBrowser(t)
	const raw = `<html><body><script>
		var d = document.createElement('div');
		d.id = 'created-by-script';
		d.textContent = 'scriptGeneratedMarker';
		document.body.appendChild(d);
	</script></body></html>`
	url := servePage(t, raw)
	if strings.Contains(raw, "scriptGeneratedMarker</div>") {
		t.Fatal("fixture is wrong: the marker must not be present in the served HTML")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dom, err := b.RenderedDOM(ctx, url)
	if err != nil {
		t.Fatalf("RenderedDOM failed: %v", err)
	}
	if !strings.Contains(dom, "scriptGeneratedMarker") {
		t.Fatal("post-script markup absent from RenderedDOM; without this the DOM rows gain nothing over the HTTP-only scanner")
	}
}

func TestAMissingChromeBinaryIsReportedAsNoCapabilityNamingWhatWasLookedFor(t *testing.T) {
	_, err := NewBrowser(context.Background(), Options{ChromePath: "/nonexistent/chrome-binary"})
	if err == nil {
		t.Fatal("NewBrowser succeeded with a nonexistent binary; a caller would then read zero DOM observations as 'no DOM vulnerability'")
	}
	if !strings.Contains(err.Error(), "/nonexistent/chrome-binary") {
		t.Errorf("error %q does not name the path that was tried, so an operator cannot tell what to install", err.Error())
	}
}

func TestObservationsForSinkFiltersToTheRequestedSink(t *testing.T) {
	// Pure; no browser needed.
	in := []Observation{
		{Sink: SinkEval, Canary: "a"},
		{Sink: SinkInnerHTML, Canary: "b"},
		{Sink: SinkEval, Canary: "c"},
	}
	if got := ObservationsForSink(in, SinkEval); len(got) != 2 {
		t.Fatalf("got %d eval observations, want 2", len(got))
	}
	if got := ObservationsForSink(in, SinkCookie); got != nil {
		t.Fatalf("a sink with no observations must yield nil, got %+v", got)
	}
}

// The zero value must be headless. Every live test in this repo builds Options{} without naming
// this field, so if the default ever flips back the whole suite starts opening windows on whoever
// runs it - which is exactly how this was found.
func TestTheZeroValueOptionsIsHeadless(t *testing.T) {
	if (Options{}).Headed {
		t.Fatal("Options{} requests a visible browser window; headless must be the default because " +
			"callers that never mention the field are the common case")
	}
}
