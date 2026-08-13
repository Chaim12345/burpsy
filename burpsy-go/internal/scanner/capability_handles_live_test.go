package scanner

// Live proof that the browser handle is real: the provider launches Chrome, a check reaches
// it through CheckContext, taint is observed on a served page, and a browser that has been
// closed is reported as unavailable rather than handed back.
//
// Untagged, matching internal/domexec's own tests, which already launch Chrome in the normal
// suite.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

// chromeAvailable fails when Chrome is missing instead of skipping.
//
// A silent skip here is the expensive kind of quiet: 51 catalog rows are DOM rows whose only
// live validation runs through this browser, so a machine without Chrome would report a green
// suite while none of them were exercised. Absence has to be declared, not inferred — set
// BURPSY_ALLOW_NO_CHROME=1 to accept the reduced coverage, and the skip then says so.
func chromeAvailable(t *testing.T) {
	t.Helper()
	for _, name := range []string{"chromium", "google-chrome", "google-chrome-stable", "chrome"} {
		if _, err := exec.LookPath(name); err == nil {
			return
		}
	}
	if os.Getenv("BURPSY_ALLOW_NO_CHROME") == "1" {
		t.Skip("BURPSY_ALLOW_NO_CHROME=1: skipping the DOM capability tests; the DOM catalog rows are NOT exercised in this run")
	}
	t.Fatal("no Chrome binary on PATH: the DOM capability and every DOM catalog row would go untested. " +
		"Install Chrome/Chromium, or set BURPSY_ALLOW_NO_CHROME=1 to accept that this run does not exercise them.")
}

func TestTheBrowserHandleReachesARealBrowserAndObservesTaint(t *testing.T) {
	chromeAvailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="x"></div><script>
			document.getElementById('x').innerHTML = location.hash.slice(1);
		</script></body></html>`)
	}))
	defer srv.Close()

	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	provider := NewLazyBrowserProvider(domexec.Options{})
	cc.Scanner.WithBrowserProvider(provider)
	t.Cleanup(func() { _ = cc.Scanner.CloseCapabilities() })

	browser, err := cc.Browser(context.Background())
	if err != nil {
		t.Fatalf("Browser() through the check context: %v", err)
	}
	if !browser.Available() {
		t.Fatal("provider returned an unavailable browser")
	}

	const canary = "bsycanary123"
	obs, err := browser.ObserveTaint(context.Background(), srv.URL, domexec.SourceLocationHash, canary)
	if err != nil {
		t.Fatalf("ObserveTaint: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("a hash source flowing into innerHTML produced no observation; the DOM capability is not actually working")
	}
	var sawCanary bool
	for _, o := range obs {
		if strings.Contains(o.Canary, canary) {
			sawCanary = true
		}
	}
	if !sawCanary {
		t.Errorf("observations did not carry the canary: %+v", obs)
	}
}

// The same provider must hand back one browser, not one per call.
func TestTheBrowserProviderSharesOneBrowserAcrossChecks(t *testing.T) {
	chromeAvailable(t)

	provider := NewLazyBrowserProvider(domexec.Options{})
	defer func() { _ = provider.Close() }()

	first, err := provider.Browser(context.Background())
	if err != nil {
		t.Fatalf("first Browser(): %v", err)
	}
	second, err := provider.Browser(context.Background())
	if err != nil {
		t.Fatalf("second Browser(): %v", err)
	}
	if first != second {
		t.Error("the provider launched a second browser; DOM checks would pay a Chrome start each")
	}
}

// A browser whose process is gone must be reported as unavailable. Handing it back would
// produce zero observations that a caller reads as "no DOM vulnerability".
func TestAClosedBrowserIsReportedUnavailableRatherThanHandedBack(t *testing.T) {
	chromeAvailable(t)

	provider := NewLazyBrowserProvider(domexec.Options{})
	b, err := provider.Browser(context.Background())
	if err != nil {
		t.Fatalf("Browser(): %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if b.Available() {
		t.Fatal("a closed browser still reports itself available; the fixture cannot test the guard")
	}

	if _, err := provider.Browser(context.Background()); err == nil {
		t.Fatal("the provider handed back a dead browser; a DOM check would read zero observations as clean")
	}
}
