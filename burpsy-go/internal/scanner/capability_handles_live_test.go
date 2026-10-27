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
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
)

// chromeAvailable makes a missing Chrome a counted skip, which fails the package, not a quiet one.
//
// A silent skip here is the expensive kind of quiet: 51 catalog rows are DOM rows whose only
// live validation runs through this browser, so a machine without Chrome would report a green
// suite while none of them were exercised. Absence has to be declared, not inferred — set
// BURPSY_ALLOW_NO_CHROME=1 to accept the reduced coverage, and the package then passes saying so.
func chromeAvailable(t *testing.T) {
	t.Helper()
	if domexectest.ChromeOnPath() {
		return
	}
	// Counted: TestMain fails the package unless BURPSY_ALLOW_NO_CHROME=1 (domexectest).
	domexectest.Skip(t, "no Chrome binary on PATH: the DOM capability and every DOM catalog row are untested")
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
	cc.Scanner.WithBrowserProvider(sharedBrowserProvider())
	// No CloseCapabilities cleanup: the attached provider is the package-wide shared
	// Chrome, and closing it here would leave every later DOM test with a dead
	// browser that reads as zero observations. TestMain owns the close. This
	// scanner carries no out-of-band collaborator, so the only handle CloseCapabilities
	// would release is the one TestMain already releases.

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

// The same provider must hand back one browser, not one per call. Runs against the
// package-shared provider: if an earlier test already launched it, this still holds
// the pointer-equality contract; if this test runs first, it pays the one launch.
func TestTheBrowserProviderSharesOneBrowserAcrossChecks(t *testing.T) {
	chromeAvailable(t)

	provider := sharedBrowserProvider()

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
