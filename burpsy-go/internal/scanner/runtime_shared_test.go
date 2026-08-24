package scanner

// One seeded target for the whole package, instead of one per test function.
//
// Four tests drive the live corpus, and each used to build its own: two httptest servers, ~150 real
// seeding requests, a fresh headless Chrome, and its own audit memo. The setup cost was minor; the
// duplicated AUDITS were not. TestAnAuditSendsProbesAndStaysWithinARequestBudget audits every
// endpoint in the manifest, and the detection and safe-counterpart tests had already audited nearly
// all of them — so the same work was done two or three times over, browser included.
//
// Sharing the target shares the memo, which is what collapses that. What it does NOT do is weaken the
// safe-counterpart pairing: that test requires a row's vulnerable twin to have fired in this run
// before it will trust the safe endpoint's silence, and a memoised result from earlier in the same
// process is still an audit that genuinely happened in this run. The assertion means "this check works
// AND does not fire here", and it still means exactly that.
//
// The stored rows remain serial and origin-scoped, so a shared ledger cannot let one endpoint's canary
// settle another's claim - see deferStoredClaim, and the regression test that pins it.

import (
	"os"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

var (
	sharedTargetOnce sync.Once
	sharedTarget     *runtimeTarget
	sharedTargetTB   testing.TB
	// One headless Chrome for the whole test binary. Five separate providers across
	// the live-capability and runtime-coverage tests each used to launch their own
	// process — five real Chrome starts whose only difference was the port chromedp
	// picked. The provider is lazy, so a run with BURPSY_ALLOW_NO_CHROME=1 never
	// starts one at all, and the skip messages still say what was not exercised.
	sharedChromeOnce sync.Once
	sharedChrome     BrowserProvider
)

// TestMain owns the shared target's teardown.
//
// t.Cleanup cannot: it would close the servers when the FIRST test finished, and every later test
// would then audit a dead host and report every row as silent - a whole-suite false negative.
// The same reasoning owns the shared browser: closing it in the first test's cleanup would leave
// every later DOM check staring at a dead process, which reads as zero observations, which reads
// as clean - the exact miscount this package exists to prevent.
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedTarget != nil {
		if sharedTarget.srv != nil {
			sharedTarget.srv.Close()
		}
		if sharedTarget.tlsSrv != nil {
			sharedTarget.tlsSrv.Close()
		}
		if sharedTarget.domScan != nil {
			_ = sharedTarget.domScan.CloseCapabilities()
		}
	}
	if sharedChrome != nil {
		_ = sharedChrome.Close()
	}
	os.Exit(code)
}

// sharedBrowserProvider returns the package-wide browser provider, launching Chrome on first use.
//
// Safe to share because Browser hands out an isolated tab per call (see domexec's newTab contract):
// concurrent or sequential checks never see each other's instrumentation state. That is the same
// guarantee a production scan already relies on when it drives many DOM checks through one browser,
// so the tests are exercising the handle exactly the way the scanner will.
func sharedBrowserProvider() BrowserProvider {
	sharedChromeOnce.Do(func() {
		sharedChrome = NewLazyBrowserProvider(domexec.Options{Headed: os.Getenv("BURPSY_DOM_HEADED") == "1"})
	})
	return sharedChrome
}

// sharedRuntimeTarget returns the package-wide target, building it on first use.
//
// The builder is handed the first caller's *testing.T only to report a setup failure. That is safe
// because a failure here is fatal for every test that would use it, but it means a setup error is
// attributed to whichever test happened to run first — hence the explicit message.
func sharedRuntimeTarget(t *testing.T) *runtimeTarget {
	t.Helper()
	sharedTargetOnce.Do(func() {
		sharedTargetTB = t
		sharedTarget = buildRuntimeTarget(t)
	})
	if sharedTarget == nil {
		t.Fatalf("the shared runtime target failed to build (first attempted by %v); every live "+
			"corpus test depends on it", sharedTargetTB)
	}
	return sharedTarget
}
