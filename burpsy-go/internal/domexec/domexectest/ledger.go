// Package domexectest is the test-side half of one rule: a test that needs a real browser may skip
// when there is none, but the package it lives in may not then report green.
//
// # Why a skip has to be counted
//
// A test skipped because Chrome could not launch and a test that passed look identical in a
// `go test` summary: both are silent, and the package line says "ok". internal/domexec has ~35
// tests behind one shared browser, so a machine whose Chrome cannot start reported a green package
// that had verified nothing about DOM taint observation at all. That is "we did not look" reading
// as "we looked and found nothing", the one outcome this project's standard forbids
// (bead burpsy-react-ui-chrome-skip-green).
//
// So a browser test skips through Skip/Skipf, which records the test and its reason before
// skipping, and the package's TestMain runs through Main, which fails the package when anything
// was recorded. BURPSY_ALLOW_NO_CHROME=1 accepts a deliberately reduced environment: the package
// then passes, and says on stderr exactly which tests it did not exercise.
//
// TestMain rather than a "final" test that inspects the ledger: Go runs parallel top-level tests
// after every sequential one has returned, so a final test would read the ledger before
// internal/domexec's parallel tests had recorded anything, and a `-run` filter would drop it.
//
// # Why this is a package rather than a helper in each test file
//
// Every package whose tests drive a browser (domexec, blindxss, browser, crawler, scanner, web)
// needs the same rule, and the point is that they cannot drift: one copy that forgot the escape
// hatch, or that skipped without counting, is exactly the hole this closes. It imports nothing
// from internal/ so that internal/domexec's own tests can use it without an import cycle.
package domexectest

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// AllowNoChromeEnv names the escape hatch. Set to "1", a package whose browser tests skipped still
// passes; anything else and it fails. CI never sets it (scripts/ci-install-tools.sh refuses to
// continue without a startable Chrome instead).
const AllowNoChromeEnv = "BURPSY_ALLOW_NO_CHROME"

// ChromeCandidates are the binary names looked up on PATH. They match the names internal/domexec
// launches (its chromeCandidates; a domexec test pins the two lists equal), so "on PATH" here
// means "domexec would find it" and not merely "some binary called chrome exists".
var ChromeCandidates = []string{"chromium", "google-chrome", "google-chrome-stable"}

// ChromeOnPath reports whether a Chrome/Chromium binary domexec would launch is on PATH.
func ChromeOnPath() bool {
	for _, name := range ChromeCandidates {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

var (
	mu    sync.Mutex
	skips []string
)

// Skip records that t is not exercised because the browser capability is missing, then skips it.
// Use it for that reason only; a skip for any other reason (a slow test under -short, say) is not
// a missing capability and must not be counted as one.
func Skip(t testing.TB, reason string) {
	t.Helper()
	mu.Lock()
	skips = append(skips, fmt.Sprintf("%s (%s)", t.Name(), reason))
	mu.Unlock()
	t.Skip(reason + ": this test is NOT exercised in this run (counted; the package fails unless " +
		AllowNoChromeEnv + "=1)")
}

// Skipf is Skip with a formatted reason.
func Skipf(t testing.TB, format string, args ...any) {
	t.Helper()
	Skip(t, fmt.Sprintf(format, args...))
}

// Main runs the package's tests and applies the ledger; a TestMain calls it in place of m.Run and
// passes the result to os.Exit after its own teardown.
func Main(m *testing.M) int {
	return Verdict(m.Run(), os.Getenv(AllowNoChromeEnv) == "1", os.Stderr)
}

// Verdict turns the tests' exit code into the package's: unchanged when nothing was skipped for a
// missing browser, 1 when something was and the escape hatch is not set. Either way a non-empty
// ledger is written to w, so an allowed reduced run still says what it did not exercise.
func Verdict(code int, allowed bool, w io.Writer) int {
	mu.Lock()
	recorded := append([]string(nil), skips...)
	mu.Unlock()
	if len(recorded) == 0 {
		return code
	}
	list := "  - " + strings.Join(recorded, "\n  - ")
	if allowed {
		fmt.Fprintf(w, "BROWSER CAPABILITY UNVERIFIED (allowed by %s=1): %d test(s) did not run for want of a "+
			"browser, so this package verified nothing about them:\n%s\n", AllowNoChromeEnv, len(recorded), list)
		return code
	}
	fmt.Fprintf(w, "FAIL: browser capability ledger: %d test(s) skipped because no browser could be launched, "+
		"so this package would report green having verified nothing about them:\n%s\n"+
		"Install Chrome/Chromium (one of %s on PATH) and make sure it starts, or set %s=1 to accept "+
		"a run that does not exercise them.\n", len(recorded), list, strings.Join(ChromeCandidates, ", "), AllowNoChromeEnv)
	return 1
}

// reset empties the ledger; the package's own tests use it.
func reset() {
	mu.Lock()
	skips = nil
	mu.Unlock()
}
