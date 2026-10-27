package domexectest

import (
	"bytes"
	"strings"
	"testing"
)

func TestAnEmptyLedgerLeavesTheExitCodeAlone(t *testing.T) {
	reset()
	var out bytes.Buffer
	for _, code := range []int{0, 1, 2} {
		for _, allowed := range []bool{false, true} {
			if got := Verdict(code, allowed, &out); got != code {
				t.Errorf("Verdict(%d, allowed=%v) with nothing skipped = %d, want %d", code, allowed, got, code)
			}
		}
	}
	if out.Len() != 0 {
		t.Errorf("an empty ledger wrote %q; it has nothing to report", out.String())
	}
}

func TestACountedSkipFailsThePackageUnlessAllowed(t *testing.T) {
	reset()
	t.Cleanup(reset)
	t.Run("needs a browser", func(t *testing.T) {
		Skipf(t, "no browser: %s", "launch failed")
	})

	var out bytes.Buffer
	if got := Verdict(0, false, &out); got != 1 {
		t.Fatalf("a recorded browser skip with the escape hatch unset left the package at exit %d; it must fail", got)
	}
	for _, want := range []string{"needs_a_browser", "no browser: launch failed", AllowNoChromeEnv + "=1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the failure does not name %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if got := Verdict(0, true, &out); got != 0 {
		t.Errorf("with %s=1 a reduced run must pass; got exit %d", AllowNoChromeEnv, got)
	}
	if !strings.Contains(out.String(), "UNVERIFIED") || !strings.Contains(out.String(), "needs_a_browser") {
		t.Errorf("an allowed reduced run must still say what it did not exercise:\n%s", out.String())
	}
	// Allowing a missing browser never turns a real failure green.
	if got := Verdict(1, true, &out); got != 1 {
		t.Errorf("Verdict(1, allowed) = %d; the escape hatch must not mask a failing test", got)
	}
}
