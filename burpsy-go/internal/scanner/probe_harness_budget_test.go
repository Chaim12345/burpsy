package scanner

// The native probe path must bound each probe with ScanConfig.ProbeTimeout — the same per-probe
// clock bcheck_runner.go's sendProbe applies on the BCheck path. Before this, ProbeHarness.sendVia
// handed the dispatch context straight to the gate, so one probe against a target that accepts the
// request and never answers rode the WHOLE audit item deadline. The live shape: an `&echo …`
// command-injection payload leaves VulnerableApp's shell waiting on a stdout that never closes, and
// auditing that exchange hung for the full 120 s budget — the benchmark auditing it blocked on the
// case every run, and an operator's audit looked like a hang with no progress to observe.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// hangOnCanary answers the baseline normally but blocks on the probe payload until the test ends —
// a target that behaves until it is injected into, which is what the app does: `?id=1` answers, and
// an `&echo …` payload leaves its shell waiting on a stdout that never closes.
func hangOnCanary(t *testing.T, canary string) http.HandlerFunc {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, canary) {
			w.Write([]byte("ok"))
			return
		}
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}
}

func TestANativeProbeIsBoundedByItsOwnClockNotTheWholeAuditBudget(t *testing.T) {
	const canary = "zgqcanary"
	cc := harnessAgainst(t, hangOnCanary(t, canary), "/hang?q=seed")
	// A 300ms per-probe clock, an audit context with no deadline of its own: the ONLY thing that can
	// end the probe is the per-probe budget, which is exactly the contract being pinned.
	cc.Scanner.UpdateScanConfig(func(c *ScanConfig) { c.ProbeTimeout = 300 * time.Millisecond })

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	point := h.Points()[0]

	type result struct{ err error }
	ch := make(chan result, 1)
	start := time.Now()
	go func() {
		_, err := h.Send(context.Background(), point, canary)
		ch <- result{err}
	}()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("a native probe against a never-answering target did not return within 10s under a " +
			"300ms ProbeTimeout: the per-probe clock is not reaching the native send path, so one " +
			"wedged probe hangs the whole audit for its entire budget")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the probe returned after %v, nowhere near its 300ms clock", elapsed)
	}
}
