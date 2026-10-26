package scanner

// Auto-backoff after 429/503 (burpsy-react-ui-fkl8) — Burp's resource-pool auto_backoff in
// the smallest honest shape: observe the status once in the shared probe path, wait a
// configured beat before the next step, count the waits in the outcome. What these tests pin:
//
//   - the observation: rateLimited marks the meter, the last status wins, the nil meter is safe;
//   - the wait: the dispatch loop delays when the meter is marked and a positive backoff is
//     configured; set-and-zero is the real off and waits nothing;
//   - the counter: the outcome's RateLimited names the waits so the summary can say the audit
//     was throttled;
//   - the wire: the config's unset / set-zero / set-custom states stay distinct.
import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// rateLimitedSeed builds a scanner over a store holding one exchange whose target answers
// the given statuses in order, cycling.
func rateLimitedSeed(t *testing.T, statuses ...int) (*ActiveScanner, core.ExchangeID, AuditConfig, func()) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&hits, 1)
		w.WriteHeader(statuses[int(n-1)%len(statuses)])
		_, _ = w.Write([]byte("ok"))
	}))
	store := core.NewTrafficStore()
	h, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}
	host := h
	snd := sender.NewSender(nil)
	id := seedAuditExchange(t, store, host, port, "/limited?id=1", "<html></html>")
	// Two checks, two steps: the backoff waits before the SECOND step after the first
	// step's probes saw 429, so the audit must be observably slower with it on.
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(snd).WithConfig(&ScanConfig{
		MaxConcurrency:     1,
		CheckSqli:          true,
		CheckPathTraversal: true,
	})
	return scan, id, DefaultAuditConfig(), srv.Close
}

func TestRateLimitedMarksTheMeterAndTheLastStatusWins(t *testing.T) {
	m := &probeMeter{}
	m.rateLimited(429)
	if m.rateLimitedCount.Load() != 1 || m.limitedStatus.Load() != 429 {
		t.Fatal("control: rateLimited(429) did not mark the meter")
	}
	m.rateLimited(503)
	if m.limitedStatus.Load() != 503 {
		t.Errorf("the last status wins: got %d, want 503", m.limitedStatus.Load())
	}
	var nilMeter *probeMeter
	nilMeter.rateLimited(429) // nil-safe: a check outside an audit has no meter
}

func TestSetAndZeroDisablesTheBackoffWait(t *testing.T) {
	scan, id, cfg, done := rateLimitedSeed(t, 429)
	defer done()
	cfg.AutoBackoffMs = SomeUint32(0)
	start := time.Now()
	_, _ = scan.AuditWithin(context.Background(), id, cfg)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("a set-and-zero backoff still waited %v — zero is the real off, not a spelling of unset", elapsed)
	}
}

func TestAPositiveBackoffDelaysTheNextStep(t *testing.T) {
	scan, id, cfg, done := rateLimitedSeed(t, 429)
	defer done()
	cfg.AutoBackoffMs = SomeUint32(300)
	start := time.Now()
	_, _ = scan.AuditWithin(context.Background(), id, cfg)
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Fatalf("the 300ms backoff did not delay the audit (elapsed %v) — a rate-limiting target keeps getting hit at full pace, the exact defect", elapsed)
	}
}

func TestTheOutcomeCountsTheBackoffWaitsAndTheSummaryNamesIt(t *testing.T) {
	scan, id, cfg, done := rateLimitedSeed(t, 429)
	defer done()
	cfg.AutoBackoffMs = SomeUint32(1) // fast: the test measures counting, not waiting
	out, _ := scan.AuditWithin(context.Background(), id, cfg)
	if out.RateLimited == 0 {
		t.Fatal("the outcome's RateLimited is 0 although the target answered 429 — the summary cannot say the audit was throttled")
	}
	if !strings.Contains(out.Summary(), "rate limiting") {
		t.Errorf("summary = %q, want it to name the rate limiting", out.Summary())
	}
}

func TestTheBackoffConfigStatesStayDistinct(t *testing.T) {
	unset := AuditConfig{}
	if unset.AutoBackoffMs.Set {
		t.Fatal("an unset config must not read as set")
	}
	off := AuditConfig{}
	off.AutoBackoffMs = SomeUint32(0)
	if !off.AutoBackoffMs.Set || off.AutoBackoffMs.Value != 0 {
		t.Fatal("set-and-zero lost its zero — the only spelling that turns the backoff off")
	}
	custom := AuditConfig{}
	custom.AutoBackoffMs = SomeUint32(500)
	if custom.AutoBackoffMs.Value != 500 {
		t.Fatal("a custom backoff lost its value")
	}
}

func TestA503ThroughTheHarnessPathIsAlsoObserved(t *testing.T) {
	// The injection families send through ProbeHarness.send, not sendTestRequestFull — the
	// mutation that dropped 503 from that path survived the first test set, which only ever
	// drove 429. A 503 is the other half of the rule and must not slip past either path.
	scan, id, cfg, done := rateLimitedSeed(t, 503)
	defer done()
	cfg.AutoBackoffMs = SomeUint32(1)
	out, _ := scan.AuditWithin(context.Background(), id, cfg)
	if out.RateLimited == 0 {
		t.Fatal("a 503 through the probe-harness path was not observed — the rule must hold on every send path, not just the one the first tests happened to drive")
	}
}

func TestAnUnsetConfigInheritsTheDefaultBackoffWait(t *testing.T) {
	// The unset-default resolution survived the first mutation set too: every wait test set
	// the key explicitly. An unset config must wait the engine default (2s), which the
	// set-and-zero test can measure against: the unset audit takes at least the default,
	// the zero audit far less.
	scan, id, cfg, done := rateLimitedSeed(t, 429)
	defer done()
	start := time.Now()
	_, _ = scan.AuditWithin(context.Background(), id, cfg) // cfg untouched: unset
	if elapsed := time.Since(start); elapsed < time.Duration(DefaultAutoBackoffMs)*time.Millisecond {
		t.Fatalf("an unset config waited only %v, want the inherited default of %dms — unset must not read as zero",
			elapsed, DefaultAutoBackoffMs)
	}
}

// rateLimitedSeedWide is rateLimitedSeed with a wide active set, so the plan has more steps
// than the per-item backoff cap - the shape the cap test needs.
func rateLimitedSeedWide(t *testing.T, statuses ...int) (*ActiveScanner, core.ExchangeID, AuditConfig, func()) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&hits, 1)
		w.WriteHeader(statuses[int(n-1)%len(statuses)])
		_, _ = w.Write([]byte("ok"))
	}))
	store := core.NewTrafficStore()
	h, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}
	snd := sender.NewSender(nil)
	id := seedAuditExchange(t, store, h, port, "/limited?id=1", "<html></html>")
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(snd).WithConfig(&ScanConfig{
		MaxConcurrency:        1,
		CheckSqli:             true,
		CheckPathTraversal:    true,
		CheckSSRF:             true,
		CheckActiveInjection:  true,
		CheckReflectionProbes: true,
		CheckCachePoisoning:   true,
		CheckHeaders:          true,
	})
	return scan, id, DefaultAuditConfig(), srv.Close
}

func TestAutoBackoffPaymentsAreCappedPerItem(t *testing.T) {
	// fkl8-c: a target that keeps 429ing must not be paid a courtesy wait per step for the
	// whole plan. The consecutive-limited breaker bounds the uniformly-throttled item, but a
	// meter that flaps - a per-key cap that answers some probe shapes 200 - never reaches it,
	// and unbounded beats turned one vulnapp login-form row into 90s of waiting that produced
	// no evidence. The plan here outlives the cap, so the wait count must stop at it.
	scan, id, cfg, done := rateLimitedSeedWide(t, 429)
	defer done()
	cfg.AutoBackoffMs = SomeUint32(1) // count the waits, do not pay for them
	out, _ := scan.AuditWithin(context.Background(), id, cfg)
	if out.RateLimited == 0 {
		t.Fatal("no backoff waits counted at all - the courtesy beat itself regressed")
	}
	if out.RateLimited > MaxItemAutoBackoffWaits {
		t.Fatalf("one item paid %d backoff waits, want at most %d - the per-item cap did not hold", out.RateLimited, MaxItemAutoBackoffWaits)
	}
	t.Logf("waits paid: %d (cap %d)", out.RateLimited, MaxItemAutoBackoffWaits)
}
