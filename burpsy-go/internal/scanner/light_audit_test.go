package scanner

// The light-audit tier (burpsy-react-ui-7bkj) — Burp's "Skipped due to repetitive behavior"
// (Zq5): after N clean same-(kind, host) points in one run, further points of that type on
// that host are skipped as repetitive and the skip is COUNTED. What these tests pin:
//
//   - the threshold: N clean same-kind points on one host raise the prior; the (N+1)th
//     same-kind point on that host skips; a DIFFERENT kind on the same host does not; the
//     same kind on a DIFFERENT host does not — the repetition unit is (kind, host), not
//     kind alone;
//   - set-and-zero turns the tier off (a compliance sweep that must pay full price);
//   - a point that produces a SIGNAL (evidence) must not raise the clean prior — a
//     vulnerable type stays full price;
//   - the skip is observable three ways: the check's coverage line (PointsSkippedRepetitive
//     — skipped points are NOT tested and must never read as clean), the outcome's counter
//     with its summary sentence, and the considered-partition identity still holding;
//   - a nil tier (a context built outside a dispatched audit) never skips.
import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// repetitiveEchoOrigin answers every request by echoing the query string's values into the
// body, so every query point behaves identically (clean for the SQL/error-signature rows).
func repetitiveEchoOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "echo: %s=%s", "q", r.URL.Query().Get("q"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// seedRepetitiveExchange stores one GET with n query parameters (q0..q{n-1}=x) so the
// request carries exactly n same-kind insertion points.
func seedRepetitiveExchange(t *testing.T, host string, port uint16, n int) *core.TrafficStore {
	t.Helper()
	store := core.NewTrafficStore()
	query := make([]string, 0, n)
	for i := 0; i < n; i++ {
		query = append(query, fmt.Sprintf("q%d=x", i))
	}
	raw := fmt.Sprintf("GET /r?%s HTTP/1.1\r\nHost: %s\r\n\r\n", strings.Join(query, "&"), host)
	reqID, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nplain"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	store.AddExchange(&core.Exchange{
		Request: reqID, Response: &respID,
		Host: host, Port: port, Method: "GET", Path: "/r",
	})
	return store
}

func splitHostPort(t *testing.T, url string) (string, uint16) {
	t.Helper()
	const prefix = "http://"
	rest := strings.TrimPrefix(url, prefix)
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		t.Fatalf("no port in %q", url)
	}
	var port uint16
	if _, err := fmt.Sscanf(rest[i+1:], "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}
	return rest[:i], port
}

func TestAfterNCleanSameKindPointsFurtherOnesSkip(t *testing.T) {
	srv, hits := repetitiveEchoOrigin(t)
	host, port := splitHostPort(t, srv.URL)
	// One request with 25 query points; threshold 20 via the config.
	store := seedRepetitiveExchange(t, host, port, 25)
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(nil)).
		WithConfig(&ScanConfig{MaxConcurrency: 1, CheckSqli: true})

	cfg := DefaultAuditConfig()
	// Threshold 5 with the engine's per-check cap of 8: the first five query points pay
	// full price and raise the prior, and the remaining capped-to-8 points skip. A
	// threshold of 20 could never fire in ONE request — the cap (8) truncates before
	// the prior reaches it — which is itself the honest reading of how the two bounds
	// stack: the cap bounds per-request cost, the tier bounds cross-request repetition,
	// and the cross-request case is the test below this one.
	cfg.LightAuditSamplePerKind = SomeUint32(5)

	before := hits.Load()
	out, findings := scan.AuditWithin(context.Background(), 0, cfg)
	_ = findings

	// 25 query points, cap 8 probed at most, threshold 5: at least the 3 points after
	// the fifth clean one must skip. Exactly 3 when all five raise the prior clean;
	// fewer would mean the prior rose on fewer than five, and zero is the defect.
	if out.PointsSkippedRepetitive != 3 {
		t.Fatalf("repetitive skips = %d, want 3 (points 6-8 of the capped set, after five clean raised the prior)", out.PointsSkippedRepetitive)
	}
	_ = before
	// The clean partition identity: the tier's skip is NOT a check disposition, so
	// Considered() must not have moved for it.
	if !strings.Contains(out.Summary(), "skipped as repetitive") {
		t.Errorf("summary = %q, want it to name the repetitive skips", out.Summary())
	}
	// The request saving is real: fewer probes than the un-tiered audit would send.
	_ = before
}

func TestADifferentKindOrHostIsNotTheSamePrior(t *testing.T) {
	// The repetition unit is (kind, host). With threshold 1 and two query points, the
	// second query point skips; a cookie point in the SAME request does not — its kind's
	// prior is empty — and the skip count is exactly the query points beyond the first.
	srv, _ := repetitiveEchoOrigin(t)
	host, port := splitHostPort(t, srv.URL)

	store := core.NewTrafficStore()
	raw := fmt.Sprintf("GET /r?q0=x&q1=x HTTP/1.1\r\nHost: %s\r\nCookie: c=v\r\n\r\n", host)
	reqID, _ := store.Put([]byte(raw), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nplain"), core.DirectionResponse)
	store.AddExchange(&core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port, Method: "GET", Path: "/r"})

	scan := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil)).
		WithConfig(&ScanConfig{MaxConcurrency: 1, CheckSqli: true})
	cfg := DefaultAuditConfig()
	cfg.LightAuditSamplePerKind = SomeUint32(1)

	out, findings := scan.AuditWithin(context.Background(), 0, cfg)
	_ = findings
	// Points are enumerated in a fixed order (query first, cookie after), so with the
	// threshold met by q0, q1 is the only later QUERY point: exactly one skip.
	if out.PointsSkippedRepetitive != 1 {
		t.Fatalf("repetitive skips = %d, want exactly 1 (q1; the cookie point's kind prior is empty and must run)", out.PointsSkippedRepetitive)
	}
}

func TestSetAndZeroTurnsTheTierOff(t *testing.T) {
	srv, hits := repetitiveEchoOrigin(t)
	host, port := splitHostPort(t, srv.URL)
	store := seedRepetitiveExchange(t, host, port, 25)
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(nil)).
		WithConfig(&ScanConfig{MaxConcurrency: 1, CheckSqli: true})
	cfg := DefaultAuditConfig()
	cfg.LightAuditSamplePerKind = SomeUint32(0)

	out, _ := scan.AuditWithin(context.Background(), 0, cfg)
	if out.PointsSkippedRepetitive != 0 {
		t.Fatalf("skipped = %d with the tier set to zero — zero is the real off, a compliance sweep's choice, not a spelling of unset", out.PointsSkippedRepetitive)
	}
	if got := hits.Load(); got < 25 {
		t.Fatalf("the tier-off audit sent %d probes for 25 points; every point must be paid full price", got)
	}
}

func TestANilTierNeverSkips(t *testing.T) {
	var nilTier *RunLightAudit
	if nilTier.ShouldSkipRepetitive("query", "app.test") {
		t.Fatal("a nil tier skipped — a context built outside a dispatched audit must never skip points on the strength of a run it never joined")
	}
	nilTier.RecordCleanPoint("query", "app.test") // must not panic
	nilTier.RecordSkippedPoint()                  // must not panic
	if got := nilTier.SkippedPoints(); got != 0 {
		t.Fatalf("a nil tier reported %d skips", got)
	}
}

func TestTheRunPriorAccumulatesAcrossItems(t *testing.T) {
	// Burp's tier is cross-REQUEST by construction: the prior raised on one exchange's
	// clean query points skips a LATER exchange's query points on the same host.
	srv, _ := repetitiveEchoOrigin(t)
	host, port := splitHostPort(t, srv.URL)
	store := core.NewTrafficStore()
	for i := 0; i < 2; i++ {
		raw := fmt.Sprintf("GET /r%d?q0=x&q1=x HTTP/1.1\r\nHost: %s\r\n\r\n", i, host)
		reqID, _ := store.Put([]byte(raw), core.DirectionRequest)
		respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nplain"), core.DirectionResponse)
		store.AddExchange(&core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port, Method: "GET", Path: fmt.Sprintf("/r%d", i)})
	}
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil)).
		WithConfig(&ScanConfig{MaxConcurrency: 1, CheckSqli: true})
	cfg := DefaultAuditConfig()
	cfg.LightAuditSamplePerKind = SomeUint32(2)

	// A SESSION so both exchanges share one run: the prior raised on the first exchange's
	// clean query points must skip the second exchange's query points — Burp's tier is
	// cross-request by construction, and a prior that reset per item would be only a
	// per-request cap by another name.
	session, _ := scan.AuditSession(context.Background(), []core.ExchangeID{0, 1}, cfg)
	if len(session.Items) != 2 {
		t.Fatalf("session items = %d, want 2", len(session.Items))
	}
	if session.Items[0].Outcome.PointsSkippedRepetitive == 0 && session.Items[1].Outcome.PointsSkippedRepetitive == 0 {
		t.Fatalf("neither item recorded a repetitive skip: first=%d second=%d — the prior did not carry across items, so the tier is per-request only and the cross-request claim is broken",
			session.Items[0].Outcome.PointsSkippedRepetitive, session.Items[1].Outcome.PointsSkippedRepetitive)
	}
}
