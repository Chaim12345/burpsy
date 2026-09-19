package web

// The live sweep's per-source gate (burpsy-react-ui-zk35) — Burp's scope source choice
// ("Proxy" / "Everything", Zhwl :1606-1607). What these tests pin:
//
//   - the default is Proxy: crawler captures are refused while the operator never chose —
//     a sweep that audited the crawler's own traffic by default would audit its own
//     feedback loop;
//   - "everything" admits crawler captures; the choice survives a round-trip on the wire;
//   - the refusal is COUNTED per the sweep's own discipline: an in-scope exchange the gate
//     skipped is a floor on coverage with its own reason, not a silent gap;
//   - an unknown source value is refused at the door — a typo must not widen the gate;
//   - the probe traffic the sweep ITSELF produces is never re-admitted under "proxy"
//     (SourceScanner != SourceProxy), which is the loop Burp's choice exists to prevent.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// seededSourceExchange stores one completed in-scope exchange attributed to a source.
func seededSourceExchange(t *testing.T, s *Server, host string, port uint16, path string, src core.Source) core.ExchangeID {
	t.Helper()
	raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: &respID,
		Host: host, Port: port, Method: "GET", Path: path,
		Source: src,
	})
	return core.ExchangeID(len(s.store.Exchanges())) - 1
}

func TestTheDefaultIsProxyAndCrawlerCapturesAreRefused(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := targetHostPort(t, target.URL)
	s := auditableServer(t, target.URL)

	seededSourceExchange(t, s, host, port, "/from-crawler", core.SourceCrawl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	// The crawler capture is refused by the source gate and counted. Nothing else in this
	// fixture can produce a sweep target hit from the crawl exchange.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.RefusedSource() == 0 {
		time.Sleep(sweepTick)
	}
	if s.liveAudit.RefusedSource() == 0 {
		t.Fatal("a crawler capture was never refused by the source gate — the default is not Proxy, and the sweep is auditing the crawler's own traffic")
	}
	view := s.liveAuditStatus()
	if view.TrafficSource != "proxy" {
		t.Fatalf("the view reports traffic_source=%q for an unset choice; the default is proxy and must be a stated answer, not an absence", view.TrafficSource)
	}
	if view.RefusedSource == 0 {
		t.Error("the view hides the source refusals")
	}
}

func TestEverythingAdmitsCrawlerCaptures(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := targetHostPort(t, target.URL)
	s := auditableServer(t, target.URL)

	id := seededSourceExchange(t, s, host, port, "/from-crawler", core.SourceCrawl)

	// Choose everything over the API, the door the operator uses.
	rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": true, "traffic_source": "everything"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST traffic_source=everything: %d", rec.Code)
	}
	// The choice round-trips.
	view := s.liveAuditStatus()
	if view.TrafficSource != "everything" {
		t.Fatalf("traffic_source = %q after the POST, want everything", view.TrafficSource)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	// The crawler capture is audited: the sweep reaches the target through the seeded
	// crawl exchange, and nothing was refused.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Swept() == 0 {
		time.Sleep(sweepTick)
	}
	_ = id
	if s.liveAudit.Swept() == 0 {
		t.Fatal("the crawler capture was not swept under the everything choice — the gate refused it anyway")
	}
	if s.liveAudit.RefusedSource() != 0 {
		t.Errorf("refused_source = %d with everything chosen; the gate must admit every in-scope source", s.liveAudit.RefusedSource())
	}
}

func TestAnUnknownSourceValueIsRefusedNotWidened(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false, "traffic_source": "evrything"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a typo'd traffic_source = %d, want 400 — a typo must not silently widen the gate", rec.Code)
	}
	if got := s.liveAudit.TrafficSource(); got != LiveAuditSourceProxy {
		t.Fatalf("the refused call changed the choice to %q", got)
	}
}

func TestTheSweepsOwnProbeTrafficIsNotAdmittedUnderProxy(t *testing.T) {
	// The unit-level claim: SourceScanner exchanges are refused under the default, which is
	// the loop Burp's "Proxy" choice exists to prevent — the sweep's own probes would
	// otherwise be audited by the sweep. The exchange must be in scope so the refusal is the
	// SOURCE gate's, not scope's.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := targetHostPort(t, target.URL)
	s := auditableServer(t, target.URL)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nprobe-ok"), core.DirectionResponse)
	ex := &core.Exchange{
		Host: host, Port: port, Path: "/probe", Method: "GET", Response: &respID,
		Source: core.SourceScanner,
	}
	before := s.liveAudit.RefusedSource()
	if s.liveAuditAdmits(ex) {
		t.Fatal("a SourceScanner exchange was admitted under the proxy choice — the sweep would audit its own probes")
	}
	if s.liveAudit.RefusedSource() != before+1 {
		t.Fatal("the source refusal was not counted — an in-scope refusal the pane cannot see is a silent gap")
	}
}
