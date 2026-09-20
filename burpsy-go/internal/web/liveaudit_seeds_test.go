package web

// The live passive crawl's seed path (burpsy-react-ui-tqug): the sweep's admitted, in-scope,
// wire-observed URLs seed a crawl, so a page a user browses is not only audited — its origin
// becomes crawlable without the operator retyping it. What these tests pin:
//
//   - the collector: an admitted exchange's URL joins the set once, in first-seen order, query
//     stripped, default ports spelled off — a seed is an origin to walk, not an exact request
//     to replay;
//   - the consumer: a crawl started with include_live_seen unions the held set into its
//     seeds, and TAKES it — a second crawl finds nothing held and says so rather than
//     silently re-walking the same harvest;
//   - the honest refusals: include_live_seen with nothing held AND no seeds is refused with
//     the reason; without include_live_seen nothing is taken;
//   - the count rides the reply (live_seen_used), so an operator knows how much of the seed
//     list came from the wire rather than their typing;
//   - the pane's view reports the held count.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestNoteLiveURLDedupesAndNormalizes(t *testing.T) {
	la := NewLiveAuditState()
	if !la.NoteLiveURL("http://app.test:80/search?q=1") {
		t.Fatal("the first note was not new")
	}
	if la.NoteLiveURL("http://app.test/search?q=other") {
		t.Fatal("the same origin (query stripped) was noted twice — the seed set would re-walk one origin")
	}
	if !la.NoteLiveURL("https://app.test/admin") {
		t.Fatal("a different origin was refused")
	}
	urls, n := la.TakeLiveSeenURLs()
	if n != 2 || len(urls) != 2 {
		t.Fatalf("took %d URLs, want 2", n)
	}
	if urls[0] != "http://app.test/search" || urls[1] != "https://app.test/admin" {
		t.Errorf("URLs = %v, want the query stripped and the default port spelled off", urls)
	}
	if got := la.LiveSeenCount(); got != 0 {
		t.Errorf("after taking, the set holds %d, want 0 — a consumed harvest must not linger", got)
	}
}

func TestTheSweepCollectsAdmittedExchangesURLs(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := targetHostPort(t, target.URL)
	s := auditableServer(t, target.URL)
	seededSourceExchange(t, s, host, port, "/browsed-page", core.SourceProxy)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.LiveSeenCount() == 0 {
		time.Sleep(sweepTick)
	}
	if got := s.liveAudit.LiveSeenCount(); got == 0 {
		t.Fatal("the sweep never collected the admitted exchange's URL — the live passive crawl has no seed to offer")
	}
	view := s.liveAuditStatus()
	if view.LiveSeenHeld == 0 {
		t.Error("the view hides the held count")
	}
}

func TestACrawlFromLiveSeenUnionsTakesAndRefusesEmpty(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s := auditableServer(t, target.URL)

	// Nothing held, nothing named: the honest refusal.
	rec := postJSON(t, s, "/api/crawl", map[string]any{"include_live_seen": true})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("include_live_seen with nothing held = %d, want 400 naming what is missing: %s", rec.Code, rec.Body.String())
	}

	// Seed the collector by hand (the sweep's own collection is pinned above) and crawl from it.
	s.liveAudit.NoteLiveURL(target.URL + "/from-live")
	rec = postJSON(t, s, "/api/crawl", map[string]any{"include_live_seen": true, "max_requests": 2})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("crawl from live = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Seeds        []string `json:"seeds"`
		LiveSeenUsed int      `json:"live_seen_used"`
	}
	if err := decodeJSONT(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.LiveSeenUsed != 1 {
		t.Errorf("live_seen_used = %d, want 1 — the operator must know how much of the seed list came from the wire", out.LiveSeenUsed)
	}
	found := false
	for _, sd := range out.Seeds {
		if sd == target.URL+"/from-live" {
			found = true
		}
	}
	if !found {
		t.Errorf("seeds = %v, want the live URL among them", out.Seeds)
	}
	// The take consumed: a second include_live_seen crawl refuses with nothing held.
	rec2 := postJSON(t, s, "/api/crawl", map[string]any{"include_live_seen": true})
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("a second crawl re-walked the consumed harvest instead of refusing: %d", rec2.Code)
	}
}

func TestWithoutTheFlagNothingIsTaken(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s := auditableServer(t, target.URL)
	s.liveAudit.NoteLiveURL(target.URL + "/held")

	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{target.URL + "/own"}, "max_requests": 1})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("plain crawl = %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.liveAudit.LiveSeenCount(); got != 1 {
		t.Fatalf("a plain crawl took the live set (held=%d, want 1) — only include_live_seen consumes it", got)
	}
}

func decodeJSONT(b []byte, v any) error {
	return decodeJSON(b, v)
}
