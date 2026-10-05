package scanner

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

// A session with MaxConcurrency well above MaxItemsInProgress must still never have more items
// past the admission gate than the cap allows, at any instant during the run. Six distinct URLs
// (so each captures its own per-URL dispatch unit rather than collapsing into AlreadyCovered) give
// six workers something real to contend over; a slow target holds each item in the Auditing state
// long enough for the overlap to be observable rather than accidental.
func Test_a_session_with_a_cap_of_two_never_holds_more_than_two_items_past_admission(t *testing.T) {
	var inFlight, maxObserved atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			cur := maxObserved.Load()
			if n <= cur || maxObserved.CompareAndSwap(cur, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>nothing interesting</html>")
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse target port: %v", err)
	}

	const items = 6
	store := core.NewTrafficStore()
	ids := make([]core.ExchangeID, items)
	for i := range ids {
		ids[i] = seedAuditExchange(t, store, host, port, fmt.Sprintf("/item%d?id=1", i), "<html></html>")
	}
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil)).WithConfig(&ScanConfig{
		MaxConcurrency: items,
		Timeout:        5 * time.Second,
		CheckSqli:      true,
	})

	cfg := DefaultAuditConfig()
	cfg.MaxItemsInProgress = SomeUint32(2)
	session, _ := scan.AuditSession(context.Background(), ids, cfg)

	if got := int(maxObserved.Load()); got > 2 {
		t.Errorf("observed %d requests in flight at once, want at most the cap of 2", got)
	}
	if got := int(maxObserved.Load()); got < 2 {
		t.Errorf("observed only %d requests in flight at once, want the cap actually reached (2), or this test proves nothing about the gate", got)
	}
	ran := 0
	for _, item := range session.Items {
		ran += item.Outcome.Ran
	}
	if ran != items {
		t.Errorf("dispatched %d of %d distinct URLs, want all %d admitted (none collapsed or refused)", ran, items, items)
	}
}
