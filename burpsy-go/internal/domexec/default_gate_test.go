package domexec

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
)

func TestTheDefaultGateCoversUngatedNavigations(t *testing.T) {
	b, err := NewBrowser(context.Background(), Options{Timeout: 30 * time.Second})
	if err != nil {
		domexectest.Skipf(t, "no browser could be launched: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	var outsideHits atomic.Int32
	outside, _ := countingServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { outsideHits.Add(1) }))
	inside, insideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<script src="%s/x.js"></script><img src="%[1]s/p.gif">`, outside.URL)
	}))
	b.SetDefaultGate(gateFor(t, inside.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = b.ObserveTaint(ctx, inside.URL+"/#x", SourceLocationHash, "x")
	_, _ = b.ObserveTaint(ctx, outside.URL+"/#x", SourceLocationHash, "x")
	if insideAccepts.Load() == 0 {
		t.Fatal("the in-scope page was never loaded")
	}
	if n := outsideHits.Load(); n != 0 {
		t.Fatalf("out-of-scope host got %d request(s)", n)
	}
}
