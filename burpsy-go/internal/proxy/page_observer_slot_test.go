package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The page observer is attached after the proxy is already relaying traffic, which is how main wires
// the live passive crawl (the web server that owns the observer is built after the proxy starts). The
// slot is handed to WithPageObserver before NewServer, so the relay goroutines never read a config
// field that is written while they run; under -race this test is the proof. Pages relayed before Set
// are not observed, and every page relayed after it is.
func TestPageObserverSlotInstalledWhileServing(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<a href="/next">next</a>`)
	}))
	defer origin.Close()

	var slot PageObserverSlot
	px := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithPageObserver(slot.Observe))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go px.ListenAndServe(ctx, "127.0.0.1:0")
	deadline := time.Now().Add(5 * time.Second)
	for px.ListenerAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.ListenerAddr() == "" {
		t.Fatal("proxy never bound")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: px.ListenerAddr()})}}
	get := func() {
		resp, err := client.Get(origin.URL + "/")
		if err != nil {
			t.Error(err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Traffic in flight on several connections while the observer is installed.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					get()
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)

	var seen atomic.Int64
	slot.Set(func(ex *core.Exchange, response []byte) {
		if len(response) == 0 || ex == nil {
			t.Errorf("observer called with exchange %v and %d response bytes", ex, len(response))
		}
		seen.Add(1)
	})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	// After Set returns, a page relayed from then on reaches the observer. The record happens after the
	// client has its body, so wait for it rather than reading the counter immediately.
	before := seen.Load()
	get()
	deadline = time.Now().Add(5 * time.Second)
	for seen.Load() == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if seen.Load() == before {
		t.Fatalf("a page relayed after Set was not observed (seen=%d)", seen.Load())
	}

	// Detaching stops observation.
	slot.Set(nil)
	time.Sleep(50 * time.Millisecond)
	after := seen.Load()
	get()
	time.Sleep(100 * time.Millisecond)
	if seen.Load() != after {
		t.Errorf("observer still called after Set(nil): %d -> %d", after, seen.Load())
	}
}

// An empty slot observes nothing and does not panic; a detached slot is empty again; and an observer
// installed after a page was offered is not handed that page retroactively (the slot forwards, it
// does not buffer). The zero value is the state main's slot is in until the web server exists.
func TestPageObserverSlotEmpty(t *testing.T) {
	var slot PageObserverSlot
	if fn := slot.fn.Load(); fn != nil {
		t.Fatal("the zero-value slot holds an observer")
	}
	// Panics fail the test on their own; a nil exchange is the hardest input an empty slot can get.
	slot.Observe(&core.Exchange{}, []byte("x"))
	slot.Observe(nil, nil)

	var calls []string
	slot.Set(func(ex *core.Exchange, response []byte) { calls = append(calls, ex.Path+"="+string(response)) })
	if len(calls) != 0 {
		t.Fatalf("installing an observer replayed %d page(s) offered while the slot was empty: %v", len(calls), calls)
	}
	slot.Observe(&core.Exchange{Path: "/a"}, []byte("A"))
	if len(calls) != 1 || calls[0] != "/a=A" {
		t.Fatalf("an installed observer got %v, want exactly the one page offered after Set", calls)
	}

	slot.Set(nil)
	if fn := slot.fn.Load(); fn != nil {
		t.Fatal("Set(nil) left an observer installed")
	}
	slot.Observe(&core.Exchange{Path: "/b"}, []byte("B"))
	if len(calls) != 1 {
		t.Fatalf("a detached slot still forwarded: %v", calls)
	}
}
