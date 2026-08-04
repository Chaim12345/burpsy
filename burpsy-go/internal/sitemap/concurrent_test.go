package sitemap

import (
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Hosts() used to hand back the live *HostNode pointers and release the lock, so a reader walked
// hn.Paths and pn.ExchangeIDs while the store's append path wrote them. That is not a stale read:
// the Go runtime raises `fatal error: concurrent map iteration and map write`, which is not a panic
// and cannot be recovered — the process dies and takes the proxy listener with it.
//
// This test reads the way the real handler does (api_toolkit.go walks Paths, PathsSorted,
// ExchangeIDs, MethodsSorted and StatusesSorted after Hosts() returns) while traffic arrives
// through the observer the store actually calls. Under `-race` it fails on the unsynchronised
// access; without `-race` it fails by killing the test binary outright. Both are the bug.
func TestReadingTheTreeWhileTrafficArrivesIsSafe(t *testing.T) {
	store := core.NewTrafficStore()
	sm := New()
	sm.Follow(store)

	status := uint16(200)
	var wg sync.WaitGroup

	// Writer: the capture path. AddExchange invokes sm.Add under the store's lock.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			store.AddExchange(&core.Exchange{
				Host:   "app.test",
				Port:   443,
				TLS:    true,
				Method: "GET",
				// A fresh path every iteration, so the writer keeps inserting into the same
				// host's Paths map — the map the reader iterates.
				Path:   "/p/" + intToStr(i),
				Status: &status,
			})
		}
	}()

	// Reader: exactly what the site-map handler does with what Hosts() returns.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			for _, hn := range sm.Hosts() {
				_ = len(hn.Paths)
				for _, pn := range hn.PathsSorted() {
					_ = len(pn.ExchangeIDs)
					_ = pn.MethodsSorted()
					_ = pn.StatusesSorted()
				}
				for _, pn := range hn.Paths {
					_ = pn.Path
				}
			}
		}
	}()

	wg.Wait()
}

// A snapshot must not change under the caller after the lock is gone — that is the property that
// makes the unsafe read unwritable rather than merely discouraged.
func TestASnapshotDoesNotChangeWhenMoreTrafficArrives(t *testing.T) {
	store := core.NewTrafficStore()
	sm := New()
	sm.Follow(store)

	store.AddExchange(&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "GET", Path: "/one"})

	before := sm.Hosts()
	if len(before) != 1 || len(before[0].Paths) != 1 {
		t.Fatalf("expected one host with one path, got %d hosts", len(before))
	}

	store.AddExchange(&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/two"})
	store.AddExchange(&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "GET", Path: "/one"})

	if n := len(before[0].Paths); n != 1 {
		t.Errorf("the snapshot grew to %d paths; a caller holding it is reading live state", n)
	}
	if n := len(before[0].Paths["/one"].Methods); n != 1 {
		t.Errorf("the snapshot's method map grew to %d entries; it shares the live map", n)
	}
	if n := len(before[0].Paths["/one"].ExchangeIDs); n != 1 {
		t.Errorf("the snapshot's id slice grew to %d; it shares the live backing array", n)
	}
	// And the map is genuinely current on a fresh read, so the snapshot is not a stale cache.
	if n := len(sm.Hosts()[0].Paths); n != 2 {
		t.Errorf("a fresh read shows %d paths, want 2", n)
	}
}
