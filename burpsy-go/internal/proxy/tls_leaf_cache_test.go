package proxy

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
)

// cachedLeafCount reports how many CA-signed leaves the engine holds. Tests use
// it instead of reaching into the cache, so the cache representation can change
// (sync.Map -> bounded LRU, burpsy-react-ui-iyew) without the assertions moving.
func cachedLeafCount(e *TlsEngine) int {
	e.poolMu.Lock()
	defer e.poolMu.Unlock()
	return e.certPool.Len()
}

// The pool held one leaf per host FOREVER: a long session crawling thousands of
// vhosts grew it without limit, one RSA keypair per hostname an SNI scan cares to
// invent (burpsy-react-ui-iyew). The bound is an LRU: eviction costs a re-mint on
// the next visit, nothing more.
func TestTheLeafCacheIsBounded(t *testing.T) {
	old := leafCacheBound
	leafCacheBound = 16
	defer func() { leafCacheBound = old }()

	engine := newEngine(t, "bounded CA")
	for i := 0; i < 24; i++ {
		if _, err := engine.GetCertificate(fmt.Sprintf("h%02d.test", i)); err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
	}
	if n := cachedLeafCount(engine); n > leafCacheBound {
		t.Errorf("%d cached leaves, want at most the %d bound — the pool is unbounded", n, leafCacheBound)
	}
	// Eviction is LRU: the oldest entries leave, the newest stay.
	engine.poolMu.Lock()
	keys := engine.certPool.Keys()
	engine.poolMu.Unlock()
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	if seen["h00.test"] {
		t.Error("h00.test survived; the oldest leaf should have been evicted first")
	}
	if !seen["h23.test"] {
		t.Error("h23.test missing; the newest leaf should still be cached")
	}
}

// The same bound applies to the self-signed pool (burpsy-react-ui-4trc separated
// it from the CA-signed one; iyew bounds both): a listener in CertModeSelfSigned
// is just as reachable by a hostname scan.
func TestTheSelfSignedCacheIsBounded(t *testing.T) {
	old := leafCacheBound
	leafCacheBound = 16
	defer func() { leafCacheBound = old }()

	engine := newEngine(t, "bounded CA")
	for i := 0; i < 24; i++ {
		if _, err := engine.selfSignedCertificate(fmt.Sprintf("s%02d.test", i)); err != nil {
			t.Fatalf("selfSignedCertificate: %v", err)
		}
	}
	engine.poolMu.Lock()
	n := engine.selfSigned.Len()
	engine.poolMu.Unlock()
	if n > leafCacheBound {
		t.Errorf("%d cached self-signed leaves, want at most %d", n, leafCacheBound)
	}
}

// Concurrent first visits to the SAME host must share one mint: N goroutines, one
// keypair, one cache entry — and every caller gets the identical certificate.
func TestConcurrentMissesForOneHostMintOneLeaf(t *testing.T) {
	engine := newEngine(t, "shared CA")
	const callers = 8
	certs := make([]*tls.Certificate, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := engine.GetCertificate("same.test")
			if err != nil {
				t.Errorf("GetCertificate: %v", err)
				return
			}
			certs[i] = c
		}(i)
	}
	wg.Wait()
	for i := 1; i < callers; i++ {
		if certs[i] == nil || certs[0] == nil || certs[i] != certs[0] {
			t.Fatalf("caller %d got a different certificate; concurrent misses minted more than one leaf", i)
		}
	}
	if n := cachedLeafCount(engine); n != 1 {
		t.Errorf("%d cached leaves for one host, want 1", n)
	}
}
