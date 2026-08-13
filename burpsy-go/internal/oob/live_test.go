//go:build oob_live

// This test talks to the real public Interactsh OAST pool and needs both the
// interactsh-client binary and outbound network access. It is behind the oob_live build
// tag so it never runs in the default gate: a scanner test suite whose result depends on
// a third-party service being reachable is a flaky suite, and a flaky gate is worse than
// an uncovered one because it trains people to ignore red.
//
// Run it deliberately:
//
//	go test -tags oob_live ./internal/oob/... -count=1 -v
package oob

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestARealDNSPingbackRoundTripsThroughThePublicOASTPool(t *testing.T) {
	c, err := NewClient(context.Background(), Options{Timeout: 45 * time.Second})
	if err != nil {
		t.Fatalf("could not register against the public pool: %v", err)
	}
	defer func() { _ = c.Close() }()

	domain := c.Domain()
	if domain == "" {
		t.Fatal("registered but no payload domain was announced")
	}
	t.Logf("registered payload domain: %s", domain)

	// Resolving the domain IS the pingback: the interaction server is authoritative for
	// it, so the lookup itself is recorded. A failed lookup is not fatal here — some
	// resolvers refuse to answer, but the query still reached the authoritative server,
	// which is what we are waiting to observe.
	if _, err := net.LookupHost(domain); err != nil {
		t.Logf("lookup returned %v; the query may still have reached the authoritative server", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.Interactions()
		if err != nil {
			t.Fatalf("polling interactions failed: %v", err)
		}
		for _, in := range got {
			if in.Protocol == "dns" {
				t.Logf("observed %d raw interactions, %d after dedupe; first dns from resolver %s",
					len(got), len(Deduplicate(got)), in.RemoteAddress)
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no dns interaction arrived for %s within 30s", domain)
}
