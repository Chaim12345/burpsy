package proxy

// The Alt-Svc table (vln3): origins advertise their h3 endpoint on responses burpsy itself
// received, and later forwards to that origin may ride QUIC. The table honors ma= exactly - an
// expired advertisement is the origin saying "stop" - and honors clear, because an origin that
// withdraws the advertisement must not keep getting QUIC dials it asked to stop.

import (
	"testing"
	"time"
)

// An h3 advertisement is learned with its endpoint port and used while its ma= lasts.
func TestAltSvcLearnsAnH3Advertisement(t *testing.T) {
	table := newAltSvcTable()
	now := time.Now()
	table.learn("example.test", 443, `h3=":8443"; ma=3600`, now)

	endpoint, ok := table.h3Endpoint("example.test", 443, now.Add(30*time.Minute))
	if !ok || endpoint != "example.test:8443" {
		t.Fatalf("h3Endpoint = %q, %v; want example.test:8443, true", endpoint, ok)
	}
}

// ma=0 means the advertisement is already dead; past ma= it is gone.
func TestAltSvcHonoursMaExpiry(t *testing.T) {
	table := newAltSvcTable()
	now := time.Now()
	table.learn("example.test", 443, `h3=":443"; ma=60`, now)

	if _, ok := table.h3Endpoint("example.test", 443, now.Add(2*time.Minute)); ok {
		t.Fatal("an advertisement outlived its ma=")
	}

	table.learn("dead.test", 443, `h3=":443"; ma=0`, now)
	if _, ok := table.h3Endpoint("dead.test", 443, now); ok {
		t.Fatal("a ma=0 advertisement was usable at all")
	}
}

// clear withdraws every advertisement for the origin.
func TestAltSvcHonoursClear(t *testing.T) {
	table := newAltSvcTable()
	now := time.Now()
	table.learn("example.test", 443, `h3=":443"; ma=3600`, now)
	table.learn("example.test", 443, "clear", now)

	if _, ok := table.h3Endpoint("example.test", 443, now); ok {
		t.Fatal("an advertisement survived Alt-Svc: clear")
	}
}

// Draft identifiers and non-h3 protocols are not HTTP/3: only the exact h3 token counts, and an
// advertisement for one origin never leaks onto another port's origin.
func TestAltSvcLearnsOnlyExactH3(t *testing.T) {
	table := newAltSvcTable()
	now := time.Now()
	table.learn("example.test", 443, `h3-29=":443"; ma=3600, h2=":443"; ma=3600`, now)
	if _, ok := table.h3Endpoint("example.test", 443, now); ok {
		t.Fatal("draft or non-h3 tokens were treated as HTTP/3")
	}

	table.learn("example.test", 443, `h3=":8443"; ma=3600`, now)
	if _, ok := table.h3Endpoint("example.test", 8443, now); ok {
		t.Fatal("an advertisement for :443 leaked onto the :8443 origin")
	}
}
