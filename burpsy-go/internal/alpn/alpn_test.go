package alpn

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestFilterKeepsTheCallersOrder(t *testing.T) {
	got := Filter([]string{"spdy/3.1", HTTP11, H2}, true)
	if len(got) != 2 || got[0] != HTTP11 || got[1] != H2 {
		t.Fatalf("want the client's own order preserved, got %v", got)
	}
}

func TestFilterWithoutH2KeepsOnlyHTTP11(t *testing.T) {
	got := Filter([]string{H2, HTTP11}, false)
	if len(got) != 1 || got[0] != HTTP11 {
		t.Fatalf("want http/1.1 alone, got %v", got)
	}
}

func TestFilterInventsNothingForAPeerThatOfferedNothing(t *testing.T) {
	if got := Filter(nil, true); got != nil {
		t.Fatalf("want nil for an empty offer, got %v", got)
	}
}

func TestEgressOfferAlwaysIncludesHTTP11SoAnH1TargetDoesNotFailTheHandshake(t *testing.T) {
	got := EgressOffer(true)
	if len(got) != 2 || got[0] != H2 || got[1] != HTTP11 {
		t.Fatalf("want h2 first and http/1.1 as the fallback, got %v", got)
	}
	if got := EgressOffer(false); len(got) != 1 || got[0] != HTTP11 {
		t.Fatalf("want http/1.1 alone when h2 is not wanted, got %v", got)
	}
}

func TestProtocolMapsTheWireValues(t *testing.T) {
	if p, err := Protocol(H2); err != nil || p != core.ProtocolHTTP2 {
		t.Fatalf("h2: got %v, %v", p, err)
	}
	// No ALPN at all is HTTP/1.1 and is not an error: that is what a peer with no ALPN support carries.
	if p, err := Protocol(""); err != nil || p != core.ProtocolHTTP1 {
		t.Fatalf("empty: got %v, %v", p, err)
	}
	p, err := Protocol("spdy/3.1")
	if err == nil {
		t.Fatal("want an error for an unrecognised ALPN value")
	}
	if p != core.ProtocolHTTP1 {
		t.Fatalf("an unrecognised value must still answer conservatively, got %v", p)
	}
}

func TestSingleFallsBackToHTTP11WhenNothingWasNegotiated(t *testing.T) {
	if got := Single(""); len(got) != 1 || got[0] != HTTP11 {
		t.Fatalf("want http/1.1, got %v", got)
	}
	if got := Single(H2); len(got) != 1 || got[0] != H2 {
		t.Fatalf("want the negotiated protocol alone, got %v", got)
	}
}
