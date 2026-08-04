package proxy

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestAlpnOfferFiltersUnknownProtocols(t *testing.T) {
	got := AlpnOffer([]string{"spdy/3.1", alpnHTTP11, alpnH2}, false)
	if len(got) != 2 || got[0] != alpnHTTP11 || got[1] != alpnH2 {
		t.Fatalf("got %v", got)
	}
}

func TestAlpnOfferWithInterceptionOnlyHTTP11(t *testing.T) {
	got := AlpnOffer([]string{alpnH2, alpnHTTP11}, true)
	if len(got) != 1 || got[0] != alpnHTTP11 {
		t.Fatalf("got %v", got)
	}
}

func TestAlpnOfferH2OnlyClientBlockedWhileIntercepting(t *testing.T) {
	got := AlpnOffer([]string{alpnH2}, true)
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestNegotiatedProtocol(t *testing.T) {
	p, err := NegotiatedProtocol(alpnH2)
	if err != nil || p != core.ProtocolHTTP2 {
		t.Fatalf("h2: %v %v", p, err)
	}
	p, err = NegotiatedProtocol("")
	if err != nil || p != core.ProtocolHTTP1 {
		t.Fatalf("empty: %v %v", p, err)
	}
	if _, err := NegotiatedProtocol("spdy/3.1"); err == nil {
		t.Fatal("expected error for unknown alpn")
	}
}
