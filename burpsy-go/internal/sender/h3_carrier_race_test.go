package sender

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// burpsy-react-ui-o388-predial-vs-dial residual (5): the h3 pin's carrier refusal read s.carrier
// without s.mu, a data race against WithUpstreamCarrier — and the refusal is the only thing
// standing between an h3-pinned send and a direct QUIC dial that bypasses a configured SOCKS
// hop. Both carriers here have a hop configured, so every send must be refused whichever one
// it reads; the race detector is the assertion that fails without the fix.
func TestTheH3CarrierRefusalReadsTheCarrierUnderTheLock(t *testing.T) {
	s := NewSender(DefaultSenderConfig())
	first := upstream.NewCarrier()
	second := upstream.NewCarrier()
	for _, c := range []*upstream.Carrier{first, second} {
		if err := c.SetSocks("socks5://127.0.0.1:1", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	s.WithUpstreamCarrier(first)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				s.WithUpstreamCarrier(second)
			} else {
				s.WithUpstreamCarrier(first)
			}
		}
	}()
	raw := rawGet("127.0.0.1", 443)
	for i := 0; i < 200; i++ {
		_, _, err := s.sendH3(context.Background(), "127.0.0.1", 443, true, raw)
		if err == nil || !strings.Contains(err.Error(), "SOCKS carrier") {
			t.Fatalf("an h3-pinned send under a configured carrier was not refused for it: %v", err)
		}
	}
	wg.Wait()
}
