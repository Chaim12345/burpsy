package sender

import (
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// burpsy-react-ui-o388-predial-vs-dial residual (4): DeriveWithTimeouts read the carrier after
// releasing s.mu, so a derivation concurrent with WithUpstreamCarrier was a data race and could
// pair the pre-swap settings with the post-swap carrier. The carrier is read in the same locked
// section as the settings now. The race detector is the assertion that fails without the fix (the
// package gate runs -race); the membership check is what a plain run can see.
func TestDeriveWithTimeoutsReadsTheCarrierWithTheSettings(t *testing.T) {
	s := NewSender(DefaultSenderConfig())
	first := upstream.NewCarrier()
	second := upstream.NewCarrier()
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
	for i := 0; i < 200; i++ {
		d, err := s.DeriveWithTimeouts(TimeoutOverride{})
		if err != nil {
			t.Fatal(err)
		}
		if c := d.UpstreamCarrier(); c != first && c != second {
			t.Fatalf("derived sender holds a carrier that was never attached: %p", c)
		}
	}
	wg.Wait()
}
