package web

import (
	"encoding/json"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The two response timers must survive the trip to the browser as two distinct facts, and an
// unmeasured one must arrive as null rather than as zero.
//
// Asserting the MARSHALLED JSON rather than the struct, because that is where this can go wrong:
// a *uint64 that is nil serialises to null, and a plain uint64 serialises to 0 — and 0 is a claim
// (the origin answered instantly) about every exchange no producer timed, which is most of them.
// The struct cannot tell those two apart by inspection; the bytes can.
func TestTheTwoResponseTimersCrossTheWireSeparatelyAndUnmeasuredArrivesAsNull(t *testing.T) {
	// A slow-to-respond origin: a second of thinking, then a body that lands almost at once.
	slow := core.Exchange{
		Duration: core.ExchangeDuration{Us: 1_200_000, Measured: true},
		TTFB:     core.ExchangeDuration{Us: 1_000_000, Measured: true},
	}
	body := viewJSON(t, exchangeView(&slow))
	if body["ttfb_ms"] != float64(1000) {
		t.Errorf("ttfb_ms = %v, want 1000 — the wait before the origin answered is the whole point of the split", body["ttfb_ms"])
	}
	if body["duration_ms"] != float64(1200) {
		t.Errorf("duration_ms = %v, want 1200", body["duration_ms"])
	}

	// The same total, spent the other way round: a quick first byte and a long body. If the two
	// fields were one, these two exchanges would be indistinguishable — which is the bug.
	slowBody := core.Exchange{
		Duration: core.ExchangeDuration{Us: 1_200_000, Measured: true},
		TTFB:     core.ExchangeDuration{Us: 20_000, Measured: true},
	}
	other := viewJSON(t, exchangeView(&slowBody))
	if other["ttfb_ms"] == body["ttfb_ms"] {
		t.Errorf("a slow-to-respond origin and a slow-bodied one reported the same ttfb_ms (%v), so the split says nothing", other["ttfb_ms"])
	}

	// A producer that only ever knew the round trip: Repeater, Intruder, the crawler, or a row
	// restored from before the field existed.
	untimed := core.Exchange{Duration: core.ExchangeDuration{Us: 500_000, Measured: true}}
	u := viewJSON(t, exchangeView(&untimed))
	if got, ok := u["ttfb_ms"]; !ok || got != nil {
		t.Errorf("ttfb_ms = %v, want null — a producer that never timed the first byte must not report one, and 0 would claim it arrived instantly", got)
	}
}

func viewJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}
