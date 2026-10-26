package web

// The integer conversions in extension_services.go (gosec G115): each one is now a named, bounded
// step with a pinned outcome at its limit, instead of a bare cast.

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/extension"
)

func Test_elapsed_milliseconds_never_goes_negative_and_keeps_real_durations(t *testing.T) {
	if got := elapsedMillis(time.Now().Add(time.Hour)); got != 0 {
		t.Errorf("a start in the future = %d ms, want 0 (a duration is never negative)", got)
	}
	got := elapsedMillis(time.Now().Add(-1500 * time.Millisecond))
	if got < 1500 || got > 5000 {
		t.Errorf("1.5s ago = %d ms, want about 1500", got)
	}
}

func Test_a_traffic_item_with_an_id_that_does_not_fit_an_int_is_left_out_not_wrapped(t *testing.T) {
	var page extension.TrafficPage
	tr := extensionTraffic{}
	huge := &core.Exchange{ID: core.ExchangeID(math.MaxUint64), Host: "h.test", Method: "GET", Path: "/"}
	tr.addIfMatch(&page, huge, extension.TrafficQuery{}, 0, 10)
	if len(page.Items) != 0 || page.Total != 0 {
		t.Fatalf("an id past MaxInt was served or counted: total %d items %+v", page.Total, page.Items)
	}
	ok := &core.Exchange{ID: 7, Host: "h.test", Method: "GET", Path: "/"}
	tr.addIfMatch(&page, ok, extension.TrafficQuery{}, 0, 10)
	if len(page.Items) != 1 || page.Items[0].ID != 7 || page.Total != 1 {
		t.Fatalf("an ordinary exchange was not served: total %d items %+v", page.Total, page.Items)
	}
}

func Test_an_organizer_item_with_a_negative_exchange_id_is_skipped(t *testing.T) {
	s := newTestServer()
	if s.organizer == nil {
		t.Skip("this test server has no organizer")
	}
	s.organizer.Add(-1)
	page, err := s.ExtensionServices().Traffic.Query(context.TODO(), "plug", extension.TrafficQuery{Source: extension.TrafficOrganizer})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("a negative organizer id resolved to rows: %+v", page.Items)
	}
}
