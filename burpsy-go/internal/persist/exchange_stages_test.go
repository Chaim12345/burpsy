package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The retained earlier readings of a message must survive a restart (burpsy-react-ui-c05).
//
// Worth a test of its own because losing them is silent: the exchange, its bytes and every column
// the History table renders come back perfectly, and the only thing that goes missing is the
// operator's ability to see what a Match & Replace rule did — a blank comparison rather than an
// error, on a row that still claims to be the same row. The columns hold message ids, so the failure
// mode this guards against is specifically a NULL written by mistake or an id written into the
// wrong column, both of which read back as a plausible exchange.

func TestRetainedStagesSurviveSaveLoadRoundTrip(t *testing.T) {
	s := newTestStore(t)
	reqOriginal, reqAuto := core.MsgId(11), core.MsgId(12)
	respOriginal, respAuto := core.MsgId(21), core.MsgId(22)
	ex := &core.Exchange{
		Request: 10, Response: ptr(core.MsgId(20)),
		Host: "stages.test", Port: 443, TLS: true, Method: "POST", Path: "/login",
		RequestOriginal: &reqOriginal, RequestAuto: &reqAuto,
		ResponseOriginal: &respOriginal, ResponseAuto: &respAuto,
	}
	s.SaveExchange(ex)

	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	got := loaded[0]
	for _, tc := range []struct {
		what string
		got  *core.MsgId
		want core.MsgId
	}{
		{"request_original", got.RequestOriginal, reqOriginal},
		{"request_auto", got.RequestAuto, reqAuto},
		{"response_original", got.ResponseOriginal, respOriginal},
		{"response_auto", got.ResponseAuto, respAuto},
	} {
		if tc.got == nil || *tc.got != tc.want {
			t.Errorf("%s = %v, want %d", tc.what, tc.got, tc.want)
		}
	}
	// The readings are what the operator actually sees, so the round trip is asserted through the
	// same walk the viewer uses rather than only on the raw ids: an id that landed in the wrong
	// column would pass the four checks above only by coincidence of the values chosen.
	if id, _ := got.VariantFor(core.DirectionRequest, core.VariantOriginal); id != reqOriginal {
		t.Errorf("the original request reading is %d after a restart, want %d", id, reqOriginal)
	}
	if id, _ := got.VariantFor(core.DirectionResponse, core.VariantAutoModified); id != respAuto {
		t.Errorf("the auto-modified response reading is %d after a restart, want %d", id, respAuto)
	}
}

// A row that retained nothing comes back retaining nothing. This is the column's common value and
// the one the memory cost depends on, so it is asserted rather than left implied by the test above:
// a load that invented a stage id — pointing the original at the recorded bytes, say — would claim a
// comparison that was never kept.
func TestAnUnmodifiedExchangeReloadsWithNoRetainedStages(t *testing.T) {
	s := newTestStore(t)
	s.SaveExchange(&core.Exchange{
		Request: 10, Response: ptr(core.MsgId(20)),
		Host: "plain.test", Port: 80, Method: "GET", Path: "/",
	})

	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	got := loaded[0]
	if got.RequestOriginal != nil || got.RequestAuto != nil || got.ResponseOriginal != nil || got.ResponseAuto != nil {
		t.Fatalf("an unmodified exchange reloaded with stages: req=(%v,%v) resp=(%v,%v)",
			got.RequestOriginal, got.RequestAuto, got.ResponseOriginal, got.ResponseAuto)
	}
	if got.HasRetainedStage(core.DirectionRequest) || got.HasRetainedStage(core.DirectionResponse) {
		t.Error("an unmodified exchange reports a retained stage after a restart")
	}
}

// A partial retention is preserved as partial: one direction changed, the other untouched. The two
// chains are independent columns and a save that wrote one direction's ids into the other's would
// otherwise look correct whenever both happened to be set.
func TestOnlyTheDirectionThatWasRetainedComesBack(t *testing.T) {
	s := newTestStore(t)
	reqAuto := core.MsgId(12)
	s.SaveExchange(&core.Exchange{
		Request: 10, Response: ptr(core.MsgId(20)),
		Host: "half.test", Port: 80, Method: "GET", Path: "/",
		// A response-only rewrite, which is the ordinary shape of a Match & Replace response rule.
		ResponseAuto: &reqAuto,
	})

	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	got := loaded[0]
	if got.HasRetainedStage(core.DirectionRequest) {
		t.Error("the request reports a retained stage; only its response was changed")
	}
	if !got.HasRetainedStage(core.DirectionResponse) {
		t.Error("the response's retained stage did not come back")
	}
	if id, _ := got.VariantFor(core.DirectionResponse, core.VariantEdited); id != core.MsgId(20) {
		t.Errorf("the edited response reading is %d, want 20", id)
	}
}

func ptr(id core.MsgId) *core.MsgId { return &id }
