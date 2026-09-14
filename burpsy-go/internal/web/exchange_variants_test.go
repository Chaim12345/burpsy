package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The wire half of Burp's three readings (burpsy-react-ui-c05, under epic mrjw).
//
// The History viewer needs two different answers per direction and they must not be conflated:
// *which* message holds an earlier reading, and *whether* an earlier reading exists at all. The
// server answers both with one nullable id — non-null means "this reading exists and here it is" —
// which is why the null cases below are asserted as carefully as the present ones. A shape that
// answered only the first question would have the viewer offer three readings for every row in a
// capture, two of which show the same bytes as the third.

// variantWire is the part of the exchange view this file is about: the row's own message ids plus
// the group the readings arrive in. Deliberately decoded as a nested object rather than flattened,
// because that is the shape the UI consumes and a test that flattened it by accident would not
// notice the server had moved.
type variantWire struct {
	Request  uint64  `json:"request"`
	Response *uint64 `json:"response"`
	Variants struct {
		RequestOriginal  *uint64 `json:"request_original"`
		RequestAuto      *uint64 `json:"request_auto_modified"`
		ResponseOriginal *uint64 `json:"response_original"`
		ResponseAuto     *uint64 `json:"response_auto_modified"`
		Edited           bool    `json:"edited"`
	} `json:"variants"`
}

// seedVariantExchange stores one exchange whose four stages, and whose "the operator edited this"
// flag, are set as the caller asks, so each test below is about the wire shape rather than about how
// the stages got there — that is the proxy's tests' job, and this file deliberately does not repeat
// it.
//
// The flag is a separate input from the stages deliberately. They answer different questions — the
// stages say what the bytes became, the flag says who changed them (burpsy-react-ui-sd0d) — and a
// seed that derived one from the other would let a projection that conflated them still pass.
func seedVariantExchange(t *testing.T, s *Server, reqOriginal, reqAuto, respOriginal, respAuto, userEdited bool) core.ExchangeID {
	t.Helper()
	put := func(body string, dir core.Direction) core.MsgId {
		id, err := s.store.Put([]byte(body), dir)
		if err != nil {
			t.Fatalf("put %v: %v", dir, err)
		}
		return id
	}
	reqID := put("GET /page HTTP/1.1\r\nHost: shop.test\r\n\r\n", core.DirectionRequest)
	respID := put("HTTP/1.1 200 OK\r\n\r\nhello", core.DirectionResponse)
	status := uint16(200)
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     "shop.test",
		Port:     80,
		Method:   "GET",
		Path:     "/page",
		Status:   &status,

		UserEdited: userEdited,
	}
	// Descending ids so a field landing in the wrong column is visible in the assertion rather than
	// hidden by two stages sharing a value.
	if reqOriginal {
		id := put("GET /page HTTP/1.1\r\nHost: shop.test\r\nX-As-Sent: 1\r\n\r\n", core.DirectionRequest)
		ex.RequestOriginal = &id
	}
	if reqAuto {
		id := put("GET /page HTTP/1.1\r\nHost: shop.test\r\nX-Auto: 1\r\n\r\n", core.DirectionRequest)
		ex.RequestAuto = &id
	}
	if respOriginal {
		id := put("HTTP/1.1 200 OK\r\n\r\nfrom-origin", core.DirectionResponse)
		ex.ResponseOriginal = &id
	}
	if respAuto {
		id := put("HTTP/1.1 200 OK\r\n\r\nafter-rules", core.DirectionResponse)
		ex.ResponseAuto = &id
	}
	s.store.AddExchange(ex)
	return ex.ID
}

func exchangeVariantWire(t *testing.T, s *Server, id core.ExchangeID) variantWire {
	t.Helper()
	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/exchange/%d = %d, want 200", id, rec.Code)
	}
	var got variantWire
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode exchange %d: %v", id, err)
	}
	return got
}

// An exchange nothing touched reports every reading as absent and edited=false. This is the state of
// almost every row in a capture, so it is the case that decides whether the feature is usable: a
// viewer that offered comparisons here would bury the rows that have something to compare.
func TestAnUnmodifiedExchangeOffersNoEarlierReadings(t *testing.T) {
	s := newTestServer()
	id := seedVariantExchange(t, s, false, false, false, false, false)

	got := exchangeVariantWire(t, s, id)
	if got.Variants.RequestOriginal != nil || got.Variants.RequestAuto != nil || got.Variants.ResponseOriginal != nil || got.Variants.ResponseAuto != nil {
		t.Fatalf("an unmodified exchange offered readings: req=(%v,%v) resp=(%v,%v)",
			got.Variants.RequestOriginal, got.Variants.RequestAuto, got.Variants.ResponseOriginal, got.Variants.ResponseAuto)
	}
	if got.Variants.Edited {
		t.Error("edited = true for an exchange nothing modified; the History column would mark every row")
	}
}

// A rule-only change reports the bytes the client sent as the original reading, and nothing for the
// auto-modified one — because with no manual edit the auto-modified reading *is* the bytes that
// travelled, so a column for it would show the operator the same message twice.
//
// That asymmetry is the shape's whole point: a non-null id means "this reading differs", not merely
// "this reading exists", and the viewer offers a comparison exactly when one exists.
func TestARuleOnlyChangeReportsThePreRuleBytesAsTheOriginal(t *testing.T) {
	s := newTestServer()
	id := seedVariantExchange(t, s, true, false, false, false, false)

	got := exchangeVariantWire(t, s, id)
	// Not edited, and that is the point of the pair of assertions (burpsy-react-ui-sd0d).
	// A Match & Replace rule rewrote these bytes; nobody edited them. Burp's flag is "the request or
	// response were modified by the user" — which is why its viewer offers a separate Auto-modified
	// reading — so an automatic rewrite must not raise it. What it must do is leave something to
	// compare, which the reading assertion below checks, and the two are different questions: this
	// row offers a comparison *and* is not "Edited", and the projection that used to derive one from
	// the other could not express that.
	if got.Variants.Edited {
		t.Error("edited = true for an exchange a rule rewrote; history would mark the operator's own work where they had none")
	}
	if got.Variants.RequestOriginal == nil {
		t.Fatal("the original reading is absent; the client's own bytes are what the operator needs to compare against")
	}
	if *got.Variants.RequestOriginal == got.Request {
		t.Error("the original reading points at the bytes that travelled, so the comparison shows one message twice")
	}
	if got.Variants.RequestAuto != nil {
		t.Errorf("auto-modified = %d; no manual edit followed the rule, so that reading is the bytes that travelled and must be absent", *got.Variants.RequestAuto)
	}
	// The response was untouched, so its readings must stay absent even though the row is edited.
	if got.Variants.ResponseOriginal != nil || got.Variants.ResponseAuto != nil {
		t.Errorf("the untouched response offered readings: (%v,%v)", got.Variants.ResponseOriginal, got.Variants.ResponseAuto)
	}
}

// A manual-only change is the case the naive shape gets wrong: nothing fired a rule, so the
// pre-edit bytes live in the *auto-modified* stage and the original reading must resolve to them
// rather than falling through to the bytes that travelled.
func TestAManualOnlyChangeReportsThePreEditBytesAsBothReadings(t *testing.T) {
	s := newTestServer()
	id := seedVariantExchange(t, s, false, true, false, false, true)

	got := exchangeVariantWire(t, s, id)
	if !got.Variants.Edited {
		t.Error("edited = false for an exchange the operator edited by hand; the flag is exactly this case")
	}
	if got.Variants.RequestOriginal == nil || got.Variants.RequestAuto == nil {
		t.Fatalf("readings = (%v, %v), want both present after a manual edit", got.Variants.RequestOriginal, got.Variants.RequestAuto)
	}
	if *got.Variants.RequestOriginal != *got.Variants.RequestAuto {
		t.Errorf("original = %d, auto-modified = %d; no rule fired, so both readings are the pre-edit bytes",
			*got.Variants.RequestOriginal, *got.Variants.RequestAuto)
	}
	if *got.Variants.RequestOriginal == got.Request {
		t.Error("the original reading points at the edited bytes; the operator would see their own edit labelled as what the client sent")
	}
}

// Changed both ways: three distinct readings, in order.
func TestAnExchangeChangedTwiceReportsThreeDistinctReadings(t *testing.T) {
	s := newTestServer()
	id := seedVariantExchange(t, s, true, true, false, false, true)

	got := exchangeVariantWire(t, s, id)
	if got.Variants.RequestOriginal == nil || got.Variants.RequestAuto == nil {
		t.Fatalf("readings = (%v, %v), want both present", got.Variants.RequestOriginal, got.Variants.RequestAuto)
	}
	seen := map[uint64]bool{got.Request: true, *got.Variants.RequestOriginal: true, *got.Variants.RequestAuto: true}
	if len(seen) != 3 {
		t.Errorf("readings are %d, %d and the edited %d; three stages that all differ must be three messages",
			*got.Variants.RequestOriginal, *got.Variants.RequestAuto, got.Request)
	}
}

// The response's readings are independent of the request's, which is the ordinary shape of a
// response-direction rule. Asserted separately rather than inferred, because a projection that
// branched once for both directions would look right whenever only one of them had changed.
func TestAResponseOnlyChangeLeavesTheRequestsReadingsAbsent(t *testing.T) {
	s := newTestServer()
	id := seedVariantExchange(t, s, false, false, true, true, false)

	got := exchangeVariantWire(t, s, id)
	if got.Variants.RequestOriginal != nil || got.Variants.RequestAuto != nil {
		t.Errorf("the untouched request offered readings: (%v,%v)", got.Variants.RequestOriginal, got.Variants.RequestAuto)
	}
	if got.Variants.ResponseOriginal == nil || got.Variants.ResponseAuto == nil {
		t.Fatalf("response readings = (%v,%v), want both present", got.Variants.ResponseOriginal, got.Variants.ResponseAuto)
	}
	if *got.Variants.ResponseOriginal == *got.Variants.ResponseAuto {
		t.Error("the response's two earlier readings are the same message despite a rule and an edit both having run")
	}
	// A rule rewrote the response and nobody edited it, so the flag stays down while the readings
	// above are both present — see TestARuleOnlyChangeReportsThePreRuleBytesAsTheOriginal for why
	// those are separate answers (burpsy-react-ui-sd0d).
	if got.Variants.Edited {
		t.Error("edited = true for a response only a rule rewrote")
	}
}

// A response the operator edited by hand raises the flag on its own, with the request half of the row
// carrying no stages at all. Asserted from the response side deliberately: a projection that read the
// request half twice would look correct on every test above, because the request is the half those
// seeds put the stages on.
func TestAnOperatorsEditToTheResponseRaisesTheFlag(t *testing.T) {
	s := newTestServer()
	id := seedVariantExchange(t, s, false, false, false, true, true)

	got := exchangeVariantWire(t, s, id)
	if !got.Variants.Edited {
		t.Error("edited = false for an exchange whose response the operator edited by hand")
	}
	if got.Variants.RequestOriginal != nil || got.Variants.RequestAuto != nil {
		t.Errorf("the untouched request offered readings: (%v,%v)", got.Variants.RequestOriginal, got.Variants.RequestAuto)
	}
}

// An exchange with no response reports no response readings and does not claim to be edited on the
// strength of a request stage it does not have. The null Response is the tell that separates "no
// response yet" from "an unmodified response", and the readings must agree with it.
func TestAnExchangeWithNoResponseOffersNoResponseReadings(t *testing.T) {
	s := newTestServer()
	reqID, err := s.store.Put([]byte("GET /page HTTP/1.1\r\nHost: shop.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Host: "shop.test", Port: 80, Method: "GET", Path: "/page"}
	s.store.AddExchange(ex)

	got := exchangeVariantWire(t, s, ex.ID)
	if got.Response != nil {
		t.Fatalf("response = %v, want null for an exchange with no response", got.Response)
	}
	if got.Variants.ResponseOriginal != nil || got.Variants.ResponseAuto != nil {
		t.Errorf("a response-less exchange offered response readings: (%v,%v)", got.Variants.ResponseOriginal, got.Variants.ResponseAuto)
	}
	if got.Variants.Edited {
		t.Error("edited = true for an exchange with no response and no modification")
	}
}
