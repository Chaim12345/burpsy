package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The macro recorder's wire half (burpsy-react-ui-escl): "Select the items you need from the Proxy
// history list" becomes a POST carrying those rows' ids, and the answer is the steps themselves.
//
// The tests below care most about the answer's *second* list. A recorder that returned only the
// steps it managed to build is the shape that fails quietly: the operator selects four rows, gets
// three steps, and finds out at the next login that a request is missing — with nothing on screen
// ever having said so. So every case that drops a row asserts that the row is named and the reason
// is not empty.

type macroStepsWire struct {
	Steps []struct {
		Method  string      `json:"method"`
		URL     string      `json:"url"`
		Headers [][2]string `json:"headers"`
		Body    string      `json:"body"`
	} `json:"steps"`
	Skipped []struct {
		Exchange uint64 `json:"exchange"`
		Reason   string `json:"reason"`
	} `json:"skipped"`
}

// seedHistoryRow stores one capture: the request bytes, the exchange row addressing them, and
// nothing else. The macro recorder needs exactly those two records, so a helper that took more would
// be testing the proxy rather than this endpoint.
func seedHistoryRow(t *testing.T, s *Server, host string, port uint16, tls bool, raw string) core.ExchangeID {
	t.Helper()
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Host: host, Port: port, TLS: tls, Method: "GET", Path: "/"}
	s.store.AddExchange(ex)
	return ex.ID
}

func postMacroSteps(t *testing.T, s *Server, body interface{}) macroStepsWire {
	t.Helper()
	rec := postJSON(t, s, "/api/session/macro-steps", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/session/macro-steps = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var got macroStepsWire
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode macro-steps response %q: %v", rec.Body.String(), err)
	}
	return got
}

// A selection of history rows becomes one step each, in the order they were selected, addressed at
// the authority the exchange recorded rather than at anything re-derived from the bytes.
func TestSelectedHistoryRowsBecomeMacroStepsInOrder(t *testing.T) {
	s := newTestServer()
	login := seedHistoryRow(t, s, "shop.test", 443, true,
		"POST /login HTTP/1.1\r\nHost: shop.test\r\nAccept: */*\r\n\r\nuser=alice&password=hunter2")
	cart := seedHistoryRow(t, s, "shop.test", 443, true,
		"GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	got := postMacroSteps(t, s, map[string]any{"exchanges": []uint64{uint64(login), uint64(cart)}})
	if len(got.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want nothing: both rows were selected and both are readable", got.Skipped)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(got.Steps))
	}
	if got.Steps[0].Method != "POST" || got.Steps[0].URL != "https://shop.test/login" {
		t.Errorf("step 1 = %s %s, want POST https://shop.test/login", got.Steps[0].Method, got.Steps[0].URL)
	}
	if got.Steps[0].Body != "user=alice&password=hunter2" {
		t.Errorf("step 1 body = %q, want the captured bytes", got.Steps[0].Body)
	}
	// Order is the macro's semantics: these replay in sequence, so a recorder that reordered them
	// would build a macro that posts to /cart before logging in.
	if got.Steps[1].Method != "GET" || got.Steps[1].URL != "https://shop.test/cart" {
		t.Errorf("step 2 = %s %s, want GET https://shop.test/cart", got.Steps[1].Method, got.Steps[1].URL)
	}
}

// The step is a copy of the request the operator selected, headers included. A recorder that dropped
// them would produce a macro that sends less than the request it was recorded from.
func TestARecordedStepCarriesTheCapturedHeaders(t *testing.T) {
	s := newTestServer()
	id := seedHistoryRow(t, s, "shop.test", 80, false,
		"POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx=1")

	got := postMacroSteps(t, s, map[string]any{"exchanges": []uint64{uint64(id)}})
	if len(got.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(got.Steps))
	}
	headers := map[string]string{}
	for _, kv := range got.Steps[0].Headers {
		headers[kv[0]] = kv[1]
	}
	if headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want the captured value", headers["Content-Type"])
	}
	if got.Steps[0].URL != "http://shop.test/login" {
		t.Errorf("URL = %q, want http://shop.test/login", got.Steps[0].URL)
	}
}

// A row the recorder cannot convert is named in the answer rather than omitted. This is the case
// that decides whether the feature is honest: a partial recording must not look like a whole one.
func TestARowThatCannotBecomeAStepIsNamedRatherThanDropped(t *testing.T) {
	s := newTestServer()
	good := seedHistoryRow(t, s, "shop.test", 80, false, "GET /ok HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	// A request whose target is absolute-form: a stored message is origin-form, so these are not the
	// bytes a step can be built from and the refusal is the honest answer.
	odd := seedHistoryRow(t, s, "shop.test", 80, false, "GET http://elsewhere.test/x HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	got := postMacroSteps(t, s, map[string]any{"exchanges": []uint64{uint64(good), uint64(odd), 99999}})
	if len(got.Steps) != 1 {
		t.Fatalf("steps = %d, want the one convertible row", len(got.Steps))
	}
	if len(got.Skipped) != 2 {
		t.Fatalf("skipped = %+v, want both the unconvertible row and the unknown id named", got.Skipped)
	}
	byID := map[uint64]string{}
	for _, row := range got.Skipped {
		byID[row.Exchange] = row.Reason
	}
	if byID[uint64(odd)] == "" {
		t.Errorf("exchange %d was skipped with no reason; the operator cannot tell what to fix", odd)
	}
	if byID[99999] == "" {
		t.Errorf("the unknown id was skipped with no reason")
	}
}

// The default reading is the bytes that travelled, and the other two are selectable. A macro is meant
// to replay what the client sent, so a recorder that defaulted to the pre-rule reading would send a
// request the target has already seen rewritten — but an operator diagnosing a Match & Replace rule
// needs the earlier reading on purpose.
func TestTheVariantSelectsWhichReadingOfTheRequestIsRecorded(t *testing.T) {
	s := newTestServer()
	reqID, err := s.store.Put([]byte("GET /page HTTP/1.1\r\nHost: shop.test\r\nX-As-Sent: 1\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put edited request: %v", err)
	}
	origID, err := s.store.Put([]byte("GET /page HTTP/1.1\r\nHost: shop.test\r\nX-Original: 1\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put original request: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), RequestOriginal: &origID, Host: "shop.test", Port: 80, Method: "GET", Path: "/page"}
	s.store.AddExchange(ex)

	edited := postMacroSteps(t, s, map[string]any{"exchanges": []uint64{uint64(ex.ID)}})
	if len(edited.Steps) != 1 || headerOf(edited.Steps[0].Headers, "X-As-Sent") == "" {
		t.Fatalf("default reading = %+v, want the bytes that travelled", edited.Steps)
	}
	original := postMacroSteps(t, s, map[string]any{"exchanges": []uint64{uint64(ex.ID)}, "variant": "original"})
	if len(original.Steps) != 1 || headerOf(original.Steps[0].Headers, "X-Original") == "" {
		t.Fatalf("original reading = %+v, want the pre-rule bytes", original.Steps)
	}
}

func headerOf(headers [][2]string, name string) string {
	for _, kv := range headers {
		if kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

// A recorder handed nothing, or an unknown variant name, is refused rather than answered with an
// empty success. {"steps":[]} for a selection of none is indistinguishable from a successful
// recording of nothing, and a variant that does not exist must not silently become the default.
func TestAnEmptyOrUnintelligibleRecordingRequestIsRefused(t *testing.T) {
	s := newTestServer()
	id := seedHistoryRow(t, s, "shop.test", 80, false, "GET /ok HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"no exchanges", map[string]any{}},
		{"empty selection", map[string]any{"exchanges": []uint64{}}},
		{"unknown variant", map[string]any{"exchanges": []uint64{uint64(id)}, "variant": "before-everything"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, s, "/api/session/macro-steps", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST = %d (%s), want 400", rec.Code, rec.Body.String())
			}
		})
	}
}
