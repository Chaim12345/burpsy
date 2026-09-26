package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// httptestNewRecorder and jsonUnmarshal are named so the assertions above read as sentences; they are
// the stdlib, wrapped once here rather than repeated in every test.
func httptestNewRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func jsonUnmarshal(data []byte, into any) error { return json.Unmarshal(data, into) }

func reflectTypeOf(v any) reflect.Type {
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Ptr {
		return t
	}
	return t.Elem()
}

// A blind CONNECT tunnel has no request and no response — the proxy records it as a row that says
// "a client opened a tunnel here and we did not look inside" — and the exchange's Request field stays
// at its zero value because there are no bytes to record (burpsy-react-ui-wtov).
//
// The zero value is a REAL message id: the store is a dense counter from zero, so the first message
// ever captured is id 0. exchangeView emitted that zero unconditionally, the UI read it as "this row's
// request", and the detail pane rendered the first request in the project under the label Request for
// a tunnel that has no request at all. That is evidence corruption rather than a missing feature.
//
// Response already handles this — it is a *uint64 and can be null. Request is a uint64 and cannot, so
// "absent" is unrepresentable on the wire, and every consumer has to guess whether 0 means "no
// request" or "the first message".

// A blind tunnel's row must not carry a request id at all.
func TestABlindTunnelEmitsNoRequestId(t *testing.T) {
	// A real message 0, so the zero the tunnel would emit is genuinely a fetchable id — the whole
	// point. A test with an empty store would pass against the old code by accident.
	store := core.NewTrafficStore()
	if _, err := store.Put([]byte("GET /the-first-request-ever HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"), core.DirectionRequest); err != nil {
		t.Fatalf("seeding message 0: %v", err)
	}
	if _, err := store.Put([]byte("GET /decoy HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"), core.DirectionResponse); err != nil {
		t.Fatalf("seeding message 1: %v", err)
	}

	// The tunnel row, exactly as tunnelConnection builds it: no Request, no Response.
	tunnel := &core.Exchange{Host: "tunnelled.test", Port: 443, TLS: true, Method: "CONNECT"}

	view := exchangeView(tunnel)
	if view.Request != nil {
		t.Errorf("request = %v, want null: a blind tunnel has no request bytes, and emitting 0 points "+
			"the UI at message 0 — the first request captured in the project, which belongs to a "+
			"different exchange (burpsy-react-ui-wtov)", *view.Request)
	}
	// The premise, stated as a fact rather than left implicit: message 0 EXISTS and holds a request
	// that belongs to a different exchange. The old wire shape pointed a tunnel's row at exactly this
	// message, which is why the bug is evidence corruption and not a missing feature.
	msg, err := store.Get(core.MsgId(0))
	if err != nil {
		t.Fatalf("test premise is wrong: message 0 must exist for the zero to be misleading, got %v", err)
	}
	if !strings.Contains(string(msg.Raw()), "/the-first-request-ever") {
		t.Fatalf("message 0 holds %q, not the decoy request this test seeded", msg.Raw())
	}
}

// A normal exchange is unaffected: its request id is real and must still be on the wire.
func TestAnOrdinaryExchangeStillCarriesItsRequestId(t *testing.T) {
	store := core.NewTrafficStore()
	id, err := store.Put([]byte("GET /real HTTP/1.1\r\nHost: a.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	// A request whose id happens to be 0 is a REAL request and must still be on the wire. This is the
	// case the old shape could not express at all, and the one that makes "absent" ambiguous: the fix
	// is to make the wire say null, never to treat 0 as absent.
	view := exchangeView(&core.Exchange{Host: "a.test", Method: "GET", Path: "/real", Request: core.MsgPtr(id)})
	if view.Request == nil {
		t.Fatal("request = null for an exchange that HAS a request; making the field nullable must not " +
			"turn it into an absence")
	}
	if *view.Request != uint64(id) {
		t.Errorf("request = %d, want %d", *view.Request, id)
	}
	if id != 0 {
		t.Skipf("this run seeded message ids from %d, so it does not exercise the id-0 case this test "+
			"exists for", id)
	}
}

// The asymmetry is the bug. Response has always been nullable and Request has not, so one half of an
// exchange could say "absent" and the other could not — and a consumer reading both had to learn two
// different rules for the same question. One type, one rule.
func TestTheWireShapeTreatsRequestAndResponseAlike(t *testing.T) {
	// Same Go type, so the two halves cannot drift apart again — which is the whole claim, and the
	// reason it is asserted on the type rather than on a value. Whether either half is present
	// depends on the exchange; that they are ASKED THE SAME WAY does not.
	view := exchangeView(&core.Exchange{Host: "a.test", Method: "GET", Path: "/x"})
	if got, want := reflectTypeOf(view.Request), reflectTypeOf(view.Response); got != want {
		t.Errorf("Request is %s and Response is %s; a consumer must not need two rules to ask "+
			"'does this half exist'", got, want)
	}
	// And the two halves answer independently: a request present with no response is a state the
	// shape has to express, which it could not when one half was a bare number.
	onlyRequest := exchangeView(&core.Exchange{Host: "a.test", Request: core.MsgPtr(3)})
	if onlyRequest.Request == nil || onlyRequest.Response != nil {
		t.Errorf("request-only exchange came out as request=%v response=%v; the halves must be able "+
			"to answer independently", onlyRequest.Request, onlyRequest.Response)
	}
}

// A tunnel row and a normal row must be distinguishable on the wire alone, because that is all the
// UI has.
func TestATunnelRowAndANormalRowAreDistinguishableOnTheWire(t *testing.T) {
	store := core.NewTrafficStore()
	id, _ := store.Put([]byte("GET /real HTTP/1.1\r\nHost: a.test\r\n\r\n"), core.DirectionRequest)

	tunnel := exchangeView(&core.Exchange{Host: "t.test", Method: "CONNECT"})
	normal := exchangeView(&core.Exchange{Host: "a.test", Method: "GET", Path: "/real", Request: core.MsgPtr(id)})

	if (tunnel.Request == nil) == (normal.Request == nil) {
		t.Error("a tunnel row and an ordinary row are indistinguishable by their request id, so the " +
			"UI cannot tell 'no request' from 'a request'")
	}
}

// The JSON must not encode the absence as 0. A number the UI cannot distinguish from a real id is the
// defect, whatever the Go type says.
func TestTheWireJSONCarriesNullRatherThanZeroForAnAbsentRequest(t *testing.T) {
	rec := httptestNewRecorder()
	view := exchangeView(&core.Exchange{Host: "t.test", Method: "CONNECT"})
	writeJSON(rec, http.StatusOK, view)

	var decoded struct {
		Request *uint64 `json:"request"`
	}
	if err := jsonUnmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Request != nil {
		t.Errorf("the wire carries request=%d for a tunnel with no request; the UI reads that as a "+
			"message id and fetches whatever is there", *decoded.Request)
	}
}
