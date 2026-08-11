package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// HONEST-05.
//
// core.ExchangeID is a uint64 handed out by an incrementing counter starting at zero, so the first
// request a session captures is exchange 0 — the top row of HTTP history, and the one an operator
// reaches for first. Both audit routes used to treat that id as "absent": /api/audit/{id} answered
// 400 "Invalid exchange id" for a perfectly well-formed id, and /api/scanner/audit answered 400
// "exchange_id is required" for a field that had been supplied. The one row least likely to be
// missed was the one row that could not be audited, and the error blamed the caller for it.
//
// Both routes are covered, because they had the same bug spelled two different ways and fixing only
// the path form would leave the legacy alias refusing the row the new one accepts.
func Test_exchange_zero_can_be_audited_HONEST_05(t *testing.T) {
	for _, route := range []string{"path", "legacy"} {
		t.Run(route, func(t *testing.T) {
			s := newTestServer()
			reqID, err := s.store.Put([]byte("GET /first HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
			if err != nil {
				t.Fatalf("put request: %v", err)
			}
			respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\n<html>hello</html>"), core.DirectionResponse)
			if err != nil {
				t.Fatalf("put response: %v", err)
			}
			ex := &core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/first"}
			s.store.AddExchange(ex)
			// Asserted, not assumed: if the store ever stopped counting from zero this test would
			// still pass while proving nothing, which is the failure mode it exists to catch.
			if ex.ID != 0 {
				t.Fatalf("the first exchange added got id %d, want 0 — ids are a dense counter from zero", ex.ID)
			}

			var rec = postJSON(t, s, "/api/audit/0", nil)
			if route == "legacy" {
				rec = postJSON(t, s, "/api/scanner/audit", map[string]any{"exchange_id": 0})
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("auditing exchange 0 answered %d (%s), want 200", rec.Code, rec.Body.String())
			}
			var body struct {
				Started    bool            `json:"started"`
				ExchangeID core.ExchangeID `json:"exchange_id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode audit response %q: %v", rec.Body.String(), err)
			}
			if !body.Started || body.ExchangeID != 0 {
				t.Errorf("started = %v, exchange_id = %d; want the audit to have run against exchange 0",
					body.Started, body.ExchangeID)
			}
		})
	}
}

// The other half of the fix, and the reason it is not simply "accept every id".
//
// Removing the zero guard must not make an id that names nothing look auditable. It does not,
// because the refusal was never this handler's job: the engine already answers an unknown id as
// outcome.state "unauditable" with the reason on the wire, which is a fuller reply than a bare 404
// and arrives in the same shape as every successful audit. That behaviour is pinned by
// Test_the_audit_endpoint_names_an_unauditable_exchange; what is pinned here is that the legacy
// alias reaches it too — it used to short-circuit on `exchange_id == 0` before the engine saw
// anything — and that a genuinely malformed id keeps its 400, since "this is not a number" and
// "nothing here has that number" are different complaints.
func Test_an_unknown_exchange_id_reaches_the_engines_refusal_rather_than_a_guard_HONEST_05(t *testing.T) {
	s := newTestServer()
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"path":   postJSON(t, s, "/api/audit/4242", nil),
		"legacy": postJSON(t, s, "/api/scanner/audit", map[string]any{"exchange_id": 4242}),
	} {
		if rec.Code != http.StatusOK {
			t.Errorf("%s route answered %d (%s), want 200 carrying the engine's refusal", name, rec.Code, rec.Body.String())
			continue
		}
		var body struct {
			Outcome struct {
				State string `json:"state"`
				Error string `json:"error"`
			} `json:"outcome"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s route: decode %q: %v", name, rec.Body.String(), err)
		}
		if body.Outcome.State != "unauditable" || body.Outcome.Error == "" {
			t.Errorf("%s route: outcome.state = %q, error = %q; want \"unauditable\" and a named reason",
				name, body.Outcome.State, body.Outcome.Error)
		}
	}
	// A malformed id keeps its 400.
	if rec := postJSON(t, s, "/api/audit/not-a-number", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("POST /api/audit/not-a-number answered %d, want 400", rec.Code)
	}
}
