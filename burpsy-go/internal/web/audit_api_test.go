package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The audit endpoints used to answer `{started: true, exchange_id: N}` whatever happened, which is the
// same reply for a host whose whole check set ran and a host that was never touched. This pins the
// richer body: the two original keys are still there, and the engine's outcome is what makes them mean
// something.
func Test_the_audit_endpoint_reports_what_the_engine_did_not_dispatch(t *testing.T) {
	s := newTestServer()
	reqID, err := s.store.Put([]byte("GET /shop HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\n<html>hello</html>"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	// Two exchanges, and the second one is audited: the route has always rejected id 0 as invalid, so
	// exchange 0 — the first capture of a session — is not addressable through it. That predates the
	// audit engine and is left alone here rather than changed under cover of this test.
	s.store.AddExchange(&core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/first"})
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/shop"}
	s.store.AddExchange(ex)

	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(ex.ID, 10), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/%d: %d", ex.ID, rec.Code)
	}
	var body struct {
		Started       bool   `json:"started"`
		ExchangeID    uint64 `json:"exchange_id"`
		ActiveChecks  int    `json:"active_checks"`
		Unimplemented int    `json:"unimplemented"`
		Summary       string `json:"summary"`
		Outcome       struct {
			State   string `json:"state"`
			Ran     int    `json:"ran"`
			Skipped int    `json:"skipped"`
			NotRun  int    `json:"not_run"`
		} `json:"outcome"`
		Dispositions []struct {
			Disposition    string `json:"disposition"`
			Reason         string `json:"reason"`
			Count          int    `json:"count"`
			StoppedLooking bool   `json:"stopped_looking"`
		} `json:"dispositions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode audit response %q: %v", rec.Body.String(), err)
	}

	if !body.Started || body.ExchangeID != ex.ID {
		t.Errorf("started = %v, exchange_id = %d; the original two keys must survive", body.Started, body.ExchangeID)
	}
	if body.ActiveChecks == 0 {
		t.Error("active_checks = 0, want the size of the check set the engine dispatched")
	}
	// The default ScanConfig switches SSRF on, and nothing implements it. The endpoint has to say so,
	// or a caller reads four configured checks as four checks that produced a verdict.
	if body.Unimplemented != 1 {
		t.Errorf("unimplemented = %d, want 1 (SSRF is on by default with nothing behind it)", body.Unimplemented)
	}
	// The state must be a name, not an ordinal: a stored report has to keep meaning if a state is ever
	// inserted into the middle of the enum.
	if body.Outcome.State != "audited" {
		t.Errorf("outcome.state = %q, want \"audited\"", body.Outcome.State)
	}
	if len(body.Dispositions) != 9 {
		t.Fatalf("dispositions = %d buckets, want the whole nine-way partition", len(body.Dispositions))
	}
	sum, stopped := 0, 0
	for _, d := range body.Dispositions {
		sum += d.Count
		if d.StoppedLooking {
			stopped++
		}
		if d.Reason == "" {
			t.Errorf("bucket %q carries no reason", d.Disposition)
		}
		if d.Disposition == "unsupported" && d.Count != 1 {
			t.Errorf("unsupported bucket = %d, want the 1 unimplemented check", d.Count)
		}
	}
	if sum != body.ActiveChecks {
		t.Errorf("dispositions sum to %d, want the whole check set (%d)", sum, body.ActiveChecks)
	}
	if stopped != 6 {
		t.Errorf("buckets marked as the engine declining to look = %d, want 6", stopped)
	}
	if body.Summary == "" {
		t.Error("summary is empty; it is what a log line and the CLI print")
	}
}

// A refused item must not answer with an empty finding list and nothing else, which is what the
// endpoint did before the engine could name a refusal.
func Test_the_audit_endpoint_names_an_unauditable_exchange(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/audit/4242", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/4242: %d", rec.Code)
	}
	var body struct {
		Outcome struct {
			State string `json:"state"`
			Error string `json:"error"`
		} `json:"outcome"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode audit response %q: %v", rec.Body.String(), err)
	}
	if body.Outcome.State != "unauditable" {
		t.Errorf("outcome.state = %q, want \"unauditable\"", body.Outcome.State)
	}
	if body.Outcome.Error == "" {
		t.Error("a refusal must name itself on the wire, not only in the log")
	}
}
