package web

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- nqww: Burp's "Store requests" / "Store responses" through POST /api/intruder/run ---------------

type storageView struct {
	Report struct {
		Sent            int  `json:"sent"`
		RequestsStored  bool `json:"requests_stored"`
		ResponsesStored bool `json:"responses_stored"`
		Attempts        []struct {
			RequestID  *uint64 `json:"request_id"`
			ResponseID *uint64 `json:"response_id"`
			Status     *int    `json:"status"`
		} `json:"attempts"`
		Buckets []struct {
			Count             int     `json:"count"`
			ExampleRequestID  *uint64 `json:"example_request_id"`
			ExampleResponseID *uint64 `json:"example_response_id"`
		} `json:"buckets"`
	} `json:"report"`
}

// Each switch removes exactly its half from the traffic store and nothing else from the attack: every
// request is still sent and bucketed, the ids of the half not stored go out null, the report says it was
// the setting, and the session jar keeps learning.
func TestIntruderStorageSwitchesKeepTheirHalfOutOfTheStore(t *testing.T) {
	target := startCaptureTarget(t, statusByPayload)
	_, portStr, _ := net.SplitHostPort(target.addr)
	port, _ := strconv.Atoi(portStr)
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	start := strings.Index(raw, "alpha")
	// Three payloads of different lengths: three buckets, three exemplars when everything is stored.
	payloads := []string{"okA", "okBB", "okCCC"}

	run := func(fields map[string]any) (storageView, json.RawMessage, int, *session.Coordinator) {
		t.Helper()
		scope := core.NewScope()
		scope.AddInclude("127.0.0.1")
		store := core.NewTrafficStore()
		srv := NewServer(store, scope)
		coord := session.NewCoordinator(zap.NewNop())
		srv.WithSessionCoordinator(coord)
		id := requestMessage(t, store, raw)
		before, _ := store.Count()
		body := map[string]any{
			"msg_id": id, "target": "http://" + target.addr, "mode": "sniper",
			"manual_points": []map[string]int{{"start": start, "end": start + len("alpha")}},
			"payload_sets":  [][]string{payloads}, "rps": 1000, "max_in_flight": 1, "retries": 0,
		}
		for k, v := range fields {
			body[k] = v
		}
		var out json.RawMessage
		if code := postJSONInto(t, srv, "/api/intruder/run", body, &out); code != http.StatusOK {
			t.Fatalf("run(%v) = %d: %s", fields, code, out)
		}
		var view storageView
		if err := json.Unmarshal(out, &view); err != nil {
			t.Fatal(err)
		}
		after, _ := store.Count()
		return view, out, after - before, coord
	}

	all, _, grewAll, _ := run(nil)
	if !all.Report.RequestsStored || !all.Report.ResponsesStored || grewAll != 6 {
		t.Fatalf("defaults: stored req=%v resp=%v, store grew %d — want both on and 6 messages (3 requests, 3 exemplar responses)",
			all.Report.RequestsStored, all.Report.ResponsesStored, grewAll)
	}

	noResp, wire, grew, coord := run(map[string]any{"store_responses": false})
	if noResp.Report.Sent != 3 || len(noResp.Report.Buckets) != 3 {
		t.Fatalf("store_responses:false sent %d into %d buckets, want the whole attack still run and bucketed", noResp.Report.Sent, len(noResp.Report.Buckets))
	}
	if grew != 3 || noResp.Report.ResponsesStored || !noResp.Report.RequestsStored {
		t.Fatalf("store_responses:false: store grew %d (want the 3 requests only), responses_stored=%v requests_stored=%v",
			grew, noResp.Report.ResponsesStored, noResp.Report.RequestsStored)
	}
	for _, b := range noResp.Report.Buckets {
		if b.ExampleResponseID != nil || b.ExampleRequestID == nil {
			t.Fatalf("bucket %+v: want a null response id and a stored request", b)
		}
	}
	if !strings.Contains(string(wire), `"example_response_id":null`) {
		t.Fatalf("the marshalled report does not carry example_response_id:null: %s", wire)
	}
	if jar := coord.CookieHeader("127.0.0.1", uint16(port), false, "/"); !strings.Contains(jar, "seen_okA=1") {
		t.Fatalf("jar = %q: an attack that does not store responses must still feed the session jar", jar)
	}

	noReq, _, grew, _ := run(map[string]any{"store_requests": false})
	if grew != 3 || noReq.Report.RequestsStored || !noReq.Report.ResponsesStored {
		t.Fatalf("store_requests:false: store grew %d (want the 3 responses only), requests_stored=%v responses_stored=%v",
			grew, noReq.Report.RequestsStored, noReq.Report.ResponsesStored)
	}
	for _, a := range noReq.Report.Attempts {
		if a.RequestID != nil {
			t.Fatalf("attempt %+v carries a request id with store_requests off", a)
		}
	}

	neither, _, grew, _ := run(map[string]any{"store_requests": false, "store_responses": false})
	if grew != 0 || neither.Report.Sent != 3 {
		t.Fatalf("both off: store grew %d, sent %d — want nothing stored and everything sent", grew, neither.Report.Sent)
	}
}
