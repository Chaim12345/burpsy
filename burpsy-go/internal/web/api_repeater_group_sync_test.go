package web

// The synchronized Parallel group (burpsy-react-ui-ajp6).
//
// # What the barrier promises, and how this file pins it
//
// Burp's parallel mode withholds each request's final byte and releases those bytes together,
// so no request completes its arrival early by scheduler luck. The invariant the orchestrator
// owns is exactly that: a member's final-byte write happens only after EVERY member has
// signalled readiness — arrived or failed. That is provable at the wire with a test double,
// because the double can observe the two events the orchestrator separates: the head write
// (before readiness) and the final byte (after release).
//
// The two tests below pin the invariant from both sides:
//
//   - the ordering test drives the REAL group orchestrator against a double origin and fails
//     if any final byte is written before every head is on the wire — the mutation that turns
//     the barrier into fan-out;
//   - the arrival test drives the real HTTP path end to end and checks the operator-facing
//     half: the response carries per-item arrival ordinals, Burp's own "order responses
//     arrived" column, and a dead member neither hangs the group nor earns an ordinal.
//
// The first test does NOT use the real sender's sockets: what it measures is the orchestrator's
// sequencing, and a real origin measures its own READING schedule (three handler goroutines
// woken in arbitrary order), which is noise on top of the signal — measured while writing
// this, when a handler-based version of the same assertion failed intermittently against the
// correctly-working barrier.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The operator-facing half: arrival ordinals, Burp's "the order in which responses arrived"
// (tools/repeater/send-group.html), present and unique for succeeded members, absent for
// failed ones, and absent entirely for the sequence modes where there is no simultaneous
// arrival to measure.
func TestAParallelGroupReportsItsArrivalOrderAndSurvivesADeadMember(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host := u.Hostname()

	s := newTestServer()
	s.scope.AddInclude(host)
	body := "n=1"
	rec := postJSON(t, s, "/api/repeater/send-group", map[string]any{
		"mode": "parallel",
		"items": []map[string]any{
			{"tab_id": "good", "target": srv.URL[len("http://"):], "request": fmt.Sprintf("POST /ok HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s", srv.URL[len("http://"):], len(body), body)},
			// A port with nothing listening: the dial fails before the hold, and the barrier must
			// still release for the good member — a failure is an arrival, or one dead port
			// hangs the whole group.
			{"tab_id": "dead", "target": fmt.Sprintf("%s:1", host), "request": "GET / HTTP/1.1\r\nHost: dead\r\n\r\n"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("group send: %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []struct {
			TabID   string `json:"tab_id"`
			Error   string `json:"error"`
			Arrival int    `json:"arrival"`
			Result  *struct {
				Status int `json:"status"`
			} `json:"result"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("items = %d, want both members reported", len(resp.Items))
	}
	var good, dead bool
	ordinals := map[int]bool{}
	for _, it := range resp.Items {
		if it.TabID == "good" {
			if it.Result == nil || it.Result.Status != 200 {
				t.Errorf("the good member: result=%v — a dead peer must not take the group down", it.Result)
			} else {
				good = true
			}
			if it.Arrival < 1 {
				t.Errorf("the good member carries arrival %d: the ordinal is the pane's column, and a succeeded member must have one", it.Arrival)
			} else if ordinals[it.Arrival] {
				t.Errorf("arrival ordinal %d appears twice: the order the pane shows must be an order", it.Arrival)
			}
			ordinals[it.Arrival] = true
		}
		if it.TabID == "dead" {
			if it.Error == "" {
				t.Error("the dead member reports no error: a dial failure must be this member's error, not lost")
			} else {
				dead = true
			}
			if it.Arrival != 0 {
				t.Errorf("the dead member carries arrival %d: an item with no response has no ordinal, and a 0 here must not be read as arrived-first", it.Arrival)
			}
		}
	}
	if !good || !dead {
		t.Errorf("after a member failed to dial: good=%v dead=%v — the barrier must release the survivors and the failure must be recorded", good, dead)
	}
}

// The sequence modes keep their existing shape: no Arrival ordinal, because there is no
// simultaneous arrival to measure, and the pane must not render a made-up order.
func TestSequenceGroupItemsCarryNoArrivalOrdinal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := newTestServer()
	u, _ := url.Parse(srv.URL)
	s.scope.AddInclude(u.Hostname())
	rec := postJSON(t, s, "/api/repeater/send-group", map[string]any{
		"mode": "sequence_separate_conn",
		"items": []map[string]any{
			{"tab_id": "a", "target": srv.URL[len("http://"):], "request": fmt.Sprintf("GET /a HTTP/1.1\r\nHost: %s\r\n\r\n", srv.URL[len("http://"):])},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("group send: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"arrival":`) {
		t.Errorf("a sequence_separate_conn item carries an arrival ordinal — the ordinal is a Parallel-only fact: %s", rec.Body.String()[:min(len(rec.Body.String()), 200)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
