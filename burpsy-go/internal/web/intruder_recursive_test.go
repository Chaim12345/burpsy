package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The recursive grep chain over the real run endpoint (ztuu): the request names the payload
// source per position (Burp's own shape — the type is picked in the payload-type menu), and
// the attack walks a response-derived sequence against a live origin. This is the wire the
// bundled UI posts, so the test pins the whole path: source detection, forced serial
// execution, the chain driver, and the derived payloads riding the report.
func Test_intruder_recursive_grep_over_the_run_endpoint(t *testing.T) {
	// A four-row table whose responses name the next key, then a final row that names nothing —
	// the natural end of the exercise (Burp: "the exercise is complete").
	rows := []string{"accounts", "billing", "cards", "end"}
	var hits int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&hits, 1))
		if n <= len(rows) {
			fmt.Fprintf(w, "row %s -> next: %s", r.URL.Query().Get("q"), rows[n-1])
			return
		}
		w.Write([]byte("no more rows"))
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=%%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d,
		"target": "%s:%d",
		"mode": "sniper",
		"points": [0],
		"max_requests": 50,
		"max_in_flight": 10,
		"payload_sources": [{"type": "recursive_grep", "initial": "a", "extract_re": "next: ([a-z]+)", "stop_duplicate": false}]
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Report struct {
			Sent    int      `json:"sent"`
			Failed  int      `json:"failed"`
			Status  string   `json:"status"`
			Chain   []string `json:"chain_payloads"`
			Planned int      `json:"planned"`
		} `json:"report"`
		Examples []struct {
			Payloads []string `json:"payloads"`
		} `json:"examples"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The chain: a -> accounts -> billing -> cards -> end, and "end" is echoed into a response
	// that names nothing, so the chain stops after 5 sends with zero failures. The payload set
	// holds only the initial (planned=1), because the rest are response-derived — the honest
	// account is the chain record, not the set.
	want := []string{"a", "accounts", "billing", "cards", "end"}
	if len(view.Report.Chain) != len(want) {
		t.Fatalf("chain should record %d derived payloads, got %v", len(want), view.Report.Chain)
	}
	for i, p := range want {
		if view.Report.Chain[i] != p {
			t.Fatalf("chain[%d] = %q, want %q (full: %v)", i, view.Report.Chain[i], p, view.Report.Chain)
		}
	}
	if view.Report.Sent != len(want) || view.Report.Failed != 0 {
		t.Fatalf("sent=%d failed=%d, want 5/0", view.Report.Sent, view.Report.Failed)
	}
	if got := atomic.LoadInt32(&hits); got != 5 {
		t.Fatalf("origin saw %d requests, want exactly the 5 chain links", got)
	}

	// The examples table names the derived payloads — plan arithmetic could not, because the
	// payloads only exist because the responses did.
	var sawEnd bool
	for _, ex := range view.Examples {
		for _, p := range ex.Payloads {
			if p == "end" {
				sawEnd = true
			}
		}
	}
	if !sawEnd {
		t.Fatalf("no example row names the derived payload 'end'; examples: %+v", view.Examples)
	}
}

// Both wire forms at once is a contradiction the endpoint refuses by name: the source is what
// the operator sees in the payload-type menu, and a second config in the request field would
// compete with it silently.
func Test_intruder_refuses_recursive_grep_named_twice(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nope"))
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d,
		"target": "%s:%d",
		"mode": "sniper",
		"points": [0],
		"payload_sources": [{"type": "recursive_grep", "initial": "a", "extract_re": "x"}],
		"recursive_grep": {"initial": "b", "extract_re": "y"}
	}`, id, host, port))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("both forms should be refused with 400, got %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "both") {
		t.Fatalf("the refusal should name the conflict, got: %s", strings.TrimSpace(rec.Body.String()))
	}
}

// An extract pattern that does not compile is refused before any request goes out — the same
// discipline grep-match and grep-extract already hold.
func Test_intruder_refuses_a_recursive_grep_pattern_that_does_not_compile(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a refused attack must not reach the wire")
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d,
		"target": "%s:%d",
		"mode": "sniper",
		"points": [0],
		"payload_sources": [{"type": "recursive_grep", "initial": "a", "extract_re": "([unclosed"}]
	}`, id, host, port))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad pattern should be refused with 400, got %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

func hostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	parts := strings.Split(host, ":")
	if len(parts) != 2 {
		t.Fatalf("test origin URL %q is not host:port", srv.URL)
	}
	port := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			t.Fatalf("non-numeric port in %q", srv.URL)
		}
		port = port*10 + int(c-'0')
	}
	return parts[0], port
}

func putMessage(t *testing.T, s *Server, raw []byte, dir core.Direction) uint64 {
	t.Helper()
	id, err := s.store.Put(raw, dir)
	if err != nil {
		t.Fatalf("store.Put: %v", err)
	}
	return uint64(id)
}

func decodeInto(rec *httptest.ResponseRecorder, out any) error {
	return json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(out)
}

// The Grep - Match list over the wire (irt): the response body carries two expressions' worth
// of hits and the report must name the labels and the per-attempt counts. The both-forms trap
// (single grep_match AND a list) is refused — the operator would have typed two expression
// sets and had one silently dropped.
func Test_intruder_grep_match_list_counts_and_refuses_both_forms(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "error error exception quiet")
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d,
		"target": "%s:%d",
		"mode": "sniper",
		"points": [0],
		"payloads": ["a", "b"],
		"grep_match_list": ["error", "exception", "missing"],
		"grep_match_simple": true
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Report struct {
			GrepMatchLabels []string `json:"grep_match_labels"`
			Attempts        []struct {
				GrepMatchCounts []int `json:"grep_match_counts"`
			} `json:"attempts"`
			Buckets []struct {
				GrepMatchTotals []int `json:"grep_match_totals"`
			} `json:"buckets"`
		} `json:"report"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := view.Report
	if len(r.GrepMatchLabels) != 3 || r.GrepMatchLabels[0] != "error" {
		t.Fatalf("labels should carry the expressions as typed, got %v", r.GrepMatchLabels)
	}
	if len(r.Attempts) != 2 || len(r.Attempts[0].GrepMatchCounts) != 3 {
		t.Fatalf("two attempts with three count slots each, got %d attempts, counts %v",
			len(r.Attempts), r.Attempts[0].GrepMatchCounts)
	}
	if r.Attempts[0].GrepMatchCounts[0] != 2 || r.Attempts[0].GrepMatchCounts[1] != 1 || r.Attempts[0].GrepMatchCounts[2] != 0 {
		t.Fatalf("counts should read [2 1 0] for 'error error exception quiet', got %v",
			r.Attempts[0].GrepMatchCounts)
	}
	// Payload "a" reflects in the first response and "b" does not in the second, so the two
	// attempts land in two buckets — each bucket's totals are one response's worth, and their
	// slot-wise sum across buckets is the attack's [4 2 0].
	totalErr := 0
	for _, b := range r.Buckets {
		if len(b.GrepMatchTotals) == 3 {
			totalErr += b.GrepMatchTotals[0]
		}
	}
	if totalErr != 4 {
		t.Fatalf("the buckets together should account for 4 'error' occurrences (2 per response), got %d", totalErr)
	}

	// Both forms at once: refused by name.
	rec2 := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d,
		"target": "%s:%d",
		"mode": "sniper",
		"points": [0],
		"payloads": ["a"],
		"grep_match": "x",
		"grep_match_list": ["error"]
	}`, id, host, port))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("grep_match + grep_match_list should be refused with 400, got %d: %s",
			rec2.Code, strings.TrimSpace(rec2.Body.String()))
	}
	if !strings.Contains(rec2.Body.String(), "same feature") {
		t.Fatalf("the refusal should name the conflict, got: %s", strings.TrimSpace(rec2.Body.String()))
	}
}

// Error handling over the wire (n39): the request names retries and the origin fails once then
// answers; the report carries retries_used and the attempt row carries the eventual answer.
// Burp's bounds travel with it: a negative count and an out-of-range pause are refused.
func Test_intruder_error_handling_retries_over_the_wire(t *testing.T) {
	var calls int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			// Simulate a network failure at the transport: close without responding.
			panic(http.ErrAbortHandler)
		}
		fmt.Fprintf(w, "recovered")
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	runBody := func(extra string) string {
		return fmt.Sprintf(`{
			"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
			"payloads": ["a"], "retry_delay_ms": 0, %s
		}`, id, host, port, extra)
	}

	rec := postJSONRaw(t, s, "/api/intruder/run", runBody(`"retries": 2`))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Report struct {
			Sent        int `json:"sent"`
			Failed      int `json:"failed"`
			RetriesUsed int `json:"retries_used"`
		} `json:"report"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Report.Failed != 0 || view.Report.RetriesUsed < 1 {
		t.Fatalf("the aborted first send should have been retried to success: failed=%d retries=%d",
			view.Report.Failed, view.Report.RetriesUsed)
	}

	// Bounds: negative retries and a pause past Burp's 600000 ceiling are refused.
	if rec := postJSONRaw(t, s, "/api/intruder/run", runBody(`"retries": -1`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("negative retries should be refused, got %d", rec.Code)
	}
	if rec := postJSONRaw(t, s, "/api/intruder/run", runBody(`"retry_delay_ms": 600001`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("retry_delay_ms past 600000 should be refused, got %d", rec.Code)
	}
}

// The baseline over the wire (v34): the report names it, the attack requests' ordinals shift
// by one, and payloadsAt's plan arithmetic is compensated — a payloadsAt called with the
// shifted ordinal would label the baseline row with the first payload.
func Test_intruder_baseline_request_is_item_0_with_shifted_ordinals(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "answer for %s", r.URL.RawQuery)
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payloads": ["one", "two"], "baseline": true
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Report struct {
			Baseline bool `json:"baseline"`
			Sent     int  `json:"sent"`
			Attempts []struct {
				Ordinal int    `json:"ordinal"`
				Payload string `json:"payload"`
			} `json:"attempts"`
		} `json:"report"`
		Examples []struct {
			FirstOrdinal int      `json:"first_ordinal"`
			Payloads     []string `json:"payloads"`
		} `json:"examples"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := view.Report
	if !r.Baseline || r.Sent != 3 {
		t.Fatalf("baseline + two attack requests = 3 sends, got baseline=%v sent=%d", r.Baseline, r.Sent)
	}
	if len(r.Attempts) != 3 {
		t.Fatalf("three rows, got %d", len(r.Attempts))
	}
	if r.Attempts[0].Ordinal != 0 {
		t.Fatalf("item 0 is the baseline, got ordinal=%d", r.Attempts[0].Ordinal)
	}
	// The examples table carries the payloads: ordinal 0 none (baseline), 1 and 2 one/two —
	// the payloadsAt shift is what keeps those labels honest.
	byOrdinal := map[int]string{}
	for _, ex := range view.Examples {
		if len(ex.Payloads) > 0 {
			byOrdinal[ex.FirstOrdinal] = ex.Payloads[0]
		}
	}
	if byOrdinal[0] != "" {
		t.Fatalf("the baseline example names no payload, got %q", byOrdinal[0])
	}
	if byOrdinal[1] != "one" || byOrdinal[2] != "two" {
		t.Fatalf("ordinals 1,2 should carry one,two — the shift keeps payload labels honest, got %q,%q",
			byOrdinal[1], byOrdinal[2])
	}
}
