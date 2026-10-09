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

// ---- ip2b: the results capture filter through POST /api/intruder/run ---------------------------------

// statusByPayload answers a request whose q value starts with "ok" with 200, everything else with 404,
// and sets a cookie named after the payload, so the jar has something to learn from every response.
func statusByPayload(req string) string {
	line := strings.SplitN(req, " ", 3)[1]
	q := line[strings.Index(line, "q=")+2:]
	status := "404 Not Found"
	if strings.HasPrefix(q, "ok") {
		status = "200 OK"
	}
	body := "reply to " + q
	return "HTTP/1.1 " + status + "\r\nSet-Cookie: seen_" + q + "=1; Path=/\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

func TestIntruderCaptureFilterDiscardsRowsAndStorageButCountsEverything(t *testing.T) {
	target := startCaptureTarget(t, statusByPayload)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	coord := session.NewCoordinator(zap.NewNop())
	srv.WithSessionCoordinator(coord)
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, store, raw)
	start := strings.Index(raw, "alpha")
	messagesBefore, _ := store.Count()

	var body json.RawMessage
	if code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id, "target": "http://" + target.addr, "mode": "sniper",
		"manual_points":  []map[string]int{{"start": start, "end": start + len("alpha")}},
		"payload_sets":   [][]string{{"okA", "nopeB", "okCC", "nopeDD"}},
		"capture_filter": map[string]any{"statuses": []string{"2xx"}},
		"rps":            1000, "max_in_flight": 1, "retries": 0,
	}, &body); code != http.StatusOK {
		t.Fatalf("run = %d: %s", code, body)
	}
	var view struct {
		Report struct {
			Sent      int `json:"sent"`
			Failed    int `json:"failed"`
			Discarded int `json:"discarded"`
			Attempts  []struct {
				Ordinal    int     `json:"ordinal"`
				Status     *int    `json:"status"`
				ResponseID *uint64 `json:"response_id"`
			} `json:"attempts"`
			Buckets []struct {
				Status            *int    `json:"status"`
				Count             int     `json:"count"`
				ExampleResponseID *uint64 `json:"example_response_id"`
				ExampleOrdinal    *int    `json:"example_ordinal"`
			} `json:"buckets"`
			CaptureFilter map[string]any `json:"capture_filter"`
		} `json:"report"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	r := view.Report
	if len(target.requests()) != 4 || r.Sent != 4 {
		t.Fatalf("listener saw %d requests, report sent %d: the filter must never stop a send", len(target.requests()), r.Sent)
	}
	if r.Discarded != 2 || len(r.Attempts)+r.Discarded != r.Sent+r.Failed {
		t.Fatalf("discarded=%d rows=%d sent=%d failed=%d", r.Discarded, len(r.Attempts), r.Sent, r.Failed)
	}
	for _, a := range r.Attempts {
		if a.Status == nil || *a.Status != 200 {
			t.Fatalf("a 404 left a row: %+v", r.Attempts)
		}
	}
	for _, b := range r.Buckets {
		if b.Status != nil && *b.Status == 404 && (b.ExampleResponseID != nil || b.ExampleOrdinal != nil) {
			t.Fatalf("the discarded 404 bucket stored an exemplar: %+v", b)
		}
	}
	// Stored: one request and one response per captured item (each 200 opens its own bucket — the
	// lengths differ), nothing for the discarded 404s.
	messagesAfter, _ := store.Count()
	if got := messagesAfter - messagesBefore; got != 4 {
		t.Fatalf("the store grew by %d messages, want 4 (two captured items, request and response each)", got)
	}
	if got := r.CaptureFilter["statuses"]; got == nil {
		t.Fatalf("report.capture_filter = %v, want the filter echoed", r.CaptureFilter)
	}
	// The jar still learned from a discarded response: the bucket's opening 404 carried seen_nopeB.
	_, portStr, _ := net.SplitHostPort(target.addr)
	port, _ := strconv.Atoi(portStr)
	if jar := coord.CookieHeader("127.0.0.1", uint16(port), false, "/"); !strings.Contains(jar, "seen_nopeB=1") {
		t.Fatalf("jar = %q: a discarded response must still feed the session jar", jar)
	}
}

func TestIntruderCaptureFilterRefusesWhatItCannotApply(t *testing.T) {
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	for name, filter := range map[string]map[string]any{
		"unknown class":     {"statuses": []string{"6xx"}},
		"uncompilable term": {"term": "(", "regex": true},
	} {
		got := httpBody(t, srv, map[string]any{
			"msg_id": id, "target": "http://127.0.0.1:1", "manual_points": points,
			"payload_sets": [][]string{{"x"}}, "mode": "sniper", "capture_filter": filter,
		})
		if !strings.Contains(got, "capture_filter") {
			t.Fatalf("%s: response %q, want a capture_filter refusal", name, got)
		}
	}
}
