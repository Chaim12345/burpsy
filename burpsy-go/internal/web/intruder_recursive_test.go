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
