package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's "Request item again" (burpsy-react-ui-2rw7) through its route: the stored attempt request
// is re-sent byte for byte, recorded as Intruder traffic, and answered as a replacement row; a
// request id that names a response, or a target the scope refuses, is a row with its reason.
func TestRequestItemAgainResendsTheStoredAttempt(t *testing.T) {
	var hits atomic.Int64
	var lastPath atomic.Value
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastPath.Store(r.URL.RequestURI())
		io.WriteString(w, "fresh")
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")

	s := newTestServer()
	raw := fmt.Sprintf("GET /item?payload=x%%27 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)

	rec := postJSON(t, s, "/api/intruder/again", map[string]any{"target": origin.URL, "request_ids": []uint64{uint64(reqID), uint64(respID)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Rows []intruderAgainRow `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Rows) != 2 {
		t.Fatalf("rows = %+v", resp.Rows)
	}
	first := resp.Rows[0]
	if first.Error != nil || first.Status == nil || *first.Status != 200 || first.ResponseID == nil || first.OriginalRequestID != uint64(reqID) {
		t.Errorf("re-sent row = %+v", first)
	}
	if hits.Load() != 1 || lastPath.Load() != "/item?payload=x%27" {
		t.Errorf("origin saw %d request(s), last %v; want the stored request once, byte for byte", hits.Load(), lastPath.Load())
	}
	if resp.Rows[1].Error == nil || !strings.Contains(*resp.Rows[1].Error, "no stored request") {
		t.Errorf("a response id was re-sent: %+v", resp.Rows[1])
	}
	found := false
	for _, ex := range s.store.Exchanges() {
		if ex.Source == core.SourceIntruder && ex.Path == "/item?payload=x%27" {
			found = true
		}
	}
	if !found {
		t.Error("the re-sent attempt was not recorded as Intruder traffic")
	}

	// A scope that excludes the origin refuses the send; the row carries the refusal.
	s.scope.AddExclude(strings.Split(host, ":")[0])
	rec = postJSON(t, s, "/api/intruder/again", map[string]any{"target": origin.URL, "request_ids": []uint64{uint64(reqID)}})
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Rows) != 1 || resp.Rows[0].Error == nil || hits.Load() != 1 {
		t.Errorf("an out-of-scope re-send = %+v (origin hits %d), want a refused row and no request", resp.Rows, hits.Load())
	}
}
