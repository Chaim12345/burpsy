package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The wire shapes are the Rust web layer's contract (crates/web/src/lib.rs: PointsReq/PointView
// :792-835, RunReq/RunView :837-947, AttemptView :900-910) as consumed by the bundled UI's
// intruder.ts. These tests pin that contract over HTTP: the handlers are what stand between the
// UI and the engine, and the JSON here is what the UI parses.

type wirePoint struct {
	Index   int    `json:"index"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Offset  int    `json:"offset"`
	Len     int    `json:"len"`
	Current string `json:"current"`
}

type wireDropReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type wirePayloadSetView struct {
	Kind       string           `json:"kind"`
	Count      int              `json:"count"`
	Total      uint64           `json:"total"`
	TotalExact bool             `json:"total_exact"`
	Truncated  bool             `json:"truncated"`
	MaxCount   int              `json:"max_count"`
	Skipped    int              `json:"skipped"`
	Dropped    []wireDropReason `json:"dropped"`
}

type wireBucketExample struct {
	FirstOrdinal int      `json:"first_ordinal"`
	Payloads     []string `json:"payloads"`
}

type wireRunReport struct {
	Report struct {
		Kind         string `json:"kind"`
		Combinations uint64 `json:"combinations"`
		MaxRequests  int    `json:"max_requests"`
		Planned      int    `json:"planned"`
		Sent         int    `json:"sent"`
		Failed       int    `json:"failed"`
		Truncated    bool   `json:"truncated"`
		Attempts     []struct {
			Ordinal int `json:"ordinal"`
		} `json:"attempts"`
	} `json:"report"`
	Examples    []wireBucketExample  `json:"examples"`
	PayloadSets []wirePayloadSetView `json:"payload_sets"`
}

type wireAttempt struct {
	Payload     string  `json:"payload"`
	Status      *int    `json:"status"`
	Len         int     `json:"len"`
	DurationMs  uint64  `json:"duration_ms"`
	Error       *string `json:"error"`
	GrepMatched *bool   `json:"grep_matched"`
	GrepExtract *string `json:"grep_extract"`
}

// postJSONInto runs one request through the server's mux and decodes a 2xx body into out,
// returning the status code. Distinct from the package's postJSON helper, which only returns the
// recorder.
func postJSONInto(t *testing.T, srv *Server, path string, body any, out any) int {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(http.MethodPost, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code >= 200 && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %d response %q: %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code
}

// requestMessage stores a raw request and returns its message id.
func requestMessage(t *testing.T, store *core.TrafficStore, raw string) uint64 {
	t.Helper()
	id, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("store request: %v", err)
	}
	return uint64(id)
}

// echoServer answers every request with its request line echoed back, so a
// payload spliced into the URL lands in the response at its own length. This is
// the Rust web layer's own test trick (crates/web/src/lib.rs): the report
// buckets responses by (status, length, reflected), and attacks run
// concurrently up to max_in_flight, so two same-length payloads collapse into
// one bucket whose `first_ordinal` is whichever send finished first — racy.
// Distinct-length payloads against an echo target give each payload its own
// bucket, which makes the examples' ordinal→payload resolution deterministic.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				body := strings.TrimSuffix(line, "\r\n")
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestIntruderPointsServesTheWireShape(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	id := requestMessage(t, store, "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	var points []wirePoint
	if code := postJSONInto(t, srv, "/api/intruder/points", map[string]any{
		"msg_id": id,
		"all":    false,
	}, &points); code != http.StatusOK {
		t.Fatalf("points status = %d, want 200", code)
	}

	var q *wirePoint
	for i := range points {
		if points[i].Kind == "url_param_value" && points[i].Label == "q" {
			q = &points[i]
			break
		}
	}
	if q == nil {
		t.Fatalf("no url_param_value point for q in %+v", points)
	}
	if q.Current != "alpha" {
		t.Fatalf("current = %q, want the existing query value alpha", q.Current)
	}
	if q.Offset < 0 || q.Len <= 0 || q.Index < 0 {
		t.Fatalf("point must carry byte span and sequential index: %+v", q)
	}
	// The index is the position in the returned slice, not a byte offset.
	for i, p := range points {
		if p.Index != i {
			t.Fatalf("point[%d].index = %d, want sequential", i, p.Index)
		}
	}
}

func TestIntruderPointsForAMissingMessageIs404(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	if code := postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": 999}, &struct{}{}); code != http.StatusNotFound {
		t.Fatalf("points for a missing message = %d, want 404", code)
	}
}

// The run endpoint answers the full RunView — report, examples and per-set counting — whenever
// the operator names a mode or a generator. That is the shape the UI renders for anything beyond
// the one-position legacy form.
func TestIntruderRunServesTheFullReport(t *testing.T) {
	// The echo target + distinct-length payloads matter: two same-length
	// payloads would collapse into one result bucket, and its `first_ordinal`
	// (hence its example) is whichever concurrent send finished first — racy.
	addr := echoServer(t)

	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points)
	var qIndex int = -1
	for i := range points {
		if points[i].Kind == "url_param_value" && points[i].Label == "q" {
			qIndex = i
			break
		}
	}
	if qIndex < 0 {
		t.Fatalf("no q point in %+v", points)
	}

	var out wireRunReport
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{qIndex},
		"payload_sets": [][]string{{"good", "nicely"}},
		"max_requests": 100,
		"rps":          1000,
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d, want 200", code)
	}
	if out.Report.Kind != "sniper" {
		t.Fatalf("report.kind = %q, want sniper", out.Report.Kind)
	}
	if out.Report.Planned != 2 || out.Report.Sent != 2 {
		t.Fatalf("planned/sent = %d/%d, want 2/2", out.Report.Planned, out.Report.Sent)
	}
	if len(out.PayloadSets) != 1 {
		t.Fatalf("payload_sets = %+v, want one set", out.PayloadSets)
	}
	ps := out.PayloadSets[0]
	if ps.Kind != "list" || ps.Count != 2 || ps.Total != 2 || !ps.TotalExact {
		t.Fatalf("payload_sets[0] = %+v, want an honest list set of 2", ps)
	}
	if ps.Skipped != 0 || len(ps.Dropped) != 0 {
		t.Fatalf("payload_sets[0] must report no drops: %+v", ps)
	}
	if len(out.Examples) == 0 {
		t.Fatalf("examples empty; every bucket must resolve to payloads")
	}
	// Each payload echoes back at its own length, so each gets its own bucket
	// and the examples cover both — after sorting, order is not racy.
	var got []string
	for _, ex := range out.Examples {
		if len(ex.Payloads) > 0 {
			got = append(got, ex.Payloads[0])
		}
	}
	sort.Strings(got)
	if want := []string{"good", "nicely"}; !slices.Equal(got, want) {
		t.Fatalf("examples resolve to %v, want every payload %v", got, want)
	}
}

// Examples must name every attempt ordinal the report kept, not only the first ordinal of each
// bucket — and the name must be the payload actually sent, post payload-processing-rule, not the
// pre-rule text the browser typed. add_prefix is count-preserving (it drops nothing), so both
// payloads still land in the request; and both prefixed payloads are the same length, so the echo
// target puts them in the *same* bucket — meaning only one of the two ordinals is a bucket's
// first_ordinal. The other's payload can only come from a wire example, not from the bucket loop.
// This pins the fix for burpsy-react-ui-fvx: without it, the second ordinal's example would be
// missing and the bundled UI would fall back to the browser's stale pre-rule text.
func TestIntruderRunExamplesCoverEveryAttemptWithThePostRulePayload(t *testing.T) {
	addr := echoServer(t)

	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points)
	var qIndex int = -1
	for i := range points {
		if points[i].Kind == "url_param_value" && points[i].Label == "q" {
			qIndex = i
			break
		}
	}
	if qIndex < 0 {
		t.Fatalf("no q point in %+v", points)
	}

	var out wireRunReport
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{qIndex},
		"payload_sets": [][]string{{"aa", "bb"}},
		"payload_rules": []map[string]any{
			{"rule": "add_prefix", "text": "X"},
		},
		"max_requests": 100,
		"rps":          1000,
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d, want 200", code)
	}
	if len(out.Report.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2 (aa and bb both survive add_prefix)", len(out.Report.Attempts))
	}
	// Both prefixed payloads ("Xaa", "Xbb") are 3 bytes, so the echo target puts them in one
	// bucket: at most one of the two ordinals is that bucket's first_ordinal.
	byOrdinal := make(map[int][]string, len(out.Examples))
	for _, ex := range out.Examples {
		byOrdinal[ex.FirstOrdinal] = ex.Payloads
	}
	want := map[int]string{0: "Xaa", 1: "Xbb"}
	for _, a := range out.Report.Attempts {
		pl, ok := byOrdinal[a.Ordinal]
		if !ok || len(pl) == 0 {
			t.Fatalf("attempt %d has no example in %+v", a.Ordinal, out.Examples)
		}
		if pl[0] != want[a.Ordinal] {
			t.Fatalf("attempt %d example = %q, want the post-rule payload %q (not the pre-rule browser text)", a.Ordinal, pl[0], want[a.Ordinal])
		}
	}
}

// A request with no mode, no payload_sets and no payload_sources is the bundled UI's one-position
// form, and gets back the flat per-attempt array. Same engine, projected.
func TestIntruderRunLegacyFormServesTheFlatArray(t *testing.T) {
	addr, seen := recordServer(t)

	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points)
	var qIndex int = -1
	for i := range points {
		if points[i].Kind == "url_param_value" && points[i].Label == "q" {
			qIndex = i
			break
		}
	}
	if qIndex < 0 {
		t.Fatalf("no q point in %+v", points)
	}

	var rows []wireAttempt
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":   id,
		"target":   "http://" + addr,
		"points":   []int{qIndex},
		"payloads": []string{"good", "nice"},
		"rps":      1000,
	}, &rows)
	if code != http.StatusOK {
		t.Fatalf("run status = %d, want 200", code)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want two attempts", rows)
	}
	for i, row := range rows {
		if row.Status == nil || *row.Status != 200 {
			t.Fatalf("rows[%d].status = %v, want 200", i, row.Status)
		}
	}
	// Both requests went out against the target.
	if len(*seen) != 2 {
		t.Fatalf("the target saw %d requests, want 2: %v", len(*seen), *seen)
	}
}

// A whole-host exclude must be refused up front with 403 — attacking a host outside the
// engagement is the one intruder bug with consequences outside the tool.
func TestIntruderRunForbidsAWholeHostOutOfScope(t *testing.T) {
	addr, _ := recordServer(t)
	scope := core.NewScope()
	scope.AddExclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{0},
		"payload_sets": [][]string{{"x"}},
	}, &struct{}{})
	if code != http.StatusForbidden {
		t.Fatalf("out-of-scope host = %d, want 403", code)
	}
}

// The per-request gate must still catch a payload that rewrites the path out of scope, even
// though the host is authorised: only the actual outbound bytes can be trusted.
func TestIntruderRunRefusesAPayloadThatRewritesThePathOutOfScope(t *testing.T) {
	addr, seen := recordServer(t)

	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/admin"))

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	// Path positions are off under the default config, so the UI/operator asks for them all.
	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": true}, &points)
	var pathIndex int = -1
	for i := range points {
		if points[i].Kind == "url_path_filename" {
			pathIndex = i
			break
		}
	}
	if pathIndex < 0 {
		t.Fatalf("no url_path_filename point in %+v", points)
	}

	var out wireRunReport
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"all":          true,
		"mode":         "sniper",
		"points":       []int{pathIndex},
		"payload_sets": [][]string{{"good", "admin/delete-all"}},
		"max_requests": 100,
		"rps":          1000,
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d, want 200 (the refusal is per-attempt, not per-run)", code)
	}
	if out.Report.Sent != 1 || out.Report.Failed != 1 {
		t.Fatalf("sent/failed = %d/%d, want the out-of-scope payload refused, not sent", out.Report.Sent, out.Report.Failed)
	}
	if len(*seen) != 1 || (*seen)[0] != "GET /good HTTP/1.1" {
		t.Fatalf("the target saw %v, want only the in-scope /good", *seen)
	}
}

// The flat-array form keeps the original 500-request cap; the report form reports the operator's
// own bound. Both must be surfaced, never silent.
func TestIntruderRunRefusesAnUnknownMode(t *testing.T) {
	addr, _ := recordServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search?q=a HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intruder/run", strings.NewReader(`{
		"msg_id": `+strconv.Itoa(int(id))+`,
		"target": "http://`+addr+`",
		"mode": "warp_drive",
		"points": [0],
		"payload_sets": [["x"]]
	}`))
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown mode = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "warp_drive") {
		t.Fatalf("the 400 must name the bad mode: %s", rec.Body.String())
	}
}

func TestIntruderRunRefusesAPointOutOfRange(t *testing.T) {
	addr, _ := recordServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search?q=a HTTP/1.1\r\nHost: shop.test\r\n\r\n")

	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{42},
		"payload_sets": [][]string{{"x"}},
	}, &struct{}{})
	if code != http.StatusBadRequest {
		t.Fatalf("point 42 of 1 = %d, want 400", code)
	}
}
