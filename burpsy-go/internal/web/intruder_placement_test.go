package web

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureTarget is a local HTTP/1.1 listener that records every request it receives — head and
// Content-Length body, byte for byte — and answers with whatever respond returns for it. The Intruder
// tests in this phase assert on what reached the wire, so the listener keeps the exact bytes.
type captureTarget struct {
	addr string
	mu   sync.Mutex
	reqs []string
}

func startCaptureTarget(t *testing.T, respond func(req string) string) *captureTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ct := &captureTarget{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				var head strings.Builder
				length := 0
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head.WriteString(l)
					if l == "\r\n" {
						break
					}
					if name, value, ok := strings.Cut(strings.TrimRight(l, "\r\n"), ":"); ok && strings.EqualFold(name, "Content-Length") {
						length, _ = strconv.Atoi(strings.TrimSpace(value))
					}
				}
				body := make([]byte, length)
				if _, err := io.ReadFull(br, body); err != nil {
					return
				}
				req := head.String() + string(body)
				ct.mu.Lock()
				ct.reqs = append(ct.reqs, req)
				ct.mu.Unlock()
				io.WriteString(c, respond(req))
			}(c)
		}
	}()
	return ct
}

// requests is every request received so far, sorted so concurrent arrival order does not matter.
func (ct *captureTarget) requests() []string {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	out := append([]string(nil), ct.reqs...)
	sort.Strings(out)
	return out
}

// okResponse answers 200 with body, framed by Content-Length and closed.
func okResponse(body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// pointsWire is PointView as the browser receives it.
type pointsWire struct {
	Index     int    `json:"index"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Offset    int    `json:"offset"`
	Len       int    `json:"len"`
	Current   string `json:"current"`
	Placement string `json:"placement"`
}

// ---- 1krs: Automatic payload placement — Append to base parameter value ----------------------------

// /points (what the UI shows) and /run (what the attack sends) take the same payload_placement, and
// the spans the first reports are exactly where the second puts the payload: the listener receives the
// base request with each payload inserted at /points' offset.
func TestIntruderAppendPlacementPointsAndRunAgreeOnTheWire(t *testing.T) {
	target := startCaptureTarget(t, func(string) string { return okResponse("ok") })
	srv, id, _ := intruderSendFixture(t, "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	base := "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n"

	var pts []pointsWire
	if code := postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "payload_placement": "append"}, &pts); code != http.StatusOK {
		t.Fatalf("points = %d", code)
	}
	var q *pointsWire
	for i := range pts {
		if pts[i].Label == "q" && pts[i].Kind == "url_param_value" {
			q = &pts[i]
		}
	}
	if q == nil {
		t.Fatalf("no q in %+v", pts)
	}
	wantOff := strings.Index(base, "alpha") + len("alpha")
	if q.Placement != "append" || q.Len != 0 || q.Offset != wantOff || q.Current != "alpha" {
		t.Fatalf("q = %+v, want placement append, len 0 at offset %d, current alpha", *q, wantOff)
	}

	run := func(placement string) []string {
		t.Helper()
		before := len(target.requests())
		body := map[string]any{
			"msg_id": id, "target": "http://" + target.addr, "mode": "sniper",
			"points": []int{q.Index}, "payload_sets": [][]string{{"X1", "Y22"}},
			"rps": 1000, "max_in_flight": 1, "retries": 0,
		}
		if placement != "" {
			body["payload_placement"] = placement
		}
		var view sendSettingsView
		if code := postJSONInto(t, srv, "/api/intruder/run", body, &view); code != http.StatusOK {
			t.Fatalf("run(%q) = %d", placement, code)
		}
		if view.Report.Sent != 2 {
			t.Fatalf("run(%q) sent %d, want 2", placement, view.Report.Sent)
		}
		got := target.requests()
		if len(got) != before+2 {
			t.Fatalf("listener saw %d new requests, want 2", len(got)-before)
		}
		return got
	}

	got := run("append")
	for _, p := range []string{"X1", "Y22"} {
		want := base[:q.Offset] + p + base[q.Offset:]
		found := false
		for _, r := range got {
			if strings.HasPrefix(r, strings.SplitN(want, "\r\n", 2)[0]+"\r\n") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no request carried %q appended at /points' offset; listener saw %q", p, got)
		}
	}

	// Control: the same index with no placement replaces the value, which is the behaviour every API
	// client had before the field existed.
	got = run("")
	sawReplace := false
	for _, r := range got {
		if strings.HasPrefix(r, "GET /search?q=X1&page=2 ") {
			sawReplace = true
		}
	}
	if !sawReplace {
		t.Fatalf("an absent payload_placement must replace; listener saw %q", got)
	}
}

func TestIntruderUnknownPayloadPlacementIsRefusedOnBothRoutes(t *testing.T) {
	srv, id, _ := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	for _, path := range []string{"/api/intruder/points", "/api/intruder/run"} {
		var sink any
		code := postJSONInto(t, srv, path, map[string]any{
			"msg_id": id, "target": "http://127.0.0.1:1", "points": []int{0},
			"payload_sets": [][]string{{"a"}}, "payload_placement": "prepend",
		}, &sink)
		if code != http.StatusBadRequest {
			t.Fatalf("%s with payload_placement prepend = %d, want 400", path, code)
		}
	}
}

// A manual marker that ends exactly where an appended position inserts would make the request depend
// on the splice order. It is refused, naming both, rather than spliced one way or dropped.
func TestIntruderManualMarkerTouchingAnAppendedPositionIsRefused(t *testing.T) {
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	srv, id, _ := intruderSendFixture(t, raw)
	end := strings.Index(raw, "alpha") + len("alpha")
	body := map[string]any{
		"msg_id": id, "target": "http://127.0.0.1:1", "mode": "pitchfork",
		"points": []int{0}, "manual_points": []map[string]int{{"start": end - 2, "end": end}},
		"payload_sets": [][]string{{"a"}, {"b"}}, "payload_placement": "append",
	}
	if got := httpBody(t, srv, body); !strings.Contains(got, "overlaps discovered point") {
		t.Fatalf("response = %q, want the touching manual marker refused as an overlap", got)
	}
	// Under replace the same marker sits inside the value, which was always an overlap.
	body["payload_placement"] = "replace"
	if got := httpBody(t, srv, body); !strings.Contains(got, "overlaps discovered point") {
		t.Fatalf("replace response = %q, want an overlap refusal", got)
	}
}
