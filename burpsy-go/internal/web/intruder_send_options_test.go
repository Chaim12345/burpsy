package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Intruder send settings through POST /api/intruder/run (burpsy-react-ui-xixe.1, Phase 1) ------
//
// Every test here drives the real route against a real local listener and counts on the listener's
// side, because the settings are claims about what reached the wire.

// intruderSendFixture stores a base request and returns a server and the request's message id, with
// the payload position marked over "pha" in the query.
func intruderSendFixture(t *testing.T, raw string) (*Server, uint64, []map[string]int) {
	t.Helper()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, raw)
	start := strings.Index(raw, "pha")
	if start < 0 {
		t.Fatalf("fixture request has no \"pha\" to mark: %q", raw)
	}
	return srv, id, []map[string]int{{"start": start, "end": start + 3}}
}

// runView is the part of the report these tests read, decoded from the marshalled bytes.
type sendSettingsView struct {
	Report struct {
		Sent   int `json:"sent"`
		Failed int `json:"failed"`
	} `json:"report"`
	ConnectionsOpened *int64 `json:"connections_opened"`
	ConnectionsReused *int64 `json:"connections_reused"`
	HostHeaderUpdated bool   `json:"host_header_updated"`
	HostHeaderSkipped string `json:"host_header_skipped"`
}

// ---- mmca: response_timeout_ms --------------------------------------------------------------------

// Each request in the attack is bounded by response_timeout_ms, inside the attempt's total timeout_ms,
// and the shared network settings are untouched.
func TestAnIntruderResponseTimeoutBoundsEveryRequest(t *testing.T) {
	addr, accepts := silentListener(t)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	before := srv.sender.Network()
	rec, elapsed := postJSONWithin(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":              id,
		"target":              "http://" + addr,
		"mode":                "sniper",
		"manual_points":       points,
		"payload_sets":        [][]string{{"a", "b"}},
		"rps":                 1000,
		"max_in_flight":       2,
		"retries":             0,
		"timeout_ms":          5000,
		"response_timeout_ms": 200,
	}, 15*time.Second)
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d (%s)", rec.Code, rec.Body.String())
	}
	var view sendSettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Report.Failed != 2 || accepts.Load() != 2 {
		t.Fatalf("failed=%d accepts=%d, want both requests sent and both failed: %s", view.Report.Failed, accepts.Load(), rec.Body.String())
	}
	// Two requests at concurrency 2, each bounded at 200ms. timeout_ms (5s) is what a regression
	// falls back to.
	if elapsed > 3*time.Second {
		t.Fatalf("response_timeout_ms=200 did not bound the attack's requests: the run took %s", elapsed)
	}
	if !strings.Contains(rec.Body.String(), "response timeout") {
		t.Fatalf("the report's errors do not name the response timeout: %s", rec.Body.String())
	}
	if after := srv.sender.Network(); !reflect.DeepEqual(before, after) {
		t.Fatal("an attack's response timeout changed the shared network settings")
	}
}

// Two bounds where one can never apply are refused by name, before anything is sent.
func TestAnIntruderResponseTimeoutLongerThanTheTotalIsRefused(t *testing.T) {
	addr, accepts := silentListener(t)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	for _, tc := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"longer than timeout_ms", map[string]any{"timeout_ms": 1000, "response_timeout_ms": 2000}, "timeout_ms"},
		{"zero", map[string]any{"response_timeout_ms": 0}, "response_timeout_ms"},
	} {
		body := map[string]any{
			"msg_id": id, "target": "http://" + addr, "mode": "sniper",
			"manual_points": points, "payload_sets": [][]string{{"a"}},
		}
		for k, v := range tc.body {
			body[k] = v
		}
		rec := postJSON(t, srv, "/api/intruder/run", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: got %d (%s), want 400 naming %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatal("a refused attack reached the target")
	}
}

// ---- xhqr: HTTP/1 connection reuse and the HTTP version override ---------------------------------

// keepAliveEcho answers every request on a connection with its request line echoed back, framed by
// Content-Length, and keeps the connection open. withClose adds "Connection: close" to every response
// and STILL keeps serving on the socket, so a pool that ignored the header would succeed at reusing it
// and be caught by the accept count rather than by a dead socket.
type keepAliveEcho struct {
	addr    string
	accepts atomic.Int64
	served  atomic.Int64
	mu      sync.Mutex
	hosts   []string
}

func startKeepAliveEcho(t *testing.T, withClose bool) *keepAliveEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e := &keepAliveEcho{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.accepts.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					c.SetReadDeadline(time.Now().Add(5 * time.Second))
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					for {
						h, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if h == "\r\n" {
							break
						}
						if name, value, ok := strings.Cut(strings.TrimRight(h, "\r\n"), ":"); ok && strings.EqualFold(name, "Host") {
							e.mu.Lock()
							e.hosts = append(e.hosts, strings.TrimSpace(value))
							e.mu.Unlock()
						}
					}
					e.served.Add(1)
					body := strings.TrimSuffix(line, "\r\n")
					extra := ""
					if withClose {
						extra = "Connection: close\r\n"
					}
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n%s", extra, len(body), body)
				}
			}(c)
		}
	}()
	return e
}

// hostHeaders is every Host header value the listener received, in arrival order.
func (e *keepAliveEcho) hostHeaders() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.hosts...)
}

func payloads(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "p" + strconv.Itoa(i)
	}
	return out
}

func TestIntruderConnectionReuseRidesFewerSocketsThanRequests(t *testing.T) {
	const n, k = 12, 3
	echo := startKeepAliveEcho(t, false)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	var view sendSettingsView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id, "target": "http://" + echo.addr, "mode": "sniper",
		"manual_points": points, "payload_sets": [][]string{payloads(n)},
		"rps": 1000, "max_in_flight": k, "retries": 0,
		"http1_connection_reuse": true,
	}, &view)
	if code != http.StatusOK {
		t.Fatalf("run = %d", code)
	}
	accepts := echo.accepts.Load()
	if view.Report.Failed != 0 || echo.served.Load() != n {
		t.Fatalf("failed=%d served=%d, want every one of %d requests answered", view.Report.Failed, echo.served.Load(), n)
	}
	if accepts >= n || accepts > k {
		t.Fatalf("%d sockets for %d requests at max_in_flight %d: reuse did not happen or was not bounded", accepts, n, k)
	}
	if view.ConnectionsOpened == nil || view.ConnectionsReused == nil {
		t.Fatalf("connections_opened/connections_reused are null with reuse on")
	}
	if *view.ConnectionsOpened != accepts {
		t.Fatalf("connections_opened=%d, the listener accepted %d", *view.ConnectionsOpened, accepts)
	}
	if *view.ConnectionsReused <= 0 || *view.ConnectionsReused != n-accepts {
		t.Fatalf("connections_reused=%d; %d requests over %d sockets means %d", *view.ConnectionsReused, n, accepts, n-accepts)
	}
}

// The control: the same attack without reuse dials once per request, and says it counted nothing.
func TestIntruderWithoutReuseDialsPerRequestAndCountsNothing(t *testing.T) {
	const n = 6
	echo := startKeepAliveEcho(t, false)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	rec := postJSON(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id, "target": "http://" + echo.addr, "mode": "sniper",
		"manual_points": points, "payload_sets": [][]string{payloads(n)},
		"rps": 1000, "max_in_flight": 2, "retries": 0,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := echo.accepts.Load(); got != n {
		t.Fatalf("%d sockets for %d requests with reuse off", got, n)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"connections_opened", "connections_reused"} {
		if string(top[key]) != "null" {
			t.Fatalf("%s = %s with reuse off; want null (not counted), not absent and not a number", key, top[key])
		}
	}
}

// Connection: close on every response means no reuse at all, even though the listener would answer.
func TestIntruderReuseNeverReusesAConnectionCloseResponse(t *testing.T) {
	const n = 6
	echo := startKeepAliveEcho(t, true)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	var view sendSettingsView
	if code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id, "target": "http://" + echo.addr, "mode": "sniper",
		"manual_points": points, "payload_sets": [][]string{payloads(n)},
		"rps": 1000, "max_in_flight": 2, "retries": 0, "http1_connection_reuse": true,
	}, &view); code != http.StatusOK {
		t.Fatalf("run = %d", code)
	}
	if got := echo.accepts.Load(); got != n {
		t.Fatalf("%d sockets for %d Connection: close responses", got, n)
	}
	if view.ConnectionsReused == nil || *view.ConnectionsReused != 0 {
		t.Fatalf("connections_reused = %v, want 0", view.ConnectionsReused)
	}
}

func TestIntruderReuseWithSetConnectionCloseIsRefusedNamingBoth(t *testing.T) {
	addr, accepts := silentListener(t)
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	rec := postJSON(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id, "target": "http://" + addr, "mode": "sniper",
		"manual_points": points, "payload_sets": [][]string{{"a"}},
		"http1_connection_reuse": true, "set_connection_close": true,
	})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "http1_connection_reuse") || !strings.Contains(body, "set_connection_close") {
		t.Fatalf("got %d (%s), want 400 naming both settings", rec.Code, body)
	}
	rec = postJSON(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id, "target": "http://" + addr, "mode": "sniper",
		"manual_points": points, "payload_sets": [][]string{{"a"}}, "http_version": "h3",
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "http_version") {
		t.Fatalf("got %d (%s), want 400 naming http_version", rec.Code, rec.Body.String())
	}
	time.Sleep(20 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatal("a refused attack reached the target")
	}
}

// http_version:"http1" against a TLS listener that negotiates h2 puts HTTP/1.1 on the wire. The
// positive control — the same attack with no pin — must arrive as h2, or the test proves nothing.
func TestIntruderHTTPVersionHTTP1PinsAnH2CapableTarget(t *testing.T) {
	var mu sync.Mutex
	var protos []int
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos = append(protos, r.ProtoMajor)
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	authority := strings.TrimPrefix(ts.URL, "https://")
	srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
	srv.sender.WithTLSVerify(false)

	run := func(version string) []int {
		t.Helper()
		mu.Lock()
		protos = nil
		mu.Unlock()
		body := map[string]any{
			"msg_id": id, "target": ts.URL, "mode": "sniper", "manual_points": points,
			"payload_sets": [][]string{{"a", "b"}}, "rps": 1000, "max_in_flight": 1, "retries": 0,
		}
		if version != "" {
			body["http_version"] = version
		}
		var view sendSettingsView
		if code := postJSONInto(t, srv, "/api/intruder/run", body, &view); code != http.StatusOK {
			t.Fatalf("run(%q) = %d", version, code)
		}
		if view.Report.Failed != 0 {
			t.Fatalf("run(%q): %d requests failed", version, view.Report.Failed)
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), protos...)
	}
	if got := run(""); len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Fatalf("control: an unpinned attack arrived as %v, want h2 for both — the listener is not h2-capable and the pin proves nothing", got)
	}
	if got := run("http1"); len(got) != 2 || got[0] != 1 || got[1] != 1 {
		t.Fatalf("http_version=http1 arrived as %v, want HTTP/1.x for both", got)
	}
}
