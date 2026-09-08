package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- /api/repeater/send-group -------------------------------------------------------------------
//
// The claim these tests exist to check is not "the handler returns N results" — that would pass on an
// implementation that dialled N times and called it a shared socket. It is *which socket the bytes
// rode*, so every test here counts accepted connections at a raw listener, and the single-connection
// mode's whole assertion is that the count is 1.
//
// A raw net.Listener rather than httptest.NewServer for the same reason internal/sender's pipeline
// tests use one: net/http's test server manages connection reuse itself, and a test whose subject is
// connection reuse cannot delegate that to the thing under test.

// groupTarget is a plaintext origin that answers every request it can read on a connection with a 200
// whose body is the request target it saw, and reports how many connections were accepted and which
// paths arrived, in arrival order.
//
// Echoing the path back is what makes a concurrent assertion possible: with three requests in flight
// at once, "result 2 is the response to item 2" is only checkable if the response says which request
// it answered.
func groupTarget(t *testing.T) (host string, port uint16, stats func() (conns int, paths []string)) {
	t.Helper()
	return groupTargetFunc(t, nil)
}

// groupTargetFunc is groupTarget with an optional hook that decides whether to keep serving the
// connection after each response, so a test can make a peer close mid-batch.
func groupTargetFunc(t *testing.T, keepServing func(served int) bool) (string, uint16, func() (int, []string)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns int
	var paths []string
	var open []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			c.Close()
		}
	})
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			conns++
			open = append(open, conn)
			mu.Unlock()
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(conn)
				served := 0
				for {
					// Every request these tests send is a bodyless GET, so the head is the whole
					// request and "until the blank line" is a complete read.
					head := ""
					for !strings.HasSuffix(head, "\r\n\r\n") {
						line, rerr := br.ReadString('\n')
						if rerr != nil {
							return
						}
						head += line
					}
					target := "?"
					if fields := strings.Fields(head); len(fields) >= 2 {
						target = fields[1]
					}
					mu.Lock()
					paths = append(paths, target)
					mu.Unlock()
					fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(target), target)
					served++
					if keepServing != nil && !keepServing(served) {
						return
					}
				}
			}(conn)
		}
	}()
	host, port := targetHostPort(t, "http://"+ln.Addr().String())
	return host, port, func() (int, []string) {
		mu.Lock()
		defer mu.Unlock()
		return conns, append([]string(nil), paths...)
	}
}

// groupItemResult mirrors repeaterGroupItemResult on the wire, decoded rather than reused so the test
// reads the JSON contract the panel reads instead of the Go struct behind it.
type groupItemResult struct {
	TabID  string `json:"tab_id"`
	Result *struct {
		Status      int    `json:"status"`
		DurationMs  uint64 `json:"duration_ms"`
		Response    string `json:"response"`
		ExchangeID  int    `json:"exchange_id"`
		RequestMsg  uint64 `json:"request_msg_id"`
		ResponseMsg uint64 `json:"response_msg_id"`
	} `json:"result"`
	Error            string `json:"error"`
	Framing          string `json:"framing"`
	ResponseComplete *bool  `json:"response_complete"`
	DurationMeasured bool   `json:"duration_measured"`
}

type groupSendResult struct {
	Mode              string            `json:"mode"`
	Items             []groupItemResult `json:"items"`
	SharedConnection  string            `json:"shared_connection"`
	BatchDurationMs   uint64            `json:"batch_duration_ms"`
	FollowedRedirects bool              `json:"followed_redirects"`
}

// groupItem builds one send-group item aimed at host:port over plaintext.
func groupItem(tabID, host string, port uint16, path string) map[string]any {
	authority := fmt.Sprintf("%s:%d", host, port)
	return map[string]any{
		"tab_id":   tabID,
		"target":   authority,
		"protocol": "http",
		"request":  "GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
	}
}

// sendGroup posts one group send and returns the decoded body, failing the test on a non-200.
func sendGroup(t *testing.T, s *Server, mode string, items ...map[string]any) groupSendResult {
	t.Helper()
	rec := postJSON(t, s, "/api/repeater/send-group", map[string]any{"mode": mode, "items": items})
	if rec.Code != http.StatusOK {
		t.Fatalf("send-group %s = %d (%s)", mode, rec.Code, rec.Body.String())
	}
	var out groupSendResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

// The mode this whole feature was blocked on. Two requests, one accepted connection: that count is the
// entire acceptance criterion for burpsy-react-ui-6i4, because every send before it dialled fresh and
// closed, and no smuggling or desync test can be performed from a tool that cannot reuse a socket.
func TestRepeaterGroupSingleConnectionPutsEveryRequestDownOneSocket(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, host)

	got := sendGroup(t, s, "sequence_single_conn",
		groupItem("tab-a", host, port, "/one"),
		groupItem("tab-b", host, port, "/two"),
	)

	conns, paths := stats()
	if conns != 1 {
		t.Fatalf("the target accepted %d connections, want exactly 1: a group sent in single-connection "+
			"mode that dials per request is the defect this mode exists to fix", conns)
	}
	if len(paths) != 2 || paths[0] != "/one" || paths[1] != "/two" {
		t.Errorf("the target saw %v, want /one then /two in tab order", paths)
	}
	if got.Mode != "sequence_single_conn" {
		t.Errorf("mode = %q, want it echoed back", got.Mode)
	}
	if got.SharedConnection != fmt.Sprintf("http://%s:%d", host, port) {
		t.Errorf("shared_connection = %q, want the authority the one socket addressed", got.SharedConnection)
	}
	if got.FollowedRedirects {
		t.Error("followed_redirects = true on the shared socket: a hop is a new connection, and claiming " +
			"the policy was applied when it was not is the failure this field exists to prevent")
	}
	if len(got.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(got.Items))
	}
	for i, want := range []struct{ tab, path string }{{"tab-a", "/one"}, {"tab-b", "/two"}} {
		item := got.Items[i]
		if item.TabID != want.tab {
			t.Errorf("item %d tab_id = %q, want %q", i, item.TabID, want.tab)
		}
		if item.Error != "" {
			t.Fatalf("item %d error = %q, want none", i, item.Error)
		}
		if item.Result == nil {
			t.Fatalf("item %d has no result", i)
		}
		if item.Result.Status != 200 {
			t.Errorf("item %d status = %d, want 200", i, item.Result.Status)
		}
		// The body echoes the request target, so this is the assertion that item i's result is the
		// response to item i's request and not to its neighbour's.
		if !strings.HasSuffix(item.Result.Response, want.path) {
			t.Errorf("item %d response = %q, want it to echo %q", i, item.Result.Response, want.path)
		}
		if item.Framing != "content-length" {
			t.Errorf("item %d framing = %q, want content-length: the framing rule is the comparison a "+
				"smuggling test is made of, so it must be reported per exchange", i, item.Framing)
		}
		if item.ResponseComplete == nil || !*item.ResponseComplete {
			t.Errorf("item %d response_complete = %v, want true", i, item.ResponseComplete)
		}
		if item.DurationMeasured {
			t.Errorf("item %d duration_measured = true, but sender.SendKeepAlive reports no per-exchange "+
				"timing — a 0 that claims to be a measurement is exactly what this flag exists to deny", i)
		}
	}
	// Both halves of both exchanges are in the store, so history and the decoder can reach them.
	if n := len(s.store.Exchanges()); n != 2 {
		t.Errorf("the store holds %d exchanges, want 2: a shared-socket send is still a recorded send", n)
	}
}

// Every raw request on the shared socket clears its own scope gate. The include here is path-scoped,
// so the host-level gate the single send uses passes for both requests and only a per-raw AuthoriseRaw
// call can tell them apart — which is exactly what internal/sender/pipeline.go requires of a caller,
// and why: "a smuggled prefix can address a different target than the socket it rides in on".
func TestRepeaterGroupSingleConnectionAuthorisesEveryRawRequestIndividually(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	s.scope.Add(core.NewScopeRuleWithPath(core.ScopeInclude, host, "/allowed"))

	// The host-level gate is genuinely open for both: without this the test below would pass on an
	// implementation that refused the whole host.
	if !s.scope.MayContainHost(host, port, false) {
		t.Fatalf("the host-level gate refuses %s, so this test could not tell a per-raw check from a per-host one", host)
	}

	rec := postJSON(t, s, "/api/repeater/send-group", map[string]any{
		"mode": "sequence_single_conn",
		"items": []map[string]any{
			groupItem("tab-a", host, port, "/allowed/first"),
			groupItem("tab-b", host, port, "/blocked/second"),
		},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("send-group = %d (%s), want 403: the second request's path is out of scope", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "tab-b") {
		t.Errorf("refusal %q does not name the tab that was refused", rec.Body.String())
	}
	// Nothing was sent, not even the request that would have cleared the gate. A group that put the
	// first request on the wire and then refused the second would already have sent traffic the
	// operator's group was not authorised to send in full.
	if conns, paths := stats(); conns != 0 || len(paths) != 0 {
		t.Errorf("the target accepted %d connections and saw %v, want nothing: the refusal must precede the dial", conns, paths)
	}

	// Positive control. The same two requests, with the path restriction lifted, do go out on one
	// socket — so the refusal above is the path check doing its job, not a group send that never works.
	open := newTestServer()
	includeInScope(t, open, host)
	got := sendGroup(t, open, "sequence_single_conn",
		groupItem("tab-a", host, port, "/allowed/first"),
		groupItem("tab-b", host, port, "/blocked/second"),
	)
	if len(got.Items) != 2 || got.Items[0].Result == nil || got.Items[1].Result == nil {
		t.Fatalf("positive control did not send both requests: %+v", got.Items)
	}
	if conns, paths := stats(); conns != 1 || len(paths) != 2 {
		t.Errorf("positive control: %d connections, paths %v; want 1 connection carrying both", conns, paths)
	}
}

// One socket addresses one authority. A group whose tabs name different targets is refused rather than
// having the first tab's authority silently applied to everyone else's bytes.
func TestRepeaterGroupSingleConnectionRefusesTabsThatNameDifferentTargets(t *testing.T) {
	hostA, portA, statsA := groupTarget(t)
	_, portB, statsB := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, hostA)

	rec := postJSON(t, s, "/api/repeater/send-group", map[string]any{
		"mode": "sequence_single_conn",
		"items": []map[string]any{
			groupItem("tab-a", hostA, portA, "/one"),
			groupItem("tab-b", hostA, portB, "/two"),
		},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("send-group = %d (%s), want 400", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "tab-b") || !strings.Contains(body, "separate connections") {
		t.Errorf("refusal %q must name the offending tab and the mode that would work", body)
	}
	if connsA, _ := statsA(); connsA != 0 {
		t.Errorf("target A accepted %d connections on a refused group, want 0", connsA)
	}
	if connsB, _ := statsB(); connsB != 0 {
		t.Errorf("target B accepted %d connections on a refused group, want 0", connsB)
	}
}

// A peer that answers the first request and then closes is the case a desync test reads: the second
// request's fate is the evidence. It is reported as that request's own error, with the first
// request's result untouched — not as a failure of the whole group.
func TestRepeaterGroupSingleConnectionReportsThePerRequestFailureWhenThePeerClosesMidBatch(t *testing.T) {
	host, port, stats := groupTargetFunc(t, func(served int) bool { return served < 1 })
	s := newTestServer()
	includeInScope(t, s, host)

	got := sendGroup(t, s, "sequence_single_conn",
		groupItem("tab-a", host, port, "/one"),
		groupItem("tab-b", host, port, "/two"),
	)
	if conns, _ := stats(); conns != 1 {
		t.Fatalf("the target accepted %d connections, want 1", conns)
	}
	if len(got.Items) != 2 {
		t.Fatalf("got %d items, want 2: a request that could not be sent still gets its own result", len(got.Items))
	}
	if got.Items[0].Result == nil || got.Items[0].Error != "" {
		t.Errorf("item 0 = %+v, want the answered request's result with no error", got.Items[0])
	}
	if got.Items[1].Error == "" {
		t.Error("item 1 error is empty: the request the peer never answered must say so rather than " +
			"arriving as an empty success")
	}
	if got.Items[1].Result != nil {
		t.Errorf("item 1 result = %+v, want nil: no bytes arrived, so there is no exchange to point at", got.Items[1].Result)
	}
	if n := len(s.store.Exchanges()); n != 1 {
		t.Errorf("the store holds %d exchanges, want 1: only the answered request is a recorded send", n)
	}
}

// Parallel mode: N requests, N connections, all overlapping. The connection count is what separates
// this mode from single-connection mode, and the per-item echo is what proves the results were not
// reordered by whichever request happened to finish first.
func TestRepeaterGroupParallelFiresEachRequestOnItsOwnConnectionAndAnswersInTabOrder(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, host)

	got := sendGroup(t, s, "parallel",
		groupItem("tab-a", host, port, "/alpha"),
		groupItem("tab-b", host, port, "/beta"),
		groupItem("tab-c", host, port, "/gamma"),
	)

	conns, paths := stats()
	if conns != 3 {
		t.Fatalf("the target accepted %d connections, want 3: parallel mode is one fresh connection per request", conns)
	}
	sort.Strings(paths)
	if want := []string{"/alpha", "/beta", "/gamma"}; strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("the target saw %v, want all three requests", paths)
	}
	if got.SharedConnection != "" {
		t.Errorf("shared_connection = %q, want empty: nothing was shared here", got.SharedConnection)
	}
	if !got.FollowedRedirects {
		t.Error("followed_redirects = false, but each item ran the ordinary single send, redirect policy included")
	}
	if len(got.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(got.Items))
	}
	exchanges := map[int]bool{}
	for i, want := range []struct{ tab, path string }{{"tab-a", "/alpha"}, {"tab-b", "/beta"}, {"tab-c", "/gamma"}} {
		item := got.Items[i]
		if item.TabID != want.tab {
			t.Errorf("item %d tab_id = %q, want %q: results are ordered by tab, never by latency", i, item.TabID, want.tab)
		}
		if item.Result == nil {
			t.Fatalf("item %d has no result: %q", i, item.Error)
		}
		if !strings.HasSuffix(item.Result.Response, want.path) {
			t.Errorf("item %d response = %q, want it to echo %q", i, item.Result.Response, want.path)
		}
		if !item.DurationMeasured {
			t.Errorf("item %d duration_measured = false, but this send had its own connection and its own stopwatch", i)
		}
		if exchanges[item.Result.ExchangeID] {
			t.Errorf("item %d reuses exchange id %d: N independent requests are N exchanges", i, item.Result.ExchangeID)
		}
		exchanges[item.Result.ExchangeID] = true
	}
	if n := len(s.store.Exchanges()); n != 3 {
		t.Errorf("the store holds %d exchanges, want 3", n)
	}
}

// The separate-connections sequence: tab order on the wire, one connection each. Both halves matter —
// the count distinguishes it from single-connection mode, the order distinguishes it from parallel.
func TestRepeaterGroupSequenceOnSeparateConnectionsSendsInTabOrderOneConnectionEach(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, host)

	got := sendGroup(t, s, "sequence_separate_conn",
		groupItem("tab-a", host, port, "/first"),
		groupItem("tab-b", host, port, "/second"),
	)

	conns, paths := stats()
	if conns != 2 {
		t.Fatalf("the target accepted %d connections, want 2: this mode is the ordinary single send, twice", conns)
	}
	if len(paths) != 2 || paths[0] != "/first" || paths[1] != "/second" {
		t.Errorf("the target saw %v, want /first then /second", paths)
	}
	if len(got.Items) != 2 || got.Items[0].Result == nil || got.Items[1].Result == nil {
		t.Fatalf("want two results with responses, got %+v", got.Items)
	}
	for i, item := range got.Items {
		if item.Framing != "" || item.ResponseComplete != nil {
			t.Errorf("item %d reports framing %q / complete %v, but a fresh-connection send has no second "+
				"take to compare against and must not imply it does", i, item.Framing, item.ResponseComplete)
		}
	}
}

// The refusals that happen before anything is prepared, let alone sent.
func TestRepeaterGroupRefusesAnUnusableRequest(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, host)

	cases := []struct {
		name string
		body map[string]any
		code int
		says string
	}{
		{
			name: "unknown mode",
			body: map[string]any{"mode": "single_socket", "items": []map[string]any{groupItem("tab-a", host, port, "/x")}},
			code: http.StatusBadRequest,
			says: "unknown mode",
		},
		{
			name: "no items",
			body: map[string]any{"mode": "parallel", "items": []map[string]any{}},
			code: http.StatusBadRequest,
			says: "at least one request",
		},
		{
			name: "an item with no tab id could not be routed back to a tab",
			body: map[string]any{"mode": "parallel", "items": []map[string]any{
				{"target": fmt.Sprintf("%s:%d", host, port), "protocol": "http", "request": "GET / HTTP/1.1\r\n\r\n"},
			}},
			code: http.StatusBadRequest,
			says: "tab_id",
		},
		{
			name: "one tab cannot hold two positions",
			body: map[string]any{"mode": "parallel", "items": []map[string]any{
				groupItem("tab-a", host, port, "/x"),
				groupItem("tab-a", host, port, "/y"),
			}},
			code: http.StatusBadRequest,
			says: "twice",
		},
		{
			name: "an unknown option key refuses the whole group",
			body: map[string]any{"mode": "parallel", "items": []map[string]any{
				{
					"tab_id": "tab-a", "target": fmt.Sprintf("%s:%d", host, port), "protocol": "http",
					"request": "GET / HTTP/1.1\r\n\r\n",
					"options": map[string]any{"redirect_mode": "sideways"},
				},
			}},
			code: http.StatusBadRequest,
			says: "redirect_mode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, s, "/api/repeater/send-group", tc.body)
			if rec.Code != tc.code {
				t.Fatalf("send-group = %d (%s), want %d", rec.Code, rec.Body.String(), tc.code)
			}
			if !strings.Contains(rec.Body.String(), tc.says) {
				t.Errorf("refusal %q does not say %q", rec.Body.String(), tc.says)
			}
		})
	}
	if conns, paths := stats(); conns != 0 || len(paths) != 0 {
		t.Errorf("a refused group reached the target: %d connections, paths %v", conns, paths)
	}
}

// An excluded host is refused in every mode. Grouping is not a way around the scope: the gate runs per
// item, before the mode is even chosen, so all three modes refuse identically.
func TestRepeaterGroupRefusesAnExcludedTargetInEveryMode(t *testing.T) {
	host, port, stats := groupTarget(t)
	for _, mode := range []string{"sequence_single_conn", "sequence_separate_conn", "parallel"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer()
			includeInScope(t, s, host)
			if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "exclude", "pattern": host}); rec.Code != http.StatusOK {
				t.Fatalf("exclude %s: %d (%s)", host, rec.Code, rec.Body.String())
			}
			rec := postJSON(t, s, "/api/repeater/send-group", map[string]any{
				"mode":  mode,
				"items": []map[string]any{groupItem("tab-a", host, port, "/x")},
			})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("send-group %s = %d (%s), want 403", mode, rec.Code, rec.Body.String())
			}
		})
	}
	if conns, _ := stats(); conns != 0 {
		t.Errorf("an excluded group reached the target on %d connections", conns)
	}
}

// The one place the three modes do NOT behave alike, pinned so it is a documented contract rather than
// a surprise a QA pass has to rediscover.
//
// core.Scope.MayContainHost — the host-level gate /api/repeater/send has always used, and which the two
// separate-connection modes inherit unchanged because they *are* that send, N times — answers "could
// any request to this host be in scope". A path-scoped include (`include(h, "/allowed")`) makes it
// true for the whole host, even though Contains("/blocked") is false. So a single send to a path that is
// out of scope still goes out — that is the repeater's deliberate, documented trade of scope exactness
// for a fast, connection-reuse-friendly host gate.
//
// The shared-socket mode is strictly stricter than the two that dial per request, because
// internal/sender/pipeline.go requires AuthoriseRaw per raw and this endpoint runs it. A path outside
// the scope include therefore refuses the group even though the single send would pass the host gate.
// That asymmetry is not something this endpoint invented and it is not something it can fix here:
// MayContainHost is the gate the single send, the intruder and the proxy pre-filter all share, and
// tightening it is a change to every one of them. It is recorded here so nobody reads the difference as
// a bug in the group send.
//
// (The no-longer-tested case — a host matching *no* include rule — used to be this asymmetry's other
// example, but MayContainHost was tightened to agree with Contains there, so all three modes now refuse
// such a host. What survives, and what this pins, is the path-within-an-included-host case, where the
// per-request AuthoriseRaw is inherently stricter than any host-level gate can be.)
func TestRepeaterGroupSharedSocketIsStricterThanTheHostLevelGateTheOtherModesInherit(t *testing.T) {
	host, port, stats := groupTarget(t)

	// A path-scoped include names the host, so the host-level gate is open for every path: the single
	// send passes /blocked even though that path is out of scope. The scope holds only this include —
	// a whole-host include would sweep /blocked back in and make the comparison meaningless.
	lenient := newTestServer()
	lenient.scope.Add(core.NewScopeRuleWithPath(core.ScopeInclude, host, "/allowed"))

	// The single send does pass: MayContainHost genuinely opens the whole host because a path-scoped
	// include makes the host worth considering.
	single := postJSON(t, lenient, "/api/repeater/send", map[string]any{
		"target":   fmt.Sprintf("%s:%d", host, port),
		"protocol": "http",
		"request":  "GET /blocked HTTP/1.1\r\nHost: " + fmt.Sprintf("%s:%d", host, port) + "\r\n\r\n",
	})
	if single.Code != http.StatusOK {
		t.Fatalf("/api/repeater/send to an out-of-scope path on an included host = %d (%s), want 200: the "+
			"host-level gate is documented as lenient about path, so the comparison below would be a straw man",
			single.Code, single.Body.String())
	}

	// The same request in the separate-connection mode goes out too — it *is* that send, N times.
	got := sendGroup(t, lenient, "sequence_separate_conn", groupItem("tab-a", host, port, "/blocked"))
	if len(got.Items) != 1 || got.Items[0].Result == nil {
		t.Fatalf("separate-connection group = %+v, want the same outcome /api/repeater/send gives this scope", got.Items)
	}

	// But the shared-socket mode refuses: it runs AuthoriseRaw per raw, and /blocked is not within the
	// /allowed include. Nothing reaches the wire — the single send and the separate-connection group
	// above already dialed, so the refusal must not add a connection on top of that baseline.
	before, _ := stats()
	rec := postJSON(t, lenient, "/api/repeater/send-group", map[string]any{
		"mode":  "sequence_single_conn",
		"items": []map[string]any{groupItem("tab-a", host, port, "/blocked")},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("single-connection send-group to an out-of-scope path = %d (%s), want 403: AuthoriseRaw "+
			"refuses a path the host gate waves through", rec.Code, rec.Body.String())
	}
	if conns, _ := stats(); conns != before {
		t.Fatalf("the refused single-connection group reached the target on %d new connections (was %d)", conns, before)
	}
}
