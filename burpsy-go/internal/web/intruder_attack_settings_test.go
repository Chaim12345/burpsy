package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's attack settings, end to end over a real socket (burpsy-react-ui-fmxv). The point of
// running these through the HTTP API and a listener rather than against intruder.Run is that the
// wire field has to survive the whole path — request struct, attack construction, splice, egress,
// scope chokepoint — and a test that stops at the engine cannot tell whether it did.

// echoRequestServer answers every request with the request it received, verbatim, in the body. That
// makes "what actually went out" readable from the attack report instead of inferred.
func echoRequestServer(t *testing.T) (addr string, seen func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
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
				var b strings.Builder
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				b.WriteString(line)
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						break
					}
					b.WriteString(l)
					if l == "\r\n" || l == "\n" {
						break
					}
				}
				req := b.String()
				mu.Lock()
				got = append(got, req)
				mu.Unlock()
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(req), req)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// settingsRunView is the slice of RunView these tests read.
type settingsRunView struct {
	Report struct {
		Sent     int               `json:"sent"`
		Attempts []json.RawMessage `json:"attempts"`
	} `json:"report"`
}

func runWithSettings(t *testing.T, extra map[string]any) (*settingsRunView, func() []string) {
	t.Helper()
	addr, seen := echoRequestServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")

	body := map[string]any{
		"msg_id":        id,
		"target":        "http://" + addr,
		"mode":          "sniper",
		"point_index":   0,
		"payload_sets":  [][]string{{"alpha", "beta"}},
		"max_requests":  10,
		"max_in_flight": 1,
		"rps":           1000,
	}
	for k, v := range extra {
		body[k] = v
	}
	var out settingsRunView
	if code := postJSONInto(t, srv, "/api/intruder/run", body, &out); code != http.StatusOK {
		t.Fatalf("run status = %d, want 200", code)
	}
	return &out, seen
}

// The control: without the setting, the target sees the template's own headers and no Connection
// header at all. Without this the next test could pass against a build that always sets it.
func TestAttackSettingsConnectionCloseAbsentByDefaultOnTheWire(t *testing.T) {
	out, seen := runWithSettings(t, nil)
	if out.Report.Sent != 2 {
		t.Fatalf("fixture: sent=%d, want 2", out.Report.Sent)
	}
	reqs := seen()
	if len(reqs) != 2 {
		t.Fatalf("the target received %d requests, want 2", len(reqs))
	}
	for i, r := range reqs {
		if strings.Contains(strings.ToLower(r), "connection:") {
			t.Errorf("request %d reached the target with a Connection header nobody asked for:\n%s", i, r)
		}
	}
}

// set_connection_close=true must reach the socket, not just the struct. The assertion is on the
// bytes the listener read.
func TestAttackSettingsConnectionCloseReachesTheTarget(t *testing.T) {
	out, seen := runWithSettings(t, map[string]any{"set_connection_close": true})
	if out.Report.Sent != 2 {
		t.Fatalf("fixture: sent=%d, want 2", out.Report.Sent)
	}
	reqs := seen()
	if len(reqs) != 2 {
		t.Fatalf("the target received %d requests, want 2", len(reqs))
	}
	for i, r := range reqs {
		if !strings.Contains(r, "Connection: close") {
			t.Errorf("request %d arrived without Connection: close — the wire field did not reach the socket:\n%s", i, r)
		}
		if !strings.Contains(r, "a=alpha") && !strings.Contains(r, "a=beta") {
			t.Errorf("request %d lost its payload while the header was added:\n%s", i, r)
		}
	}
}

// store_full_payloads decides whether the report can name its own payloads. Asserted on the
// MARSHALLED attempt rows, because a Go nil slice and an empty one are the same struct field and
// different JSON, and the wire is what a reader gets.
func TestAttackSettingsStoreFullPayloadsIsAbsentUntilAsked(t *testing.T) {
	out, _ := runWithSettings(t, nil)
	if len(out.Report.Attempts) == 0 {
		t.Fatal("fixture: no attempt rows")
	}
	for i, raw := range out.Report.Attempts {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if v, ok := m["payloads"]; ok {
			t.Errorf("attempt %d carries payloads=%v without the setting; absent is what says the values were not stored", i, v)
		}
	}
}

func TestAttackSettingsStoreFullPayloadsNamesThePayloads(t *testing.T) {
	out, _ := runWithSettings(t, map[string]any{"store_full_payloads": true})
	if len(out.Report.Attempts) != 2 {
		t.Fatalf("fixture: %d attempt rows, want 2", len(out.Report.Attempts))
	}
	want := map[string]bool{"alpha": true, "beta": true}
	for i, raw := range out.Report.Attempts {
		var m struct {
			Payloads []string `json:"payloads"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if len(m.Payloads) != 1 || !want[m.Payloads[0]] {
			t.Errorf("attempt %d reports payloads %v; the attack sent alpha and beta, so the report cannot name what it did", i, m.Payloads)
		}
	}
}

// Denial-of-service mode is refused, and the refusal is the feature. Running the attack without it
// would send the same requests and report full responses, and nothing in the result would tell the
// operator the setting they ticked did nothing.
func TestAttackSettingsDenialOfServiceModeIsRefusedWithItsReason(t *testing.T) {
	addr, seen := echoRequestServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")

	rec := postJSON(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":            id,
		"target":            "http://" + addr,
		"mode":              "sniper",
		"point_index":       0,
		"payload_sets":      [][]string{{"alpha"}},
		"max_requests":      10,
		"max_in_flight":     1,
		"rps":               1000,
		"denial_of_service": true,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — an unimplemented mode that runs an ordinary attack instead is a silent no-op", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "denial-of-service mode is not implemented") {
		t.Errorf("the refusal does not say what is missing:\n%s", body)
	}
	if !strings.Contains(body, "without reading the response") {
		t.Errorf("the refusal does not say what the setting would have done, so the operator cannot judge whether they needed it:\n%s", body)
	}
	if got := seen(); len(got) != 0 {
		t.Errorf("the refused attack still sent %d requests to the target", len(got))
	}
}

// An explicit false is not a refusal: a UI that serialises its whole settings panel sends it on
// every run, and failing that would make the honest answer the one that breaks.
func TestAttackSettingsDenialOfServiceFalseRunsNormally(t *testing.T) {
	out, seen := runWithSettings(t, map[string]any{"denial_of_service": false})
	if out.Report.Sent != 2 {
		t.Fatalf("sent=%d, want 2 — denial_of_service=false is not a refusal", out.Report.Sent)
	}
	if got := seen(); len(got) != 2 {
		t.Fatalf("the target received %d requests, want 2", len(got))
	}
}
