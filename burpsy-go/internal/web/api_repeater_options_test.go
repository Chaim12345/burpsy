package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// ---- Repeater per-send options ------------------------------------------------------------------
//
// The options object is only real if a send actually obeys it. These tests assert the wiring, not
// the struct: a refused key names itself, a transform reaches the bytes the test origin receives,
// and a per-send redirect override changes what a single send follows without touching the network
// settings the next send sees.

// TestARefusedOptionsKeyNamesTheKeyAndSendsNothing pins the validate-all-before-apply contract: an
// unknown redirect_mode is a 400 that says which key was refused, and no request leaves the process.
func TestARefusedOptionsKeyNamesTheKeyAndSendsNothing(t *testing.T) {
	s := newTestServer()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a send with invalid options must not reach the wire")
	}))
	defer srv.Close()

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  strings.TrimPrefix(srv.URL, "http://"),
		"request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"options": map[string]any{"redirect_mode": "anywhere"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid options = %d, want 400 (refuse, don't partially apply)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "redirect_mode") {
		t.Fatalf("refusal %q must name the refused key", rec.Body.String())
	}
}

// TestAProtocolPreferenceRefusalNamesItsKeyToo covers the second enum the same way.
func TestAProtocolPreferenceRefusalNamesItsKeyToo(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  "127.0.0.1:1",
		"request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"options": map[string]any{"protocol_preference": "h3"},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "protocol_preference") {
		t.Fatalf("got %d (%s), want 400 naming protocol_preference", rec.Code, rec.Body.String())
	}
}

// TestStripConnectionReachesTheWire sends with strip_connection through an origin that reports
// whether a Connection header arrived. Replay's hop-by-hop header is exactly what this switch
// exists to remove, so the assertion is on the bytes the origin saw — not on the option's echo.
func TestStripConnectionReachesTheWire(t *testing.T) {
	var sawConnection bool
	var reqCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		sawConnection = r.Header.Get("Connection") != ""
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := newTestServer()
	authority := strings.TrimPrefix(srv.URL, "http://")
	raw := "GET / HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n"

	// Without the option: the header the operator wrote arrives.
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": authority, "request": raw, "protocol": "http",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("plain send = %d (%s)", rec.Code, rec.Body.String())
	}
	if !sawConnection {
		t.Fatal("Connection header missing without strip_connection: the origin did not see the operator's own bytes")
	}

	// With it: the header is gone from the wire.
	sawConnection = false
	rec = postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": authority, "request": raw, "protocol": "http",
		"options": map[string]any{"strip_connection": true},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("strip send = %d (%s)", rec.Code, rec.Body.String())
	}
	if sawConnection {
		t.Fatal("Connection header survived strip_connection: the option is a switch that does nothing")
	}
	if reqCount != 2 {
		t.Fatalf("origin saw %d requests, want 2", reqCount)
	}
}

// TestNormalizeLineEndingsFixesBareLF sends a request written with bare LF endings and asserts the
// origin parses it as a well-formed request line (Go's HTTP/1.1 reader rejects bare-LF request
// lines, so a 200 here is the transform having happened).
func TestNormalizeLineEndingsFixesBareLF(t *testing.T) {
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOK = r.URL.Path == "/fixed"
	}))
	defer srv.Close()

	s := newTestServer()
	authority := strings.TrimPrefix(srv.URL, "http://")
	raw := "GET /fixed HTTP/1.1\nHost: " + authority + "\n\n"

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": authority, "request": raw, "protocol": "http",
		"options": map[string]any{"normalize_line_endings": true},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d (%s)", rec.Code, rec.Body.String())
	}
	if !gotOK {
		t.Fatal("origin never answered /fixed: bare-LF endings reached it unnormalised")
	}
}

// TestUpdateContentLengthFollowsTheBody edits a body without touching its stale Content-Length and
// asserts the origin received a body it can read whole — the header followed the body, which is the
// option's whole point.
func TestUpdateContentLengthFollowsTheBody(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		n, _ := io.ReadFull(r.Body, buf)
		gotBody = string(buf[:n])
	}))
	defer srv.Close()

	s := newTestServer()
	authority := strings.TrimPrefix(srv.URL, "http://")
	// The header says 5; the body is 17 bytes. Unfixed, the origin truncates at 5.
	raw := "POST / HTTP/1.1\r\nHost: " + authority + "\r\nContent-Length: 5\r\n\r\n" +
		`{"patched":true}`

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": authority, "request": raw, "protocol": "http",
		"options": map[string]any{"update_content_length": true},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d (%s)", rec.Code, rec.Body.String())
	}
	if gotBody != `{"patched":true}` {
		t.Fatalf("origin read %q, want the whole body: Content-Length did not follow the edit", gotBody)
	}
}

// TestRedirectOverrideKeepsTheHopBudget pins that an override replaces only the mode: MaxHops stays
// the standing budget, so an override cannot smuggle in an unbounded chain.
func TestRedirectOverrideKeepsTheHopBudget(t *testing.T) {
	opts := repeaterSendOptions{RedirectMode: "always"}
	got := opts.redirectPolicy(sender.RedirectSettings{Mode: sender.RedirectNever, MaxHops: 7})
	if got.Mode != sender.RedirectAlways || got.MaxHops != 7 {
		t.Fatalf("override = %+v, want mode=always with the standing MaxHops=7: the budget is an anti-loop bound, not a policy choice", got)
	}
}

// The same override must not silently revoke the operator's standing decision about carrying a
// target-set cookie. A mode dropdown is not a statement about credentials, and a rebuild of the
// settings struct field by field dropped ReplayCookies to false — so a send that named "always" read
// as "always, but never replay a cookie" while the console showed the setting on
// (burpsy-react-ui-mr83).
//
// This is the shape of the bug rather than its symptom: a field ADDED to RedirectSettings later
// would default to false here for the same reason, so the assertion is on the whole struct.
func TestRedirectOverrideKeepsTheStandingCookieReplayDecision(t *testing.T) {
	standing := sender.RedirectSettings{
		Mode:          sender.RedirectNever,
		MaxHops:       7,
		ReplayCookies: true,
	}
	got := (repeaterSendOptions{RedirectMode: "always"}).redirectPolicy(standing)
	if !got.ReplayCookies {
		t.Error("the per-send mode override cleared ReplayCookies; the operator's standing decision about " +
			"carrying a target-set credential was revoked by a dropdown that says nothing about credentials")
	}

	// And the other way: an operator who turned it OFF does not get it back from a mode override.
	standing.ReplayCookies = false
	got = (repeaterSendOptions{RedirectMode: "always"}).redirectPolicy(standing)
	if got.ReplayCookies {
		t.Error("the override turned cookie replay ON; the standing decision is the operator's and an " +
			"override has no business inverting it")
	}
}

// TestProcessCookiesNeverOverridesTheOperator pins the precedence: a Cookie header the operator
// wrote wins over the jar, and an empty jar adds nothing.
func TestProcessCookiesNeverOverridesTheOperator(t *testing.T) {
	opts := repeaterSendOptions{ProcessCookies: true}
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\nCookie: session=operators-own\r\n\r\n")
	got := string(opts.applyToRequest(raw, "session=jars-value"))
	if !strings.Contains(got, "Cookie: session=operators-own") || strings.Contains(got, "jars-value") {
		t.Fatalf("operator's Cookie header was not left alone: %q", got)
	}

	added := string(opts.applyToRequest([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "session=jars-value"))
	if !strings.Contains(added, "Cookie: session=jars-value") {
		t.Fatalf("empty-Cookie request did not gain the jar's header: %q", added)
	}
	if n := strings.Count(added, "\r\n\r\n"); n != 1 {
		t.Fatalf("header insertion left %d blank-line terminators, want 1: %q", n, added)
	}
}

// TestPerSendRedirectOverrideBeatsTheStandingPolicy is the heart of the override: with the network
// settings at never, one send carrying redirect_mode=always follows the chain, and the next send
// without options follows nothing — the override changed one send, not the global table.
func TestPerSendRedirectOverrideBeatsTheStandingPolicy(t *testing.T) {
	s := newTestServer()
	putNetworkSettings(t, s, `{"redirects": {"mode": "never"}}`)

	var seen int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.URL.Path == "/go" {
			http.Redirect(w, r, srv.URL+"/landed", http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	defer srv.Close()
	authority := strings.TrimPrefix(srv.URL, "http://")

	// Without options: standing policy (never) — one request on the wire, the 30x is the response.
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  authority,
		"request": "GET /go HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("plain send = %d (%s)", rec.Code, rec.Body.String())
	}
	if seen != 1 {
		t.Fatalf("plain send put %d requests on the wire, want 1: the standing policy is never", seen)
	}

	// With the override: the chain is followed — a second request leaves the process.
	seen = 0
	rec = postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  authority,
		"request": "GET /go HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n",
		"options": map[string]any{"redirect_mode": "always"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("override send = %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Redirects *struct {
			Mode string `json:"mode"`
			Sent int    `json:"sent"`
		} `json:"redirects"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if out.Redirects == nil {
		t.Fatal("override send produced no redirects object: the override did nothing")
	}
	if out.Redirects.Mode != "always" {
		t.Fatalf("chain mode = %q, want the override (always), not the standing policy", out.Redirects.Mode)
	}
	if seen != 2 {
		t.Fatalf("override send put %d requests on the wire, want 2 (the 30x and the followed hop)", seen)
	}
}

// ---- helpers ------------------------------------------------------------------------------------

func hostOf(authority string) string {
	host, _, _ := strings.Cut(authority, ":")
	return host
}

func portOf(authority string) uint16 {
	_, port, _ := strings.Cut(authority, ":")
	var p uint16
	fmt.Sscanf(port, "%d", &p)
	return p
}
