package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/http2/h2test"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- Kettled HTTP/2 requests (burpsy-react-ui-jae5) ---------------------------------------------
//
// Driven through the real routes. The send tests assert what a raw h2 origin decoded — one field whose
// value contains CR LF — because the claim is about the wire, not about the answer's echo.

// kettledServer is a server whose scope admits one host and one path prefix, with certificate checks off
// for the test origin's self-signed certificate.
func kettledServer(host, prefix string) (*Server, *core.TrafficStore) {
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPath(core.ScopeInclude, host, prefix))
	s := NewServer(store, scope)
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))
	return s, store
}

func kettledList(authority, path string) []map[string]string {
	return []map[string]string{
		{"name": ":method", "value": "POST"},
		{"name": ":scheme", "value": "https"},
		{"name": ":authority", "value": authority},
		{"name": ":path", "value": path},
		{"name": "content-type", "value": "text/plain"},
		{"name": "x-inject", "value": "a\r\nTransfer-Encoding: chunked"},
	}
}

func TestKettledRepeaterSendPutsOneCRLFHeaderOnTheWire(t *testing.T) {
	origin := h2test.Start(t, h2test.Options{ResponseBody: []byte("answered")})
	authority := fmt.Sprintf("%s:%d", origin.Host, origin.Port)
	s, store := kettledServer(origin.Host, "/k")

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":     "https://" + authority,
		"protocol":   "https",
		"request":    "POST /k HTTP/2\r\nHost: " + authority + "\r\nx-inject: a\r\n\r\nthe body",
		"h2_headers": kettledList(authority, "/k"),
		"note":       "tab note",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("kettled send = %d (%s)", rec.Code, rec.Body.String())
	}

	got := origin.Requests()
	if len(got) != 1 {
		t.Fatalf("the origin decoded %d requests", len(got))
	}
	var inject []string
	for _, f := range got[0].Fields {
		if string(f.Name) == "x-inject" {
			inject = append(inject, string(f.Value))
		}
	}
	if len(inject) != 1 || inject[0] != "a\r\nTransfer-Encoding: chunked" {
		t.Fatalf("the origin decoded x-inject as %q; want one field carrying the CR LF", inject)
	}
	if string(got[0].Body) != "the body" {
		t.Fatalf("the body arrived as %q", got[0].Body)
	}

	// The marshalled answer: status, the rendered response, and the kettled block with notes as [].
	raw := rec.Body.String()
	if !strings.Contains(raw, `"kettled":{"fields":6,"notes":[],"ended":"the stream ended"}`) {
		t.Fatalf("the answer's kettled block is wrong: %s", raw)
	}
	var resp struct {
		Status     int             `json:"status"`
		Response   string          `json:"response"`
		ExchangeID core.ExchangeID `json:"exchange_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || !strings.HasSuffix(resp.Response, "answered") {
		t.Fatalf("status %d response %q", resp.Status, resp.Response)
	}

	// The record: HTTP/2, Repeater-sourced, a rendering that does not split the injected header, and a
	// note that lists the field exactly.
	ex, err := store.GetExchange(resp.ExchangeID)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Protocol != core.ProtocolHTTP2 || ex.Source != core.SourceRepeater || ex.Method != "POST" || ex.Path != "/k" {
		t.Fatalf("exchange row: protocol %v source %v %s %s", ex.Protocol, ex.Source, ex.Method, ex.Path)
	}
	msg, err := store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		t.Fatal(err)
	}
	stored := string(msg.Raw())
	if !strings.Contains(stored, "x-inject: a\\r\\nTransfer-Encoding: chunked\r\n") {
		t.Fatalf("the stored rendering does not escape the CR LF: %q", stored)
	}
	if strings.Contains(stored, "\r\nTransfer-Encoding: chunked") {
		t.Fatalf("the stored rendering split the injected header into a line of its own: %q", stored)
	}
	if ex.Notes == nil || !strings.HasPrefix(*ex.Notes, "tab note\n\n[burpsy] kettled HTTP/2 request") ||
		!strings.Contains(*ex.Notes, `"x-inject": "a\r\nTransfer-Encoding: chunked"`) {
		t.Fatalf("the exchange note does not record the fields: %v", ex.Notes)
	}
}

// An h1-only target answers with the negotiation named; a plaintext target and an HTTP/1 pin are
// refused before anything is dialled; a space in :path is refused by the classifier with 403.
func TestKettledRepeaterSendRefusals(t *testing.T) {
	h1 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an HTTP/1.1-only target was sent a kettled request")
	}))
	h1.EnableHTTP2 = false
	h1.StartTLS()
	defer h1.Close()
	h1Authority := strings.TrimPrefix(h1.URL, "https://")
	h1Host := strings.Split(h1Authority, ":")[0]

	origin := h2test.Start(t, h2test.Options{})
	authority := fmt.Sprintf("%s:%d", origin.Host, origin.Port)

	cases := []struct {
		name   string
		target string
		list   []map[string]string
		opts   map[string]any
		code   int
		phrase string
	}{
		{"h1-only target", "https://" + h1Authority, kettledList(h1Authority, "/k"), nil, http.StatusBadGateway, `negotiated "http/1.1"`},
		{"plaintext target", "http://" + authority, kettledList(authority, "/k"), nil, http.StatusBadRequest, "only over TLS"},
		{"HTTP/1 pin", "https://" + authority, kettledList(authority, "/k"), map[string]any{"protocol_preference": "http1"}, http.StatusBadRequest, "pins HTTP/1"},
		{"space in :path", "https://" + authority, kettledList(authority, "/k /x"), nil, http.StatusForbidden, ":path with a space in it"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := kettledServer(h1Host, "/")
			body := map[string]any{
				"target": tc.target, "request": "POST /k HTTP/2\r\nHost: x\r\n\r\n", "h2_headers": tc.list,
			}
			if tc.opts != nil {
				body["options"] = tc.opts
			}
			rec := postJSON(t, s, "/api/repeater/send", body)
			if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.phrase) {
				t.Fatalf("got %d %q, want %d naming %q", rec.Code, rec.Body.String(), tc.code, tc.phrase)
			}
		})
	}
	if n := len(origin.Requests()); n != 0 {
		t.Fatalf("a refused kettled send reached the h2 origin %d times", n)
	}
}

// An empty h2_headers is no list: the send takes the text path, never a headerless kettled send.
func TestAnEmptyKettledListTakesTheTextPath(t *testing.T) {
	var seen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	authority := strings.TrimPrefix(srv.URL, "http://")
	rec := postJSON(t, newTestServer(), "/api/repeater/send", map[string]any{
		"target": authority, "protocol": "http", "h2_headers": []map[string]string{},
		"request": "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
	})
	if rec.Code != http.StatusOK || seen != 1 || strings.Contains(rec.Body.String(), `"kettled"`) {
		t.Fatalf("an empty list = %d %s (origin saw %d)", rec.Code, rec.Body.String(), seen)
	}
}

// The tab's transforms act on the list in its own terms, and the ones that cannot are named.
func TestKettledRepeaterSendAppliesTabSettingsToTheList(t *testing.T) {
	origin := h2test.Start(t, h2test.Options{})
	authority := fmt.Sprintf("%s:%d", origin.Host, origin.Port)
	s, _ := kettledServer(origin.Host, "/")
	list := append(kettledList(authority, "/k"),
		map[string]string{"name": "connection", "value": "close"},
		map[string]string{"name": "content-length", "value": "999"})
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": "https://" + authority, "request": "POST /k HTTP/2\r\nHost: x\r\n\r\nfive!",
		"h2_headers": list,
		"options": map[string]any{
			"strip_connection": true, "update_content_length": true, "h2_connection_reuse": true,
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d (%s)", rec.Code, rec.Body.String())
	}
	got := origin.Requests()[0].Fields
	for _, f := range got {
		if string(f.Name) == "connection" {
			t.Fatal("strip_connection left the connection field in the list")
		}
		if string(f.Name) == "content-length" && string(f.Value) != "5" {
			t.Fatalf("update_content_length sent content-length %q for a 5-byte body", f.Value)
		}
	}
	if !strings.Contains(rec.Body.String(), "connection reuse is on for this tab, but a kettled request is always sent") {
		t.Fatalf("the unhonoured reuse setting is not named: %s", rec.Body.String())
	}
}

// POST /api/http2/kettle: both answers, marshalled as [] when empty.
func TestHTTP2KettleRouteAnswersBothQuestions(t *testing.T) {
	s := newTestServer()
	plain := []map[string]string{
		{"name": ":method", "value": "GET"}, {"name": ":scheme", "value": "https"},
		{"name": ":authority", "value": "a.test"}, {"name": ":path", "value": "/"},
	}
	rec := postJSON(t, s, "/api/http2/kettle", map[string]any{"fields": plain, "tls": true})
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"kettled":false,"reasons":[],"send_refusals":[]}` {
		t.Fatalf("a plain list = %d %s", rec.Code, rec.Body.String())
	}

	injected := append(append([]map[string]string{}, plain...), map[string]string{"name": "x", "value": "a\r\nb"})
	rec = postJSON(t, s, "/api/http2/kettle", map[string]any{"fields": injected, "tls": true})
	var resp h2KettleResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Kettled || len(resp.Reasons) != 1 || resp.Reasons[0].Kind != "newline-in-value" || resp.Reasons[0].Index != 4 {
		t.Fatalf("a CRLF value = %+v", resp)
	}
	if len(resp.SendRefusals) != 0 || !strings.Contains(rec.Body.String(), `"send_refusals":[]`) {
		t.Fatalf("a CRLF in a regular value must be sendable: %s", rec.Body.String())
	}

	spaced := append([]map[string]string{}, plain...)
	spaced[3] = map[string]string{"name": ":path", "value": "/a b"}
	rec = postJSON(t, s, "/api/http2/kettle", map[string]any{"fields": spaced, "tls": true})
	resp = h2KettleResp{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Kettled || len(resp.SendRefusals) != 1 || !strings.Contains(resp.SendRefusals[0], ":path with a space in it") {
		t.Fatalf("a space in :path must be kettled and refused: %+v", resp)
	}

	for _, bad := range []any{
		map[string]any{"fields": []map[string]string{}},
		map[string]any{"fields": make([]map[string]string, maxKettledFields+1)},
	} {
		if rec := postJSON(t, s, "/api/http2/kettle", bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("a list outside the bounds = %d", rec.Code)
		}
	}
	if rec := get(t, s, "/api/http2/kettle"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", rec.Code)
	}
}

// The literal encoding and the HPACK decode agree on the escape-free bytes the rendering escapes.
func TestKettledRenderingEscapesOnlyLineBreaks(t *testing.T) {
	got := string(kettledRendering([]http2.HeaderField{
		http2.NewHeaderField(":method", "GET"), http2.NewHeaderField(":scheme", "https"),
		http2.NewHeaderField(":authority", "a.test"), http2.NewHeaderField(":path", "/"),
		http2.NewHeaderField("X-Up", "v\r\nw"),
	}, []byte("b")))
	want := "GET / HTTP/2\r\nHost: a.test\r\nX-Up: v\\r\\nw\r\n\r\nb"
	if got != want {
		t.Fatalf("rendering %q, want %q", got, want)
	}
}

// Override SNI reaches a kettled send's ClientHello, as it does a text send's (k011).
func TestKettledRepeaterSendCarriesOverrideSNI(t *testing.T) {
	origin := h2test.Start(t, h2test.Options{})
	authority := fmt.Sprintf("%s:%d", origin.Host, origin.Port)
	s, _ := kettledServer(origin.Host, "/")
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": "https://" + authority, "request": "GET /k HTTP/2\r\nHost: x\r\n\r\n",
		"h2_headers": kettledList(authority, "/k"), "sni": "collab.oast.example",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := origin.ServerNames(); len(got) != 1 || got[0] != "collab.oast.example" {
		t.Fatalf("the ClientHello carried %q, want the override", got)
	}
}

// Process cookies path-matches the jar against the list's own :path, query cut, as the text path does
// against the target's path: a Path=/k cookie rides a send to /k?x and not one to /other.
func TestKettledRepeaterSendPathMatchesTheJar(t *testing.T) {
	origin := h2test.Start(t, h2test.Options{})
	authority := fmt.Sprintf("%s:%d", origin.Host, origin.Port)
	s, _ := kettledServer(origin.Host, "/")
	coordinator := session.NewCoordinator(nil)
	s.WithSessionCoordinator(coordinator)
	coordinator.AbsorbResponseCookies(session.SourceProxy, origin.Host, origin.Port, true,
		[]byte("HTTP/1.1 200 OK\r\nSet-Cookie: scoped=1; Path=/k\r\nContent-Length: 0\r\n\r\n"))

	cookieSent := func(path string) bool {
		t.Helper()
		rec := postJSON(t, s, "/api/repeater/send", map[string]any{
			"target": "https://" + authority, "request": "GET " + path + " HTTP/2\r\nHost: x\r\n\r\n",
			"h2_headers": kettledList(authority, path), "options": map[string]any{"process_cookies": true},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("send %s = %d (%s)", path, rec.Code, rec.Body.String())
		}
		got := origin.Requests()
		for _, f := range got[len(got)-1].Fields {
			if string(f.Name) == "cookie" && string(f.Value) == "scoped=1" {
				return true
			}
		}
		return false
	}
	if !cookieSent("/k?x=1") {
		t.Fatal("a Path=/k cookie did not ride a kettled send to /k?x=1")
	}
	if cookieSent("/other") {
		t.Fatal("a Path=/k cookie rode a kettled send to /other")
	}
}
