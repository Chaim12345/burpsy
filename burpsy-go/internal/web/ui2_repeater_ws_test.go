package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2/h2test"
)

func ui2PostRW(t *testing.T, s *Server, path string, form url.Values) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func ui2GetRW(t *testing.T, s *Server, path string) string {
	t.Helper()
	rec := get(t, s, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// ---- WebSocket ----

func TestUI2RepeaterWSLoadsAFrameEscaped(t *testing.T) {
	s := newTestServer()
	s.store.AddExchange(&core.Exchange{Host: "127.0.0.1", Port: 18094, Path: "/chat"})
	s.store.AddWsMessage(&core.WsMessage{Exchange: 0, FromClient: true, Opcode: core.WsOpcodeText}, []byte(`<img src=x onerror=alert(1)>`))
	body := ui2GetRW(t, s, "/ui2/repeater/ws?frame=0")
	if strings.Contains(body, "<img src=x") {
		t.Fatal("a captured frame reached the page unescaped")
	}
	for _, want := range []string{"&lt;img src=x onerror=alert(1)&gt;", "Loaded frame #0", `value="clone" selected`, "ws://127.0.0.1:18094"} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

func TestUI2RepeaterWSPreviewLoadsTheHandshake(t *testing.T) {
	s := newTestServer()
	body := ui2GetRW(t, s, "/ui2/repeater/ws?preview=1&mode=new&target=ws%3A%2F%2Fexample.test%3A8080&path=%2Fsock")
	if !strings.Contains(body, "GET /sock HTTP/1.1") || !strings.Contains(body, "Sec-WebSocket-Key") {
		t.Fatalf("preview did not load the synthetic handshake: %s", body)
	}
}

func TestUI2RepeaterWSSendShowsTheEcho(t *testing.T) {
	target := wsEchoTarget(t)
	host, port := repeaterWsTargetOf(target)
	s := newTestServer()
	s.scope.AddInclude(host)
	body := ui2PostRW(t, s, "/ui2/repeater/ws/send", url.Values{
		"mode": {"new"}, "target": {fmt.Sprintf("ws://%s:%d", host, port)}, "path": {"/"},
		"opcode": {"text"}, "direction": {"server"}, "payload": {"ping <b>"},
	})
	if !strings.Contains(body, "echo: ping &lt;b&gt;") || !strings.Contains(body, "recorded as WebSocket #") {
		t.Fatalf("reply pane is missing the echo: %s", body)
	}
}

func TestUI2RepeaterWSSendToClientOnANewConnectionIsRefused(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/ws/send", url.Values{
		"mode": {"new"}, "target": {"ws://127.0.0.1:1"}, "opcode": {"text"}, "direction": {"client"}, "payload": {"x"},
	})
	if !strings.Contains(body, "to-client cannot run from a resend") {
		t.Fatalf("to-client refusal missing: %s", body)
	}
}

// ---- HTTP/2 ----

func TestUI2RepeaterH2SeedsTheHeaderList(t *testing.T) {
	s := newTestServer()
	id := seedUI2Exchange(t, s, "GET /a?b=1 HTTP/1.1\r\nHost: h2.test\r\nX-Token: t\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n")
	body := ui2GetRW(t, s, "/ui2/repeater/h2?exchange="+strconv.Itoa(int(id)))
	for _, want := range []string{`value=":authority"`, `value="h2.test"`, `value=":path"`, `value="/a?b=1"`, `value="x-token"`} {
		if !strings.Contains(body, want) {
			t.Errorf("seeded list is missing %s", want)
		}
	}
}

func h2Form(target string, tls bool, fields ...string) url.Values {
	v := url.Values{"target": {target}}
	if tls {
		v.Set("tls", "on")
	}
	for i := 0; i+1 < len(fields); i += 2 {
		v.Add("name", fields[i])
		v.Add("value", fields[i+1])
	}
	return v
}

func TestUI2RepeaterH2PreviewNamesTheKettleReason(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/h2/preview", h2Form("https://h2.test:443", true,
		":method", "GET", ":scheme", "https", ":authority", "h2.test", ":path", "/", "x-inject", `a\r\nb: c`))
	if !strings.Contains(body, "This request is kettled because") || !strings.Contains(body, `x-inject: a\r\nb: c`) {
		t.Fatalf("preview did not report the kettle reason and rendering: %s", body)
	}
}

func TestUI2RepeaterH2PreviewRefusesAnUnknownEscape(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/h2/preview", h2Form("https://h2.test:443", true, ":method", `G\qET`))
	if !strings.Contains(body, `unknown escape \q`) || strings.Contains(body, "kettled because") {
		t.Fatalf("a bad escape was not refused: %s", body)
	}
}

func TestUI2RepeaterH2SendPutsTheListOnTheWire(t *testing.T) {
	origin := h2test.Start(t, h2test.Options{ResponseBody: []byte("answered")})
	authority := fmt.Sprintf("%s:%d", origin.Host, origin.Port)
	s, _ := kettledServer(origin.Host, "/k")
	body := ui2PostRW(t, s, "/ui2/repeater/h2/send", h2Form("https://"+authority, true,
		":method", "GET", ":scheme", "https", ":authority", authority, ":path", "/k", "x-inject", `a\r\nTransfer-Encoding: chunked`))
	if !strings.Contains(body, "answered") || !strings.Contains(body, "header fields sent") {
		t.Fatalf("send outcome missing: %s", body)
	}
	got := origin.Requests()
	if len(got) != 1 {
		t.Fatalf("origin decoded %d requests", len(got))
	}
	found := false
	for _, f := range got[0].Fields {
		found = found || string(f.Name) == "x-inject" && string(f.Value) == "a\r\nTransfer-Encoding: chunked"
	}
	if !found {
		t.Fatalf("the CR LF field did not reach the wire as one field: %v", got[0].Fields)
	}
}

func TestUI2RepeaterH2SendRefusesPlainHTTP(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/h2/send", h2Form("http://h2.test:80", false,
		":method", "GET", ":scheme", "http", ":authority", "h2.test", ":path", "/"))
	if !strings.Contains(body, "Repeater speaks HTTP/2 only over TLS") {
		t.Fatalf("plaintext kettled send was not refused: %s", body)
	}
}

// ---- GraphQL ----

const ui2GQLBody = `{"query":"query Q { me { id } }","variables":{}}`

func ui2GQLRequest() string {
	return "POST /graphql HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(ui2GQLBody)) + "\r\n\r\n" + ui2GQLBody
}

func TestUI2RepeaterGraphQLShowsTheCarrierQuery(t *testing.T) {
	s := newTestServer()
	id := seedExchange(t, s, ui2GQLRequest(), jsonResponse(`{"data":{}}`))
	body := ui2GetRW(t, s, "/ui2/repeater/graphql?exchange="+strconv.Itoa(int(id)))
	if !strings.Contains(body, "query Q { me { id } }") || !strings.Contains(body, "1 operation(s)") {
		t.Fatalf("query editor was not seeded from the carrier: %s", body)
	}
}

func TestUI2RepeaterGraphQLValidate(t *testing.T) {
	s := newTestServer()
	ok := ui2PostRW(t, s, "/ui2/repeater/graphql/validate", url.Values{"query": {"{ me { id } }"}, "request": {ui2GQLRequest()}})
	if !strings.Contains(ok, "Valid GraphQL document.") {
		t.Fatalf("valid document not reported valid: %s", ok)
	}
	bad := ui2PostRW(t, s, "/ui2/repeater/graphql/validate", url.Values{"query": {"{ me { id }"}, "request": {ui2GQLRequest()}})
	if !strings.Contains(bad, "Invalid GraphQL document") || !regexp.MustCompile(`line \d+, column \d+`).MatchString(bad) {
		t.Fatalf("invalid document not reported with a position: %s", bad)
	}
}

func TestUI2RepeaterGraphQLSetsTheIntrospectionQuery(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/graphql/query", url.Values{"request": {ui2GQLRequest()}, "index": {"0"}, "preset": {"introspection"}})
	if !strings.Contains(body, `__schema {\n`) || !strings.Contains(body, "body carrier") {
		t.Fatalf("introspection query not written into the body: %s", body)
	}
}

func TestUI2RepeaterGraphQLQueryRefusesARequestWithNoCarrier(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/graphql/query", url.Values{"request": {"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"}, "query": {"{a}"}})
	if !strings.Contains(body, "no GraphQL carrier") {
		t.Fatalf("carrier-less request was not refused: %s", body)
	}
}

func TestUI2RepeaterGraphQLSendNamesTheNewExchange(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"me":{"id":"1"}}}`))
	}))
	t.Cleanup(origin.Close)
	authority := strings.TrimPrefix(origin.URL, "http://")
	s := newTestServer()
	req := strings.Replace(ui2GQLRequest(), "Host: api.test", "Host: "+authority, 1)
	body := ui2PostRW(t, s, "/ui2/repeater/graphql/send", url.Values{"request": {req}})
	if !strings.Contains(body, `{&#34;data&#34;:{&#34;me&#34;`) || !strings.Contains(body, "Review save of exchange #") {
		t.Fatalf("send outcome or save offer missing: %s", body)
	}
}

func TestUI2RepeaterGraphQLSendRefusesWithoutATarget(t *testing.T) {
	s := newTestServer()
	body := ui2PostRW(t, s, "/ui2/repeater/graphql/send", url.Values{"request": {"POST /graphql HTTP/1.1\r\n\r\n{}"}})
	if !strings.Contains(body, "no target") {
		t.Fatalf("send without a target was not refused: %s", body)
	}
}

var ui2ReviewRe = regexp.MustCompile(`name="review_id" value="([0-9a-f]+)"><input type="hidden" name="token" value="([0-9a-f]+)"`)

func TestUI2RepeaterGraphQLSitemapReviewThenSave(t *testing.T) {
	s := newTestServer()
	id := seedExchange(t, s, ui2GQLRequest(), jsonResponse(introspectionFixture))
	before := len(s.store.Exchanges())
	review := ui2PostRW(t, s, "/ui2/repeater/graphql/sitemap-confirm", url.Values{"exchange": {strconv.Itoa(int(id))}})
	if len(s.store.Exchanges()) != before {
		t.Fatal("the review step wrote to the store")
	}
	m := ui2ReviewRe.FindStringSubmatch(review)
	if m == nil || !strings.Contains(review, "createUser") || !strings.Contains(review, "data-arm-on-load") {
		t.Fatalf("review sheet is missing its operations or held call: %s", review)
	}
	done := ui2PostRW(t, s, "/ui2/repeater/graphql/sitemap-run", url.Values{"review_id": {m[1]}, "token": {m[2]}})
	if !strings.Contains(done, "Saved 3 unsent request(s)") || len(s.store.Exchanges()) != before+3 {
		t.Fatalf("save did not land: %s", done)
	}
	again := ui2PostRW(t, s, "/ui2/repeater/graphql/sitemap-run", url.Values{"review_id": {m[1]}, "token": {m[2]}})
	if !strings.Contains(again, "already used") || len(s.store.Exchanges()) != before+3 {
		t.Fatalf("a spent review was accepted twice: %s", again)
	}
}

func TestUI2RepeaterGraphQLSitemapConfirmRefusesAnUnansweredExchange(t *testing.T) {
	s := newTestServer()
	reqID, _ := s.store.Put([]byte(ui2GQLRequest()), core.DirectionRequest)
	ex := &core.Exchange{Host: "api.test", Port: 443, Request: core.MsgPtr(reqID)}
	s.store.AddExchange(ex)
	body := ui2PostRW(t, s, "/ui2/repeater/graphql/sitemap-confirm", url.Values{"exchange": {strconv.Itoa(int(ex.ID))}})
	if !strings.Contains(body, "send the introspection query first") || strings.Contains(body, "review_id") {
		t.Fatalf("unanswered exchange was not refused: %s", body)
	}
}

func TestUI2RepeaterGraphQLSitemapRunRefusesAWrongToken(t *testing.T) {
	s := newTestServer()
	id := seedExchange(t, s, ui2GQLRequest(), jsonResponse(introspectionFixture))
	before := len(s.store.Exchanges())
	m := ui2ReviewRe.FindStringSubmatch(ui2PostRW(t, s, "/ui2/repeater/graphql/sitemap-confirm", url.Values{"exchange": {strconv.Itoa(int(id))}}))
	if m == nil {
		t.Fatal("no review minted")
	}
	body := ui2PostRW(t, s, "/ui2/repeater/graphql/sitemap-run", url.Values{"review_id": {m[1]}, "token": {"00"}})
	if !strings.Contains(body, "confirmation does not match") || len(s.store.Exchanges()) != before {
		t.Fatalf("a wrong token was accepted: %s", body)
	}
}
