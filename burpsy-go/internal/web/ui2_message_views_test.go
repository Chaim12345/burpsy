package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A JWT whose payload carries markup: {"alg":"HS256","typ":"JWT"} . {"sub":"<script>x</script>","exp":2000000000}
const ui2TestJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI8c2NyaXB0Png8L3NjcmlwdD4iLCJleHAiOjIwMDAwMDAwMDB9.c2ln"

func seedUI2MessageExchange(t *testing.T, s *Server) string {
	t.Helper()
	body := `{"query":"query Q { me { name } }","variables":{"a":"<script>v</script>"}}`
	req := "POST /graphql?x=1&y=%3Cb%3E HTTP/1.1\r\nHost: g.test\r\nAuthorization: Bearer " + ui2TestJWT +
		"\r\nCookie: sid=abc; t=2\r\nContent-Type: application/json\r\nX-Tab:\ta\r\n\r\n" + body
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: s=1; HttpOnly\r\n\r\n<h1>hi</h1><script>alert(1)</script>"
	return strconv.FormatUint(uint64(seedUI2Exchange(t, s, req, resp)), 10)
}

func getUI2HX(t *testing.T, s *Server, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestUI2MessageViewsRenderEachView(t *testing.T) {
	s := newTestServer()
	id := seedUI2MessageExchange(t, s)
	base := "/ui2/history/" + id + "?"
	cases := []struct{ query, marker string }{
		{"view_req=hex", `class="hx-off">00000000</span>`},
		{"view_req=jwt", "alg <strong>HS256</strong>"},
		{"view_req=jwt", "Authorization header"},
		{"view_req=graphql", `class="gql-ok">parses`},
		{"view_req=graphql", "  me {"},
		{"view_resp=render", `<iframe class="msg-render" sandbox="" src="/ui2/message/render/` + id + `"`},
		{"view_req=raw&nonprint=1", "␉a"},
		{"inspector=1", `data-copy="abc"`},
		{"inspector=1", "Request query parameters (2)"},
		{"inspector=1", "HttpOnly"},
	}
	for _, c := range cases {
		if body := getUI2HX(t, s, base+c.query); !strings.Contains(body, c.marker) {
			t.Errorf("%s: missing %q", c.query, c.marker)
		}
	}
	// A view that does not apply falls back to Pretty and says so.
	if body := getUI2HX(t, s, base+"view_resp=protobuf"); !strings.Contains(body, "Protobuf view does not apply") {
		t.Errorf("an inapplicable view did not fall back with a note")
	}
}

// No view but Render may put captured markup into the page as markup.
func TestUI2MessageViewsEscapeCapturedScript(t *testing.T) {
	s := newTestServer()
	id := seedUI2MessageExchange(t, s)
	for _, q := range []string{"", "view_req=raw&view_resp=raw", "view_req=hex&view_resp=hex", "view_req=jwt", "view_req=graphql",
		"view_resp=render", "inspector=1", "nonprint=1&charset=windows-1252&hide=1"} {
		if body := getUI2HX(t, s, "/ui2/history/"+id+"?"+q); strings.Contains(strings.ToLower(body), "<script") {
			t.Errorf("%q rendered a live <script>", q)
		}
	}
}

func TestUI2MessageRenderIsSandboxed(t *testing.T) {
	s := newTestServer()
	id := seedUI2MessageExchange(t, s)
	rec := getUI2(t, s, "/ui2/message/render/"+id)
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != http.StatusOK || !strings.HasPrefix(csp, "sandbox;") || strings.Contains(csp, "allow-scripts") ||
		!strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("render = %d, CSP %q", rec.Code, csp)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("render headers: %v", rec.Header())
	}
	if rec := getUI2(t, s, "/ui2/message/render/9999"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d", rec.Code)
	}
}

func TestUI2MessageCharsetDecodesBody(t *testing.T) {
	s := newTestServer()
	id := strconv.FormatUint(uint64(seedUI2Exchange(t, s, "GET / HTTP/1.1\r\nHost: c.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=windows-1252\r\n\r\ncaf\xe9")), 10)
	if body := getUI2HX(t, s, "/ui2/history/"+id+"?view_resp=raw&charset=auto"); !strings.Contains(body, "café") {
		t.Errorf("charset=auto did not decode the body as windows-1252")
	}
	if body := getUI2HX(t, s, "/ui2/history/"+id+"?view_resp=raw"); strings.Contains(body, "café") {
		t.Errorf("the default reading decoded a non-UTF-8 body")
	}
}

func TestUI2MessageProtobufViewAndSchema(t *testing.T) {
	s := newTestServer()
	id := strconv.FormatUint(uint64(seedUI2Exchange(t, s, "POST /x HTTP/1.1\r\nHost: p.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\n\r\n\x08\x96\x01")), 10)
	if body := getUI2HX(t, s, "/ui2/history/"+id+"?view_resp=protobuf"); !strings.Contains(body, "#1</span>") || !strings.Contains(body, "150") {
		t.Errorf("schemaless decode missing field #1 = 150")
	}
	rec := postUI2Form(t, s, "/ui2/message/protobuf/"+id+"/schema?view_resp=protobuf", url.Values{
		"side": {"resp"}, "proto": {`syntax = "proto3"; message M { int32 user_id = 1; }`}})
	if body := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(body, "<strong>user_id</strong>") {
		t.Errorf("schema decode did not name the field: %d", rec.Code)
	}
	if rec := postUI2Form(t, s, "/ui2/message/protobuf/"+id+"/schema", url.Values{"side": {"sideways"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a bad side = %d, want 400", rec.Code)
	}
}

// The reflection fetch is egress: a review holds it, a wrong token refuses, a review runs once.
func TestUI2MessageReflectReviewIsSingleUse(t *testing.T) {
	s := newTestServer()
	id := strconv.FormatUint(uint64(seedUI2Exchange(t, s, "POST /pkg.S/M HTTP/1.1\r\nHost: p.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\n\r\n\x00\x00\x00\x00\x03\x08\x96\x01")), 10)
	rec := postUI2Form(t, s, "/ui2/message/protobuf/"+id+"/reflect-review", url.Values{
		"side": {"resp"}, "target": {"127.0.0.1:1"}, "service": {"pkg.S"}})
	review := rec.Body.String()
	if !strings.Contains(review, "service: pkg.S") || !strings.Contains(review, "data-arm-on-load") {
		t.Fatalf("no review sheet: %s", review)
	}
	field := func(name string) string {
		m := regexp.MustCompile(`name="` + name + `" value="([0-9a-f]+)"`).FindStringSubmatch(review)
		if m == nil {
			t.Fatalf("review has no %s", name)
		}
		return m[1]
	}
	reviewID, token := field("review_id"), field("token")
	run := "/ui2/message/protobuf/" + id + "/reflect-run"
	if body := postUI2Form(t, s, run, url.Values{"review_id": {reviewID}, "token": {"00"}}).Body.String(); !strings.Contains(body, "already used or expired") {
		t.Errorf("a wrong token was not refused")
	}
	// The wrong-token attempt spent the review: the right token no longer runs it.
	if body := postUI2Form(t, s, run, url.Values{"review_id": {reviewID}, "token": {token}}).Body.String(); !strings.Contains(body, "already used or expired") {
		t.Errorf("a spent review ran")
	}
}
