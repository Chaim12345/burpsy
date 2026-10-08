package bcheck

// u411: the hash and encode functions and the reserved variables Burp's BCheck reference documents —
// sha1, sha256, md5, base64_encode, user_agent, request.http_version, response.http_version and
// request.url.protocol — resolve to real values. Before, each rendered "" and the check compared
// against nothing.

import (
	"strings"
	"testing"
)

func TestHashAndEncodeFunctionsMatchBurpsReferenceDigests(t *testing.T) {
	ctx := NewContext()
	ctx.Variables["word"] = Value{Type: "str", StringVal: "hello"}
	for expr, want := range map[string]string{
		// The reference's example digests (they are the digests of "hello").
		`sha1("hello")`:                "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		`sha256("hello")`:              "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		`md5("hello")`:                 "5d41402abc4b2a76b9719d911017c592",
		`MD5("hello")`:                 "5d41402abc4b2a76b9719d911017c592",
		`sha1({word})`:                 "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		`base64_encode("hello world")`: "aGVsbG8gd29ybGQ=",
	} {
		if got := ctx.resolveRef(expr); got != want {
			t.Errorf("resolveRef(%s) = %q, want %q", expr, got, want)
		}
	}
	if u := ctx.Unresolved(); len(u) != 0 {
		t.Errorf("functions were recorded unresolved: %v", u)
	}
}

func TestUserAgentIsTheSendersThenTheRequestsOwnElseUnresolved(t *testing.T) {
	ctx := NewContext()
	ctx.UserAgent = "burpsy/1.0"
	ctx.Request = []byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 test\r\n\r\n")
	if got := ctx.resolveRef("user_agent"); got != "burpsy/1.0" {
		t.Errorf("with a sender agent: %q, want burpsy/1.0", got)
	}
	ctx = NewContext()
	ctx.Request = []byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 test\r\n\r\n")
	if got := ctx.resolveRef("user_agent"); got != "Mozilla/5.0 test" {
		t.Errorf("falling back to the request's own: %q", got)
	}
	ctx = NewContext()
	ctx.Request = []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := ctx.resolveRef("user_agent"); got != "" || len(ctx.Unresolved()) != 1 {
		t.Errorf("with neither: %q, unresolved %v; want empty and recorded", got, ctx.Unresolved())
	}
}

func TestBaseRequestAndResponseVersionAndURLParts(t *testing.T) {
	ctx := NewContext()
	ctx.Request = []byte("GET /catalog/product?productId=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	ctx.Response = []byte("HTTP/2 200 OK\r\n\r\nbody")
	ctx.Host, ctx.Port, ctx.TLS, ctx.Path = "shop.test", 443, true, "/catalog/product?productId=1"
	for ref, want := range map[string]string{
		"base.request.http_version":  "HTTP/1.1",
		"base.response.http_version": "HTTP/2",
		"base.request.url.protocol":  "https",
		"base.request.url.path":      "/catalog/product",
		"base.request.url.file":      "/catalog/product?productId=1",
		"base.request.url.query":     "productId=1",
		"base.request.url.port":      "443",
	} {
		if got := ctx.resolveRef(ref); got != want {
			t.Errorf("{%s} = %q, want %q", ref, got, want)
		}
	}
}

func TestSentRequestVersionProtocolAndPortThroughTheEvaluator(t *testing.T) {
	ctx := NewContext()
	ctx.Request = []byte("GET /orig?a=1 HTTP/1.1\r\nHost: x.test\r\n\r\n")
	ctx.Response = ok200("base")
	ctx.Host, ctx.Port, ctx.TLS, ctx.Path = "x.test", 443, true, "/orig?a=1"
	ctx.UserAgent = "burpsy/1.0"
	m := &mockSink{replies: []mockReply{{body: []byte("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")}}}
	_, err := RunActive(parseCheck(`given host then
  send request called probe:
    path: "/first"
  send request:
    appending headers:
      "X-Probe": `+"`{probe.request.url.protocol}|{probe.request.url.port}|{probe.request.http_version}|{probe.response.http_version}`,"+`
      "X-Hash": `+"`{sha256(\"hello\")}|{base64_encode(\"hi\")}|{user_agent}`"+`
`), ctx, m, &Target{Host: "x.test", Port: 443, TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.count() != 2 {
		t.Fatalf("want two sends, got %d", m.count())
	}
	second := m.sent[1]
	for _, want := range []string{
		"X-Probe: https|443|HTTP/1.1|HTTP/1.0",
		"X-Hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824|aGk=|burpsy/1.0",
	} {
		if !strings.Contains(second, want) {
			t.Errorf("second send lacks %q:\n%s", want, second)
		}
	}
	if u := ctx.Unresolved(); len(u) != 0 {
		t.Errorf("unresolved: %v", u)
	}
}
