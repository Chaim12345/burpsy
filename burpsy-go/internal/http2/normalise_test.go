package http2

import (
	"strings"
	"testing"
)

func TestRenderRequestPreservesFieldOrderAndCasing(t *testing.T) {
	headers := []Header{
		{Name: "X-Foo", Value: "1"},
		{Name: "x-foo", Value: "2"},
		{Name: "Set-COOKIE", Value: "a=b"},
	}
	out := string(RenderRequest("GET", "/x", "example.com", headers, []byte("hi")))
	if !strings.Contains(out, "GET /x HTTP/2\r\n") {
		t.Fatalf("missing start line: %q", out)
	}
	if !strings.Contains(out, "X-Foo: 1\r\n") || !strings.Contains(out, "x-foo: 2\r\n") {
		t.Fatalf("duplicate/casing headers lost: %q", out)
	}
	if !strings.HasSuffix(out, "Content-Length: 2\r\n\r\nhi") {
		t.Fatalf("body framing wrong: %q", out)
	}
}

func TestRenderResponseOmitsReasonPhrase(t *testing.T) {
	out := string(RenderResponse(204, nil, nil))
	if out != "HTTP/2 204\r\nContent-Length: 0\r\n\r\n" {
		t.Fatalf("got %q", out)
	}
}
