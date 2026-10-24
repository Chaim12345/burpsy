package proxy

// withCookieHeader against the request shapes real browsers send. The gate's original
// acceptance test proxied a one-header request ("Host" and nothing else), which is the
// single shape the old rebuild survived: fed a slice starting at the first header,
// headerLines dropped that header as if it were the request line, and the head's own
// terminating marker was appended whole, smuggling one blank line into the body. The
// TLS-tunnel and h2 legs made both visible — a Go client sends three headers, and its
// origin answered 400 (missing Host). These pin the rebuild's exact bytes.

import (
	"strings"
	"testing"
)

func TestWithCookieHeaderKeepsEveryHeaderAndTerminatesOnce(t *testing.T) {
	req := "GET /protected HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"User-Agent: Go-http-client/1.1\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"\r\n"
	got := string(withCookieHeader([]byte(req), "sessid=fresh"))
	want := "GET /protected HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"User-Agent: Go-http-client/1.1\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"Cookie: sessid=fresh\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("rebuilt request:\n%q\nwant:\n%q", got, want)
	}
}

func TestWithCookieHeaderReplacesTheStaleCookie(t *testing.T) {
	req := "GET /protected HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"Cookie: sessid=stale\r\n" +
		"X-Other: 1\r\n" +
		"\r\n"
	got := string(withCookieHeader([]byte(req), "sessid=fresh"))
	want := "GET /protected HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"X-Other: 1\r\n" +
		"Cookie: sessid=fresh\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("rebuilt request:\n%q\nwant:\n%q", got, want)
	}
	if strings.Count(got, "Cookie:") != 1 {
		t.Fatalf("two Cookie headers in %q — undefined behaviour every origin reads differently", got)
	}
}

func TestWithCookieHeaderPreservesTheBody(t *testing.T) {
	req := "POST /login HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"Content-Length: 7\r\n" +
		"\r\n" +
		"user=ann"
	got := string(withCookieHeader([]byte(req), "sessid=fresh"))
	want := "POST /login HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"Content-Length: 7\r\n" +
		"Cookie: sessid=fresh\r\n" +
		"\r\n" +
		"user=ann"
	if got != want {
		t.Fatalf("rebuilt request:\n%q\nwant:\n%q", got, want)
	}
}

// The one-header shape the old build happened to survive: pinned so a future simplification
// does not regress it while fixing the general case.
func TestWithCookieHeaderSingleHeaderRequest(t *testing.T) {
	req := "GET /protected HTTP/1.1\r\nHost: app.test\r\n\r\n"
	got := string(withCookieHeader([]byte(req), "sessid=fresh"))
	want := "GET /protected HTTP/1.1\r\nHost: app.test\r\nCookie: sessid=fresh\r\n\r\n"
	if got != want {
		t.Fatalf("rebuilt request:\n%q\nwant:\n%q", got, want)
	}
}
