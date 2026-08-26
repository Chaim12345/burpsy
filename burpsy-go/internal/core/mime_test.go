package core

import (
	"testing"
	"time"
)

// TestMimeEssence covers each case the five capture sites can be handed. The malformed ones are not
// hypothetical padding: a response with no Content-Type is the common case for a 204 or a redirect, a
// bare `Content-Type:` is what some proxies emit, and the case of the header name is whatever the
// origin felt like sending.
func TestMimeEssence(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "parameters are stripped and the type is lowercased",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/HTML; charset=utf-8\r\n\r\n<html>",
			want: "text/html",
		},
		{
			name: "no Content-Type header at all",
			raw:  "HTTP/1.1 204 No Content\r\nServer: nginx\r\n\r\n",
			want: "",
		},
		{
			name: "header present with an empty value",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type:\r\nServer: nginx\r\n\r\nbody",
			want: "",
		},
		{
			name: "header carrying only parameters names no media type",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: ; charset=utf-8\r\n\r\nbody",
			want: "",
		},
		{
			name: "several Content-Type headers: the first one wins, deterministically",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n{}",
			want: "application/json",
		},
		{
			name: "the header name is matched case-insensitively",
			raw:  "HTTP/1.1 200 OK\r\ncOnTeNt-TyPe: Application/JSON\r\n\r\n{}",
			want: "application/json",
		},
		{
			name: "no headers at all, only a status line",
			raw:  "HTTP/1.1 200 OK\r\n\r\n",
			want: "",
		},
		{
			name: "empty input is not a panic",
			raw:  "",
			want: "",
		},
		{
			name: "LF-only line endings, as a hand-written or proxied response may use",
			raw:  "HTTP/1.1 200 OK\nContent-Type: image/png\n\n\x89PNG",
			want: "image/png",
		},
		{
			name: "surrounding whitespace in the value is trimmed",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type:    text/css   \r\n\r\nbody{}",
			want: "text/css",
		},
		{
			name: "a header whose name merely contains content-type is not a match",
			raw:  "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n",
			want: "",
		},
		{
			name: "no header terminator: the head is still searched rather than skipped",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/plain",
			want: "text/plain",
		},
		{
			// The truncation cases below are the infinite loop that shipped in the first cut of this
			// function, kept as value assertions here and as a termination assertion in
			// TestMimeEssenceTerminatesOnTruncatedInput. nextLineStart cannot step past a CR whose LF is
			// missing, so an unguarded loop never advanced and hung the caller.
			name: "a header line truncated on a bare CR still yields its value",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r",
			want: "text/plain",
		},
		{
			name: "a bare CR after a header that is not Content-Type does not hang or match",
			raw:  "HTTP/1.1 200 OK\r\nX-Foo: bar\r",
			want: "",
		},
		{
			name: "a status line truncated on a bare CR has no headers to read",
			raw:  "HTTP/1.1 200 OK\r",
			want: "",
		},
		{
			name: "an absolute-form request line is not mistaken for a header",
			raw:  "GET http://example.com/p HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MimeEssence([]byte(tc.raw)); got != tc.want {
				t.Fatalf("MimeEssence(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// MimeEssence terminates on every truncation of a well-formed head.
//
// This is a regression test for a real hang, not a hypothetical. The first cut of the header walk
// advanced with `pos = nextLineStart(head, eol)` and trusted it to move. It does not: nextLineStart
// looks for the LF following a CR, and when the buffer ends on a lone CR that LF is absent, so it
// returns the CR's own index and pos stays put — an infinite loop with no error, no output and no
// allocation, which would wedge whichever capture site called it. A response cut between the CR and
// the LF is not exotic; it is what a proxy sees when a connection drops mid-header.
//
// Asserted as termination rather than as a value, because a value assertion on a spinning function
// never gets to run. Every prefix is tried so the property is the loop's and not one input's.
func TestMimeEssenceTerminatesOnTruncatedInput(t *testing.T) {
	full := "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html>"
	for i := 0; i <= len(full); i++ {
		prefix := full[:i]
		done := make(chan string, 1)
		go func() { done <- MimeEssence([]byte(prefix)) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("MimeEssence did not terminate on the %d-byte prefix %q", i, prefix)
		}
	}
}
