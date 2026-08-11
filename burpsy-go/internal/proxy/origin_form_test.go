package proxy

import "testing"

// A client configured to use a proxy sends absolute-form — `GET http://host/path HTTP/1.1` (RFC 9112
// §3.2.2) — because the proxy needs to know which origin it is talking to. The origin server must
// then be sent origin-form, `GET /path HTTP/1.1` (§3.2.1). The plain-HTTP path forwarded the client's
// request line verbatim, so the target received the entire absolute URI as its request path: a demo
// target echoing its own path answered "GET http://127.0.0.1:18199/hello?a=1&b=2" where the Rust
// implementation produced "GET /hello?a=1&b=2". Every path-routing framework, and every application
// that reads its own path, sees a different request than the operator sent.
func Test_an_absolute_form_request_line_is_rewritten_to_origin_form(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		target  string
		path    string
		want    string
		comment string
	}{
		{
			name:   "absolute form with a query",
			raw:    "GET http://127.0.0.1:18199/hello?a=1&b=2 HTTP/1.1\r\nHost: 127.0.0.1:18199\r\n\r\n",
			target: "http://127.0.0.1:18199/hello?a=1&b=2",
			path:   "/hello?a=1&b=2",
			want:   "GET /hello?a=1&b=2 HTTP/1.1\r\nHost: 127.0.0.1:18199\r\n\r\n",
		},
		{
			name:   "the authority alone becomes a bare slash",
			raw:    "GET http://example.test HTTP/1.1\r\nHost: example.test\r\n\r\n",
			target: "http://example.test",
			path:   "/",
			want:   "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
		},
		{
			// Only the request line is touched, so an absolute URL that also appears in a header or a
			// body must survive unchanged. A naive bytes.Replace over the whole request would rewrite
			// the Referer too, silently editing a header the operator is inspecting.
			name:   "an absolute URL elsewhere in the request is left alone",
			raw:    "POST http://a.test/login HTTP/1.1\r\nReferer: http://a.test/login\r\n\r\nurl=http://a.test/login",
			target: "http://a.test/login",
			path:   "/login",
			want:   "POST /login HTTP/1.1\r\nReferer: http://a.test/login\r\n\r\nurl=http://a.test/login",
		},
		{
			name:   "an already-origin-form request is untouched",
			raw:    "GET /inside-a-tunnel HTTP/1.1\r\nHost: a.test\r\n\r\n",
			target: "/inside-a-tunnel",
			path:   "/inside-a-tunnel",
			want:   "GET /inside-a-tunnel HTTP/1.1\r\nHost: a.test\r\n\r\n",
		},
		{
			// Asterisk-form (RFC 9112 §3.2.4). parseTarget leaves it in `path` as-is, so this arrives
			// with target == path and is returned untouched — but it is pinned because "rewrite
			// anything that is not origin-form" would have turned a valid OPTIONS * into nonsense.
			name:   "asterisk-form OPTIONS is untouched",
			raw:    "OPTIONS * HTTP/1.1\r\nHost: a.test\r\n\r\n",
			target: "*",
			path:   "*",
			want:   "OPTIONS * HTTP/1.1\r\nHost: a.test\r\n\r\n",
		},
		{
			// Whitespace is preserved rather than normalised: this proxy's job includes showing what
			// was actually sent, and re-serialising the line would quietly correct the client.
			name:   "unusual whitespace in the request line survives",
			raw:    "GET  http://a.test/x  HTTP/1.1\r\n\r\n",
			target: "http://a.test/x",
			path:   "/x",
			want:   "GET  /x  HTTP/1.1\r\n\r\n",
		},
		{
			name:   "bare LF line endings are not converted to CRLF",
			raw:    "GET http://a.test/x HTTP/1.1\nHost: a.test\n\n",
			target: "http://a.test/x",
			path:   "/x",
			want:   "GET /x HTTP/1.1\nHost: a.test\n\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(toOriginForm([]byte(tc.raw), tc.target, tc.path))
			if got != tc.want {
				t.Errorf("toOriginForm:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The rewrite reads the target out of the first line positionally, so it has to refuse rather than
// guess when the line does not contain what it was told to look for. Corrupting a request would be
// worse than forwarding an absolute-form one.
func Test_the_origin_form_rewrite_refuses_rather_than_guesses(t *testing.T) {
	raw := "GET /something-else HTTP/1.1\r\n\r\n"
	if got := string(toOriginForm([]byte(raw), "http://a.test/x", "/x")); got != raw {
		t.Errorf("a target absent from the request line was rewritten anyway: %q", got)
	}
	// No line terminator at all: there is no first line to bound the edit to.
	headless := "GET http://a.test/x HTTP/1.1"
	if got := string(toOriginForm([]byte(headless), "http://a.test/x", "/x")); got != headless {
		t.Errorf("a request with no line terminator was edited: %q", got)
	}
	if got := string(toOriginForm([]byte(raw), "", "")); got != raw {
		t.Errorf("an empty target caused an edit: %q", got)
	}
}
