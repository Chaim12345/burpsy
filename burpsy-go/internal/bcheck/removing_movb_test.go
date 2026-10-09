package bcheck

// movb: Burp's `removing` send-request actions and the \s \b \f escapes. Each assertion reads the
// bytes the sink received — the parse succeeding proves nothing about what went out.

import (
	"strings"
	"testing"
)

const movbBase = "POST /a/b?keep=1&drop=2&drop=3 HTTP/1.1\r\nHost: x.test\r\nOrigin: http://o.test\r\nX-Gone: 1\r\nx-gone: 2\r\nContent-Type: text/plain\r\n\r\nhello"

func movbRun(t *testing.T, mods string) string {
	t.Helper()
	ctx := activeCtx()
	ctx.Request = []byte(movbBase)
	ctx.Path = "/a/b?keep=1&drop=2&drop=3"
	m := &mockSink{}
	if _, err := RunActive(parseCheck("given host then\n  send request:\n"+mods), ctx, m, tgt()); err != nil {
		t.Fatal(err)
	}
	if m.count() != 1 {
		t.Fatalf("want one send, got %d", m.count())
	}
	return m.first()
}

func TestRemovingHeadersAndQueriesDropsEveryNamedOne(t *testing.T) {
	got := movbRun(t, `    removing headers:
      "Origin",
      "X-Gone"
    removing queries:
      "drop"
`)
	line, _, _ := strings.Cut(got, "\r\n")
	if line != "POST /a/b?keep=1 HTTP/1.1" {
		t.Errorf("request line = %q, want the drop parameters gone and keep kept", line)
	}
	for _, gone := range []string{"Origin:", "X-Gone:", "x-gone:"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q survived removing headers:\n%s", gone, got)
		}
	}
	if !strings.Contains(got, "Content-Type: text/plain") || !strings.HasSuffix(got, "hello") {
		t.Errorf("an unnamed header or the body went missing:\n%s", got)
	}
}

func TestRemovingPathMethodBodyAndQueryString(t *testing.T) {
	got := movbRun(t, `    removing path
    removing body
    removing query_string:
    removing method
`)
	line, _, _ := strings.Cut(got, "\r\n")
	if line != "/ HTTP/1.1" {
		t.Errorf("request line = %q, want no method, path \"/\", no query", line)
	}
	if strings.HasSuffix(got, "hello") {
		t.Errorf("the body survived removing body:\n%s", got)
	}
}

func TestAppendingQueryStringAppendsAndReplacingQueriesReplaces(t *testing.T) {
	got := movbRun(t, `    appending query_string: "extra=9"
    replacing queries:
      "drop=X",
      "fresh=1"
`)
	line, _, _ := strings.Cut(got, "\r\n")
	if line != "POST /a/b?keep=1&drop=X&extra=9&fresh=1 HTTP/1.1" {
		t.Errorf("request line = %q", line)
	}
}

func TestSpecialCharacterEscapesInATemplate(t *testing.T) {
	got := movbRun(t, "    replacing headers:\n      \"X-Esc\": `a\\sb\\bc\\fd`\n")
	if !strings.Contains(got, "X-Esc: a b\bc\fd\r\n") {
		t.Errorf("escapes not applied:\n%q", got)
	}
	// A literal string keeps them as two characters, as Burp's reference says of "\s".
	got = movbRun(t, "    replacing headers:\n      \"X-Lit\": \"a\\sb\"\n")
	if !strings.Contains(got, `X-Lit: a\sb`) {
		t.Errorf("a literal string must not interpret \\s:\n%q", got)
	}
}
