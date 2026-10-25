package httputil

import (
	"bytes"
	"fmt"
	"testing"
)

// ibhs: native fuzz for the parsers. Crashers, if any, land in testdata via the go
// fuzzer; this file carries the seed corpus. Short local smoke runs; W5 schedules the
// nightly-length runs.

// FuzzRequestURL feeds the byte-preserving URL builder (vln3/swqq) arbitrary
// authorities and raw targets. Properties: never panic, and a successful build honors
// the verbatim contract — the request URI it produces carries the target it was
// handed whenever that target is a clean origin-form.
func FuzzRequestURL(f *testing.F) {
	seeds := []struct{ authority, target string }{
		{"example.com", "/a"},
		{"example.com:443", "/a#b"},
		{"example.com", "/a?x=1#frag"},
		{"example.com", "/a#b?c=d"},
		{"example.com", "/a b"},
		{"example.com", "http://other.example/abs"},
		{"example.com", "*"},
		{"[::1]:8443", "/"},
		{"example.com", "//double/slash"},
		{"example.com", "/%2f%2F"},
		{"example.com", "/\r\nInjected: header"},
		{"exa mple.com", "/"},
		{"", "/"},
		{"example.com", ""},
	}
	for _, s := range seeds {
		f.Add(s.authority, s.target)
	}
	f.Fuzz(func(t *testing.T, authority, rawTarget string) {
		u, err := RequestURL(authority, rawTarget)
		if err != nil {
			if u != nil {
				t.Fatalf("errored build returned a URL: %v", u)
			}
			return
		}
		if u == nil {
			t.Fatal("successful build returned nil")
		}
		// The verbatim contract: an origin-form target that url.Parse leaves
		// untransformed must come back byte-for-byte.
		if len(rawTarget) > 0 && rawTarget[0] == '/' && !bytes.ContainsAny([]byte(rawTarget), " \r\n") {
			if got := u.RequestURI(); got != rawTarget && u.Opaque == "" {
				t.Fatalf("clean origin-form target rewritten: %q -> %q", rawTarget, got)
			}
		}
	})
}

// FuzzDechunk feeds the chunk-framing parser arbitrary bytes, and asserts the
// round-trip on bodies it constructs as valid framing: what goes in framed comes out
// identical.
func FuzzDechunk(f *testing.F) {
	f.Add([]byte("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"))
	f.Add([]byte("1a;name=value\r\n0123456789abcdefghij01234567\r\n0\r\n\r\n"))
	f.Add([]byte("0\r\nTrailer: x\r\n\r\n"))
	f.Add([]byte("g\r\nnope\r\n"))
	f.Add([]byte("5\r\nabc\r\n"))
	f.Add([]byte("-1\r\nx\r\n0\r\n\r\n"))
	f.Add([]byte("ffffffffffffffff\r\nx\r\n"))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Dechunk(data)

		// Round-trip over data the fuzzer shaped: frame it, expect it back whole.
		var framed bytes.Buffer
		for rest := data; ; {
			n := len(rest)
			if n > 4096 {
				n = 4096
			}
			fmt.Fprintf(&framed, "%x\r\n", n)
			framed.Write(rest[:n])
			framed.WriteString("\r\n")
			rest = rest[n:]
			if len(rest) == 0 {
				break
			}
		}
		framed.WriteString("0\r\n\r\n")
		got, ok := Dechunk(framed.Bytes())
		if !ok {
			t.Fatalf("valid framing refused: %q", framed.Bytes())
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip lost bytes: framed %q, got %q, want %q", framed.Bytes(), got, data)
		}
	})
}
