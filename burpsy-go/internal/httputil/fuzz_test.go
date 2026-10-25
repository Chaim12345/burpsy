package httputil

import (
	"bytes"
	"fmt"
	"strings"
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

// FuzzSplitHeadBody fuzzes the head/body cut: whatever the input, a reported split must
// reassemble to the input exactly, and a refusal must mean neither separator spelling is
// present. HeadEnd must always agree with the split.
func FuzzSplitHeadBody(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"))
	f.Add([]byte("HTTP/1.1 200 OK\n\nbody"))
	f.Add([]byte("no separator at all"))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("a\r\n\r\nb\n\nc"))
	f.Add([]byte("a\n\nb\r\n\r\nc"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		head, body, sep, ok := SplitHeadBody(raw)
		if !ok {
			if HeadEnd(raw) >= 0 {
				t.Fatalf("no split but HeadEnd = %d on %q", HeadEnd(raw), raw)
			}
			return
		}
		if got := HeadEnd(raw); got != len(head)+len(sep) {
			t.Fatalf("HeadEnd = %d, split says %d on %q", got, len(head)+len(sep), raw)
		}
		reassembled := append(append(append([]byte{}, head...), sep...), body...)
		if !bytes.Equal(reassembled, raw) {
			t.Fatalf("head+sep+body != raw on %q", raw)
		}
		// Terminator precedence: a CRLF terminator wins even when a bare-LF terminator sits
		// earlier in the bytes; the LF-only gap is not a terminator on the wire.
		if i := bytes.Index(raw, crlfcrlf); i >= 0 {
			if !bytes.Equal(head, raw[:i]) || !bytes.Equal(sep, crlfcrlf) {
				t.Fatalf("CRLF terminator present but split gave %q %q on %q", head, sep, raw)
			}
		} else if i := bytes.Index(raw, lflf); i >= 0 {
			if !bytes.Equal(head, raw[:i]) || !bytes.Equal(sep, lflf) {
				t.Fatalf("LF-only message split gave %q %q on %q", head, sep, raw)
			}
		}
	})
}

// FuzzHeaderValue fuzzes the header read: a found value must appear on some line of the head
// after that line's colon, under the same case-insensitive name.
func FuzzHeaderValue(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.test\r\nAccept: */*"), "host")
	f.Add([]byte("HTTP/1.1 200 OK\nContent-Length: 5"), "CONTENT-LENGTH")
	f.Add([]byte("X: a\r\nX: b"), "x")
	f.Add([]byte("NoColonLines"), "x")
	f.Fuzz(func(t *testing.T, head []byte, name string) {
		value, ok := HeaderValue(head, name)
		if !ok {
			return
		}
		// First-match binding: the returned value must come from the FIRST line whose
		// trimmed field name folds equal - not just any matching line deeper in the head.
		for _, line := range HeadLines(head) {
			k, v, found := bytes.Cut(line, []byte(":"))
			if found && strings.EqualFold(strings.TrimSpace(string(k)), name) {
				if strings.TrimSpace(string(v)) != value {
					t.Fatalf("value %q for %q is not the first matching line's %q of %q", value, name, strings.TrimSpace(string(v)), head)
				}
				return
			}
		}
		t.Fatalf("value %q for %q is on no line of %q", value, name, head)
	})
}

// FuzzHeaderValueExact fuzzes the strict read. Oracles: a found value must sit on the FIRST
// line that starts with name+":" case-insensitively; a miss must mean NO line carries that
// prefix (the false-negative direction the lenient read's TrimSpace would otherwise mask);
// and any strict match is a match for the lenient read too.
func FuzzHeaderValueExact(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"), "content-encoding")
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Encoding : gzip\r\n"), "Content-Encoding")
	f.Add([]byte("HTTP/1.1 200 OK\r\n  X: a\r\nX: b\r\n"), "x")
	f.Add([]byte("HTTP/1.1 200 OK\r\nX: one\r\nX: two\r\n"), "X")
	f.Fuzz(func(t *testing.T, head []byte, name string) {
		if name == "" {
			return
		}
		value, ok := HeaderValueExact(head, name)
		prefix := strings.ToLower(name) + ":"
		firstStrict := -1
		var firstValue string
		for i, line := range HeadLines(head) {
			if len(line) == 0 {
				continue
			}
			if strings.HasPrefix(strings.ToLower(string(line)), prefix) {
				firstStrict = i
				firstValue = strings.TrimSpace(string(line[len(prefix):]))
				break
			}
		}
		if !ok {
			if firstStrict >= 0 {
				t.Fatalf("missed the strict %q line %d of %q", name, firstStrict, head)
			}
			return
		}
		if firstStrict < 0 {
			t.Fatalf("found %q for %q on no strict line of %q", value, name, head)
		}
		if value != firstValue {
			t.Fatalf("value %q is not the first strict match %q for %q in %q", value, firstValue, name, head)
		}
		if _, lenientOK := HeaderValue(head, name); !lenientOK {
			t.Fatalf("strict match for %q invisible to the lenient read of %q", name, head)
		}
	})
}
