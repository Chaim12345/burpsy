package core

import "testing"

// ibhs: native fuzz for the message parser and the WebSocket frame header decoder.

func inSpan(sp Span, n int) bool { return sp.Offset >= 0 && sp.Len >= 0 && sp.Offset+sp.Len <= n }

// FuzzParse: Parse never panics, and every span it returns lies inside the input.
func FuzzParse(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), false)
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), true)
	f.Add([]byte("GET / HTTP/1.1\nHost: a\n\n"), false)
	f.Add([]byte("POST /x HTTP/1.1\r\nA:\r\n B: folded\r\n\r\nbody"), false)
	f.Add([]byte("\r\n\r\n"), false)
	f.Add([]byte("GET"), false)
	f.Add([]byte{}, true)
	f.Fuzz(func(t *testing.T, raw []byte, resp bool) {
		dir := DirectionRequest
		if resp {
			dir = DirectionResponse
		}
		sh, err := Parse(raw, dir)
		if err != nil {
			return
		}
		n := len(raw)
		for name, sp := range map[string]Span{"first": sh.FirstToken, "second": sh.SecondToken, "third": sh.ThirdToken, "body": sh.Body} {
			if !inSpan(sp, n) {
				t.Fatalf("%s span %+v outside %d bytes", name, sp, n)
			}
		}
		for i, h := range sh.Headers {
			if !inSpan(h.Name, n) || !inSpan(h.Value, n) {
				t.Fatalf("header %d spans %+v outside %d bytes", i, h, n)
			}
		}
	})
}

// FuzzParseWsFrameHeader: never panics; a decoded header's length fits the input, and a header is
// never reported together with a need-more-bytes or an error.
func FuzzParseWsFrameHeader(f *testing.F) {
	f.Add([]byte{0x81, 0x05})
	f.Add([]byte{0x81, 0x7e, 0x01, 0x00})
	f.Add([]byte{0x81, 0xfe, 0x01, 0x00, 1, 2, 3, 4})
	f.Add([]byte{0x82, 0x7f, 0, 0, 0, 0, 0, 0, 1, 0})
	f.Add([]byte{0x82, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x81})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, more, err := ParseWsFrameHeader(b)
		if h == nil {
			return
		}
		if more || err != nil {
			t.Fatalf("header with more=%v err=%v", more, err)
		}
		if h.HeaderLen < 2 || h.HeaderLen > len(b) {
			t.Fatalf("HeaderLen %d for %d input bytes", h.HeaderLen, len(b))
		}
	})
}
