package httputil

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// TestParseChunkSize pins the RFC 9112 §7.1 grammar the shared parser accepts (chunk-size =
// 1*HEXDIG, optional extension, optional surrounding whitespace) and everything it refuses. The
// refusals are the bead: strconv.ParseInt(s, 16, 64) took "-1" and "+1", and "-1" reached make().
func TestParseChunkSize(t *testing.T) {
	good := []struct {
		line string
		want int64
	}{
		{"0", 0},
		{"0\r\n", 0},
		{"1a\r\n", 26},
		{"1A\r\n", 26},
		{"1a;name=value\r\n", 26},
		{"1a ; name=value\r\n", 26},
		{"  ff\t\r\n", 255},
		{"00000000000000000000001\r\n", 1}, // leading zeros are not significant digits
		{"fffffffffffffff\r\n", 1<<60 - 1}, // 15 significant digits: the bound
		{"8\n", 8},
	}
	for _, c := range good {
		got, err := ParseChunkSize(c.line)
		if err != nil || got != c.want {
			t.Errorf("ParseChunkSize(%q) = %d, %v; want %d", c.line, got, err, c.want)
		}
	}
	bad := []string{
		"-1\r\n",
		"+1\r\n",
		"-0\r\n",
		"0x1a\r\n",
		"1_0\r\n",
		"1 0\r\n",
		"\r\n",
		";ext\r\n",
		"g\r\n",
		"1000000000000000\r\n", // 16 significant digits
		"ffffffffffffffff\r\n", // MaxUint64: ParseInt refused it, ParseUint took it
		"7fffffffffffffff\r\n", // MaxInt64: would overflow any size+total sum
		"\xff\r\n",
	}
	for _, line := range bad {
		got, err := ParseChunkSize(line)
		var cse *ChunkSizeError
		if !errors.As(err, &cse) {
			t.Errorf("ParseChunkSize(%q) = %d, %v; want a *ChunkSizeError", line, got, err)
		}
	}
}

// hostileChunkSizes are chunk-size lines a hostile origin can answer with. Every one must be a
// reported error from every chunked reader, never a panic and never a silently accepted body.
var hostileChunkSizes = []string{
	"-1",
	"-8000000000000000",
	"+1",
	"1000000000000000", // overlong hex
	"ffffffffffffffffffffffffffffffff",
	"zz",
	"0x10",
	"",
}

func chunkedHead() []byte {
	return []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
}

func TestReadResponseBodyRefusesHostileChunkSizes(t *testing.T) {
	for _, size := range hostileChunkSizes {
		t.Run(size, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(size + "\r\nabcd\r\n0\r\n\r\n"))
			body, err := ReadResponseBody(br, chunkedHead())
			if err == nil {
				t.Fatalf("ReadResponseBody accepted chunk size %q: body %q", size, body)
			}
			if body != nil {
				t.Fatalf("a refused body came back with bytes: %q", body)
			}
		})
	}
}

func TestStreamResponseRefusesHostileChunkSizes(t *testing.T) {
	for _, size := range hostileChunkSizes {
		t.Run(size, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader("4\r\nfine\r\n" + size + "\r\nabcd\r\n0\r\n\r\n"))
			res, err := StreamResponse(br, chunkedHead(), nil)
			if err == nil {
				t.Fatalf("StreamResponse accepted chunk size %q: %+v", size, res)
			}
			if res.Completed {
				t.Fatalf("a refused stream reported Completed: %+v", res)
			}
			if string(res.Body) != "fine" {
				t.Fatalf("the payload before the fault should come back: %q", res.Body)
			}
		})
	}
}

// TestChunkLineIsBounded: a size line, or a trailer line, with no newline in sight is refused once
// it passes the bound rather than buffered until memory runs out.
func TestChunkLineIsBounded(t *testing.T) {
	endless := strings.Repeat("0", MaxChunkLineBytes+1)
	if _, err := ReadResponseBody(bufio.NewReader(strings.NewReader(endless)), chunkedHead()); !errors.Is(err, ErrChunkLineTooLong) {
		t.Fatalf("buffered reader: err = %v, want ErrChunkLineTooLong", err)
	}
	if _, err := StreamResponse(bufio.NewReader(strings.NewReader(endless)), chunkedHead(), nil); !errors.Is(err, ErrChunkLineTooLong) {
		t.Fatalf("stream reader: err = %v, want ErrChunkLineTooLong", err)
	}
	trailer := "0\r\nX-Long: " + strings.Repeat("a", MaxChunkLineBytes) + "\r\n\r\n"
	if _, err := ReadResponseBody(bufio.NewReader(strings.NewReader(trailer)), chunkedHead()); !errors.Is(err, ErrChunkLineTooLong) {
		t.Fatalf("trailer: err = %v, want ErrChunkLineTooLong", err)
	}
	// Control: the same shapes inside the bound read cleanly, extension and trailer included.
	ok := "4;" + strings.Repeat("e", 1000) + "\r\nWiki\r\n0\r\nX-T: v\r\n\r\n"
	body, err := ReadResponseBody(bufio.NewReader(strings.NewReader(ok)), chunkedHead())
	if err != nil || string(body) != ok {
		t.Fatalf("in-bound chunked body: %q, %v", body, err)
	}
}

func TestDechunkRefusesHostileChunkSizes(t *testing.T) {
	for _, size := range hostileChunkSizes {
		if got, ok := Dechunk([]byte(size + "\r\nabcd\r\n0\r\n\r\n")); ok {
			t.Errorf("Dechunk accepted chunk size %q: %q", size, got)
		}
	}
}

// FuzzParseChunkSize: whatever the line, the parser either refuses it or returns a size that is
// non-negative, within the digit bound, and equal to what the line's hex digits spell.
func FuzzParseChunkSize(f *testing.F) {
	for _, s := range append(hostileChunkSizes, "0", "1a", "1a;x=y\r\n", " ff \r\n", "0001", "fffffffffffffff") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		size, err := ParseChunkSize(line)
		if err != nil {
			var cse *ChunkSizeError
			if !errors.As(err, &cse) {
				t.Fatalf("error is not a *ChunkSizeError: %T %v", err, err)
			}
			return
		}
		if size < 0 || size >= 1<<60 {
			t.Fatalf("ParseChunkSize(%q) = %d, outside [0, 2^60)", line, size)
		}
		field := line
		if i := strings.IndexByte(field, ';'); i >= 0 {
			field = field[:i]
		}
		field = strings.Trim(field, " \t\r\n")
		if field == "" || strings.Trim(field, "0123456789abcdefABCDEF") != "" {
			t.Fatalf("ParseChunkSize(%q) accepted a non-hex field %q", line, field)
		}
		// Feeding it to the buffered reader must never panic, whatever it is.
		br := bufio.NewReader(strings.NewReader(line + "\nxx"))
		_, _ = ReadResponseBody(br, chunkedHead())
	})
}
