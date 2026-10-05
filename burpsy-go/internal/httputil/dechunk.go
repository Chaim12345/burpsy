package httputil

import (
	"bytes"
	"strconv"
	"strings"
)

// Dechunk collapses a chunked body — `size CRLF data CRLF … 0 CRLF trailer CRLF` — to its data. It
// returns false for framing it cannot parse, so a malformed body is left alone rather than guessed at.
//
// Exported for readers outside the proxy that need a stored body's bytes as the application sent
// them (burpsy-react-ui-8j0d's secret scan is the first): chunk framing wraps whatever is beneath it,
// so it has to come off before DecodeBody is attempted — feeding `size CRLF data` to gzip decodes the
// size prefix as payload. internal/proxy and internal/web each keep an older private copy.
func Dechunk(body []byte) ([]byte, bool) {
	var out bytes.Buffer
	rest := body
	for {
		eol := bytes.IndexByte(rest, '\n')
		if eol < 0 {
			return nil, false
		}
		sizeLine := strings.TrimSpace(string(rest[:eol]))
		rest = rest[eol+1:]
		// A chunk extension (`1a;name=value`) is legal and its size is the part before the semicolon.
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = strings.TrimSpace(sizeLine[:semi])
		}
		size, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil || size < 0 {
			return nil, false
		}
		if size == 0 {
			return out.Bytes(), true
		}
		if int64(len(rest)) < size {
			return nil, false
		}
		out.Write(rest[:size])
		rest = rest[size:]
		if len(rest) >= 2 && rest[0] == '\r' && rest[1] == '\n' {
			rest = rest[2:]
		} else if len(rest) >= 1 && rest[0] == '\n' {
			rest = rest[1:]
		} else {
			return nil, false
		}
	}
}
