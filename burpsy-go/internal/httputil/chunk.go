package httputil

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
)

// This file is the one chunk-size parser every HTTP/1 chunked reader in this package shares
// (burpsy-react-ui-negchunk-panic).
//
// The readers used to call strconv.ParseInt(sizeStr, 16, 64) each on their own, and ParseInt takes a
// sign: "-1" parsed as a size of -1, and the buffered reader handed that straight to make([]byte, n),
// which panics. One hostile origin answering "-1\r\n" killed the proxy connection goroutine — and,
// with no recover there, the whole process. RFC 9112 §7.1 gives chunk-size as 1*HEXDIG: no sign, no
// prefix, no underscore, no whitespace inside it. This parser accepts exactly that and nothing more,
// so a size it returns is always a non-negative int64 that fits comfortably in an allocation bound.

// MaxChunkSizeDigits bounds the significant hex digits of one chunk size: 15 digits is just under
// 2^60 bytes, far past every cap a reader applies, and far enough below MaxInt64 that size plus a
// running total can never overflow. Leading zeros are not counted — "0000001" is a legal 1 — but they
// still count against MaxChunkLineBytes.
const MaxChunkSizeDigits = 15

// MaxChunkLineBytes bounds one chunk-size line (size plus any extensions) and one trailer line. The
// readers used bufio.Reader.ReadString, which grows without limit: a peer that sent a size line with
// no newline made the reader buffer until memory ran out. 16 KiB is far beyond any real extension.
const MaxChunkLineBytes = 16 * 1024

// maxChunkTrailerBytes bounds a chunked body's whole trailer section, the same bound a head gets.
const maxChunkTrailerBytes = MaxResponseHeadBytes

// ErrChunkLineTooLong is a chunk-size or trailer line longer than MaxChunkLineBytes, or a trailer
// section longer than MaxResponseHeadBytes.
var ErrChunkLineTooLong = errors.New("chunk line exceeds the length bound")

// ChunkSizeError is a chunk-size line that is not a chunk size.
type ChunkSizeError struct {
	Line   string // the size field as read, extension removed and whitespace trimmed
	Reason string
}

func (e *ChunkSizeError) Error() string {
	return fmt.Sprintf("bad chunk size %q: %s", e.Line, e.Reason)
}

// ParseChunkSize reads the chunk size off one chunk-size line: the line may still carry its line
// ending and any chunk extension (`1a;name=value`), both of which are removed, along with optional
// whitespace around the size. What is left must be one or more hex digits — no sign, no "0x", no
// underscore — with at most MaxChunkSizeDigits significant ones. Anything else is a *ChunkSizeError.
func ParseChunkSize(line string) (int64, error) {
	field := line
	if semi := strings.IndexByte(field, ';'); semi >= 0 {
		field = field[:semi]
	}
	field = strings.Trim(field, " \t\r\n")
	if field == "" {
		return 0, &ChunkSizeError{Line: field, Reason: "empty"}
	}
	var size int64
	significant := 0
	for i := 0; i < len(field); i++ {
		d, ok := hexDigit(field[i])
		if !ok {
			return 0, &ChunkSizeError{Line: field, Reason: fmt.Sprintf("byte %q is not a hex digit", field[i])}
		}
		if significant == 0 && d == 0 {
			continue
		}
		significant++
		if significant > MaxChunkSizeDigits {
			return 0, &ChunkSizeError{Line: field, Reason: fmt.Sprintf("more than %d significant hex digits", MaxChunkSizeDigits)}
		}
		size = size<<4 | int64(d)
	}
	return size, nil
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// readChunkLine reads one line, through its '\n', refusing one longer than limit. On an error before
// the newline the bytes read so far come back with it, as bufio.Reader.ReadString's do.
func readChunkLine(br *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > limit {
			return "", ErrChunkLineTooLong
		}
		line = append(line, frag...)
		if err != bufio.ErrBufferFull {
			return string(line), err
		}
	}
}

// readChunkTrailers reads a chunked body's trailer section through its empty line, bounded per line
// and in total, calling keep for every line including the empty one.
func readChunkTrailers(br *bufio.Reader, keep func(string)) error {
	total := 0
	for {
		line, err := readChunkLine(br, MaxChunkLineBytes)
		if err != nil {
			return fmt.Errorf("reading chunk trailer: %w", err)
		}
		total += len(line)
		if total > maxChunkTrailerBytes {
			return fmt.Errorf("reading chunk trailer: %w", ErrChunkLineTooLong)
		}
		keep(line)
		if strings.Trim(line, "\r\n") == "" {
			return nil
		}
	}
}
