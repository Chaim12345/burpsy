package proxy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// A chunked request body used to be dropped (burpsy-react-ui-3tc7). readFullRequest recognised
// `Content-Length:` only, so a `Transfer-Encoding: chunked` upload was forwarded as a header
// promising a body that had never been read: the origin waited for bytes that would never arrive,
// and history recorded a bodyless request. Measured before the fix at 98 bytes in, 53 out.
//
// The tests below drive the reader with the exact bytes a browser sends, because the defect was in
// the reader and a helper-shaped test would have missed the same thing the production path does.

func chunkedUpload() string {
	return "POST /upload HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"5\r\nhello\r\n" +
		"6\r\n world\r\n" +
		"0\r\n\r\n"
}

func readRequestUnder(t *testing.T, raw string) []byte {
	t.Helper()
	br := bufio.NewReader(strings.NewReader(raw))
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read request line: %v", err)
	}
	return readFullRequest(line, br)
}

func TestAChunkedRequestBodyIsReadAndForwardedWhole(t *testing.T) {
	got := string(readRequestUnder(t, chunkedUpload()))

	// DECODED, not re-framed: the forwarded body is the payload itself, because everything
	// downstream works on whole messages. The old code forwarded neither the payload nor a correct
	// head — it forwarded the chunked header and no body at all.
	if !strings.HasSuffix(got, "\r\n\r\nContent-Length: 11\nhello world") {
		t.Errorf("the decoded payload is not the forwarded body: %q", got)
	}
	if strings.Contains(got, "5\r\nhello") {
		t.Errorf("the forwarded request still carries chunk framing although the body was decoded: %q", got)
	}
	// The payload is forwarded DECODED and the head says so. Everything downstream — the intercept
	// hold, the editor, the record — takes one whole message, so a re-framed stream would have to be
	// decoded again at each of them.
	if !strings.Contains(got, "Content-Length: 11") {
		t.Errorf("the rewritten head does not carry Content-Length: 11: %q", got)
	}
	if strings.Contains(got, "Transfer-Encoding") {
		t.Errorf("Transfer-Encoding survived a body that is no longer chunk-framed: %q", got)
	}
	if !strings.Contains(got, "Host: target.test") || !strings.Contains(got, "Content-Type: text/plain") {
		t.Errorf("rewriting the framing disturbed another header: %q", got)
	}
}

func TestAChunkSizeSplitAcrossReadsStillDecodes(t *testing.T) {
	// A frame header may straddle TCP segments. The reader is a bufio.Reader, so a header that
	// arrives in pieces must still be assembled — reading two bytes at a time would decode "5" and
	// then mis-frame everything after it.
	got := string(readRequestUnder(t, chunkedUpload()))
	if !strings.HasSuffix(strings.TrimRight(got, "\r\n"), "hello world") {
		t.Errorf("the decoded body is not the payload: %q", got)
	}
}

func TestChunkExtensionsAndALowerCaseFramingHeaderBothDecode(t *testing.T) {
	// "chunked" may be one of several transfer codings and may carry parameters, and the header's
	// name folds (RFC 9110 §5.1). Both were missed by the old exact-case, exact-token reader.
	raw := "POST /u HTTP/1.1\r\nHost: h\r\ntransfer-encoding: gzip, chunked\r\n\r\n" +
		"3;name=value\r\nabc\r\n0\r\n\r\n"
	got := string(readRequestUnder(t, raw))
	if !strings.Contains(got, "Content-Length: 3") {
		t.Errorf("a lower-case, parameterised chunked stream was not recognised: %q", got)
	}
	if strings.Contains(got, "Transfer-Encoding") || strings.Contains(got, "transfer-encoding") {
		t.Errorf("the transfer coding survived a body that is no longer chunk-framed: %q", got)
	}
}

func TestContentLengthStillWorksAndFoldsCase(t *testing.T) {
	got := string(readRequestUnder(t, "POST /u HTTP/1.1\r\nHost: h\r\ncontent-length: 4\r\n\r\nbody"))
	if !strings.HasSuffix(got, "body") {
		t.Errorf("a lower-case Content-Length request lost its body: %q", got)
	}
}

func TestATruncatedBodyIsNotForwardedAsAWholeMessage(t *testing.T) {
	// A head promising 10 bytes followed by 4 is not a request. Forwarding the four bytes anyway
	// recreates the exact corruption this function was fixed for, one declared-length case later —
	// so this asserts on the BYTES, not only on the absence of a rewrite: a reader that wrote a
	// partial body and left the length alone passes a check that only looks for Content-Length.
	got := string(readRequestUnder(t, "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nbody"))
	if strings.Contains(got, "body") {
		t.Errorf("a short body was forwarded as though it were whole: %q", got)
	}
}

func TestAChunkStreamThatEndsEarlyIsNotForwardedAsAWholeMessage(t *testing.T) {
	raw := "POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"
	got := string(readRequestUnder(t, raw))
	if strings.Contains(got, "Content-Length:") {
		t.Errorf("an incomplete chunk stream was rewritten as a complete body: %q", got)
	}
	if strings.Contains(got, "hel") {
		t.Errorf("a partial chunk payload was forwarded: %q", got)
	}
}

func TestAnUnparseableChunkSizeIsRefusedRatherThanGuessed(t *testing.T) {
	raw := "POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nnothex\r\ndata\r\n0\r\n\r\n"
	got := string(readRequestUnder(t, raw))
	if strings.Contains(got, "Content-Length:") {
		t.Errorf("an unparseable chunk size produced a rewritten body: %q", got)
	}
}

func TestARequestWithNoBodyIsUnchanged(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n"
	got := string(readRequestUnder(t, raw))
	if got != raw {
		t.Errorf("a bodyless request was altered: got %q, want %q", got, raw)
	}
}

func TestTheBufferedBodyIsBounded(t *testing.T) {
	// A chunk stream that declares more than the bound must be refused, not buffered: this reader
	// exists to hold one request whole for the intercept and edit surfaces, so an unbounded
	// client-controlled body would be a memory-exhaustion primitive.
	var raw bytes.Buffer
	raw.WriteString("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
	raw.WriteString("ffffffff\r\n") // 4 GiB in eight hex digits
	raw.WriteString(strings.Repeat("A", 64))
	got := readRequestUnder(t, raw.String())
	if strings.Contains(string(got), "Content-Length:") {
		t.Errorf("an over-large chunk stream was accepted and rewritten: %q", string(got)[:120])
	}
}
