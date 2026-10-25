package proxy

// Unpacking a compressed HTTP message on the proxy path.
//
// Before this the proxy had no decompressor at all. Every response-modification rule skipped a
// compressed body — counted as SkippedCompressed and surfaced on the settings panel, whose copy said
// so — and the only workaround offered was strip_accept_encoding, which changes what the client asks
// the origin for and is detectable server-side. So the operator had to choose between reading the
// traffic and observing the traffic the client would really have received.
//
// Burp's Proxy → Miscellaneous panel has these as two switches, "unpack gzip" and "unpack deflate".

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/httputil"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func gzipResponse(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	return encodedResponse(buf.Bytes(), "gzip")
}

func deflateResponse(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib: %v", err)
	}
	return encodedResponse(buf.Bytes(), "deflate")
}

func encodedResponse(packed []byte, encoding string) []byte {
	head := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Encoding: " + encoding + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(packed)) + "\r\n\r\n"
	return append([]byte(head), packed...)
}

// chunkedGzipResponse frames a gzip body in chunks, which is what a real origin sends: the chunk
// sizes wrap the compressed bytes, so the framing must come off before the decompressor sees them.
func chunkedGzipResponse(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	packed := buf.Bytes()
	var framed bytes.Buffer
	// Two chunks, so a decoder that only handled the single-chunk case fails here.
	half := len(packed) / 2
	for _, part := range [][]byte{packed[:half], packed[half:]} {
		framed.WriteString(strconv.FormatInt(int64(len(part)), 16) + "\r\n")
		framed.Write(part)
		framed.WriteString("\r\n")
	}
	framed.WriteString("0\r\n\r\n")
	head := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n"
	return append([]byte(head), framed.Bytes()...)
}

const scriptedPage = `<html><body><script>tracker()</script><p>hello</p></body></html>`

func TestAResponseRuleReachesAGzippedBodyWhenUnpackingIsOn(t *testing.T) {
	o := NewOptions()
	if err := o.Set(OptUnpackCompressedResponses, true); err != nil {
		t.Fatal(err)
	}
	if err := o.Set(OptRemoveAllJavaScript, true); err != nil {
		t.Fatal(err)
	}

	out := o.ApplyResponse(gzipResponse(t, scriptedPage))
	text := string(out)
	if strings.Contains(text, "<script>") {
		t.Errorf("the script survived: the rule did not reach the decompressed body\n%q", text)
	}
	if !strings.Contains(text, "<p>hello</p>") {
		t.Errorf("the rest of the page is gone\n%q", text)
	}
	// The header describing the body as encoded must go with the encoding, or the browser decompresses
	// plaintext and gets a broken page.
	if strings.Contains(strings.ToLower(text), "content-encoding") {
		t.Errorf("Content-Encoding survived on a decompressed body\n%q", text)
	}
	// And the length must follow the body it now describes.
	_, body, _, ok := httputil.SplitHeadBody(out)
	if !ok {
		t.Fatal("the rebuilt response has no separator")
	}
	if got, _ := httputil.HeaderValue(out[:bytes.Index(out, []byte("\r\n\r\n"))], "Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, body is %d bytes", got, len(body))
	}

	c := o.Counters()
	if c.UnpackedResponses != 1 {
		t.Errorf("unpacked_responses = %d, want 1", c.UnpackedResponses)
	}
	if c.SkippedCompressed != 0 {
		t.Errorf("skipped_compressed = %d on a response that WAS unpacked", c.SkippedCompressed)
	}
	if c.Modified != 1 {
		t.Errorf("modified = %d, want 1", c.Modified)
	}
}

func TestUnpackingWorksOnDeflateAndOnChunkedFraming(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp []byte
	}{
		{"deflate", deflateResponse(t, scriptedPage)},
		{"chunked gzip", chunkedGzipResponse(t, scriptedPage)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := NewOptions()
			o.Set(OptUnpackCompressedResponses, true)
			o.Set(OptRemoveAllJavaScript, true)
			text := string(o.ApplyResponse(tc.resp))
			if strings.Contains(text, "<script>") {
				t.Errorf("the script survived\n%q", text)
			}
			if !strings.Contains(text, "<p>hello</p>") {
				t.Errorf("the page did not decompress\n%q", text)
			}
			if o.Counters().UnpackedResponses != 1 {
				t.Errorf("unpacked_responses = %d, want 1", o.Counters().UnpackedResponses)
			}
		})
	}
}

// Unpacking on its own makes the body readable, which is half the point of the switch: a response
// that is decompressed and matched by no rule has still been changed for the better.
func TestUnpackingAloneDecompressesTheBody(t *testing.T) {
	o := NewOptions()
	o.Set(OptUnpackCompressedResponses, true)

	text := string(o.ApplyResponse(gzipResponse(t, scriptedPage)))
	if !strings.Contains(text, scriptedPage) {
		t.Errorf("the body was not decompressed with only the unpack switch on\n%q", text)
	}
	if o.Counters().UnpackedResponses != 1 {
		t.Errorf("unpacked_responses = %d, want 1", o.Counters().UnpackedResponses)
	}
}

func TestWithUnpackingOffACompressedResponseIsUntouchedAndCounted(t *testing.T) {
	o := NewOptions()
	o.Set(OptRemoveAllJavaScript, true)

	in := gzipResponse(t, scriptedPage)
	out := o.ApplyResponse(in)
	if !bytes.Equal(in, out) {
		t.Error("a compressed response was changed with unpacking off")
	}
	c := o.Counters()
	if c.SkippedCompressed != 1 {
		t.Errorf("skipped_compressed = %d, want 1", c.SkippedCompressed)
	}
	// The narrower counter must stay at zero: the reason was "the switch is off", which the operator
	// can fix, not "this build cannot decode it", which they cannot.
	if c.SkippedUnsupportedEncoding != 0 {
		t.Errorf("skipped_unsupported_encoding = %d, want 0: the encoding was decodable, the switch "+
			"was off", c.SkippedUnsupportedEncoding)
	}
}

func TestAResponseRuleReachesBrotliAndZstdBodiesWhenUnpackingIsOn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		encoding string
		pack     func(*testing.T, string) []byte
	}{
		{"brotli", "br", func(t *testing.T, body string) []byte {
			var buf bytes.Buffer
			w := brotli.NewWriter(&buf)
			if _, err := w.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			return buf.Bytes()
		}},
		{"zstd", "zstd", func(t *testing.T, body string) []byte {
			var buf bytes.Buffer
			w, err := zstd.NewWriter(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			return buf.Bytes()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := NewOptions()
			if err := o.Set(OptUnpackCompressedResponses, true); err != nil {
				t.Fatal(err)
			}
			if err := o.Set(OptRemoveAllJavaScript, true); err != nil {
				t.Fatal(err)
			}
			out := o.ApplyResponse(encodedResponse(tc.pack(t, scriptedPage), tc.encoding))
			text := string(out)
			if strings.Contains(text, "<script>") {
				t.Errorf("the script survived: the rule did not reach the %s-decoded body\n%q", tc.encoding, text)
			}
			if !strings.Contains(text, "<p>hello</p>") {
				t.Errorf("the rest of the page is gone\n%q", text)
			}
			if c := o.Counters(); c.UnpackedResponses != 1 || c.SkippedCompressed != 0 {
				t.Errorf("counters = %+v, want one unpacked and none skipped", c)
			}
		})
	}
}

func TestAnUndecodableEncodingIsLeftAloneAndSaysWhy(t *testing.T) {
	o := NewOptions()
	o.Set(OptUnpackCompressedResponses, true)
	o.Set(OptRemoveAllJavaScript, true)

	// A body labelled br that is not brotli: corrupt streams are refused by name, never partly
	// rewritten. (A body that IS brotli unpacks — the case below it.)
	in := encodedResponse([]byte("\x00\x01\x02not brotli"), "br")
	out := o.ApplyResponse(in)
	if !bytes.Equal(in, out) {
		t.Error("a corrupt brotli response was partly rewritten")
	}
	c := o.Counters()
	if c.SkippedCompressed != 1 || c.SkippedUnsupportedEncoding != 1 {
		t.Errorf("counters = %+v, want one skipped-compressed and one skipped-unsupported", c)
	}
	if c.UnpackedResponses != 0 {
		t.Errorf("unpacked_responses = %d on a response nothing could decode", c.UnpackedResponses)
	}
}

func TestACorruptCompressedBodyIsLeftWhollyAlone(t *testing.T) {
	o := NewOptions()
	o.Set(OptUnpackCompressedResponses, true)
	o.Set(OptRemoveAllJavaScript, true)

	// A body labelled gzip that is not. Half a document is worse than none: a rule would rewrite the
	// part it could see and the browser would receive a page cut in the middle.
	in := encodedResponse([]byte("this is not gzip"), "gzip")
	out := o.ApplyResponse(in)
	if !bytes.Equal(in, out) {
		t.Errorf("a body that failed to decompress was partly replaced\n%q", out)
	}
	if c := o.Counters(); c.SkippedUnsupportedEncoding != 1 || c.UnpackedResponses != 0 {
		t.Errorf("counters = %+v, want the failure counted and nothing reported unpacked", c)
	}
}

func TestAnUncompressedResponseIsNotCountedAsASkip(t *testing.T) {
	o := NewOptions()
	o.Set(OptUnpackCompressedResponses, true)

	in := htmlResponse(scriptedPage)
	out := o.ApplyResponse(in)
	if !bytes.Equal(in, out) {
		t.Error("a plaintext response was changed by the unpack switch")
	}
	c := o.Counters()
	if c.SkippedCompressed != 0 || c.UnpackedResponses != 0 {
		t.Errorf("counters = %+v: a plaintext message is not a skip, it is a message the switch has "+
			"no business touching", c)
	}
}

func TestUnpackingARequestBody(t *testing.T) {
	o := NewOptions()
	o.Set(OptUnpackCompressedRequests, true)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"q":"alpha"}`))
	zw.Close()
	packed := buf.Bytes()
	in := []byte("POST /search HTTP/1.1\r\nHost: shop.test\r\nContent-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(len(packed)) + "\r\n\r\n")
	in = append(in, packed...)

	out := o.ApplyRequest(in)
	text := string(out)
	if !strings.Contains(text, `{"q":"alpha"}`) {
		t.Errorf("the request body was not decompressed\n%q", text)
	}
	if strings.Contains(strings.ToLower(text), "content-encoding") {
		t.Errorf("Content-Encoding survived on a decompressed request\n%q", text)
	}
	if c := o.Counters(); c.UnpackedRequests != 1 {
		t.Errorf("unpacked_requests = %d, want 1", c.UnpackedRequests)
	}
	// The response-direction counter must not move: an operator reading the panel has to be able to
	// tell which direction a switch is working in.
	if c := o.Counters(); c.UnpackedResponses != 0 {
		t.Errorf("unpacked_responses = %d after a request-direction unpack", c.UnpackedResponses)
	}
}

// The two switches are independent, matching Burp's two checkboxes: unpacking responses must not
// silently start rewriting request bodies the origin expects compressed.
func TestTheTwoUnpackSwitchesAreIndependent(t *testing.T) {
	o := NewOptions()
	o.Set(OptUnpackCompressedResponses, true)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"q":"alpha"}`))
	zw.Close()
	packed := buf.Bytes()
	in := []byte("POST /search HTTP/1.1\r\nHost: shop.test\r\nContent-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(len(packed)) + "\r\n\r\n")
	in = append(in, packed...)

	if out := o.ApplyRequest(in); !bytes.Equal(in, out) {
		t.Error("the response-direction switch unpacked a request body")
	}
	if c := o.Counters(); c.UnpackedRequests != 0 {
		t.Errorf("unpacked_requests = %d", c.UnpackedRequests)
	}
}
