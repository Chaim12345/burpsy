package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The unit contract: chunk framing off, gzip decoded, Content-Encoding and Transfer-Encoding gone,
// Content-Length set to what the head now frames — and every other header kept byte for byte.
func TestReadableResponseDecodesAChunkedGzipBodyAndKeepsTheOtherHeaders(t *testing.T) {
	html := "<html><body>contact admin@example.test</body></html>"
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nX-Custom: Keep-Me\r\nTransfer-Encoding: chunked\r\n\r\n"),
		chunked(gzipped(t, html))...)

	out, undecodable := readableResponse(raw)
	if undecodable {
		t.Fatal("a gzip body was reported undecodable")
	}
	head, body, _ := splitHeadAndBody(out)
	if string(body) != html {
		t.Errorf("body = %q", body)
	}
	h := string(head)
	for _, gone := range []string{"Content-Encoding", "Transfer-Encoding"} {
		if strings.Contains(h, gone) {
			t.Errorf("%s survived into the readable head: %q", gone, h)
		}
	}
	for _, kept := range []string{"HTTP/1.1 200 OK", "Content-Type: text/html", "X-Custom: Keep-Me", "Content-Length: " + itoaForCaptureTest(len(html))} {
		if !strings.Contains(h, kept) {
			t.Errorf("readable head lacks %q: %q", kept, h)
		}
	}
}

// A plain response comes back untouched; a br body this build cannot decode comes back dechunked
// and flagged, so a clean result on it is counted as a caveat rather than read as clean.
func TestReadableResponseLeavesPlainBodiesAndFlagsAnUndecodableOne(t *testing.T) {
	plain := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	if out, undecodable := readableResponse(plain); !bytes.Equal(out, plain) || undecodable {
		t.Errorf("a plain response changed: %q (undecodable %v)", out, undecodable)
	}
	br := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n"), chunked([]byte("\x0b\x02\x80opaque"))...)
	out, undecodable := readableResponse(br)
	if !undecodable {
		t.Error("a br body was not flagged undecodable")
	}
	if !strings.Contains(string(out), "Content-Encoding: br") || strings.Contains(string(out), "Transfer-Encoding") {
		t.Errorf("an undecodable body should keep its Content-Encoding and lose only its chunk framing: %q", out)
	}
}

func passiveFindingNames(fs *core.FindingStore, path string) []string {
	var names []string
	for _, f := range fs.All() {
		if f.Target.Path == path {
			names = append(names, f.Name)
		}
	}
	sort.Strings(names)
	return names
}

// The acceptance of burpsy-react-ui-jgnf: a gzip+chunked HTML response yields the same passive
// findings as its plain twin — the built-in body checks (an email address) and the static DOM pass
// (a source flowing into a sink) alike. Before, the compressed twin yielded only header findings.
func TestACompressedResponseYieldsTheSamePassiveFindingsAsItsPlainTwin(t *testing.T) {
	html := `<html><body>mail admin@example.test<script>document.write(location.hash)</script></body></html>`
	cap, _, findings := newTestCapture()
	record := func(path, head string, body []byte) {
		resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"+head+"\r\n"), body...)
		if _, err := cap.Record(CapturedExchange{
			Host: "app.test", Port: 80, Method: "GET", Path: path,
			Request:  []byte("GET " + path + " HTTP/1.1\r\nHost: app.test\r\n\r\n"),
			Response: resp, Started: time.Now(), Duration: time.Millisecond,
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	record("/plain", "Content-Length: "+itoaForCaptureTest(len(html))+"\r\n", []byte(html))
	record("/packed", "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n", chunked(gzipped(t, html)))

	plain, packed := passiveFindingNames(findings, "/plain"), passiveFindingNames(findings, "/packed")
	if strings.Join(plain, "|") != strings.Join(packed, "|") {
		t.Errorf("the compressed twin's findings differ:\n plain:  %v\n packed: %v", plain, packed)
	}
	joined := strings.Join(packed, "|")
	if !strings.Contains(joined, "Email Address") {
		t.Errorf("the compressed twin did not yield the email finding: %v", packed)
	}
	if len(packed) < 2 {
		t.Errorf("the compressed twin yielded only %v; the body checks did not read it", packed)
	}
}

// A loaded passive BCheck reads the decoded body too, and an undecodable one is counted on the
// coverage report rather than read as a clean scan.
func TestAPassiveBCheckReadsADecodedBodyAndCountsAnUndecodableOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.bcheck"), []byte(testPassiveBCheck), 0o644); err != nil {
		t.Fatal(err)
	}
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("*")
	ps, err := LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	scan := func(head string, body []byte) []*Finding {
		reqID, _ := store.Put([]byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"), core.DirectionRequest)
		respID, _ := store.Put(append([]byte("HTTP/1.1 200 OK\r\n"+head+"\r\n"), body...), core.DirectionResponse)
		ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "x.test", Port: 80, Method: "GET", Path: "/"}
		store.AddExchange(ex)
		return ps.Scan(ex)
	}
	if got := scan("Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n", chunked(gzipped(t, "xx BURPSY_MARKER xx"))); len(got) != 1 {
		t.Errorf("the BCheck did not see the marker in a gzip+chunked body: %d findings", len(got))
	}
	if ps.Coverage().UndecodedBodies != 0 {
		t.Error("a decodable body was counted as undecoded")
	}
	scan("Content-Encoding: br\r\nContent-Length: 4\r\n", []byte("\x0b\x02\x80x"))
	if n := ps.Coverage().UndecodedBodies; n != 1 {
		t.Errorf("undecoded bodies = %d, want 1", n)
	}
}

// The shape the proxy actually stores: a chunked response with its framing removed but the
// Transfer-Encoding header kept. Treating the failed dechunk as fatal left every proxied gzip page
// unread — the in-process twin test above passes framed bytes and could not see it; a live proxy run
// did.
func TestReadableResponseReadsTheProxysDeframedChunkedShape(t *testing.T) {
	html := "<html><body>write to admin@example.test</body></html>"
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"), gzipped(t, html)...)
	out, undecodable := readableResponse(raw)
	if undecodable {
		t.Fatal("the proxy's stored shape was reported undecodable")
	}
	if _, body, _ := splitHeadAndBody(out); string(body) != html {
		t.Errorf("body = %q", body)
	}
	if strings.Contains(string(out), "Transfer-Encoding") {
		t.Error("the readable head still claims chunk framing")
	}
}
