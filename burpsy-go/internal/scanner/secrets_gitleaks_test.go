package scanner

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// awsKeyID is AWS's documented example key ID with the last character changed, so it is not on the
// corpus's allowlist of published examples.
const awsKeyID = "AKIAIOSFODNN7EXAMPLQ"

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func chunked(b []byte) []byte {
	var out bytes.Buffer
	half := len(b) / 2
	for _, part := range [][]byte{b[:half], b[half:]} {
		fmt.Fprintf(&out, "%x\r\n", len(part))
		out.Write(part)
		out.WriteString("\r\n")
	}
	out.WriteString("0\r\n\r\n")
	return out.Bytes()
}

func recordJS(t *testing.T, cap Capture, path string, head string, body []byte) {
	t.Helper()
	resp := append([]byte("HTTP/1.1 200 OK\r\n"+head+"\r\n"), body...)
	if _, err := cap.Record(CapturedExchange{
		Host: "cdn.test", Port: 443, TLS: true, Method: "GET", Path: path,
		Request:  []byte("GET " + path + " HTTP/1.1\r\nHost: cdn.test\r\n\r\n"),
		Response: resp, Started: time.Now(), Duration: time.Millisecond,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func secretFindings(fs *core.FindingStore) []*core.Finding {
	var out []*core.Finding
	for _, f := range fs.All() {
		if strings.HasPrefix(f.Name, "Secret exposed: ") {
			out = append(out, f)
		}
	}
	return out
}

// The bead's headline case: a CDN-served, gzip-compressed, chunked JS bundle carrying an AWS key —
// stored exactly as it crossed the wire, since unpacking is opt-in on the proxy — is flagged once the
// operator turns secret detection on, with the rule and the location in the finding. Off, it is not.
func TestSecretDetectionFindsAKeyInACompressedChunkedBundleOnlyWhenOn(t *testing.T) {
	js := "(()=>{\nconst cfg = {region:'us-east-1'};\nconst k = '" + awsKeyID + "';\n})();\n"
	head := "Content-Type: application/javascript\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n"
	body := chunked(gzipped(t, js))

	cap, _, findings := newTestCapture()
	recordJS(t, cap, "/off.js", head, body)
	if got := secretFindings(findings); len(got) != 0 {
		t.Fatalf("secret detection is off by default, yet %d secret finding(s) were filed", len(got))
	}

	cap.Scanner.SetSecretDetection(true)
	recordJS(t, cap, "/app.js", head, body)
	got := secretFindings(findings)
	if len(got) != 1 {
		t.Fatalf("got %d secret findings, want 1 (the AWS key in the decoded bundle)", len(got))
	}
	f := got[0]
	if f.Name != "Secret exposed: AWS access token" || f.Evidence != awsKeyID {
		t.Errorf("finding = %q evidence %q", f.Name, f.Evidence)
	}
	if !strings.Contains(f.Description, "aws-access-token") || !strings.Contains(f.Description, "line 3") {
		t.Errorf("description does not carry the rule and the line: %q", f.Description)
	}
	if f.Target.Path != "/app.js" || len(f.Occurrences) != 1 {
		t.Errorf("finding is not joined to its exchange: %+v", f)
	}
}

// Two different keys on one page are two findings; the same key on two pages of one host is one
// finding seen twice — the MergeKey is the rule plus a hash of the secret, never the secret itself.
func TestEachDistinctSecretIsItsOwnFindingAndARepeatMerges(t *testing.T) {
	cap, _, findings := newTestCapture()
	cap.Scanner.SetSecretDetection(true)
	other := "AKIAJ7Q4Z2RWXN5LP3VD"
	head := "Content-Type: application/javascript\r\n"
	recordJS(t, cap, "/a.js", head, []byte("var a='"+awsKeyID+"', b='"+other+"';"))
	recordJS(t, cap, "/b.js", head, []byte("var a='"+awsKeyID+"';"))

	got := secretFindings(findings)
	if len(got) != 2 {
		t.Fatalf("got %d secret findings, want 2 (one per distinct key)", len(got))
	}
	for _, f := range got {
		if f.Evidence == awsKeyID && f.MergedCount != 1 {
			t.Errorf("the key seen on two pages merged %d times, want 1", f.MergedCount)
		}
	}
}

// Images, fonts and archives are not scanned: regexes over encoded bytes find noise, not keys.
func TestABinaryResponseIsNotScannedForSecrets(t *testing.T) {
	m := &SecretsModule{}
	body := []byte("PNG...." + awsKeyID + "....")
	if got := m.Analyze(body, map[string]string{"Content-Type": "image/png"}); len(got) != 0 {
		t.Errorf("an image was scanned: %+v", got)
	}
	if got := m.Analyze(body, map[string]string{"Content-Type": "image/svg+xml"}); len(got) != 1 {
		t.Errorf("an SVG is text and must be scanned: %+v", got)
	}
}

// One detector serves every capture concurrently. Run with -race: DetectString must not write
// shared state, or the proxy's concurrent responses would corrupt each other's findings.
func TestTheSharedGitleaksDetectorIsSafeUnderConcurrentScans(t *testing.T) {
	m := &SecretsModule{}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := m.Analyze([]byte("const k = '"+awsKeyID+"';"), nil)
			if len(got) != 1 {
				errs <- fmt.Sprintf("concurrent scan returned %d findings", len(got))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n := GitleaksRuleCount(); n < 150 {
		t.Errorf("the corpus loaded %d rules; the embedded gitleaks config did not load", n)
	}
}
