package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The file-upload check (burpsy-react-ui-0vzb.15) against the live vulnapp upload family. Every
// claim is asserted on a vulnerable endpoint AND denied on a safe twin built to trip the specific
// guard behind it, so each guard has a test that fails when it is removed:
//
//   - the fetch-back content-type rule (servesActive): /fu/safe/attachment stores the .html file
//     and serves it as a text/plain download;
//   - the missing-directory control (traversal): /fu/safe/attachment echoes "../" in the location
//     it reports while flattening the name it stores;
//   - the response-shape comparison (sameUploadShape): /fu/safe/allowlist answers a refused file
//     with HTTP 200 and a message quoting the refused path;
//   - the filter bypasses (uploadVariants): /fu/filtered blocks .html case-sensitively, so only the
//     mixed-case variant gets a renderable document stored.

func TestFileUploadProvesStoredXSSTraversalAndAcceptedExtension(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/fu/upload", false)

	xss := got["Cross-site scripting (stored)"]
	if xss == nil {
		t.Fatalf("an uploaded .html file served back as text/html was not reported as stored XSS; rows: %s", joinRows(got))
	}
	if !strings.Contains(xss.Evidence, `Content-Type "text/html`) || !strings.Contains(xss.Evidence, "intact") {
		t.Errorf("the stored-XSS evidence does not show the fetch-back: %q", xss.Evidence)
	}

	trav := got["File path traversal"]
	if trav == nil {
		t.Fatalf("a filename resolved as a path was not reported as traversal; rows: %s", joinRows(got))
	}
	// The traversed file is served from the parent directory here, so the proof is the read-back.
	if trav.Confidence != "certain" || !strings.Contains(trav.Evidence, "read back from") {
		t.Errorf("traversal = %s %q, want certain with the read-back as its proof", trav.Confidence, trav.Evidence)
	}

	ext := got["File upload functionality"]
	if ext == nil {
		t.Fatalf("an accepted .jsp/.php upload was not reported; rows: %s", joinRows(got))
	}
	if ext.Severity != "low" || !strings.Contains(ext.Evidence, ".jsp") || !strings.Contains(ext.Evidence, ".php") {
		t.Errorf("accepted-extension finding = %s %q; want low, naming the server-script files", ext.Severity, ext.Evidence)
	}
	// Execution is never claimed, because nothing executable was ever sent.
	if !strings.Contains(ext.Description, "NOT that anything executes") {
		t.Errorf("the accepted-extension finding does not disclaim execution: %q", ext.Description)
	}
}

func TestFileUploadBypassesACaseSensitiveExtensionFilter(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/fu/filtered/upload", false)
	f := got["Cross-site scripting (stored)"]
	if f == nil {
		t.Fatalf("the mixed-case bypass of a case-sensitive .html filter was not found; rows: %s", joinRows(got))
	}
	if !strings.Contains(f.Evidence, ".hTmL") {
		t.Errorf("the finding should name the mixed-case file that got through: %q", f.Evidence)
	}
}

func TestFileUploadStaysQuietOnTheSafeUploads(t *testing.T) {
	rt := startRuntimeTarget(t)
	// The vulnerable endpoint first, in this run: silence on a twin means nothing unless the check
	// demonstrably works here.
	vuln := rt.findingsFor(t, "/fu/upload", false)
	for _, row := range []string{"Cross-site scripting (stored)", "File path traversal", "File upload functionality"} {
		if vuln[row] == nil {
			t.Fatalf("%q did not fire on /fu/upload in this run, so the safe twins' silence proves nothing", row)
		}
	}

	att := rt.findingsFor(t, "/fu/safe/attachment/upload", false)
	if f := att["Cross-site scripting (stored)"]; f != nil {
		t.Errorf("a .html upload served as a text/plain attachment was reported as stored XSS: %q", f.Evidence)
	}
	if f := att["File path traversal"]; f != nil {
		t.Errorf("an endpoint that flattens filenames (and only echoes the \"../\") was reported as traversal: %q", f.Evidence)
	}
	// It does keep the extension it was sent, so the accepted-extension row is true here - which is
	// also what proves the check reached this endpoint's uploads at all.
	if att["File upload functionality"] == nil {
		t.Errorf("the attachment endpoint keeps any extension but the check did not say so; rows: %s", joinRows(att))
	}

	allow := rt.findingsFor(t, "/fu/safe/allowlist/upload", false)
	for _, row := range []string{"Cross-site scripting (stored)", "File path traversal", "File upload functionality"} {
		if f := allow[row]; f != nil {
			t.Errorf("%q reported against an extension allowlist whose refusals quote the refused path: %q", row, f.Evidence)
		}
	}
}

// The switch is the check's own: off, the upload endpoint gets no upload probe and reports none of
// the three rows, even though every other family is on.
func TestFileUploadIsOffWithoutItsSwitch(t *testing.T) {
	rt := startRuntimeTarget(t)
	cfg := runtimeScanConfig()
	cfg.CheckFileUpload = false
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).
		WithStoredLedger(NewStoredLedger()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, findings := scan.AuditWithin(ctx, rt.exchanges["/fu/upload"], scan.AuditConfig())
	for _, f := range findings {
		if f != nil && (f.Name == "Cross-site scripting (stored)" ||
			(f.Name == "File upload functionality" && strings.Contains(f.Description, "inert marker"))) {
			t.Errorf("%q reported with CheckFileUpload off: %q", f.Name, f.Evidence)
		}
	}
}

// A NUL the application kept is part of the stored name: "x.html\0.png" echoed back (raw, or JSON
// \u0000-escaped) was stored as a .png, and must not read as the null-byte bypass succeeding.
func TestUploadStoredNameKeepsAnEchoedNul(t *testing.T) {
	for _, body := range []string{
		`{"location":"/up/bfutok.html\u0000.png"}`,
		"{\"location\":\"/up/bfutok.html\x00.png\"}",
	} {
		resp := ProbeResponse{Raw: []byte("HTTP/1.1 200 OK\r\n\r\n" + body), Body: body, Status: 200}
		_, name := namedLocation(resp, "bfutok")
		if strings.HasSuffix(strings.ToLower(name), ".html") {
			t.Errorf("%s: stored name %q reads as .html, but the server kept the NUL and the suffix after it", body, name)
		}
	}
	// Truncated by the application: the echo ends at .html, and that IS the bypass.
	body := `{"location":"/up/123_bfutok.html"}`
	loc, name := namedLocation(ProbeResponse{Raw: []byte("HTTP/1.1 200 OK\r\n\r\n" + body), Body: body}, "bfutok")
	if loc != "/up/123_bfutok.html" || name != "123_bfutok.html" {
		t.Errorf("namedLocation = %q, %q", loc, name)
	}
}

// Locations travel JSON- and HTML-escaped and are often relative to the context root.
func TestUploadLocationsAreUnescapedAndResolved(t *testing.T) {
	body := `{"content":"app\/upload\/-77_bfutok.svg","ok":true}`
	loc, name := namedLocation(ProbeResponse{Raw: []byte("HTTP/1.1 200 OK\r\n\r\n" + body), Body: body}, "bfutok")
	if loc != "app/upload/-77_bfutok.svg" || name != "-77_bfutok.svg" {
		t.Fatalf("namedLocation = %q, %q", loc, name)
	}
	p := &uploadProber{}
	p.origin, _ = url.Parse("http://h:8080")
	p.reqURL, _ = url.Parse("http://h:8080/app/api/upload")
	var got []string
	for _, u := range p.candidates(loc) {
		got = append(got, u.String())
	}
	want := []string{"http://h:8080/app/upload/-77_bfutok.svg", "http://h:8080/app/api/app/upload/-77_bfutok.svg"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("candidates = %v, want %v", got, want)
	}
}
