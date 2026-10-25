package scanner

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
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
	for _, row := range []string{"Cross-site scripting (stored)", "File path traversal"} {
		if f := allow[row]; f != nil {
			t.Errorf("%q reported against an extension allowlist whose refusals quote the refused path: %q", row, f.Evidence)
		}
	}
	// .gif is on the allowlist, so the GIF89a HTML polyglot is genuinely stored here - the
	// accepted row is TRUE, at acceptance strength only: served as a forced text/plain download,
	// nothing renders, and the finding must not hint otherwise.
	f := allow["File upload functionality"]
	if f == nil {
		t.Errorf("the allowlist stores the GIF89a polyglot but the check did not say so; rows: %s", joinRows(allow))
	} else if !strings.Contains(f.Evidence, "polyglot") {
		t.Errorf("the accepted row does not name the polyglot as one: %q", f.Evidence)
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

// TestFileUploadPolyglotBeatsAContentSniffingFilter: a filter that demands image magic bytes for
// an image extension still stores the GIF89a HTML polyglot. Served by its extension it comes back
// as image/gif, so no XSS is claimed - but the bypass is reported, and with no delete exposed the
// finding lists the stored probe files left behind.
func TestFileUploadPolyglotBeatsAContentSniffingFilter(t *testing.T) {
	rt := startRuntimeTarget(t)
	// The open endpoint must show the check working in this run, or the row below proves nothing.
	if rt.findingsFor(t, "/fu/upload", false)["File upload functionality"] == nil {
		t.Fatal("the check found no accepted-extension row on the open upload in this run")
	}
	got := rt.findingsFor(t, "/fu/sniff/upload", false)
	f := got["File upload functionality"]
	if f == nil {
		t.Fatalf("the sniffing upload stored the GIF89a HTML polyglot but the check said nothing; rows: %s", joinRows(got))
	}
	if !strings.Contains(f.Evidence, ".gif") || !strings.Contains(f.Evidence, "polyglot") {
		t.Errorf("the accepted polyglot is not named as one: %q", f.Evidence)
	}
	if x := got["Cross-site scripting (stored)"]; x != nil {
		t.Errorf("a polyglot served as image/gif was reported as stored XSS: %q", x.Evidence)
	}
	if !strings.Contains(f.Description, "/fu/sniff/files/") {
		t.Errorf("no delete is exposed, yet the stored probe files are not listed for cleanup: %q", f.Description)
	}
}

// TestFileUploadPolyglotRendersWhenTheServerTrustsTheDeclaredType: the same sniffing filter, but
// the stored file is served with the Content-Type the upload declared. The polyglot sent as
// text/html renders, so the stored-XSS row fires with the polyglot's name in evidence.
func TestFileUploadPolyglotRendersWhenTheServerTrustsTheDeclaredType(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/fu/trustct/upload", false)
	f := got["Cross-site scripting (stored)"]
	if f == nil {
		t.Fatalf("the declared-type replay renders the polyglot but the check said nothing; rows: %s", joinRows(got))
	}
	if !strings.Contains(f.Evidence, ".gif") || !strings.Contains(f.Evidence, "text/html") {
		t.Errorf("the evidence does not show the polyglot served as a document: %q", f.Evidence)
	}
}

// TestFileUploadRemovesItsProbeFilesWhenDeleteIsExposed: on an endpoint with a delete, every
// stored probe file is removed after the findings are built, the finding says so, and the file
// the XSS proof was fetched from is gone.
func TestFileUploadRemovesItsProbeFilesWhenDeleteIsExposed(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/fu/upload", false)
	f := got["Cross-site scripting (stored)"]
	if f == nil {
		t.Fatal("the stored-XSS row did not fire on the open upload in this run")
	}
	if !strings.Contains(f.Description, "removed") {
		t.Errorf("the finding does not report the probe-file removal: %q", f.Description)
	}
	m := regexp.MustCompile(`fetched (https?://\S+?\.html)[,:]`).FindStringSubmatch(f.Evidence)
	if m == nil {
		t.Fatalf("no fetched URL in the evidence to re-check: %q", f.Evidence)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(m[1])
	if err != nil {
		t.Fatalf("re-fetching the removed probe file: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the probe file the XSS proof used is still served after the check ran: HTTP %d", resp.StatusCode)
	}
}

// TestGifHTMLPolyglotIsAnImageToASniffer pins the polyglot's two faces: image magic first, an
// HTML document with the intact canary after.
func TestGifHTMLPolyglotIsAnImageToASniffer(t *testing.T) {
	body, canary := gifHTMLPolyglot(uploadMarker("bfuTESTTOKEN"))
	if !strings.HasPrefix(body, "GIF89a") {
		t.Errorf("the polyglot does not open with GIF89a magic: %q", body[:16])
	}
	if got := http.DetectContentType([]byte(body)); got != "image/gif" {
		t.Errorf("a content sniffer reads the polyglot as %q, not image/gif", got)
	}
	if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, canary) {
		t.Errorf("the HTML face or the canary is missing from the polyglot: %q", body)
	}
}
