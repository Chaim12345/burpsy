package bcheck

import (
	"strings"
	"testing"
)

// Burp's file-upload HTML variant (burpsy-react-ui-kzt7): a file part's content point can re-send
// the part as an HTML document — new filename, Content-Type text/html, the payload as content —
// with every other byte of the body untouched.
func TestAFilePartCanBeResentAsHTML(t *testing.T) {
	body := "--B\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhi\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n"
	req := []byte("POST /up HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n" + body)
	points, _ := Enumerate(req, []string{"any"})
	var doc, title *InsertionPoint
	for i := range points {
		if points[i].Kind == IpBody && points[i].Name == "doc" {
			doc = &points[i]
		}
		if points[i].Kind == IpBody && points[i].Name == "title" {
			title = &points[i]
		}
	}
	if doc == nil || title == nil {
		t.Fatal("the multipart content points were not enumerated")
	}
	if name, ok := doc.UploadFilename(req); !ok || name != "notes.txt" {
		t.Fatalf("UploadFilename = %q, %v", name, ok)
	}
	if _, ok := title.UploadFilename(req); ok {
		t.Error("a part with no filename reported one")
	}
	if _, err := title.ApplyHTMLUpload(req, "<b>x</b>", "a.html"); err == nil {
		t.Error("a non-file part accepted the upload rewrite")
	}
	got, err := doc.ApplyHTMLUpload(req, "<b>x</b>", "notes.txtabc.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	want := "--B\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhi\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"notes.txtabc.html\"\r\nContent-Type: text/html\r\n\r\n<b>x</b>\r\n--B--\r\n"
	if !strings.HasSuffix(s, want) {
		t.Errorf("rewritten body:\n%q\nwant suffix\n%q", s, want)
	}
	if !strings.Contains(s, "Content-Length: "+itoa(len(want))) {
		t.Errorf("Content-Length was not recomputed: %q", s)
	}
}

// The file-upload check (burpsy-react-ui-0vzb.15) varies the filename, the declared part type and the
// content independently. A NUL in the filename is a filter bypass it must be able to send (it is body
// bytes, not a header); a quote, CR or LF would re-frame the part and is refused; and a part that
// declared no Content-Type gets one added rather than the rewrite silently leaving it out.
func TestAFilePartCanBeResentAsAnyFile(t *testing.T) {
	body := "--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"notes.txt\"\r\n\r\nhello\r\n--B--\r\n"
	req := []byte("POST /up HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n" + body)
	points, _ := Enumerate(req, []string{"any"})
	var doc *InsertionPoint
	for i := range points {
		if points[i].Kind == IpBody && points[i].Name == "doc" {
			doc = &points[i]
		}
	}
	if doc == nil {
		t.Fatal("the file part's content point was not enumerated")
	}
	got, err := doc.ApplyUpload(req, "marker", "a.html\x00.png", "image/png")
	if err != nil {
		t.Fatal(err)
	}
	want := "--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.html\x00.png\"\r\nContent-Type: image/png\r\n\r\nmarker\r\n--B--\r\n"
	if !strings.HasSuffix(string(got), want) {
		t.Errorf("rewritten body:\n%q\nwant suffix\n%q", got, want)
	}
	for _, bad := range []string{"a\".html", "a\r\n.html", "a\n.html"} {
		if _, err := doc.ApplyUpload(req, "x", bad, "text/html"); err == nil {
			t.Errorf("filename %q was accepted, but it re-frames the part header", bad)
		}
	}
	if _, err := doc.ApplyUpload(req, "x", "a.html", "text/html\r\nX-Injected: 1"); err == nil {
		t.Error("a content type carrying CRLF was accepted")
	}
	// The HTML variant keeps its own stricter rule: Burp's variant never sends a NUL.
	if _, err := doc.ApplyHTMLUpload(req, "x", "a.html\x00.png"); err == nil {
		t.Error("ApplyHTMLUpload accepted a NUL filename")
	}
}
