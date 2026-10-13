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

// A real upload is binary (an image, a PDF). The body used to be gated on UTF-8 as a whole, so a
// binary file part made the request look like it had no parts at all and the file-upload check never
// ran on the uploads that matter most. Binary bytes inside a FILE part's content are read; binary
// framing is still refused, and a non-file part whose value is binary is declined by name.
func TestABinaryFilePartIsStillAnUploadPoint(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n\x00\xff\xfe"
	mk := func(body string) []byte {
		return []byte("POST /up HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " +
			itoa(len(body)) + "\r\n\r\n" + body)
	}
	find := func(ps []InsertionPoint, name string) *InsertionPoint {
		for i := range ps {
			if ps[i].Kind == IpBody && ps[i].Name == name {
				return &ps[i]
			}
		}
		return nil
	}

	req := mk("--B\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhi\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"img\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n" + png + "\r\n--B--\r\n")
	ps, declined := Enumerate(req, []string{"any"})
	img, title := find(ps, "img"), find(ps, "title")
	if img == nil || title == nil {
		t.Fatalf("a multipart body with a binary file part enumerated %v (declined %v); want the file and text parts", ps, declined)
	}
	got, err := img.ApplyHTMLUpload(req, "<b>x</b>", "a.html")
	if err != nil {
		t.Fatalf("the binary file part could not be re-sent as an upload: %v", err)
	}
	if !strings.Contains(string(got), "filename=\"a.html\"\r\nContent-Type: text/html\r\n\r\n<b>x</b>\r\n--B--") {
		t.Errorf("rewritten body = %q", got)
	}
	// A splice into the text part carries the binary file part through byte for byte.
	out, err := title.Apply(req, "zz", false)
	if err != nil || !strings.Contains(string(out), png) {
		t.Errorf("splicing the text part altered the binary file content (err %v): %q", err, out)
	}

	// A binary value in a part that is not a file has no text to splice into: declined by name.
	req = mk("--B\r\nContent-Disposition: form-data; name=\"blob\"\r\n\r\n" + png + "\r\n--B--\r\n")
	ps, declined = Enumerate(req, []string{"any"})
	if find(ps, "blob") != nil {
		t.Error("a non-file part with a binary value was offered as a text point")
	}
	if len(declined) == 0 || !strings.Contains(declined[0].What, "blob") {
		t.Errorf("declined = %v, want the binary non-file part named", declined)
	}

	// Binary bytes in the framing (a part header) are not a readable part list.
	req = mk("--B\r\nContent-Disposition: form-data; name=\"x\xff\"\r\n\r\nv\r\n--B--\r\n")
	ps, declined = Enumerate(req, []string{"body"})
	if len(ps) != 0 || len(declined) == 0 {
		t.Errorf("binary framing: points %v declined %v, want the body refused", ps, declined)
	}
}
