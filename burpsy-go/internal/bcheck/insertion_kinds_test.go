package bcheck

// XML and multipart parameter kinds (burpsy-react-ui-75jm).
//
// Both containers were already enumerated, and every point they produced was reported as IpBody.
// Burp carries them as their own parameter locations (PARAM_XML / PARAM_XML_ATTR,
// PARAM_MULTIPART_ATTR), and the distinction is what lets an operator tell "this endpoint's XML was
// tested" from "its form fields were" — and makes a multipart API's fields visible to
// insertion-point selection at all.

import (
	"strings"
	"testing"
)

// An XML body's points carry the XML kind, not the generic body kind.
func TestXMLBodyPointsCarryTheXMLKind(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/xml\r\n\r\n" +
		"<order><id>7</id><qty>2</qty></order>"
	points, _ := Enumerate([]byte(raw), []string{"body"})

	var xml, body int
	for _, p := range points {
		switch p.Kind {
		case IpXML:
			xml++
		case IpBody:
			body++
		}
	}
	if xml == 0 {
		t.Fatalf("an XML body produced no XML-kind points (%d body-kind); the container is "+
			"enumerated but every point still reports as a body parameter", body)
	}
}

// A multipart body's ATTRIBUTES carry the multipart-attribute kind, while a part's CONTENT stays a
// body parameter. The split is the point: the content is what the application reads as the
// parameter's value and is a body byte range like any other; the attributes are MIME header
// parameters with their own escaping.
func TestMultipartAttributesAreTheirOwnKindAndContentStaysBody(t *testing.T) {
	body := strings.Join([]string{
		"--B",
		`Content-Disposition: form-data; name="upload"; filename="a.txt"`,
		"",
		"file-contents",
		"--B--",
		"",
	}, "\r\n")
	raw := "POST /u HTTP/1.1\r\nHost: app.test\r\n" +
		"Content-Type: multipart/form-data; boundary=B\r\n\r\n" + body
	points, _ := Enumerate([]byte(raw), []string{"body"})

	var attrs, contents int
	for _, p := range points {
		switch p.Kind {
		case IpMultipartAttr:
			attrs++
		case IpBody:
			contents++
		}
	}
	// BOTH attributes, not merely one: the part declares a name AND a filename, and counting
	// "at least one" would pass with either still reported as a body parameter.
	if attrs != 2 {
		t.Errorf("the part's name and filename produced %d multipart-attribute point(s), want 2; "+
			"an attribute still reported as a body parameter is invisible to insertion-point "+
			"selection", attrs)
	}
	if contents == 0 {
		t.Error("a multipart part's CONTENT is no longer a body point; the content is the " +
			"parameter's value and is a body byte range like any other")
	}
}

// The kinds are distinct strings, so a selection naming one cannot silently select the other.
func TestTheNewKindsAreDistinctFromTheBodyKind(t *testing.T) {
	for _, k := range []IpKind{IpXML, IpMultipartAttr} {
		if k == IpBody || k == "" {
			t.Errorf("kind %q collides with the body kind or is empty", k)
		}
	}
	if IpXML == IpMultipartAttr {
		t.Error("the XML and multipart kinds are the same string")
	}
}
