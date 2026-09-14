package intruder

import (
	"bytes"
	"encoding/xml"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"testing"
)

// 63jg: a multipart body and an XML body are containers with named values, the
// same way a JSON body is. The scanner's enumerator models both (bodyPoints →
// multipartBodyPoints / xmlPoints), so Intruder adopts every position it
// reports rather than offering the whole body as one opaque blob. These tests
// pin what the operator sees — one position per part, per part attribute, per
// text node and per attribute value — and what the server receives: a body that
// still parses, with the payload in exactly the value that was attacked.

const multipartBoundaryX = "X"

// multipartFixture is the two-part body every multipart test here starts from:
// a plain field and a file part, with contents that are ordinary words so no
// value decodes as nested base64/JSON and quietly adds positions of its own.
func multipartFixture() (raw string, body string) {
	body = "--X\r\n" +
		"Content-Disposition: form-data; name=\"user\"\r\n" +
		"\r\n" +
		"alice\r\n" +
		"--X\r\n" +
		"Content-Disposition: form-data; name=\"avatar\"; filename=\"cat.png\"\r\n" +
		"Content-Type: image/png\r\n" +
		"\r\n" +
		"pixels\r\n" +
		"--X--"
	raw = "POST /upload HTTP/1.1\r\nHost: t.test\r\n" +
		"Content-Type: multipart/form-data; boundary=" + multipartBoundaryX + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	return raw, body
}

// xmlFixture is the document the XML tests attack. There is no whitespace
// around the text node — the enumerator trims layout whitespace out of a value
// window, so padding it would move the window the assertions pin.
func xmlFixture() (raw string, body string) {
	body = `<order id="1"><item id="7">widget</item></order>`
	raw = "POST /orders HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/xml\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	return raw, body
}

// parsedPart is one part as a server's own MIME parser reads it back.
type parsedPart struct {
	name     string
	filename string
	content  string
}

// parseMultipart reads a spliced body the way the application under test would.
// Every failure here means the request Intruder built is one the server rejects
// before the payload is ever looked at.
func parseMultipart(t *testing.T, body []byte, boundary string) []parsedPart {
	t.Helper()
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	var out []parsedPart
	for {
		part, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the spliced body no longer reads as a part list, so the server would reject it before the payload: %v\nbody: %q", err, body)
		}
		content, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("part %d has unreadable content, so its framing is broken: %v", len(out), err)
		}
		cd := part.Header.Get("Content-Disposition")
		// mime.ParseMediaType, not part.FileName(): FileName runs filepath.Base
		// over the value and would hide a payload that carries a path separator.
		_, params, err := mime.ParseMediaType(cd)
		if err != nil {
			t.Fatalf("part %d's Content-Disposition stopped being a readable header: %v (%q)", len(out), err, cd)
		}
		out = append(out, parsedPart{name: params["name"], filename: params["filename"], content: string(content)})
	}
	return out
}

// pointsOfKind collects the positions of one kind, in discovery order.
func pointsOfKind(pts []InsertionPoint, kind PointKind) []*InsertionPoint {
	var out []*InsertionPoint
	for i := range pts {
		if pts[i].Kind == kind {
			out = append(out, &pts[i])
		}
	}
	return out
}

// findPoint returns the single position of a kind carrying a label, failing the
// test when the operator would not be offered it at all.
func findPoint(t *testing.T, pts []InsertionPoint, kind PointKind, label string) *InsertionPoint {
	t.Helper()
	var found *InsertionPoint
	for i := range pts {
		if pts[i].Kind == kind && pts[i].Label == label {
			if found != nil {
				t.Fatalf("%s %q is offered twice; an attack would splice the same bytes twice", kind, label)
			}
			found = &pts[i]
		}
	}
	if found == nil {
		t.Fatalf("no %s position named %q — that value cannot be attacked at all: %+v", kind, label, pts)
	}
	return found
}

func TestMultipartBodyYieldsOnePositionPerPartContent(t *testing.T) {
	raw, body := multipartFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())

	got := pointsOfKind(pts, PointBodyMultipartValue)
	if len(got) != 2 {
		t.Fatalf("a two-part body offers %d content positions, so %d part(s) cannot be attacked: %+v", len(got), 2-len(got), got)
	}
	bodyStart := indexOf(m.Raw(), []byte("\r\n\r\n")) + 4
	for _, want := range []struct {
		label   string
		content string
	}{
		{"user", "alice"},
		{"avatar", "pixels"},
	} {
		p := findPoint(t, pts, PointBodyMultipartValue, want.label)
		// The window is pinned by offset, not just by the bytes it holds: two
		// parts could carry identical content, and only the offset says the
		// position names this part rather than its sibling.
		wantOff := bodyStart + indexOf([]byte(body), []byte("\r\n\r\n"+want.content+"\r\n--X")) + 4
		if p.Span.Offset != wantOff || p.Span.Len != len(want.content) {
			t.Errorf("part %q's position covers raw[%d:%d] = %q, but that part's content sits at raw[%d:%d] — a splice would land outside the part",
				want.label, p.Span.Offset, p.Span.End(), m.Raw()[p.Span.Offset:p.Span.End()], wantOff, wantOff+len(want.content))
		}
		if p.escape != escapeBcheck {
			t.Errorf("part %q's payload would be spliced without going through the enumerator, so Intruder and the scanner could frame the same part differently", want.label)
		}
	}
}

func TestMultipartPartPayloadArrivesVerbatimAndLeavesSiblingsUntouched(t *testing.T) {
	raw, _ := multipartFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	user := findPoint(t, pts, PointBodyMultipartValue, "user")

	// A bare `--X` with no CRLF before it is legal inside a part's content, so
	// this payload proves the content is spliced literally rather than escaped.
	payload := []byte("p--Xa'\"<y>")
	out := Apply(m.Raw(), user, payload)
	parts := parseMultipart(t, bodyOf(out), multipartBoundaryX)
	if len(parts) != 2 {
		t.Fatalf("the spliced body has %d parts, not 2 — the splice re-framed the body", len(parts))
	}
	if parts[0].name != "user" || parts[0].content != string(payload) {
		t.Errorf("part %q carries %q; the application would read something other than the payload that was sent", parts[0].name, parts[0].content)
	}
	if parts[1].name != "avatar" || parts[1].filename != "cat.png" || parts[1].content != "pixels" {
		t.Errorf("the untargeted part came out as %+v, so a splice into one part changed another", parts[1])
	}
	if cl := contentLength(out); cl != len(bodyOf(out)) {
		t.Errorf("Content-Length is %d while the body is %d bytes; the server would read the wrong number of bytes", cl, len(bodyOf(out)))
	}
}

func TestMultipartPartNameAndFilenameAreAttackablePositions(t *testing.T) {
	raw, body := multipartFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())

	bodyStart := indexOf(m.Raw(), []byte("\r\n\r\n")) + 4
	for _, want := range []struct {
		label string
		value string
	}{
		{"user name", "user"},
		{"avatar name", "avatar"},
		{"avatar filename", "cat.png"},
	} {
		p := findPoint(t, pts, PointBodyMultipartAttr, want.label)
		wantOff := bodyStart + indexOf([]byte(body), []byte("\""+want.value+"\"")) + 1
		if p.Span.Offset != wantOff || p.Span.Len != len(want.value) {
			t.Errorf("%q covers raw[%d:%d] = %q, but the attribute value sits at raw[%d:%d] — the splice would hit the header's framing",
				want.label, p.Span.Offset, p.Span.End(), m.Raw()[p.Span.Offset:p.Span.End()], wantOff, wantOff+len(want.value))
		}
	}

	// The attribute is a MIME quoted-string, so a payload carrying the quote
	// and the escape character must reach the parser as the value itself.
	filename := findPoint(t, pts, PointBodyMultipartAttr, "avatar filename")
	payload := []byte(`e"v/il\.png`)
	out := Apply(m.Raw(), filename, payload)
	parts := parseMultipart(t, bodyOf(out), multipartBoundaryX)
	if len(parts) != 2 {
		t.Fatalf("the spliced body has %d parts, not 2 — splicing the filename re-framed the body", len(parts))
	}
	if parts[1].filename != string(payload) {
		t.Errorf("the file part's filename reads back as %q; the application would see a different value than the one attacked", parts[1].filename)
	}
	if parts[1].name != "avatar" || parts[1].content != "pixels" {
		t.Errorf("splicing the filename also changed the part to %+v; only the attribute was attacked", parts[1])
	}
	if cl := contentLength(out); cl != len(bodyOf(out)) {
		t.Errorf("Content-Length is %d while the body is %d bytes; the server would read the wrong number of bytes", cl, len(bodyOf(out)))
	}
}

func TestXMLBodyYieldsAPositionPerTextNodeAndAttributeValue(t *testing.T) {
	raw, body := xmlFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())

	got := pointsOfKind(pts, PointBodyXMLValue)
	if len(got) != 3 {
		t.Fatalf("the document has three spliceable values (order@id, order/item@id, order/item) but %d positions were offered: %+v", len(got), got)
	}
	bodyStart := indexOf(m.Raw(), []byte("\r\n\r\n")) + 4
	for _, want := range []struct {
		label string
		value string
		at    string
	}{
		{"order@id", "1", `"1"`},
		{"order/item@id", "7", `"7"`},
		{"order/item", "widget", ">widget<"},
	} {
		p := findPoint(t, pts, PointBodyXMLValue, want.label)
		wantOff := bodyStart + indexOf([]byte(body), []byte(want.at)) + 1
		if p.Span.Offset != wantOff || p.Span.Len != len(want.value) {
			t.Errorf("%q covers raw[%d:%d] = %q, but that value sits at raw[%d:%d] — a splice would land in the markup instead of the value",
				want.label, p.Span.Offset, p.Span.End(), m.Raw()[p.Span.Offset:p.Span.End()], wantOff, wantOff+len(want.value))
		}
	}
}

func TestXMLPayloadArrivesAsTheDecodedValueOfItsNode(t *testing.T) {
	// Every character XML reserves, in one payload: if any of them crossed
	// unescaped the document would stop parsing, and if any were dropped the
	// application would see a probe the operator never typed.
	payload := []byte(`a<b>&"c'd`)

	for _, tc := range []struct {
		name  string
		label string
	}{
		{"text node", "order/item"},
		{"attribute", "order/item@id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := xmlFixture()
			m := storeReq(t, raw)
			pts := FindPoints(m, DefaultPointConfig())
			p := findPoint(t, pts, PointBodyXMLValue, tc.label)

			out := Apply(m.Raw(), p, payload)
			var doc struct {
				XMLName xml.Name `xml:"order"`
				ID      string   `xml:"id,attr"`
				Item    struct {
					ID   string `xml:"id,attr"`
					Text string `xml:",chardata"`
				} `xml:"item"`
			}
			if err := xml.Unmarshal(bodyOf(out), &doc); err != nil {
				t.Fatalf("the spliced document no longer parses, so the payload never reaches the code under test: %v\n%s", err, bodyOf(out))
			}
			got, other := doc.Item.Text, doc.Item.ID
			if tc.label == "order/item@id" {
				got, other = doc.Item.ID, doc.Item.Text
			}
			if got != string(payload) {
				t.Errorf("%s decodes to %q, so the application reads a different payload than the one sent", tc.label, got)
			}
			wantOther := "7"
			if tc.label == "order/item@id" {
				wantOther = "widget"
			}
			if other != wantOther || doc.ID != "1" {
				t.Errorf("the untargeted values changed to item=%q order@id=%q; only %s was attacked", other, doc.ID, tc.label)
			}
			if cl := contentLength(out); cl != len(bodyOf(out)) {
				t.Errorf("Content-Length is %d while the body is %d bytes; the server would read the wrong number of bytes", cl, len(bodyOf(out)))
			}
		})
	}
}

func TestMultipartContentPayloadCarryingTheDelimiterIsDroppedNotSpliced(t *testing.T) {
	raw, _ := multipartFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	user := findPoint(t, pts, PointBodyMultipartValue, "user")
	avatar := findPoint(t, pts, PointBodyMultipartValue, "avatar")

	// A part's content has no escape, so a payload that spells the delimiter
	// would end its own part and re-frame everything after it. The refusal is
	// per payload, not per request: the sibling splice still has to happen.
	out := ApplyAll(m.Raw(), []ApplyPlace{
		{Point: user, Payload: []byte("boom\r\n--X\r\nContent-Disposition: form-data; name=\"admin\"\r\n\r\n1")},
		{Point: avatar, Payload: []byte("PIXELPAYLOAD")},
	})

	parts := parseMultipart(t, bodyOf(out), multipartBoundaryX)
	if len(parts) != 2 {
		t.Fatalf("the body came out with %d parts: the refused payload was spliced anyway and invented framing", len(parts))
	}
	if parts[0].name != "user" || parts[0].content != "alice" {
		t.Errorf("the refused part reads %+v; a refused payload must leave its part exactly as it was", parts[0])
	}
	if parts[1].name != "avatar" || parts[1].content != "PIXELPAYLOAD" {
		t.Errorf("the spliceable sibling reads %+v; one refused payload must not drop the rest of the attack", parts[1])
	}
	if cl := contentLength(out); cl != len(bodyOf(out)) {
		t.Errorf("Content-Length is %d while the body is %d bytes; the server would read the wrong number of bytes", cl, len(bodyOf(out)))
	}
}

func TestMultipartAttrPayloadWithALineBreakIsDroppedNotSpliced(t *testing.T) {
	raw, _ := multipartFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	name := findPoint(t, pts, PointBodyMultipartAttr, "avatar name")

	// There is no spelling of CR or LF inside a MIME quoted-string, so the
	// payload has nowhere to go: it is dropped rather than emitted as a header
	// that ends in the middle of the attack.
	out := ApplyAll(m.Raw(), []ApplyPlace{
		{Point: name, Payload: []byte("x\r\nX-Injected: 1")},
	})
	parts := parseMultipart(t, bodyOf(out), multipartBoundaryX)
	if len(parts) != 2 {
		t.Fatalf("the body came out with %d parts: a line break was written into a part header", len(parts))
	}
	if parts[1].name != "avatar" || parts[1].filename != "cat.png" {
		t.Errorf("the refused attribute reads name=%q filename=%q; a refused payload must leave the header as it was", parts[1].name, parts[1].filename)
	}
}

func TestContainerPointKindsNameTheirContainerOnTheWire(t *testing.T) {
	// The kind is what the operator and the JSON API see next to a position,
	// so a renamed or duplicated wire form silently relabels attack positions.
	want := map[PointKind]string{
		PointBodyJSONValue:      "body_json_value",
		PointBodyNestedValue:    "body_nested_value",
		PointBodyXMLValue:       "body_xml_value",
		PointBodyMultipartValue: "body_multipart_value",
		PointBodyMultipartAttr:  "body_multipart_attr",
	}
	seen := map[string]PointKind{}
	for kind, name := range want {
		if got := kind.String(); got != name {
			t.Errorf("a %s position is reported as %q, so the operator is told it lands in a different container", name, got)
		}
		if other, dup := seen[kind.String()]; dup {
			t.Errorf("%q names two container kinds (%d and %d); the two are indistinguishable on the wire", kind.String(), other, kind)
		}
		seen[kind.String()] = kind
	}
}
