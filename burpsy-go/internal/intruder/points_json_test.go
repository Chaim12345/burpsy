package intruder

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// 33t: a JSON body must offer one position per string value, with payloads
// escaped so the document survives the splice — through the scanner's
// enumerator, not a second Intruder-side parser.

func TestJSONBodyYieldsOnePointPerStringValue(t *testing.T) {
	m := storeReq(t, "POST /api/login HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 34\r\n\r\n{\"user\":\"bo\",\"pass\":\"x\",\"n\":7,\"ok\":true,\"nested\":{\"k\":\"v\"}}")
	pts := FindPoints(m, DefaultPointConfig())

	var jsonPts []InsertionPoint
	for _, p := range pts {
		if p.Kind == PointBodyJSONValue {
			jsonPts = append(jsonPts, p)
		}
	}
	if len(jsonPts) != 3 {
		t.Fatalf("want 3 body_json_value points (bo, x, nested's v), got %d: %+v", len(jsonPts), jsonPts)
	}
	want := map[string]string{"user": "bo", "pass": "x", "k": "v", "nested": "v"}
	for _, p := range jsonPts {
		got := string(m.Raw()[p.Span.Offset : p.Span.Offset+p.Span.Len])
		switch p.Label {
		case "user", "pass", "k":
			if want[p.Label] != got {
				t.Errorf("label %q window holds %q, want %q", p.Label, got, want[p.Label])
			}
		case "nested":
			// The container object is not a string value; only its inner "k" is.
			t.Errorf("unexpected point on object: %q", got)
		}
		if got != "bo" && got != "x" && got != "v" {
			t.Errorf("point %q spans %q — numbers and booleans must not be points", p.Label, got)
		}
	}
}

func TestJSONPointPayloadIsEscapedSoBodyStaysWellFormed(t *testing.T) {
	raw := "POST /api/login HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"user\":\"bo\",\"id\":7}"
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	var user *InsertionPoint
	for i := range pts {
		if pts[i].Kind == PointBodyJSONValue && pts[i].Label == "user" {
			user = &pts[i]
		}
	}
	if user == nil {
		t.Fatal("no user point")
	}
	out := Apply(m.Raw(), user, []byte(`a"b\c`))
	var doc map[string]any
	if err := json.Unmarshal(bodyOf(out), &doc); err != nil {
		t.Fatalf("spliced body is not valid JSON: %v\n%s", err, out)
	}
	if doc["user"] != `a"b\c` {
		t.Errorf("payload did not arrive verbatim after unescape: %v", doc["user"])
	}
}

func TestTwoJSONPointsSpliceInOnePass(t *testing.T) {
	raw := "POST /api/login HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"user\":\"bo\",\"pass\":\"x\"}"
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	var places []ApplyPlace
	for i := range pts {
		if pts[i].Kind == PointBodyJSONValue {
			places = append(places, ApplyPlace{Point: &pts[i], Payload: []byte("PAY" + pts[i].Label)})
		}
	}
	if len(places) != 2 {
		t.Fatalf("want 2 places, got %d", len(places))
	}
	out := ApplyAll(m.Raw(), places)
	var doc map[string]any
	if err := json.Unmarshal(bodyOf(out), &doc); err != nil {
		t.Fatalf("spliced body is not valid JSON: %v\n%s", err, out)
	}
	if doc["user"] != "PAYuser" || doc["pass"] != "PAYpass" {
		t.Errorf("both fields must carry their payload: %v", doc)
	}
}

func TestNestedBase64JSONBodyValueBecomesAPoint(t *testing.T) {
	inner := `{"token":"seed"}`
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))
	body := "data=" + b64
	raw := "POST /api/session HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())

	var nested *InsertionPoint
	for i := range pts {
		if pts[i].Kind == PointBodyNestedValue && pts[i].Label == "data" {
			nested = &pts[i]
		}
	}
	if nested == nil {
		t.Fatalf("no body_nested_value point in %+v", pts)
	}
	out := Apply(m.Raw(), nested, []byte(`p"y`))
	s := string(bodyOf(out))
	if !strings.HasPrefix(s, "data=") {
		t.Fatalf("outer form framing lost: %q", s)
	}
	// containerEncode percent-escapes form values, so undo that before base64.
	wire := s[len("data="):]
	if dec, err := url.QueryUnescape(wire); err == nil {
		wire = dec
	}
	decoded, err := base64.StdEncoding.DecodeString(wire)
	if err != nil {
		t.Fatalf("outer value is not base64 after splice: %v (%q)", err, wire)
	}
	var doc map[string]any
	if err := json.Unmarshal(decoded, &doc); err != nil {
		t.Fatalf("inner value is not JSON after splice: %v (%q)", err, decoded)
	}
	if doc["token"] != `p"y` {
		t.Errorf("payload did not land inside the nested JSON: %v", doc)
	}
}

func TestJSONPointsKeepFormAndEntireBodyBehaviourIntact(t *testing.T) {
	form := "POST /login HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\nuser=admin&pass=x"
	m := storeReq(t, form)
	pts := FindPoints(m, DefaultPointConfig())
	for _, p := range pts {
		if p.Kind == PointBodyJSONValue || p.Kind == PointBodyNestedValue {
			t.Errorf("form body must not gain container points: %+v", p)
		}
		if p.escape != escapeNone {
			t.Errorf("native points must stay wire-faithful: %+v", p)
		}
	}
	hasKV(t, pts, PointBodyParamValue, "user")

	// entire_body stays available for JSON bodies too.
	jsonReq := "POST /api HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"user\":\"bo\"}"
	all := FindPoints(storeReq(t, jsonReq), AllPointConfig())
	var sawEntire bool
	for _, p := range all {
		if p.Kind == PointEntireBody {
			sawEntire = true
		}
	}
	if !sawEntire {
		t.Error("entire_body fallback missing for JSON body under AllPointConfig")
	}
}

func TestJSONPointsAppearBeforeEntireBody(t *testing.T) {
	m := storeReq(t, "POST /api HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"a\":\"1\",\"b\":\"2\"}")
	pts := FindPoints(m, AllPointConfig())
	firstJSON, lastJSON := -1, -1
	entire := -1
	for i, p := range pts {
		switch p.Kind {
		case PointBodyJSONValue:
			if firstJSON < 0 {
				firstJSON = i
			}
			lastJSON = i
		case PointEntireBody:
			entire = i
		}
	}
	if firstJSON < 0 || entire < 0 {
		t.Fatalf("missing points: %+v", pts)
	}
	if lastJSON > entire {
		t.Errorf("entire_body at %d precedes json points at %d..%d; fixed order broken", entire, firstJSON, lastJSON)
	}
}

func TestMultipartBodyGainsNoContainerPoints(t *testing.T) {
	body := "--X\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--X--"
	raw := "POST /up HTTP/1.1\r\nHost: t.test\r\nContent-Type: multipart/form-data; boundary=X\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	pts := FindPoints(storeReq(t, raw), AllPointConfig())
	for _, p := range pts {
		if p.Kind == PointBodyJSONValue || p.Kind == PointBodyNestedValue {
			t.Errorf("multipart must not gain container points: %+v", p)
		}
	}
}

func bodyOf(raw []byte) []byte {
	if i := indexOf(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[i+4:]
	}
	return raw
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
