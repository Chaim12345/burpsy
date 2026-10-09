package intruder

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// "Automatic payload placement: Append to base parameter value" (burpsy-react-ui-1krs). Burp builds
// each automatic marker as Zswj(append ? valueEnd : valueStart, valueEnd) (Zrw7.Zz): under append the
// marker is zero-length at the end of the value, so the base value goes out as captured and the
// payload follows it.

func pointOf(t *testing.T, pts []InsertionPoint, kind PointKind, label string) *InsertionPoint {
	t.Helper()
	for i := range pts {
		if pts[i].Kind == kind && pts[i].Label == label {
			return &pts[i]
		}
	}
	t.Fatalf("no %s %q in %+v", kind, label, pts)
	return nil
}

func appendConfig(all bool) *PointConfig {
	cfg := DefaultPointConfig()
	if all {
		cfg = AllPointConfig()
	}
	cfg.Placement = PlacementAppend
	return cfg
}

func TestAppendPlacementIsAZeroLengthSpanAtTheEndOfTheValue(t *testing.T) {
	raw := "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: t.test\r\nCookie: sid=abc\r\n\r\n"
	m := storeReq(t, raw)
	q := pointOf(t, FindPoints(m, appendConfig(false)), PointURLParamValue, "q")
	end := strings.Index(raw, "alpha") + len("alpha")
	if !q.Append || q.Span.Len != 0 || q.Span.Offset != end {
		t.Fatalf("q = %+v, want an appending zero-length span at offset %d", q, end)
	}
	if got := m.Text(q.BaseSpan()); got != "alpha" {
		t.Fatalf("BaseSpan text = %q, want the base value alpha", got)
	}
	out := string(Apply(m.Raw(), q, []byte("PAY")))
	if want := strings.Replace(raw, "q=alpha", "q=alphaPAY", 1); out != want {
		t.Fatalf("spliced:\n%q\nwant\n%q", out, want)
	}

	// The same discovery under replace is unchanged: the value's own span, and the splice overwrites.
	r := pointOf(t, FindPoints(m, DefaultPointConfig()), PointURLParamValue, "q")
	if r.Append || r.Span.Len != len("alpha") || m.Text(r.BaseSpan()) != "alpha" {
		t.Fatalf("replace q = %+v, want the value span", r)
	}
	if out := string(Apply(m.Raw(), r, []byte("PAY"))); !strings.Contains(out, "q=PAY&") {
		t.Fatalf("replace splice = %q, want q=PAY", out)
	}

	// Cookie values append too; the Content-Length of a form body is restated after the splice.
	c := pointOf(t, FindPoints(m, appendConfig(false)), PointCookieValue, "sid")
	if out := string(Apply(m.Raw(), c, []byte("X"))); !strings.Contains(out, "Cookie: sid=abcX\r\n") {
		t.Fatalf("cookie append = %q", out)
	}
	form := "user=admin&pass=hunter2"
	body := "POST /login HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
		strconv.Itoa(len(form)) + "\r\n\r\n" + form
	bm := storeReq(t, body)
	u := pointOf(t, FindPoints(bm, appendConfig(false)), PointBodyParamValue, "user")
	got := string(Apply(bm.Raw(), u, []byte("'--")))
	wantBody := "user=admin'--&pass=hunter2"
	if !strings.HasSuffix(got, "\r\n\r\n"+wantBody) || !strings.Contains(got, "Content-Length: "+strconv.Itoa(len(wantBody))+"\r\n") {
		t.Fatalf("body append = %q", got)
	}
}

// Only parameter values append. Names, path segments, header values and the entire body are
// burpsy discovery families beyond Burp's automatic placement, and they keep replacing.
func TestAppendPlacementLeavesNonValuePositionsReplacing(t *testing.T) {
	m := storeReq(t, "GET /a/b.php?x=1 HTTP/1.1\r\nHost: t.test\r\nUser-Agent: ua\r\n\r\n")
	for _, p := range FindPoints(m, appendConfig(true)) {
		wantAppend := p.Kind == PointURLParamValue
		if p.Append != wantAppend {
			t.Errorf("%s %q: Append=%v, want %v", p.Kind, p.Label, p.Append, wantAppend)
		}
		if !p.Append && p.Span != p.BaseSpan() {
			t.Errorf("%s %q: a replacing position's base must be its span", p.Kind, p.Label)
		}
	}
}

// A JSON body value keeps its captured (escaped) bytes and gains the payload escaped for the
// container, inside the quotes.
func TestAppendPlacementOnAJSONValueEscapesOnlyThePayload(t *testing.T) {
	js := `{"user":"bob"}`
	raw := "POST /api HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(js)) + "\r\n\r\n" + js
	m := storeReq(t, raw)
	p := pointOf(t, FindPoints(m, appendConfig(false)), PointBodyJSONValue, "user")
	if p.Span.Len != 0 {
		t.Fatalf("JSON append span = %+v, want zero-length", p.Span)
	}
	got := string(bodyOf(Apply(m.Raw(), p, []byte(`"x`))))
	if want := `{"user":"bob\"x"}`; got != want {
		t.Fatalf("JSON append body = %s, want %s (base bytes as captured, payload escaped)", got, want)
	}
}

// A nested value cannot be extended by concatenating onto its encoded text: base64 of the base
// followed by raw payload bytes is not base64 of anything. The position keeps its window and the
// payload goes after the inner value before the outer value is re-encoded.
func TestAppendPlacementOnANestedValueAppendsInsideTheDecodedBuffer(t *testing.T) {
	inner := `{"token":"seed"}`
	body := "data=" + base64.StdEncoding.EncodeToString([]byte(inner))
	raw := "POST /api/session HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	m := storeReq(t, raw)
	var nested *InsertionPoint
	pts := FindPoints(m, appendConfig(false))
	for i := range pts {
		if pts[i].Kind == PointBodyNestedValue {
			nested = &pts[i]
		}
	}
	if nested == nil {
		t.Fatalf("no nested point in %+v", pts)
	}
	if !nested.Append || nested.Span.Len == 0 || nested.Span != nested.BaseSpan() {
		t.Fatalf("nested append = %+v, want an appending position over its whole window", nested)
	}
	s := string(bodyOf(Apply(m.Raw(), nested, []byte(`p"y`))))
	wire := strings.TrimPrefix(s, "data=")
	if dec, err := url.QueryUnescape(wire); err == nil {
		wire = dec
	}
	decoded, err := base64.StdEncoding.DecodeString(wire)
	if err != nil {
		t.Fatalf("outer value is not base64 after the append: %v (%q)", err, wire)
	}
	var doc map[string]any
	if err := json.Unmarshal(decoded, &doc); err != nil {
		t.Fatalf("inner value is not JSON after the append: %v (%q)", err, decoded)
	}
	if doc["token"] != `seedp"y` {
		t.Fatalf("token = %q, want the base value with the payload after it", doc["token"])
	}
}

// Earliest-span-wins survives zero-length spans: the entire body and an appended last body value
// both end at the body's last byte, and only the earlier-starting entire body is spliced.
func TestAnAppendedValueTouchingAnEarlierPositionLosesTheSplice(t *testing.T) {
	form := "a=1&b=2"
	raw := "POST /x HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\n" + form
	m := storeReq(t, raw)
	pts := FindPoints(m, appendConfig(true))
	entire := pointOf(t, pts, PointEntireBody, "body")
	b := pointOf(t, pts, PointBodyParamValue, "b")
	out := ApplyAll(m.Raw(), []ApplyPlace{{Point: b, Payload: []byte("B")}, {Point: entire, Payload: []byte("E")}})
	if got := string(bodyOf(out)); got != "E" {
		t.Fatalf("body = %q, want only the entire-body payload (the appended b touches its end)", got)
	}
}

func TestSpansOverlap(t *testing.T) {
	sp := func(off, n int) core.Span { return core.Span{Offset: off, Len: n} }
	cases := []struct {
		a, b core.Span
		want bool
	}{
		{sp(0, 3), sp(3, 2), false}, // adjacent non-empty: not overlap
		{sp(0, 3), sp(2, 2), true},
		{sp(0, 3), sp(3, 0), true}, // insertion at the end edge
		{sp(3, 0), sp(3, 2), true}, // insertion at the start edge
		{sp(0, 3), sp(1, 0), true}, // insertion inside
		{sp(0, 3), sp(4, 0), false},
		{sp(5, 0), sp(5, 0), true},
		{sp(5, 0), sp(6, 0), false},
	}
	for _, c := range cases {
		if got := SpansOverlap(c.a, c.b); got != c.want {
			t.Errorf("SpansOverlap(%+v, %+v) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := SpansOverlap(c.b, c.a); got != c.want {
			t.Errorf("SpansOverlap(%+v, %+v) = %v, want %v (symmetry)", c.b, c.a, got, c.want)
		}
	}
}

func TestParsePlacement(t *testing.T) {
	for in, want := range map[string]Placement{"": PlacementReplace, "replace": PlacementReplace, "append": PlacementAppend} {
		got, err := ParsePlacement(in)
		if err != nil || got != want {
			t.Errorf("ParsePlacement(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParsePlacement("prepend"); err == nil || !strings.Contains(err.Error(), "prepend") {
		t.Fatalf("an unknown placement must be refused by name, got %v", err)
	}
}
