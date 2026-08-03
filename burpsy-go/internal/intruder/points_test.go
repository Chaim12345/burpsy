package intruder

import (
	"bytes"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Ports burpsy-intruder's insertion-point tests (lib.rs:466-567).

func storeReq(t *testing.T, raw string) *core.StoredMessage {
	t.Helper()
	s := core.NewTrafficStore()
	id, err := s.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	m, err := s.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return m
}

func pointKinds(pts []InsertionPoint) []PointKind {
	out := make([]PointKind, len(pts))
	for i, p := range pts {
		out[i] = p.Kind
	}
	return out
}

func hasKV(t *testing.T, pts []InsertionPoint, kind PointKind, label string) {
	t.Helper()
	for _, p := range pts {
		if p.Kind == kind && p.Label == label {
			return
		}
	}
	t.Errorf("missing %s %q in %+v", kind, label, pts)
}

func TestFindsQueryCookieAndBodyPoints(t *testing.T) {
	m := storeReq(t, "POST /app/login.php?next=/home&id=7 HTTP/1.1\r\nHost: t.test\r\nCookie: sid=abc; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 23\r\n\r\nuser=admin&pass=hunter2")
	pts := FindPoints(m, DefaultPointConfig())
	hasKV(t, pts, PointURLParamValue, "next")
	hasKV(t, pts, PointURLParamValue, "id")
	hasKV(t, pts, PointCookieValue, "sid")
	hasKV(t, pts, PointCookieValue, "theme")
	hasKV(t, pts, PointBodyParamValue, "user")
	hasKV(t, pts, PointBodyParamValue, "pass")
}

func TestAllConfigAddsPathsNamesHeaders(t *testing.T) {
	m := storeReq(t, "GET /a/b/c.php?x=1 HTTP/1.1\r\nHost: t.test\r\nUser-Agent: ua\r\n\r\n")
	pts := FindPoints(m, AllPointConfig())
	ks := pointKinds(pts)
	if !contains(ks, PointURLPathFolder) {
		t.Errorf("no url_path_folder in %v", ks)
	}
	if !contains(ks, PointURLPathFilename) {
		t.Errorf("no url_path_filename in %v", ks)
	}
	if !contains(ks, PointURLParamName) {
		t.Errorf("no url_param_name in %v", ks)
	}
	if !contains(ks, PointHeaderValue) {
		t.Errorf("no header_value in %v", ks)
	}
	for _, p := range pts {
		if p.Kind == PointHeaderValue && p.Label == "host" {
			t.Fatal("host is a boring header and must not be an attack position")
		}
	}
}

func TestApplySplicesAndFixesContentLength(t *testing.T) {
	m := storeReq(t, "POST / HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2")
	pts := FindPoints(m, DefaultPointConfig())
	var p *InsertionPoint
	for i := range pts {
		if pts[i].Label == "a" {
			p = &pts[i]
			break
		}
	}
	if p == nil {
		t.Fatal("no param a")
	}
	out := Apply(m.Raw, p, []byte("XXXXXXXXXX"))
	s := string(out)
	if !bytes.Contains(out, []byte("a=XXXXXXXXXX&b=2")) {
		t.Errorf("spliced: %s", s)
	}
	if !bytes.Contains(out, []byte("Content-Length: 16")) {
		t.Errorf("content-length not fixed: %s", s)
	}
}

func TestApplyAllFillsSeveralPositionsInOneRequest(t *testing.T) {
	m := storeReq(t, "GET /?user=aaa&role=bbb HTTP/1.1\r\nHost: t.test\r\n\r\n")
	pts := FindPoints(m, DefaultPointConfig())
	var user, role *InsertionPoint
	for i := range pts {
		switch pts[i].Label {
		case "user":
			user = &pts[i]
		case "role":
			role = &pts[i]
		}
	}
	if user == nil || role == nil {
		t.Fatalf("need user and role points, got %+v", pts)
	}
	// Longest payload first, so a naive left-to-right splice would shift the second one.
	out := ApplyAll(m.Raw, []ApplyPlace{
		{Point: user, Payload: []byte("LONGPAYLOAD")},
		{Point: role, Payload: []byte("x")},
	})
	first := string(out)
	if i := bytes.IndexByte(out, '\n'); i >= 0 {
		first = string(out[:i])
	}
	// Rust's str::lines strips a trailing \r; keep the comparison identical.
	first = strings.TrimSuffix(first, "\r")
	if first != "GET /?user=LONGPAYLOAD&role=x HTTP/1.1" {
		t.Errorf("spliced = %q", first)
	}
}

func TestApplyAllIsOrderIndependent(t *testing.T) {
	m := storeReq(t, "GET /?a=1&b=2&c=3 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	pts := FindPoints(m, DefaultPointConfig())
	byLabel := map[string]*InsertionPoint{}
	for i := range pts {
		byLabel[pts[i].Label] = &pts[i]
	}
	for _, want := range []string{"a", "b", "c"} {
		if byLabel[want] == nil {
			t.Fatalf("missing param %s", want)
		}
	}
	forward := ApplyAll(m.Raw, []ApplyPlace{
		{Point: byLabel["a"], Payload: []byte("AA")},
		{Point: byLabel["b"], Payload: []byte("BB")},
		{Point: byLabel["c"], Payload: []byte("CC")},
	})
	reverse := ApplyAll(m.Raw, []ApplyPlace{
		{Point: byLabel["c"], Payload: []byte("CC")},
		{Point: byLabel["b"], Payload: []byte("BB")},
		{Point: byLabel["a"], Payload: []byte("AA")},
	})
	if !bytes.Equal(forward, reverse) {
		t.Errorf("apply_all is not order independent:\n%s\n%s", forward, reverse)
	}
	if !bytes.Contains(forward, []byte("?a=AA&b=BB&c=CC")) {
		t.Errorf("spliced = %s", forward)
	}
}

func TestOverlappingPositionsYieldAValidRequestNotACorruptOne(t *testing.T) {
	// `entire_body` contains both body params, so all three overlap.
	m := storeReq(t, "POST / HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2")
	pts := FindPoints(m, AllPointConfig())
	var body, a *InsertionPoint
	for i := range pts {
		switch {
		case pts[i].Kind == PointEntireBody:
			body = &pts[i]
		case pts[i].Kind == PointBodyParamValue && pts[i].Label == "a":
			a = &pts[i]
		}
	}
	if body == nil || a == nil {
		t.Fatalf("need entire-body and param-a points, got %+v", pts)
	}
	out := ApplyAll(m.Raw, []ApplyPlace{
		{Point: body, Payload: []byte("WHOLE")},
		{Point: a, Payload: []byte("IGNORED")},
	})
	s := string(out)
	if !bytes.HasSuffix(out, []byte("\r\n\r\nWHOLE")) {
		t.Errorf("body should be replaced once: %s", s)
	}
	if bytes.Contains(out, []byte("IGNORED")) {
		t.Errorf("the overlapping later span must be skipped: %s", s)
	}
	if !bytes.Contains(out, []byte("Content-Length: 5")) {
		t.Errorf("framing must still be right: %s", s)
	}
}

func contains(ks []PointKind, want PointKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}
