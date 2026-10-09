package reqedit

import (
	"reflect"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }
func ip(n int) *int       { return &n }

const base = "POST /api/users?id=7&x=1 HTTP/1.1\r\nHost: shop.test\r\nX-Dup: one\r\nx-dup: two\r\nCookie: a=1; sess=abc\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"user\":{\"role\":\"viewer\"}}\n"

func apply(t *testing.T, raw string, ops ...Op) string {
	t.Helper()
	out, _, err := Apply([]byte(raw), ops)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return string(out)
}

// Each op changes its span and nothing else: the expected output is the input with exactly that
// span replaced, byte for byte.
func TestEachOpTouchesOnlyItsSpan(t *testing.T) {
	cases := []struct {
		name string
		op   Op
		want string
	}{
		{"set_method", Op{Op: "set_method", Value: sp("PUT")}, strings.Replace(base, "POST ", "PUT ", 1)},
		{"set_path", Op{Op: "set_path", Value: sp("/admin")}, strings.Replace(base, "/api/users?", "/admin?", 1)},
		{"set_query_string", Op{Op: "set_query_string", Value: sp("q=2")}, strings.Replace(base, "?id=7&x=1", "?q=2", 1)},
		{"clear query", Op{Op: "set_query_string", Value: sp("")}, strings.Replace(base, "?id=7&x=1", "", 1)},
		{"set_query_param replace", Op{Op: "set_query_param", Name: "id", Value: sp("8")}, strings.Replace(base, "id=7", "id=8", 1)},
		{"set_query_param add", Op{Op: "set_query_param", Name: "z", Value: sp("9")}, strings.Replace(base, "x=1 HTTP", "x=1&z=9 HTTP", 1)},
		{"delete_query_param", Op{Op: "delete_query_param", Name: "id"}, strings.Replace(base, "id=7&", "", 1)},
		{"set_header replaces first, keeps casing and duplicates", Op{Op: "set_header", Name: "x-DUP", Value: sp("1")}, strings.Replace(base, "X-Dup: one", "X-Dup: 1", 1)},
		{"set_header appends", Op{Op: "set_header", Name: "X-New", Value: sp("v")}, strings.Replace(base, "Content-Length: 27\r\n", "Content-Length: 27\r\nX-New: v\r\n", 1)},
		{"delete_header removes every occurrence", Op{Op: "delete_header", Name: "X-DUP"}, strings.Replace(base, "X-Dup: one\r\nx-dup: two\r\n", "", 1)},
		{"set_request_cookie", Op{Op: "set_request_cookie", Name: "sess", Value: sp("zzz")}, strings.Replace(base, "a=1; sess=abc", "a=1; sess=zzz", 1)},
		{"delete_request_cookie", Op{Op: "delete_request_cookie", Name: "a"}, strings.Replace(base, "Cookie: a=1; sess=abc", "Cookie: sess=abc", 1)},
		{"raw_replace", Op{Op: "raw_replace", Name: "shop.test", Value: sp("evil.test")}, strings.Replace(base, "shop.test", "evil.test", 1)},
		{"raw_insert_at", Op{Op: "raw_insert_at", Offset: ip(0), Value: sp("X")}, "X" + base},
		// set_json_field replaces exactly the value's bytes and fixes Content-Length (27 -> 26).
		{"set_json_field", Op{Op: "set_json_field", Name: "user.role", Value: sp(`"admin"`)}, strings.Replace(strings.Replace(base, `"viewer"`, `"admin"`, 1), "Content-Length: 27", "Content-Length: 26", 1)},
	}
	for _, c := range cases {
		if got := apply(t, base, c.op); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestBodyOpsFixContentLengthAndLeaveTheHeadAlone(t *testing.T) {
	got := apply(t, base, Op{Op: "set_body", Value: sp("hello")})
	want := strings.Replace(base, "Content-Length: 27", "Content-Length: 5", 1)
	want = want[:strings.Index(want, "\r\n\r\n")+4] + "hello"
	if got != want {
		t.Fatalf("set_body:\n got %q\nwant %q", got, want)
	}
	// A JSON key that does not exist is inserted into its parent object, nothing else moves.
	got = apply(t, base, Op{Op: "set_json_field", Name: "user.admin", Value: sp("true")})
	if !strings.HasSuffix(got, `{"user":{"role":"viewer","admin":true}}`+"\n") || !strings.Contains(got, "Content-Length: 40") {
		t.Fatalf("insert: %q", got)
	}
	// Form fields: Content-Type set, values encoded, sorted, Content-Length right.
	got = apply(t, "POST /f HTTP/1.1\r\nHost: h\r\n\r\n", Op{Op: "set_form_fields", Fields: map[string]string{"b": "x y", "a": "1&2"}})
	if got != "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\na=1%262&b=x+y" {
		t.Fatalf("form fields: %q", got)
	}
}

func TestABareLFRequestGetsBareLFHeaders(t *testing.T) {
	got := apply(t, "GET / HTTP/1.1\nHost: h\n\n", Op{Op: "set_header", Name: "X-A", Value: sp("1")})
	if got != "GET / HTTP/1.1\nHost: h\nX-A: 1\n\n" {
		t.Fatalf("%q", got)
	}
}

func TestOpsRunInOrderOnTheEarlierOutput(t *testing.T) {
	got := apply(t, base, Op{Op: "set_path", Value: sp("/v2")}, Op{Op: "raw_replace", Name: "/v2", Value: sp("/v3")})
	if !strings.HasPrefix(got, "POST /v3?id=7") {
		t.Fatalf("%q", got[:30])
	}
}

func TestInvalidOpsAreRefusedAndNothingIsReturned(t *testing.T) {
	chunked := "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
	cases := []struct {
		raw string
		ops []Op
		msg string
	}{
		{base, []Op{{Op: "explode"}}, "unknown op"},
		{base, []Op{{Op: "set_header", Value: sp("v")}}, "name is required"},
		{base, []Op{{Op: "set_header", Name: "X", Value: sp("a\r\nInjected: 1")}}, "line break"},
		{base, []Op{{Op: "set_path", Value: sp("/a?b=1")}}, "must not contain '?'"},
		{base, []Op{{Op: "set_method"}}, "value is required"},
		{base, []Op{{Op: "raw_replace", Name: "nope", Value: sp("x")}}, "not in the request"},
		{base, []Op{{Op: "set_json_field", Name: "user", Value: sp("admin")}}, "not a JSON value"},
		{base, []Op{{Op: "set_json_field", Name: "user.role.x", Value: sp("1")}}, "does not exist"},
		{chunked, []Op{{Op: "set_body", Value: sp("x")}}, "chunked"},
		// The second op fails: nothing from the first survives.
		{base, []Op{{Op: "set_method", Value: sp("GET")}, {Op: "explode"}}, "edit 1"},
	}
	for _, c := range cases {
		out, applied, err := Apply([]byte(c.raw), c.ops)
		if err == nil || !strings.Contains(err.Error(), c.msg) || out != nil || applied != nil {
			t.Errorf("%v: err=%v out=%q", c.ops, err, out)
		}
	}
}

// The schema's enum (the struct tag) is exactly the ops Apply knows.
func TestTheOpEnumTagListsExactlyTheOps(t *testing.T) {
	f, _ := reflect.TypeFor[Op]().FieldByName("Op")
	if got, want := f.Tag.Get("enum"), strings.Join(OpNames(), "|"); got != want {
		t.Fatalf("enum tag\n %s\nops\n %s", got, want)
	}
}
