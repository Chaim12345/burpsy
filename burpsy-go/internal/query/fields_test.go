package query

import (
	"strings"
	"testing"
)

// TestFieldsNamesEveryComparedField pins the introspection DSL-03's consumer depends on. The crawler
// refuses a crawl-scope query naming a field a frontier URL cannot answer, and it can only do that if
// this reports every field the query actually compares on — a missed field would be a query silently
// evaluated against a value that does not exist.
func TestFieldsNamesEveryComparedField(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{`host = "example.com"`, "host"},
		{`method = "POST"`, "method"},
		{`status = 200`, "status"},
		{`mime ~ "json"`, "mime"},
		{`body ~ "admin"`, "body"},
		// Reported in the grammar's declared order, not discovery order, so two queries naming the
		// same fields differently ordered give the same answer.
		{`status = 200 and host = "a"`, "host,status"},
		{`host = "a" and status = 200`, "host,status"},
		// Duplicates collapse.
		{`host = "a" or host = "b"`, "host"},
		// `not` and parentheses are walked through.
		{`not mime ~ "json"`, "mime"},
		{`not (host = "a" and status < 400)`, "host,status"},
		{`(host = "a" or method = "GET") and body ~ "x"`, "host,method,body"},
		// All five at once.
		{`host = "a" and method = "GET" and mime ~ "html" and status in 200..299 and body ~ "x"`,
			"host,method,mime,status,body"},
	}
	for _, tc := range cases {
		e, err := Parse(tc.query)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.query, err)
		}
		got := strings.Join(e.Fields(), ",")
		if got != tc.want {
			t.Errorf("Parse(%q).Fields() = %q, want %q", tc.query, got, tc.want)
		}
	}
}

// TestNilExprNamesNoFields pins the "no filter" case, which Match already treats as matching
// everything — a nil query names no fields and so can never be refused for naming an unavailable one.
func TestNilExprNamesNoFields(t *testing.T) {
	var e *Expr
	if got := e.Fields(); len(got) != 0 {
		t.Fatalf("a nil query names %v, want nothing", got)
	}
}

// TestFieldsIsReadOnly pins that inspecting a query neither mutates it nor changes what it matches —
// the invariant that keeps Match infallible is untouched by this accessor existing.
func TestFieldsIsReadOnly(t *testing.T) {
	e, err := Parse(`host = "example.com" and status = 200`)
	if err != nil {
		t.Fatal(err)
	}
	row := stubRow{host: "example.com", status: 200}
	before := e.Match(row)
	_ = e.Fields()
	_ = e.Fields()
	if e.Match(row) != before {
		t.Fatal("Fields changed what the query matches")
	}
	if got := strings.Join(e.Fields(), ","); got != "host,status" {
		t.Fatalf("repeated calls disagree: %q", got)
	}
}

type stubRow struct {
	host   string
	method string
	path   string
	status int
	mime   string
	body   []byte
	// Both absences are explicit, so a stub that says nothing about length or timing reports them
	// as absent rather than as zero — the same distinction the real adapters carry.
	length     int64
	hasLength  bool
	durationUs int64
	measured   bool
}

func (r stubRow) Host() string               { return r.host }
func (r stubRow) Method() string             { return r.method }
func (r stubRow) Path() string               { return r.path }
func (r stubRow) Status() int                { return r.status }
func (r stubRow) Mime() string               { return r.mime }
func (r stubRow) Body() []byte               { return r.body }
func (r stubRow) ResponseLen() (int64, bool) { return r.length, r.hasLength }
func (r stubRow) DurationUs() (int64, bool)  { return r.durationUs, r.measured }
