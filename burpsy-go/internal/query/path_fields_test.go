package query

import (
	"strings"
	"testing"
)

// ---- extension and params (burpsy-react-ui-0iw) ------------------------------------------------
//
// Both are derived from Path() rather than carried on Queryable, because both are derivable exactly
// from a string every row already has. That means no adapter answers a new question, and — more to
// the point — no adapter can answer it differently from another.
//
// # The agreement that matters
//
// The History table computes the same two values client-side, in `pathParts` (ui/src/pages/
// history.tsx), for the Extension and Query columns. A filter that disagreed with the column beside
// it would be worse than no filter: an operator would see "3" in the Query column and `params = 3`
// returning nothing, and would have no way to tell which was lying.
//
// So the cases below are deliberately the same shapes `lib/history-derive.test.ts` pins on the TS
// side, and the rules are stated identically in both: cut at `?`, last segment only, a dot that is
// neither leading nor trailing, lowercased; empty pairs not counted.
//
// One deliberate divergence, harmless on real data: this also cuts at `#`. A fragment is never sent
// on the wire so no stored path carries one, but a caller constructing a Queryable by hand might,
// and dropping it is the same answer the TS side would give for a path without one.

func TestPathExtensionMatchesTheColumnBesideIt(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
		has  bool
	}{
		{"/app.js", "js", true},
		{"/a/b/logo.PNG", "png", true},   // lower-cased
		{"/report.pdf?v=2", "pdf", true}, // query stripped first
		{"/plain", "", false},            // no extension
		{"/", "", false},                 // root
		{"/api/users?id=1", "", false},   // dot only inside the query
		{"/v1.2/users", "", false},       // dot in a directory, not the last segment
		{"/.env", "", false},             // a dotfile's whole name is ".env"
		{"/trailing.", "", false},        // trailing dot, nothing after it
		{"/archive.tar.gz", "gz", true},  // last dot wins
		{"/x?q=a.b", "", false},          // the dot is in the query string
	} {
		got, has := pathExtension(tc.path)
		if got != tc.want || has != tc.has {
			t.Errorf("pathExtension(%q) = (%q, %v), want (%q, %v)", tc.path, got, has, tc.want, tc.has)
		}
	}
}

func TestQueryParamCountMatchesTheColumnBesideIt(t *testing.T) {
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/plain", 0},
		{"/plain?", 0}, // a bare ? is no parameters
		{"/s?q=1", 1},
		{"/s?q=1&page=2", 2},
		{"/s?a=1&&b=2", 2}, // an empty pair is not a parameter
		{"/s?flag", 1},     // a valueless parameter is still one
		{"/s?a=1&b=2&c=3&d=4", 4},
	} {
		if got := queryParamCount(tc.path); got != tc.want {
			t.Errorf("queryParamCount(%q) = %d, want %d", tc.path, got, tc.want)
		}
	}
}

func TestExtensionFieldFiltersRows(t *testing.T) {
	js := fakeRow{host: "a.test", path: "/static/app.js", status: 200}
	page := fakeRow{host: "a.test", path: "/about", status: 200}

	if !mustParse(t, `extension = "js"`).Match(js) {
		t.Error(`extension = "js" did not match /static/app.js`)
	}
	if !mustParse(t, `extension = "JS"`).Match(js) {
		t.Error("the extension comparison must fold case: a URL naming LOGO.PNG names the same file " +
			"type as one naming logo.png, and Burp's own extension filter folds it too")
	}
	// An extensionless path has NO extension, which is not an empty one: it must fail `!=` too, or
	// every extensionless path piles into a query asking for "not js".
	if mustParse(t, `extension != "js"`).Match(page) {
		t.Error(`extension != "js" matched /about, which has no extension at all. An absent field ` +
			"fails every comparison, negations included — ask for absence with `not extension ~ \"\"`" +
			" or by naming what you do want")
	}
	if mustParse(t, `extension = "js"`).Match(page) {
		t.Error(`extension = "js" matched a path with no extension`)
	}
}

func TestParamsFieldCountsQueryParameters(t *testing.T) {
	three := fakeRow{host: "a.test", path: "/search?q=x&page=2&sort=asc", status: 200}
	none := fakeRow{host: "a.test", path: "/search", status: 200}

	for _, tc := range []struct {
		query string
		row   fakeRow
		want  bool
	}{
		{"params = 3", three, true},
		{"params > 2", three, true},
		{"params < 3", three, false},
		{"params in 2..5", three, true},
		{"params = 0", none, true},
		{"params > 0", none, false},
	} {
		if got := mustParse(t, tc.query).Match(tc.row); got != tc.want {
			t.Errorf("%s against %q = %v, want %v", tc.query, tc.row.path, got, tc.want)
		}
	}
}

// params is a count, so it must refuse a string the way status does rather than comparing text.
func TestParamsRefusesAStringValue(t *testing.T) {
	if _, err := Parse(`params > "three"`); err == nil {
		t.Error("params accepted a quoted string; an ill-typed comparison is refused at parse time")
	}
}

// A row with no path answers neither field. The match/replace consumer is exactly this shape.
func TestARowWithNoPathAnswersNeitherPathField(t *testing.T) {
	noPath := fakeRow{host: "a.test", status: 200} // path "" = absent, per Queryable

	for _, query := range []string{
		`extension = "js"`, `extension != "js"`, "params = 0", "params != 0", "params < 5",
	} {
		if mustParse(t, query).Match(noPath) {
			t.Errorf("%s matched a row with no path; there is nothing to derive either field from, and "+
				"`params = 0` in particular would otherwise claim a pathless row has no parameters", query)
		}
	}
}

func TestFieldsReportsThePathDerivedFields(t *testing.T) {
	e := mustParse(t, `extension = "js" and params > 2`)
	if got := strings.Join(e.Fields(), ","); got != "extension,params" {
		t.Errorf("Fields() = %q, want extension,params", got)
	}
}
