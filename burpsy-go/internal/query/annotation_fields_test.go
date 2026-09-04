package query

import (
	"strings"
	"testing"
)

// ---- highlight and comment (burpsy-react-ui-0iw) -----------------------------------------------
//
// The only two fields in this grammar that describe burpsy's own state rather than the target's, and
// that is what makes their absence rule different from every other field's.
//
// Everywhere else, "" or a nil pointer means "the target did not give us this", and failing every
// comparison is the honest response. Here "" is a REAL answer an operator wants to filter on —
// `highlight = ""` is how you ask for the rows you have not triaged — so it cannot also mean "this
// consumer has no idea". Hence the third return from Annotation, and hence these tests.

func annotated(highlight, comment string) fakeRow {
	return fakeRow{
		host: "a.test", path: "/x", status: 200,
		highlight: highlight, comment: comment, annotationKnown: true,
	}
}

func TestHighlightAndCommentFilterAnnotatedRows(t *testing.T) {
	red := annotated("red", "looks injectable")

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{`highlight = "red"`, true},
		{`highlight = "blue"`, false},
		{`highlight != "blue"`, true},
		// The vocabulary is lower-case, and an operator typing Red means red.
		{`highlight = "RED"`, true},
		{`comment ~ "injectable"`, true},
		{`comment ~ "INJECTABLE"`, true},
		{`comment ~ "safe"`, false},
	} {
		if got := mustParse(t, tc.query).Match(red); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.query, got, tc.want)
		}
	}
}

// The case the third return value exists for: an unannotated exchange is a real answer.
func TestAnUnannotatedButKnownRowReportsEmptyAsAReadAnswer(t *testing.T) {
	plain := annotated("", "")

	if !mustParse(t, `highlight = ""`).Match(plain) {
		t.Error(`highlight = "" did not match a captured exchange with no highlight. That query is how ` +
			"an operator asks for the rows they have not triaged, and it is the whole reason Annotation " +
			"returns a separate `known` flag instead of using \"\" for both meanings")
	}
	if !mustParse(t, `comment = ""`).Match(plain) {
		t.Error(`comment = "" did not match an exchange with no comment`)
	}
	if mustParse(t, `highlight = "red"`).Match(plain) {
		t.Error(`highlight = "red" matched an unhighlighted row`)
	}
}

// A consumer that cannot answer must fail every comparison — including the empty-string one, which
// is the trap. The crawler's frontier and a match/replace candidate are both this shape.
func TestAConsumerThatCannotAnswerFailsEveryAnnotationComparison(t *testing.T) {
	unknown := fakeRow{host: "a.test", path: "/x", status: 200} // annotationKnown false

	for _, query := range []string{
		`highlight = "red"`,
		`highlight != "red"`,
		`highlight = ""`,
		`comment ~ "anything"`,
		`comment = ""`,
	} {
		if mustParse(t, query).Match(unknown) {
			t.Errorf("%s matched a consumer that cannot answer. `highlight = \"\"` is the dangerous one: "+
				"a crawler frontier row is not an untriaged exchange, and reporting it as one would tell "+
				"an operator their crawl queue is full of things they have not looked at", query)
		}
	}
}

// Ordering means nothing on either field.
func TestAnnotationFieldsRefuseOrderingOperators(t *testing.T) {
	for _, query := range []string{`highlight > "red"`, `comment <= "x"`, "highlight in 1..2"} {
		if _, err := Parse(query); err == nil {
			t.Errorf("Parse(%q) succeeded; no ordering on a colour name or on prose is meaningful", query)
		}
	}
}

func TestFieldsReportsTheAnnotationFields(t *testing.T) {
	e := mustParse(t, `highlight = "red" and comment ~ "check"`)
	if got := strings.Join(e.Fields(), ","); got != "highlight,comment" {
		t.Errorf("Fields() = %q, want highlight,comment in declared order", got)
	}
}

// The crawler's pre-fetch gate refuses any field it cannot honestly evaluate, and it derives that
// from the field list rather than a blocklist — so these two are refused there automatically. Pinned
// here because the alternative (a blocklist) would have needed editing for every new field and would
// have defaulted to permitting them.
func TestAnnotationFieldsAreNamedSoAConsumerCanRefuseThem(t *testing.T) {
	e := mustParse(t, `highlight = "red"`)
	fields := e.Fields()
	if len(fields) != 1 || fields[0] != "highlight" {
		t.Fatalf("Fields() = %v, want exactly [highlight] — a consumer that cannot answer needs the "+
			"field named to refuse the query rather than evaluating it to false", fields)
	}
}
