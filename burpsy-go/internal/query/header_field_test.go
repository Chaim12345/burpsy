package query

import (
	"strings"
	"testing"
)

// ---- header predicates (burpsy-react-ui-0iw) ---------------------------------------------------
//
// The half of Bambda that actually mattered: "has X-Forwarded-For", "Set-Cookie without HttpOnly",
// "Server names nginx". Two things here are decisions rather than mechanics, and both are tested
// because either could be implemented the other way and look fine:
//
//   - indexed rather than flat text, so a match cannot straddle a header boundary;
//   - any-of over repeated values, because Set-Cookie repeats and "does any cookie contain
//     HttpOnly" is the question being asked.

func rowWithHeaders(h map[string][]string) fakeRow {
	lowered := map[string][]string{}
	for name, values := range h {
		lowered[strings.ToLower(name)] = values
	}
	return fakeRow{host: "a.test", status: 200, headers: lowered}
}

func TestHeaderPredicateMatchesOnValue(t *testing.T) {
	row := rowWithHeaders(map[string][]string{"Server": {"nginx/1.25.3"}})

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{`header["server"] ~ "nginx"`, true},
		{`header["server"] ~ "apache"`, false},
		{`header["server"] = "nginx/1.25.3"`, true},
		{`header["server"] != "apache"`, true},
		// Header names are case-insensitive per RFC 7230 §3.2, so the subscript must fold.
		{`header["Server"] ~ "nginx"`, true},
		{`header["SERVER"] ~ "nginx"`, true},
		// Values fold too: no spec makes a general header value case-sensitive.
		{`header["server"] ~ "NGINX"`, true},
	} {
		if got := mustParse(t, tc.query).Match(row); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.query, got, tc.want)
		}
	}
}

// The any-of decision. Set-Cookie is the header this field exists for, and it repeats.
func TestARepeatedHeaderMatchesIfAnyValueDoes(t *testing.T) {
	row := rowWithHeaders(map[string][]string{
		"Set-Cookie": {"session=abc; HttpOnly", "tracking=xyz; Path=/"},
	})

	if !mustParse(t, `header["set-cookie"] ~ "HttpOnly"`).Match(row) {
		t.Error("no value matched, though the first cookie carries HttpOnly — any-of is the semantics " +
			"a predicate over a repeated header needs")
	}
	// The one that a first-match implementation would get wrong: the interesting value is second.
	if !mustParse(t, `header["set-cookie"] ~ "tracking"`).Match(row) {
		t.Error("the SECOND value was not consulted. core.StoredMessage.Header returns only the first " +
			"match, which is why HeaderValues exists — a check built on the first would pass a response " +
			"whose second cookie is the insecure one")
	}
}

// Absence, and the negation that is easy to get wrong. This is the same rule status and length carry.
func TestAnAbsentHeaderFailsEveryComparisonIncludingNegations(t *testing.T) {
	row := rowWithHeaders(map[string][]string{"Server": {"nginx"}})

	for _, query := range []string{
		`header["x-api-key"] ~ "leaked"`,
		`header["x-api-key"] = "anything"`,
		`header["x-api-key"] != "leaked"`,
	} {
		if mustParse(t, query).Match(row) {
			t.Errorf("%s matched a response with no such header. For `!=` in particular this is the "+
				"trap: it would be true for every response lacking the header, which is the opposite of "+
				"what an operator asking about x-api-key wants to see", query)
		}
	}

	// And `not header[...] = ...` IS the way to ask "no value equals", which the precedence rules
	// already make expressible. Stated as a test so the workaround is discoverable.
	if !mustParse(t, `not header["server"] = "apache"`).Match(row) {
		t.Error(`not header["server"] = "apache" should hold: the header exists and does not equal that`)
	}
}

// A header present with an empty value is not an absent header. `Set-Cookie:` with nothing after it
// is a server bug worth being able to find.
func TestAPresentHeaderWithAnEmptyValueIsNotAbsent(t *testing.T) {
	row := rowWithHeaders(map[string][]string{"X-Empty": {""}})

	if !mustParse(t, `header["x-empty"] = ""`).Match(row) {
		t.Error(`header["x-empty"] = "" did not match a header present with an empty value; folding ` +
			"that into absence would hide a real server bug")
	}
	if mustParse(t, `header["x-missing"] = ""`).Match(row) {
		t.Error("an absent header matched an empty-string comparison, so absent and empty are the same " +
			"to this field — they are not")
	}
}

// ---- the syntax, refused at parse time ---------------------------------------------------------

func TestHeaderRequiresASubscript(t *testing.T) {
	_, err := Parse(`header ~ "nginx"`)
	if err == nil {
		t.Fatal("header parsed with no subscript; there is no sensible header to test")
	}
	if !strings.Contains(err.Error(), "subscript") {
		t.Errorf("error = %q, want it to name the missing subscript and show the form", err.Error())
	}
}

func TestAHeaderNameMustBeQuoted(t *testing.T) {
	_, err := Parse(`header[set-cookie] ~ "x"`)
	if err == nil {
		t.Fatal("an unquoted header name parsed")
	}
	// The reason matters: unquoted, the identifier lexer stops at the hyphen and the error would
	// surface somewhere unrelated to the mistake.
	if !strings.Contains(err.Error(), "quoted") {
		t.Errorf("error = %q, want it to say the name must be quoted", err.Error())
	}
}

func TestAnEmptyHeaderNameIsRefused(t *testing.T) {
	_, err := Parse(`header[""] ~ "x"`)
	if err == nil {
		t.Fatal(`header[""] parsed; it can match no header, and a comparison that cannot match is ` +
			"refused here rather than reported as no rows found")
	}
}

func TestAnUnclosedHeaderSubscriptIsRefused(t *testing.T) {
	for _, query := range []string{`header["server" ~ "x"`, `header["server"`} {
		if _, err := Parse(query); err == nil {
			t.Errorf("Parse(%q) succeeded with an unclosed subscript", query)
		}
	}
}

// Ordering on a header value means nothing, so the numeric operators are refused rather than
// silently comparing strings.
func TestHeaderRefusesOrderingOperators(t *testing.T) {
	for _, query := range []string{`header["age"] > "100"`, `header["age"] <= "5"`} {
		_, err := Parse(query)
		if err == nil {
			t.Errorf("Parse(%q) succeeded; no ordering on a header value is meaningful, and accepting "+
				"it would compare strings while looking like it compared numbers", query)
		}
	}
}

// Fields() must report it, which is what lets the crawler's pre-fetch gate refuse a query it cannot
// answer before a response exists.
func TestFieldsReportsTheHeaderField(t *testing.T) {
	e := mustParse(t, `host = "a.test" and header["server"] ~ "nginx"`)
	got := strings.Join(e.Fields(), ",")
	if got != "host,header" {
		t.Errorf("Fields() = %q, want host,header", got)
	}
}

// Two different headers in one query must keep their own names. A single shared slot on the Expr
// would make the second clause test the first header.
func TestTwoHeaderClausesKeepTheirOwnNames(t *testing.T) {
	row := rowWithHeaders(map[string][]string{
		"Server":       {"nginx"},
		"Content-Type": {"application/json"},
	})
	if !mustParse(t, `header["server"] ~ "nginx" and header["content-type"] ~ "json"`).Match(row) {
		t.Error("a two-header conjunction failed; each clause must carry its own header name")
	}
	if mustParse(t, `header["server"] ~ "nginx" and header["content-type"] ~ "nginx"`).Match(row) {
		t.Error("the second clause matched the FIRST header's value, so the name is being shared")
	}
}

// The field-name error must list every field, including this one. It listed six for a while after
// length and duration were added, which sent an operator who mistyped a field name a list missing
// two of the answers.
func TestTheUnknownFieldErrorListsEveryField(t *testing.T) {
	_, err := Parse(`nosuchfield = "x"`)
	if err == nil {
		t.Fatal("an unknown field parsed")
	}
	for _, want := range []string{"host", "status", "length", "duration", "header"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the unknown-field error does not mention %q: %s", want, err.Error())
		}
	}
}
