package query

import (
	"strings"
	"testing"
)

// fakeRow is the "first consumer" fake most field/operator tests run against — directly
// constructed, so the grammar is exercised without a store, a message parser, or anything else a
// real history row would drag in.
type fakeRow struct {
	host   string
	method string
	path   string // "" = absent, as Queryable documents
	status int    // 0 = absent, as Queryable documents
	mime   string
	body   []byte
}

func (f fakeRow) Host() string   { return f.host }
func (f fakeRow) Method() string { return f.method }
func (f fakeRow) Path() string   { return f.path }
func (f fakeRow) Status() int    { return f.status }
func (f fakeRow) Mime() string   { return f.mime }
func (f fakeRow) Body() []byte   { return f.body }

func row() fakeRow {
	return fakeRow{
		host:   "Example.com",
		method: "GET",
		path:   "/search",
		status: 200,
		mime:   "text/html",
		body:   []byte("<html>hello world</html>"),
	}
}

// noResponse is a captured request whose response has not arrived: no status, no Content-Type.
func noResponse() fakeRow {
	return fakeRow{host: "example.com", method: "GET", status: 0, mime: "", body: nil}
}

// matches parses src (failing the test if it does not parse) and evaluates it against q.
func matches(t *testing.T, src string, q Queryable) bool {
	t.Helper()
	e, err := Parse(src)
	if err != nil {
		t.Fatalf("%q should parse, got: %v", src, err)
	}
	return e.Match(q)
}

func assertMatch(t *testing.T, src string, q Queryable, want bool) {
	t.Helper()
	if got := matches(t, src, q); got != want {
		t.Errorf("%q: Match = %v, want %v", src, got, want)
	}
}

// ---- parentheses and precedence ----------------------------------------------------------------

// The precedence claim in the grammar doc, made operational: `a or b and c` must parse as
// `a or (b and c)`. Built so the two readings disagree — under `(a or b) and c` this row would not
// match, because its status is not 404.
func TestOrBindsLooserThanAndUnderTheDocumentedPrecedence(t *testing.T) {
	r := row() // host matches (a), method matches (b), status is 200 not 404 (c false)
	// a or (b and c) = true or (true and false) = true.
	// (a or b) and c = (true or true) and false = false.
	assertMatch(t, `host = "example.com" or method = "GET" and status = 404`, r, true)
}

// The same clause with the left side grouped flips the result — which is the whole point of adding
// parentheses, and is not expressible without them.
func TestParenthesesOverrideTheDefaultPrecedence(t *testing.T) {
	r := row()
	assertMatch(t, `(host = "example.com" or method = "GET") and status = 404`, r, false)

	r404 := row()
	r404.status = 404
	assertMatch(t, `(host = "example.com" or status = 200) and status = 404`, r404, true)
}

// Grouping must change the tree, not just the verdict on one row: the ungrouped form is an Or at
// the root, the grouped form an And.
func TestParenthesesChangeTheParseTreeShape(t *testing.T) {
	ungrouped, err := Parse(`host = "a" or method = "GET" and status = 404`)
	if err != nil {
		t.Fatalf("ungrouped should parse: %v", err)
	}
	if ungrouped.kind != kindOr {
		t.Errorf("ungrouped root kind = %v, want kindOr (and binds tighter)", ungrouped.kind)
	}
	if ungrouped.right.kind != kindAnd {
		t.Errorf("ungrouped right kind = %v, want kindAnd", ungrouped.right.kind)
	}

	grouped, err := Parse(`(host = "a" or method = "GET") and status = 404`)
	if err != nil {
		t.Fatalf("grouped should parse: %v", err)
	}
	if grouped.kind != kindAnd {
		t.Errorf("grouped root kind = %v, want kindAnd", grouped.kind)
	}
	if grouped.left.kind != kindOr {
		t.Errorf("grouped left kind = %v, want kindOr", grouped.left.kind)
	}
}

func TestNotAppliesToAGroupAsWellAsABareComparison(t *testing.T) {
	r := row()
	assertMatch(t, `not status = 404`, r, true)
	assertMatch(t, `not (status = 200 or status = 404)`, r, false)
	assertMatch(t, `not (status = 500 or status = 404)`, r, true)
}

func TestUnbalancedParenthesesAreParseErrors(t *testing.T) {
	for _, src := range []string{
		`(status = 200`,
		`status = 200)`,
		`(`,
		`(status = 200 and (host = "a")`,
	} {
		if e, err := Parse(src); err == nil {
			t.Errorf("%q must not parse, got expr %+v", src, e)
		}
	}
}

// An unclosed group reports the offset where the input ran out — the place a caret should point to
// say "it stopped here" — and a stray ')' reports its own offset.
func TestUnbalancedParenthesesReportUsefulOffsets(t *testing.T) {
	src := `(status = 200`
	_, err := Parse(src)
	qe, ok := err.(*QueryError)
	if !ok {
		t.Fatalf("want *QueryError, got %T (%v)", err, err)
	}
	if qe.At != len(src) {
		t.Errorf("unclosed group: At = %d, want %d (end of input)", qe.At, len(src))
	}

	src = `status = 200)`
	_, err = Parse(src)
	qe, ok = err.(*QueryError)
	if !ok {
		t.Fatalf("want *QueryError, got %T (%v)", err, err)
	}
	if want := strings.IndexByte(src, ')'); qe.At != want {
		t.Errorf("stray ')': At = %d, want %d", qe.At, want)
	}
}

// ---- `in low..high` ----------------------------------------------------------------------------

func TestStatusRangeMatchesInclusiveOfBothEnds(t *testing.T) {
	r := row() // status 200
	assertMatch(t, `status in 200..299`, r, true)
	assertMatch(t, `status in 200..200`, r, true) // lower bound is inclusive
	assertMatch(t, `status in 100..200`, r, true) // upper bound is inclusive
	assertMatch(t, `status in 201..299`, r, false)
	assertMatch(t, `status in 100..199`, r, false)

	r299 := row()
	r299.status = 299
	assertMatch(t, `status in 200..299`, r299, true) // just inside, at the top end
	r300 := row()
	r300.status = 300
	assertMatch(t, `status in 200..299`, r300, false) // just outside
}

func TestStatusRangeComposesWithBooleansAndGroups(t *testing.T) {
	r := row()
	assertMatch(t, `status in 200..299 and host ~ "example"`, r, true)
	assertMatch(t, `not status in 200..299`, r, false)
	assertMatch(t, `(status in 500..599 or status in 200..299) and method = "GET"`, r, true)
}

// An inverted range is well-typed and simply selects nothing, matching Rust — the bounds are
// compared, not reordered. That is a query with no rows, which is not a type error.
func TestAnInvertedStatusRangeParsesAndMatchesNothing(t *testing.T) {
	if _, err := Parse(`status in 299..200`); err != nil {
		t.Fatalf("an inverted range is well-typed and must parse: %v", err)
	}
	assertMatch(t, `status in 299..200`, row(), false)
}

func TestAMalformedStatusRangeIsAParseError(t *testing.T) {
	for _, src := range []string{
		`status in 200`,   // no `..` and no upper bound
		`status in 200..`, // no upper bound
		`status in ..299`, // no lower bound
		`status in "200".."299"`,
		`status in 200...299`, // the third dot has nowhere to go
	} {
		if e, err := Parse(src); err == nil {
			t.Errorf("%q must not parse, got expr %+v", src, e)
		}
	}
}

// ---- string escapes ----------------------------------------------------------------------------

// All five escapes the grammar has, decoded into the needle they stand for and matched against a
// body holding exactly those bytes.
func TestQuotedStringEscapesDecodeToTheirBytes(t *testing.T) {
	cases := []struct {
		src  string // the query text, with the escape written as source
		want string // the bytes the value must decode to
	}{
		{`body ~ "a\"b"`, `a"b`},
		{`body ~ "a\\b"`, `a\b`},
		{`body ~ "a\nb"`, "a\nb"},
		{`body ~ "a\tb"`, "a\tb"},
		{`body ~ "a\rb"`, "a\rb"},
		{`body ~ "a\"b\\c\nd\te\rf"`, "a\"b\\c\nd\te\rf"},
	}
	for _, c := range cases {
		e, err := Parse(c.src)
		if err != nil {
			t.Errorf("%s should parse: %v", c.src, err)
			continue
		}
		if e.str != c.want {
			t.Errorf("%s decoded to %q, want %q", c.src, e.str, c.want)
		}
		// And round-trips: a body containing exactly those bytes matches, one without does not.
		hit := fakeRow{body: []byte("xx" + c.want + "yy")}
		if !e.Match(hit) {
			t.Errorf("%s must match a body containing %q", c.src, c.want)
		}
		if e.Match(fakeRow{body: []byte("nothing like it")}) {
			t.Errorf("%s must not match an unrelated body", c.src)
		}
	}
}

// The bug the escapes close: an embedded `\"` used to end the string early, so the rest of the
// query was read as trailing junk instead of as part of the value.
func TestAnEscapedQuoteDoesNotTerminateTheString(t *testing.T) {
	e, err := Parse(`host = "say \"hi\""`)
	if err != nil {
		t.Fatalf("should parse: %v", err)
	}
	if want := `say "hi"`; e.str != want {
		t.Errorf("value = %q, want %q", e.str, want)
	}
}

func TestAnUnrecognisedEscapeIsAParseError(t *testing.T) {
	for _, src := range []string{`host ~ "a\qb"`, `host ~ "a\0b"`, `host ~ "a\"`} {
		if e, err := Parse(src); err == nil {
			t.Errorf("%s must not parse, got expr %+v", src, e)
		}
	}
}

func TestAnUnterminatedStringReportsTheOpeningQuote(t *testing.T) {
	src := `host = "abc`
	_, err := Parse(src)
	qe, ok := err.(*QueryError)
	if !ok {
		t.Fatalf("want *QueryError, got %T (%v)", err, err)
	}
	if want := strings.IndexByte(src, '"'); qe.At != want {
		t.Errorf("At = %d, want %d (the opening quote)", qe.At, want)
	}
}

// ---- DSL-04: type faults are parse faults ------------------------------------------------------

// Every one of these must come back as an error, never as an *Expr that evaluates to false — the
// two verdicts are indistinguishable to an operator reading an empty row list.
func TestIllTypedComparisonsAreRejectedAtParseTime(t *testing.T) {
	cases := []struct {
		src string
		why string
	}{
		{`status > "abc"`, "status ordered against a quoted string — DSL-04's canonical case"},
		{`status >= "400"`, "even a numeric-looking string is the wrong literal type for status"},
		{`status = "abc"`, "status equality against a quoted string"},
		{`host < "example.com"`, "ordering does not apply to a string field"},
		{`host >= "a"`, "ordering does not apply to a string field"},
		{`method > "GET"`, "ordering does not apply to a string field"},
		{`mime <= "text/html"`, "ordering does not apply to a string field"},
		{`body = "x"`, "body supports ~ only; whole-body equality is never the intent"},
		{`body != "x"`, "body supports ~ only"},
		{`body > "x"`, "body supports ~ only"},
		{`status ~ "200"`, "contains does not apply to a number"},
		{`host in 1..2`, "the range operator applies to status only"},
		{`body in 1..2`, "the range operator applies to status only"},
		{`status > 99999`, "a status literal must fit 0-65535"},
		{`host = 8080`, "a bare number is not a host; quote it to mean the text"},
		{`referer = "x"`, "not a field this grammar has"},
		{`host === "x"`, "not an operator this grammar has"},
		{`host`, "a field with no operator or value"},
		{`status =`, "an operator with no value"},
		{``, "an empty query filters on nothing"},
		{`   `, "a whitespace-only query filters on nothing"},
		{`host = "a" and`, "a dangling connective"},
		{`host = "a" host = "b"`, "two clauses with no connective between them"},
	}
	for _, c := range cases {
		e, err := Parse(c.src)
		if err == nil {
			t.Errorf("Parse(%q) must fail (%s), got expr %+v", c.src, c.why, e)
			continue
		}
		if e != nil {
			t.Errorf("Parse(%q) returned both an error and an expr %+v — an unparseable query must yield no evaluable expression", c.src, e)
		}
		if _, ok := err.(*QueryError); !ok {
			t.Errorf("Parse(%q) error is %T, want *QueryError", c.src, err)
		}
	}
}

// The distinction DSL-04 is about: a query that selects no rows is a valid expression whose Match
// is false; a malformed query is an error. Callers can tell them apart without inspecting text.
func TestAQueryMatchingNothingIsDistinguishableFromAParseFailure(t *testing.T) {
	valid, err := Parse(`status = 999`)
	if err != nil {
		t.Fatalf("a query with no matching rows still parses: %v", err)
	}
	if valid.Match(row()) {
		t.Error("status = 999 must not match a 200 row")
	}

	malformed, err := Parse(`status > "abc"`)
	if err == nil {
		t.Fatal("a malformed query must be an error, not an always-false expression")
	}
	if malformed != nil {
		t.Errorf("a malformed query must yield a nil expr, got %+v", malformed)
	}
}

// The caret is what makes the offset legible in the UI, which renders the error body verbatim.
func TestRenderPutsACaretUnderTheOffendingByte(t *testing.T) {
	src := `status > "abc"`
	_, err := Parse(src)
	if err == nil {
		t.Fatal("expected a parse error")
	}
	lines := strings.Split(Render(err), "\n")
	if len(lines) != 3 {
		t.Fatalf("Render = %q, want three lines (message, source, caret)", lines)
	}
	if lines[1] != src {
		t.Errorf("second line = %q, want the source line %q", lines[1], src)
	}
	qe := err.(*QueryError)
	if want := strings.Repeat(" ", qe.At) + "^"; lines[2] != want {
		t.Errorf("caret line = %q, want %q", lines[2], want)
	}
	if strings.IndexByte(src, '"') != qe.At {
		t.Errorf("At = %d, want %d (the quote that starts the ill-typed value)", qe.At, strings.IndexByte(src, '"'))
	}
}

// ---- fields, operators, absence ----------------------------------------------------------------

func TestHostAndMimeCompareCaseInsensitivelyAndMethodDoesNot(t *testing.T) {
	r := row() // host "Example.com", mime "text/html", method "GET"
	assertMatch(t, `host = "example.com"`, r, true)
	assertMatch(t, `host = "EXAMPLE.COM"`, r, true)
	assertMatch(t, `host ~ "AMPLE"`, r, true)
	assertMatch(t, `mime = "TEXT/HTML"`, r, true)
	assertMatch(t, `mime ~ "HTML"`, r, true)

	// The HTTP method token is case-sensitive per RFC 7230: a server defining only GET does not
	// answer `get`, so a query saying `get` describes a request that was never sent.
	assertMatch(t, `method = "GET"`, r, true)
	assertMatch(t, `method = "get"`, r, false)
	assertMatch(t, `method ~ "E"`, r, true)
	assertMatch(t, `method ~ "e"`, r, false)
}

// The path component is case-sensitive per RFC 3986 — /Admin and /admin are different resources, so
// folding case would report a hit on a path the server never served.
func TestPathComparesCaseSensitivelyAcrossItsThreeOperators(t *testing.T) {
	r := row() // path "/search"
	assertMatch(t, `path = "/search"`, r, true)
	assertMatch(t, `path = "/SEARCH"`, r, false)
	assertMatch(t, `path != "/login"`, r, true)
	assertMatch(t, `path ~ "sear"`, r, true)
	assertMatch(t, `path ~ "SEAR"`, r, false)

	// The site map's "filter history by this path" button emits exactly this shape.
	assertMatch(t, `host = "example.com" AND path ~ "/search"`, r, true)
	assertMatch(t, `host = "example.com" AND path ~ "/login"`, r, false)
}

// A consumer with no path — a match-and-replace candidate, say — reports absent, and absent means
// every comparison is false, `!=` included. Same rule status and mime already follow.
func TestAnAbsentPathMatchesNoComparisonOnPath(t *testing.T) {
	r := row()
	r.path = ""
	for _, src := range []string{`path = "/x"`, `path != "/x"`, `path ~ "x"`} {
		assertMatch(t, src, r, false)
	}
	assertMatch(t, `host = "example.com"`, r, true)
}

// Ordering comparisons are a status-only affordance; a path is not ordered.
func TestPathRejectsTheOrderingOperators(t *testing.T) {
	for _, src := range []string{`path > "/a"`, `path <= "/a"`, `path in 1..2`} {
		if _, err := Parse(src); err == nil {
			t.Errorf("%q should not parse", src)
		}
	}
}

func TestStatusScalarOperators(t *testing.T) {
	r := row() // 200
	assertMatch(t, `status = 200`, r, true)
	assertMatch(t, `status != 200`, r, false)
	assertMatch(t, `status != 404`, r, true)
	assertMatch(t, `status > 199`, r, true)
	assertMatch(t, `status > 200`, r, false)
	assertMatch(t, `status >= 200`, r, true)
	assertMatch(t, `status < 201`, r, true)
	assertMatch(t, `status < 200`, r, false)
	assertMatch(t, `status <= 200`, r, true)
}

// Absent is absent: a request still waiting for its response is not a 0-status response, so no
// comparison on status (or on a missing Content-Type) holds. Before this was explicit,
// `status < 400` matched every pending request because 0 < 400.
func TestAnAbsentStatusOrMimeMatchesNoComparisonOnThatField(t *testing.T) {
	r := noResponse()
	for _, src := range []string{
		`status = 200`, `status != 200`, `status = 0`, `status < 400`,
		`status >= 0`, `status in 0..999`,
	} {
		assertMatch(t, src, r, false)
	}
	for _, src := range []string{`mime = "text/html"`, `mime != "text/html"`, `mime ~ "html"`} {
		assertMatch(t, src, r, false)
	}
	// The fields the row does have still work, so absence is per-field and not per-row.
	assertMatch(t, `host = "example.com"`, r, true)
}

func TestBodyContainsIsByteExactAndCaseSensitive(t *testing.T) {
	r := row()
	assertMatch(t, `body ~ "hello world"`, r, true)
	assertMatch(t, `body ~ "HELLO WORLD"`, r, false)
	assertMatch(t, `body ~ "goodbye"`, r, false)
}

// Both spellings of equality parse to the same comparison. `==` is what the UI's own placeholder
// query uses; before the operator table was checked at parse time it parsed and then silently
// never matched, which is exactly the failure DSL-04 exists to prevent.
func TestEqualsAndDoubleEqualsAreBothAccepted(t *testing.T) {
	r := row()
	assertMatch(t, `status == 200`, r, true)
	assertMatch(t, `status == 404`, r, false)
	assertMatch(t, `host == "example.com" and not method == "OPTIONS"`, r, true)
	assertMatch(t, `host = "example.com" and not method = "OPTIONS"`, r, true)
}

// A named divergence from Rust, kept for the queries and CLI examples that predate this work:
// an unquoted bare word is a valid string value.
func TestABareUnquotedWordIsAValidStringValue(t *testing.T) {
	r := row()
	assertMatch(t, `host = example.com`, r, true)
	assertMatch(t, `host ~ example and method = GET`, r, true)
	assertMatch(t, `host = other.com`, r, false)
}

// ---- DSL-02: one grammar, two unrelated consumers ----------------------------------------------

// A second Queryable that computes its answers from an entirely different representation (a
// pseudo-request line plus a header), the way a match-and-replace rule candidate would. Proves the
// grammar does not secretly assume fakeRow's shape.
type ruleCandidate struct {
	requestLine  string // "METHOD host"
	responseCode int
	contentType  string
	rawBody      string
}

func (c ruleCandidate) Host() string {
	parts := strings.SplitN(c.requestLine, " ", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}
func (c ruleCandidate) Method() string { return strings.SplitN(c.requestLine, " ", 2)[0] }

// This consumer models a match-and-replace candidate, which carries no path — absent, per Queryable.
func (c ruleCandidate) Path() string { return "" }

func (c ruleCandidate) Status() int  { return c.responseCode }
func (c ruleCandidate) Mime() string { return c.contentType }
func (c ruleCandidate) Body() []byte { return []byte(c.rawBody) }

func TestTheSameParsedQueryDrivesTwoUnrelatedConsumers(t *testing.T) {
	e, err := Parse(`status in 200..299 and (host = "example.com" or host = "other.test") and body ~ "hi"`)
	if err != nil {
		t.Fatalf("should parse: %v", err)
	}
	history := fakeRow{host: "Example.com", method: "POST", status: 200, body: []byte("say hi to the world")}
	candidate := ruleCandidate{requestLine: "GET EXAMPLE.COM", responseCode: 204, contentType: "application/json", rawBody: "hi there"}

	if !e.Match(history) {
		t.Error("must match the history-filter-shaped consumer")
	}
	if !e.Match(candidate) {
		t.Error("the same parsed expression, unmodified, must also match a structurally unrelated consumer")
	}
}
