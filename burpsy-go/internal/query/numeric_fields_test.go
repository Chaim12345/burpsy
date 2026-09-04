package query

import (
	"strings"
	"testing"
)

// ---- length and duration (burpsy-react-ui-adl) --------------------------------------------------
//
// Two numeric fields, and the interesting part of both is absence. A response length of 0 is a real
// length — a 204 has an empty body — so absence cannot be inferred from the value, and an exchange
// nobody timed must not report as instantaneous. Those are the tests that would let a wrong answer
// through if they were missing, because the arithmetic is obvious and the absence rules are not.

// The guard that replaces a compiler check the compiler does not actually perform.
//
// fieldOrder is a [fieldCount]field literal. A short one is legal Go and pads with the zero value,
// which is fieldHost — so omitting a new field from it does not fail to build, it makes Fields()
// name a field the query never used. That is precisely what happened when length and duration were
// added, and it is why this test exists rather than the comment that used to claim a compile error.
func TestFieldOrderCoversEveryField(t *testing.T) {
	seen := map[field]int{}
	for _, f := range fieldOrder {
		seen[f]++
	}
	if len(seen) != fieldCount {
		t.Errorf("fieldOrder names %d distinct fields but the grammar has %d — a field is missing and "+
			"its slot has been padded with fieldHost, so Fields() will report a field no query named",
			len(seen), fieldCount)
	}
	for f, count := range seen {
		if count != 1 {
			t.Errorf("fieldOrder names %s %d times; Fields() would emit it %d times for one clause", f, count, count)
		}
	}
	// And every field must be able to name itself, or an error message says "?".
	for f := range seen {
		if f.String() == "?" {
			t.Errorf("field %d has no name, so any error mentioning it is unreadable", int(f))
		}
	}
}

func mustParse(t *testing.T, src string) *Expr {
	t.Helper()
	e, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return e
}

// ---- length ------------------------------------------------------------------------------------

func TestLengthComparesBytes(t *testing.T) {
	row := fakeRow{host: "a.test", length: 2048, hasLength: true}

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"length > 1024", true},
		{"length < 1024", false},
		{"length = 2048", true},
		{"length != 2048", false},
		{"length >= 2048", true},
		{"length <= 2048", true},
		{"length in 1024..4096", true},
		{"length in 4096..8192", false},
	} {
		if got := mustParse(t, tc.query).Match(row); got != tc.want {
			t.Errorf("%s against 2048 bytes = %v, want %v", tc.query, got, tc.want)
		}
	}
}

func TestLengthUnitsScale(t *testing.T) {
	for _, tc := range []struct {
		query  string
		length int64
		want   bool
	}{
		// The case the suffixes exist for: nobody should have to type 1048576.
		{"length > 1mb", 2 * 1024 * 1024, true},
		{"length > 1mb", 512 * 1024, false},
		{"length > 1kb", 2048, true},
		{"length = 1kb", 1024, true},
		{"length = 1024b", 1024, true},
		{"length > 1gb", 2 * 1024 * 1024 * 1024, true},
		// Bare means bytes, and that is the documented meaning rather than a guess.
		{"length > 1024", 2048, true},
		// Case-insensitive, because an operator typing 1MB means 1mb.
		{"length > 1MB", 2 * 1024 * 1024, true},
	} {
		row := fakeRow{length: tc.length, hasLength: true}
		if got := mustParse(t, tc.query).Match(row); got != tc.want {
			t.Errorf("%s against %d bytes = %v, want %v", tc.query, tc.length, got, tc.want)
		}
	}
}

// The absence rule, and the reason ResponseLen returns a bool at all.
func TestNoResponseIsNotAZeroLengthResponse(t *testing.T) {
	pending := fakeRow{host: "a.test"} // hasLength false: still in flight
	empty := fakeRow{host: "a.test", length: 0, hasLength: true}

	if mustParse(t, "length = 0").Match(pending) {
		t.Error("`length = 0` matched a request with no response; a pending request has no length, " +
			"and matching it would report every in-flight request as an empty response")
	}
	if !mustParse(t, "length = 0").Match(empty) {
		t.Error("`length = 0` did not match a genuinely empty response — a 204 is zero-length, not absent")
	}
	// != is the direction that catches a sloppy implementation: a field treated as absent must fail
	// EVERY comparison, including the negative one, or the absent rows all pile into `!=`.
	if mustParse(t, "length != 0").Match(pending) {
		t.Error("`length != 0` matched a request with no response; an absent field must fail every " +
			"comparison, negations included")
	}
	if mustParse(t, "length > 0").Match(pending) {
		t.Error("`length > 0` matched a request with no response")
	}
}

// ---- duration ----------------------------------------------------------------------------------

func TestDurationUnitsAndBareMeaningMilliseconds(t *testing.T) {
	// 250 ms, stored as microseconds the way core.ExchangeDuration does.
	row := fakeRow{durationUs: 250_000, measured: true}

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"duration > 100ms", true},
		{"duration < 100ms", false},
		{"duration = 250ms", true},
		{"duration < 1s", true},
		{"duration > 1s", false},
		{"duration = 250000us", true},
		// Bare means milliseconds, matching the History column an operator is reading when they
		// decide to write this query.
		{"duration > 100", true},
		{"duration < 100", false},
		{"duration in 100ms..500ms", true},
		{"duration in 500ms..1s", false},
	} {
		if got := mustParse(t, tc.query).Match(row); got != tc.want {
			t.Errorf("%s against 250ms = %v, want %v", tc.query, got, tc.want)
		}
	}
}

// An unmeasured exchange is not a fast one. core.ExchangeDuration carries a Measured flag for
// exactly this reason and flattening it here would undo it at the one place an operator can ask.
func TestAnUnmeasuredDurationMatchesNothing(t *testing.T) {
	unmeasured := fakeRow{host: "a.test"} // measured false

	for _, query := range []string{
		"duration < 100ms", "duration > 100ms", "duration = 0", "duration != 0", "duration in 0..1s",
	} {
		if mustParse(t, query).Match(unmeasured) {
			t.Errorf("%s matched an exchange nobody timed; reporting it would be the tool inventing a "+
				"measurement, and `duration < 100ms` would claim it was fast", query)
		}
	}
}

// ---- rejections at parse time ------------------------------------------------------------------

// The rule this grammar is built on: a comparison whose types do not fit is refused at parse time,
// not answered false at match time, because false is indistinguishable from "no rows matched".
func TestNumericFieldsRefuseNonNumericValues(t *testing.T) {
	for _, query := range []string{
		`length > "big"`,
		`duration > "slow"`,
		`length ~ "1024"`, // contains is not a numeric operator
		`duration ~ "1s"`,
	} {
		if _, err := Parse(query); err == nil {
			t.Errorf("Parse(%q) succeeded; an ill-typed comparison must be refused here rather than "+
				"matching nothing at run time", query)
		}
	}
}

func TestAnUnknownUnitIsRefusedAndNamesTheAcceptedOnes(t *testing.T) {
	_, err := Parse("length > 5tb")
	if err == nil {
		t.Fatal("an unknown unit parsed")
	}
	// The message has to say what would have worked, or the operator is left guessing.
	for _, want := range []string{"kb", "mb", "gb", "bare number means bytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}

	_, err = Parse("duration > 5fortnights")
	if err == nil {
		t.Fatal("an unknown duration unit parsed")
	}
	for _, want := range []string{"us", "ms", "bare number means milliseconds"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// An inverted range matches nothing, which on this grammar reads as "no rows are that size" — a
// verdict, not an error. Refused at parse time for the same reason a type mismatch is.
func TestAnInvertedNumericRangeIsRefused(t *testing.T) {
	for _, query := range []string{"length in 1mb..1kb", "duration in 1s..100ms"} {
		_, err := Parse(query)
		if err == nil {
			t.Errorf("Parse(%q) succeeded; an empty range would match nothing and look like a result", query)
			continue
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("error for %q = %q, want it to say the range is empty", query, err.Error())
		}
	}
}

// Fields() must report the new fields, which is what lets a consumer refuse a query it cannot
// answer — the crawler's pre-fetch gate does exactly that, and defaults unknown fields to refused.
func TestFieldsReportsTheNumericFields(t *testing.T) {
	e := mustParse(t, `host = "a.test" and length > 1kb and duration < 1s`)
	got := strings.Join(e.Fields(), ",")
	if got != "host,length,duration" {
		t.Errorf("Fields() = %q, want host,length,duration in declared order", got)
	}
}

// Overflow is refused rather than allowed to wrap. A wrapped bound becomes a negative number that
// matches everything or nothing, with no error to explain either.
func TestANumberTooLargeToScaleIsRefused(t *testing.T) {
	if _, err := Parse("length > 99999999999999999999gb"); err == nil {
		t.Error("a value that cannot be scaled into int64 parsed without error")
	}
}
