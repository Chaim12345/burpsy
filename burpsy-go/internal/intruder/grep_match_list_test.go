package intruder

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's Grep - Match list (irt): a LIST of expressions, one results column per expression,
// counting every occurrence in each response — not one boolean. Recovered from the decompiled
// original's Zru_ panel: Match type (Simple string / Regex), Case sensitive match, and Exclude
// HTTP headers, plus the matchgrep.item0..N default error-string list.
//
// The origin echoes a body carrying two of three expressions, twice each, in the BODY — and one
// only in the headers — so each of the three behaviours is observed independently on the same
// response: occurrence counting, case folding, and the headers-excluded switch.
func Test_the_grep_match_list_counts_every_occurrence_of_every_expression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Trace", "secret-in-headers")
		fmt.Fprintf(w, "body error error error exception exception quiet")
	}))
	defer srv.Close()

	base := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"))
	points := []InsertionPoint{{Kind: PointHeaderValue, Span: core.Span{Offset: 11, Len: 11}, Label: "host"}}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
	atk := NewAttack([]byte(base), points, []PayloadSet{{Items: []string{"x"}}}, plan).
		WithLimits(Unthrottled(1))

	// "error" is case-folded simple: it must count the lowercase body hits and the header's
	// "secret" contributes nothing. The header-only expression proves ExcludeHeaders decides,
	// not hopes: same list, opposite switch, different count.
	list, err := NewMatchList([]string{"error", "exception", "secret", "SECRET-UPPER"}, true, false, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	atk.WithGrep(Grep{MatchList: list})

	report := Run(atk, func(raw []byte) (Sent, error) {
		resp := "HTTP/1.1 200 OK\r\nX-Trace: secret-in-headers\r\n\r\nbody error error error exception exception quiet"
		status := 200
		return Sent{Raw: []byte(resp), Status: &status}, nil
	}, nil)

	if len(report.Attempts) != 1 {
		t.Fatalf("one attempt, got %d", len(report.Attempts))
	}
	got := report.Attempts[0].GrepMatchCounts
	// Headers excluded: "secret" (in X-Trace) counts 0; the body's three "error"s and two
	// "exception"s count; "SECRET-UPPER" folds to nothing in the body either way.
	want := []int{3, 2, 0, 0}
	if len(got) != len(want) {
		t.Fatalf("counts should carry one slot per expression (%d), got %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("counts[%d] = %d, want %d (case-folded body counting with headers excluded; full: %v)",
				i, got[i], want[i], got)
		}
	}
}

// Case-sensitive match is Burp's checkbox: with it set, the folding stops.
func Test_the_grep_match_list_is_case_sensitive_when_asked(t *testing.T) {
	list, err := NewMatchList([]string{"Error"}, true, true, false)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := list.counts([]byte("HTTP/1.1 200 OK\r\n\r\nerror Error ERROR eRRor"))
	if got[0] != 1 {
		t.Fatalf("case-sensitive simple string counts only the exact case, got %d of 4 spellings", got[0])
	}

	folded, err := NewMatchList([]string{"Error"}, true, false, false)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := folded.counts([]byte("HTTP/1.1 200 OK\r\n\r\nerror Error ERROR eRRor")); got[0] != 4 {
		t.Fatalf("case-folded simple string counts every spelling, got %d", got[0])
	}
}

// Regex mode compiles each entry as a pattern instead of a literal — Burp's Match type radio.
func Test_the_grep_match_list_supports_regex_entries(t *testing.T) {
	list, err := NewMatchList([]string{`e\w+`, "plain"}, false, false, false)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := list.counts([]byte("HTTP/1.1 200 OK\r\n\r\nerror exception plain"))
	if got[0] != 2 {
		t.Fatalf("regex entry counts its matches, got %d", got[0])
	}
	if got[1] != 1 {
		t.Fatalf("literal entry alongside a regex counts as a literal, got %d", got[1])
	}
}

// An entry that does not compile is refused with the item's index and text, not dropped: a
// column that silently counts nothing is a lie.
func Test_a_grep_match_list_entry_that_does_not_compile_is_refused_by_name(t *testing.T) {
	// Regex mode: simple mode quotes everything, so it cannot fail to compile — the refusal is
	// reachable only when the operator chose regex entries.
	_, err := NewMatchList([]string{"fine", "([unclosed"}, false, false, false)
	if err == nil {
		t.Fatal("a non-compiling entry was accepted; its column would count nothing forever")
	}
	if !strings.Contains(err.Error(), "item 2") || !strings.Contains(err.Error(), "unclosed") {
		t.Fatalf("the refusal should name the item's position and text, got: %v", err)
	}
}

// ExcludeHeaders with no header/body boundary searches whole: a response with no double CRLF
// has no header block to exclude, and dropping its content would be a fabrication.
func Test_excluding_headers_on_a_bodyless_response_still_searches_it(t *testing.T) {
	list, err := NewMatchList([]string{"token"}, true, false, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := list.counts([]byte("no headers here, just token")); got[0] != 1 {
		t.Fatalf("a response with no header split is searched whole, got %d", got[0])
	}
}

// The bucket table carries per-expression TOTALS (irt): Burp's "click on the column header to
// sort the results" reads the summed counts, so a bucket's columns must be the slot-wise sum
// over every response it holds, not the first response's counts alone.
func Test_bucket_totals_sum_every_response_in_the_bucket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "error error exception")
	}))
	defer srv.Close()

	base := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"))
	points := []InsertionPoint{{Kind: PointHeaderValue, Span: core.Span{Offset: 11, Len: 11}, Label: "host"}}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{2}, 10)
	// Two payloads, same response shape: both land in one bucket (200, same length, both
	// reflective), so the bucket's totals should be the sum of two identical responses.
	atk := NewAttack([]byte(base), points, []PayloadSet{{Items: []string{"a", "b"}}}, plan).
		WithLimits(Unthrottled(1))
	list, err := NewMatchList([]string{"error", "exception"}, true, false, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	atk.WithGrep(Grep{MatchList: list})

	report := Run(atk, func(raw []byte) (Sent, error) {
		resp := "HTTP/1.1 200 OK\r\n\r\nerror error exception"
		status := 200
		return Sent{Raw: []byte(resp), Status: &status}, nil
	}, nil)

	if len(report.Buckets) != 1 || report.Buckets[0].Count != 2 {
		t.Fatalf("one bucket holding both responses, got %+v", report.Buckets)
	}
	totals := report.Buckets[0].GrepMatchTotals
	want := []int{4, 2} // two responses' worth of "error" and "exception"
	if len(totals) != len(want) {
		t.Fatalf("totals should carry one slot per expression, got %v", totals)
	}
	for i := range want {
		if totals[i] != want[i] {
			t.Fatalf("totals[%d] = %d, want %d — the bucket must sum every response it holds, got %v",
				i, totals[i], want[i], totals)
		}
	}
}
