package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decodeCatalogue reads a GET /api/advisories response.
func decodeCatalogue(t *testing.T, rec *httptest.ResponseRecorder) advisoryCatalogueView {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/advisories answered %d, want 200: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view advisoryCatalogueView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode catalogue response: %v\nbody: %s", err, rec.Body.String())
	}
	return view
}

func Test_the_catalogue_index_lists_every_definition_that_loaded(t *testing.T) {
	s := newTestServer()
	view := decodeCatalogue(t, get(t, s, "/api/advisories"))

	if !view.Loaded {
		t.Fatal("the embedded catalogue did not load, so nothing below is a test of filtering")
	}
	if view.Count == 0 {
		t.Fatal("catalogue reports zero definitions; loadAdvisories() found nothing to embed")
	}
	// Unfiltered, matched is the whole catalogue. Asserted rather than assumed because these are the
	// two numbers the console renders as "N of M", and a handler that quietly reports Count for both
	// would make every filter look like it matched everything.
	if view.Matched != view.Count {
		t.Errorf("an unfiltered index matched %d of %d definitions; with no filter those must agree",
			view.Matched, view.Count)
	}
	if len(view.Advisories) != view.Matched {
		t.Errorf("matched says %d but %d rows were sent; the count and the list must describe the same set",
			view.Matched, len(view.Advisories))
	}
	if view.Hint != "" {
		t.Errorf("a loaded catalogue explained itself with %q; the hint is for the absent case", view.Hint)
	}
}

// The severity partition is the field that labels the filter's own options, so it has to describe the
// whole catalogue exactly. A partition that stops summing is the quiet failure of a per-bucket count:
// every bucket still looks plausible on its own.
func Test_the_severity_partition_sums_to_the_catalogue_size(t *testing.T) {
	s := newTestServer()
	view := decodeCatalogue(t, get(t, s, "/api/advisories"))

	total := 0
	for severity, n := range view.SeverityCounts {
		if !knownAdvisorySeverity(severity) {
			t.Errorf("catalogue reports %d definition(s) at severity %q, which is not one this API accepts as a filter",
				n, severity)
		}
		total += n
	}
	if total != view.Count {
		t.Errorf("severity counts sum to %d but the catalogue holds %d definitions; %v",
			total, view.Count, view.SeverityCounts)
	}
}

// A severity filter narrows to exactly the bucket the partition claims, and to nothing else. This is
// the assertion that ties the two numbers together: the option label and the result it produces.
func Test_a_severity_filter_returns_exactly_that_severitys_definitions(t *testing.T) {
	s := newTestServer()
	whole := decodeCatalogue(t, get(t, s, "/api/advisories"))

	for severity, want := range whole.SeverityCounts {
		view := decodeCatalogue(t, get(t, s, "/api/advisories?severity="+severity))
		if view.Matched != want {
			t.Errorf("?severity=%s matched %d definition(s); the unfiltered partition says there are %d",
				severity, view.Matched, want)
		}
		// Count stays the whole catalogue under a filter — it is what "N of M" needs for M.
		if view.Count != whole.Count {
			t.Errorf("?severity=%s reported a catalogue of %d; filtering must not change the total (%d)",
				severity, view.Count, whole.Count)
		}
		for _, row := range view.Advisories {
			if row.TypicalSeverity != severity {
				t.Errorf("?severity=%s returned %q at severity %s", severity, row.Name, row.TypicalSeverity)
			}
		}
	}
}

// Lowercase in, same answer out: the console's Select sends whatever it holds, and a filter that only
// works in one case is a filter that silently returns nothing.
func Test_a_severity_filter_is_case_insensitive(t *testing.T) {
	s := newTestServer()
	upper := decodeCatalogue(t, get(t, s, "/api/advisories?severity=HIGH"))
	lower := decodeCatalogue(t, get(t, s, "/api/advisories?severity=high"))
	if upper.Matched != lower.Matched || upper.Matched == 0 {
		t.Errorf("severity=HIGH matched %d and severity=high matched %d; these are one filter",
			upper.Matched, lower.Matched)
	}
}

// An unknown severity is refused rather than ignored. Serving the whole catalogue for a filter nobody
// defined answers a question the caller did not ask, and reads on screen as a filter that does nothing.
func Test_an_unknown_severity_is_refused_rather_than_ignored(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/advisories?severity=CATASTROPHIC")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("?severity=CATASTROPHIC answered %d, want 400: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	// The message has to name the accepted values, or the caller's only recourse is to guess.
	if !strings.Contains(rec.Body.String(), "HIGH") {
		t.Errorf("the refusal does not say what the catalogue accepts: %q", strings.TrimSpace(rec.Body.String()))
	}
}

func Test_a_text_search_matches_a_definitions_name(t *testing.T) {
	s := newTestServer()
	view := decodeCatalogue(t, get(t, s, "/api/advisories?q=sql+injection"))
	if view.Matched == 0 {
		t.Fatal(`?q=sql injection matched nothing; the catalogue is transcribed from Burp and holds "SQL injection"`)
	}
	found := false
	for _, row := range view.Advisories {
		if row.Name == "SQL injection" {
			found = true
			// The hexadecimal form, because that is what the detail route takes and what Burp shows.
			if row.TypeIndex != "00100200" {
				t.Errorf(`"SQL injection" carries type index %q, want 00100200 (Burp's own identifier)`, row.TypeIndex)
			}
		}
	}
	if !found {
		t.Errorf(`?q=sql injection returned %d row(s) but not "SQL injection" itself`, view.Matched)
	}
	if view.Matched >= view.Count {
		t.Errorf("a search for one issue matched %d of %d definitions; the filter is not narrowing",
			view.Matched, view.Count)
	}
}

// Search covers the description, not only the title — that is half the requirement, and the half a
// name-only search would satisfy silently for most terms.
func Test_a_text_search_reaches_the_description_prose(t *testing.T) {
	s := newTestServer()
	// "crafted input" appears in eleven definitions' description prose and in no definition's name, so
	// a name-only search cannot produce these hits. Chosen over a term like "parameterized" that lives
	// in the *remediation*: this endpoint searches name and description, and a test that leaned on
	// remediation text would be asserting a behaviour the handler deliberately does not have.
	view := decodeCatalogue(t, get(t, s, "/api/advisories?q=crafted+input"))
	if view.Matched == 0 {
		t.Fatal(`?q=crafted input matched nothing, so the search is not reading the description prose`)
	}
	for _, row := range view.Advisories {
		if strings.Contains(strings.ToLower(row.Name), "crafted") {
			t.Fatalf("%q contains the term in its name, so this case no longer proves the description is searched",
				row.Name)
		}
	}
}

// The prose, not the markup. Description is an HTML fragment; searching it raw would make every
// definition match "p" and none of those matches would be visible on screen.
func Test_a_text_search_does_not_match_the_descriptions_markup(t *testing.T) {
	s := newTestServer()
	for _, term := range []string{"<p>", "</p>", "href"} {
		view := decodeCatalogue(t, get(t, s, "/api/advisories?q="+strings.ReplaceAll(term, "<", "%3C")))
		if view.Matched > 0 {
			t.Errorf("?q=%s matched %d definition(s); the search is reading markup rather than prose (first: %q)",
				term, view.Matched, view.Advisories[0].Name)
		}
	}
}

// A filter that excludes everything is reported as exactly that, and is distinguishable from an
// absent catalogue: loaded stays true and count stays whole.
func Test_a_search_that_matches_nothing_still_reports_the_catalogue_it_searched(t *testing.T) {
	s := newTestServer()
	view := decodeCatalogue(t, get(t, s, "/api/advisories?q=zzzznosuchissuezzzz"))
	if view.Matched != 0 || len(view.Advisories) != 0 {
		t.Fatalf("a nonsense search matched %d definition(s)", view.Matched)
	}
	if !view.Loaded || view.Count == 0 {
		t.Errorf("an empty result reported loaded=%v count=%d; that is indistinguishable from no catalogue at all",
			view.Loaded, view.Count)
	}
}

// The nil catalogue is a supported state (server.go's advisories field), and the whole reason
// /api/issues reports its size. The list endpoint has to answer honestly rather than 500, and has to
// say *why* it is empty.
func Test_an_absent_catalogue_says_so_rather_than_looking_empty(t *testing.T) {
	s := newTestServer()
	s.advisories = nil

	view := decodeCatalogue(t, get(t, s, "/api/advisories"))
	if view.Loaded {
		t.Error("a nil catalogue reported loaded=true")
	}
	if view.Count != 0 || view.Matched != 0 || len(view.Advisories) != 0 {
		t.Errorf("a nil catalogue reported count=%d matched=%d rows=%d", view.Count, view.Matched, len(view.Advisories))
	}
	if view.Hint == "" {
		t.Error("a nil catalogue produced an empty list with no explanation; that reads as a load failure")
	}
}

func Test_one_definition_is_served_in_full_by_its_type_index(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/advisories/00100200")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/advisories/00100200 answered %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view issueAdvisoryView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if view.Name != "SQL injection" {
		t.Errorf("type index 00100200 is %q, want SQL injection", view.Name)
	}
	if view.TypeIndex != "00100200" {
		t.Errorf("detail carries type index %q; it must echo the one that was requested", view.TypeIndex)
	}
	// The paragraphs are what the console renders, and are the reason this endpoint exists at all —
	// the index rows deliberately do not carry them.
	if len(view.DescriptionParagraphs) == 0 {
		t.Error("no description paragraphs; the reader pane would render a blank advisory")
	}
	if len(view.RemediationParagraphs) == 0 {
		t.Error("no remediation paragraphs for SQL injection, which the catalogue definitely carries")
	}
	if len(view.Classifications) == 0 {
		t.Error("no vulnerability classifications for SQL injection; the CWE rows are part of the requirement")
	}
	if view.TypicalSeverity == "" {
		t.Error("detail reports no typical severity")
	}
}

// The detail shape is the finding path's shape. Asserted by construction rather than by comparing two
// literals: advisoryDetailView is the single producer, and this is the test that fails if a second one
// appears.
func Test_the_detail_shape_is_the_one_a_finding_carries(t *testing.T) {
	s := newTestServer()
	def, ok := s.advisories.ByIndex(0x00100200)
	if !ok {
		t.Fatal("the embedded catalogue has no SQL injection entry")
	}
	direct, err := json.Marshal(advisoryDetailView(def))
	if err != nil {
		t.Fatalf("marshal advisoryDetailView: %v", err)
	}
	overWire := get(t, s, "/api/advisories/00100200")
	if strings.TrimSpace(overWire.Body.String()) != string(direct) {
		t.Errorf("the route's body differs from advisoryDetailView's own encoding:\n over wire: %s\n direct:    %s",
			strings.TrimSpace(overWire.Body.String()), direct)
	}
}

// Every index row resolves. A list whose rows cannot be opened is worse than a short list, and the
// only thing joining them is the hexadecimal identifier — so it is checked over the whole catalogue
// rather than on the one row a spot check would pick.
func Test_every_index_row_can_be_opened_by_the_type_index_it_advertises(t *testing.T) {
	s := newTestServer()
	view := decodeCatalogue(t, get(t, s, "/api/advisories"))
	for _, row := range view.Advisories {
		rec := get(t, s, "/api/advisories/"+row.TypeIndex)
		if rec.Code != http.StatusOK {
			t.Errorf("index row %q advertises type index %s, which the detail route answers %d for",
				row.Name, row.TypeIndex, rec.Code)
		}
	}
}

func Test_an_unreadable_or_unknown_type_index_is_refused_distinguishably(t *testing.T) {
	s := newTestServer()
	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/api/advisories/", "Expected one type index", "the bare subtree is not a definition"},
		{"/api/advisories/00100200/extra", "Expected one type index", "a nested path names no single definition"},
		{"/api/advisories/not-hex", "not a hexadecimal", "an unreadable segment is refused, not guessed at"},
		{"/api/advisories/ffffffff", "No issue definition with type index", "a readable index that is not in the catalogue"},
	}
	for _, c := range cases {
		rec := get(t, s, c.path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d, want 404 (%s)", c.path, rec.Code, c.why)
			continue
		}
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("GET %s said %q; expected it to explain %s", c.path, strings.TrimSpace(rec.Body.String()), c.why)
		}
	}
}

// "The catalogue is not loaded" is a server state an operator can fix; "there is no definition with
// that index" is a fact about the catalogue. Both are 404, and they must not read as the same thing.
func Test_an_absent_catalogue_and_a_missing_definition_give_different_reasons(t *testing.T) {
	s := newTestServer()
	missing := get(t, s, "/api/advisories/ffffffff")
	s.advisories = nil
	absent := get(t, s, "/api/advisories/00100200")

	if absent.Code != http.StatusNotFound {
		t.Fatalf("a definition request against a nil catalogue answered %d, want 404", absent.Code)
	}
	if !strings.Contains(absent.Body.String(), "catalogue is loaded") {
		t.Errorf("a nil catalogue answered %q, which does not say the catalogue is what is missing",
			strings.TrimSpace(absent.Body.String()))
	}
	if strings.TrimSpace(absent.Body.String()) == strings.TrimSpace(missing.Body.String()) {
		t.Error("an absent catalogue and an unknown type index gave the same message; those call for " +
			"opposite reactions from the operator")
	}
}
