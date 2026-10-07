package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// searchFixture is one exchange with a request and a response, so a test can put a term in a
// request header, a request body, a response header or a response body and see which axis finds it.
type searchFixture struct {
	request  string
	response string
}

var searchFixtures = map[string]searchFixture{
	"alpha": {
		request:  "GET /alpha HTTP/1.1\r\nHost: alpha.test\r\nX-Marker: needle-in-request-header\r\n\r\nbody-needle-req",
		response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Echo: needle-in-response-header\r\n\r\nresponse-needle-body",
	},
	"beta": {
		request:  "POST /beta HTTP/1.1\r\nHost: beta.test\r\nContent-Type: text/plain\r\n\r\nBETA-BODY-ONLY",
		response: "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnothing here",
	},
}

// addSearchExchange stores one fixture and returns its exchange id.
func addSearchExchange(t *testing.T, s *Server, name string, source core.Source) core.ExchangeID {
	t.Helper()
	fixture, ok := searchFixtures[name]
	if !ok {
		t.Fatalf("no fixture named %q", name)
	}
	reqID, err := s.store.Put([]byte(fixture.request), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte(fixture.response), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	host := name + ".test"
	status := uint16(200)
	if name == "beta" {
		status = 404
	}
	s.store.AddExchange(&core.Exchange{
		Request:     core.MsgPtr(reqID),
		Response:    &respID,
		Host:        host,
		Port:        443,
		TLS:         true,
		Method:      "GET",
		Path:        "/" + name,
		Status:      &status,
		ResponseLen: len(fixture.response),
		Source:      source,
	})
	exchanges := s.store.Exchanges()
	return exchanges[len(exchanges)-1].ID
}

// runSearch performs GET /api/search with the given raw query and decodes the body.
func runSearch(t *testing.T, s *Server, query string) suiteSearchResponse {
	t.Helper()
	rec := get(t, s, "/api/search?"+query)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/search?%s: status = %d, body = %s", query, rec.Code, rec.Body.String())
	}
	var body suiteSearchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode search body %q: %v", rec.Body.String(), err)
	}
	return body
}

// TestSuiteSearchFindsBothDirectionsAndReportsOffsetsThatSliceBackToTheTerm is the contract the
// console's preview pane depends on: a match is (message, offset, length) and slicing the message
// the endpoint named with those numbers must yield the term. If it did not, the dialog would
// highlight bytes it did not match — the same class of lie as reporting a partial scan as complete.
func TestSuiteSearchFindsBothDirectionsAndReportsOffsetsThatSliceBackToTheTerm(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)

	body := runSearch(t, s, "q=needle")
	if len(body.Results) != 1 {
		t.Fatalf("results = %d, want the one exchange that carries the term", len(body.Results))
	}
	row := body.Results[0]
	if row.MatchCount != 4 {
		t.Fatalf("match_count = %d, want 4 (two request, two response)", row.MatchCount)
	}
	if len(row.Matches) != 4 {
		t.Fatalf("matches = %d, want 4", len(row.Matches))
	}

	directions := map[string]int{}
	for _, match := range row.Matches {
		directions[match.Direction]++
		msg, err := s.store.Get(core.MsgId(match.MessageID))
		if err != nil {
			t.Fatalf("match names message %d, which the store does not have: %v", match.MessageID, err)
		}
		raw := msg.Raw()
		if match.Offset+match.Len > len(raw) {
			t.Fatalf("match span %d+%d runs past message %d (%d bytes)", match.Offset, match.Len, match.MessageID, len(raw))
		}
		if got := string(raw[match.Offset : match.Offset+match.Len]); got != "needle" {
			t.Errorf("message %d[%d:%d] = %q, want %q: the offset does not index the bytes it claims",
				match.MessageID, match.Offset, match.Offset+match.Len, got, "needle")
		}
	}
	if directions["request"] != 2 || directions["response"] != 2 {
		t.Fatalf("directions = %v, want 2 request and 2 response", directions)
	}
}

// TestSuiteSearchIsCaseInsensitiveUntilAsked pins the default. Burp's dialog opens with "case
// sensitive" unticked, and a search that quietly required the operator's exact casing would report a
// term as absent from traffic that plainly contains it.
func TestSuiteSearchIsCaseInsensitiveUntilAsked(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "beta", core.SourceProxy)

	folded := runSearch(t, s, "q=beta-body-only")
	if len(folded.Results) != 1 {
		t.Fatalf("case-insensitive search found %d rows, want 1", len(folded.Results))
	}

	exact := runSearch(t, s, "q=beta-body-only&case=1")
	if len(exact.Results) != 0 {
		t.Fatalf("case-sensitive search found %d rows for the wrong casing, want 0", len(exact.Results))
	}

	matches := runSearch(t, s, "q=BETA-BODY-ONLY&case=1")
	if len(matches.Results) != 1 {
		t.Fatalf("case-sensitive search found %d rows for the exact casing, want 1", len(matches.Results))
	}
}

// TestSuiteSearchRefusesAPatternItCannotCompile: a regex that does not parse is the caller's
// mistake, and answering it with "no matches" would read as "the term is absent" when nothing was
// ever searched for.
func TestSuiteSearchRefusesAPatternItCannotCompile(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/search?q="+url.QueryEscape("(unclosed")+"&regex=1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an uncompilable pattern", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "regular expression") {
		t.Errorf("body = %q, want it to name the pattern as the problem", rec.Body.String())
	}
}

// TestSuiteSearchAreaNarrowsToHeadersOrBody keeps Burp's two areas honest: a term that lives only in
// a body must not be reported when the operator asked about headers, and the other way round.
func TestSuiteSearchAreaNarrowsToHeadersOrBody(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)

	headerOnly := "needle-in-request-header"
	bodyOnly := "response-needle-body"

	if body := runSearch(t, s, "q="+headerOnly+"&area=headers"); len(body.Results) != 1 {
		t.Errorf("headers search for a header term found %d rows, want 1", len(body.Results))
	}
	if body := runSearch(t, s, "q="+headerOnly+"&area=body"); len(body.Results) != 0 {
		t.Errorf("body search for a header term found %d rows, want 0", len(body.Results))
	}
	if body := runSearch(t, s, "q="+bodyOnly+"&area=body"); len(body.Results) != 1 {
		t.Errorf("body search for a body term found %d rows, want 1", len(body.Results))
	}
	if body := runSearch(t, s, "q="+bodyOnly+"&area=headers"); len(body.Results) != 0 {
		t.Errorf("headers search for a body term found %d rows, want 0", len(body.Results))
	}
	// And the area label on a match must agree with the region the offset came from, since the
	// console prints it beside the hit.
	both := runSearch(t, s, "q="+bodyOnly)
	if len(both.Results) != 1 || len(both.Results[0].Matches) != 1 {
		t.Fatalf("unfiltered search: results = %d, want 1 with 1 match", len(both.Results))
	}
	if got := both.Results[0].Matches[0].Area; got != "body" {
		t.Errorf("area = %q, want \"body\" for a term only the body holds", got)
	}
}

// TestSuiteSearchLocationNarrowsToRequestOrResponse is Burp's other axis. It is separate from area
// and composes with it, so each is checked for the one thing the other cannot express.
func TestSuiteSearchLocationNarrowsToRequestOrResponse(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)

	if body := runSearch(t, s, "q=needle-in-request-header&location=request"); len(body.Results) != 1 {
		t.Errorf("request search for a request term found %d rows, want 1", len(body.Results))
	}
	if body := runSearch(t, s, "q=needle-in-request-header&location=response"); len(body.Results) != 0 {
		t.Errorf("response search for a request term found %d rows, want 0", len(body.Results))
	}
	if body := runSearch(t, s, "q=needle-in-response-header&location=response"); len(body.Results) != 1 {
		t.Errorf("response search for a response term found %d rows, want 1", len(body.Results))
	}

	// An exchange with no response yet must not be searched as though it had one: a request-only
	// match under location=both is the honest answer, and the response half contributes nothing.
	reqID, err := s.store.Put([]byte("GET /pending HTTP/1.1\r\nHost: pending.test\r\n\r\npending-needle"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Host: "pending.test", Port: 80, Method: "GET", Path: "/pending", Source: core.SourceProxy})

	row := runSearch(t, s, "q=needle&location=response&tools=proxy")
	for _, result := range row.Results {
		for _, match := range result.Matches {
			if match.Direction != "response" {
				t.Errorf("location=response returned a %s match", match.Direction)
			}
		}
	}
}

// TestSuiteSearchToolFilterCrossesTheToolsTheStoreKeeps: the whole point of a *suite-wide* search is
// that it can be narrowed to a tool, so a Repeater-only search must not return proxy traffic and
// vice versa. Compared to /api/history, which is deliberately the opposite: it shows one tool.
func TestSuiteSearchToolFilterCrossesTheToolsTheStoreKeeps(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)   // /alpha
	addSearchExchange(t, s, "beta", core.SourceRepeater) // /beta

	all := runSearch(t, s, "q=HTTP")
	if len(all.Results) != 2 {
		t.Fatalf("unfiltered search found %d rows, want both", len(all.Results))
	}

	repeater := runSearch(t, s, "q=HTTP&tools=repeater")
	if len(repeater.Results) != 1 {
		t.Fatalf("tools=repeater found %d rows, want 1", len(repeater.Results))
	}
	if got := repeater.Results[0].Path; got != "/beta" {
		t.Errorf("tools=repeater returned %q, want the Repeater exchange /beta", got)
	}

	proxy := runSearch(t, s, "q=HTTP&tools=proxy")
	if len(proxy.Results) != 1 || proxy.Results[0].Path != "/alpha" {
		t.Fatalf("tools=proxy returned %v, want only /alpha", proxy.Results)
	}

	// Two tools are a union, not an intersection.
	both := runSearch(t, s, "q=HTTP&tools=proxy,repeater")
	if len(both.Results) != 2 {
		t.Fatalf("tools=proxy,repeater found %d rows, want both", len(both.Results))
	}
}

// TestSuiteSearchOrganizerToolIsMembershipNotSource: the Organizer is a shortlist over exchanges
// other tools produced, so selecting it must return the saved exchange regardless of which tool
// captured it — and must exclude everything else.
func TestSuiteSearchOrganizerToolIsMembershipNotSource(t *testing.T) {
	s := newTestServer()
	saved := addSearchExchange(t, s, "alpha", core.SourceProxy)
	addSearchExchange(t, s, "beta", core.SourceProxy)
	s.organizer.Add(int(saved))

	body := runSearch(t, s, "q=HTTP&tools=organizer")
	if len(body.Results) != 1 {
		t.Fatalf("tools=organizer found %d rows, want 1", len(body.Results))
	}
	if body.Results[0].Path != "/alpha" {
		t.Errorf("tools=organizer returned %q, want the saved /alpha", body.Results[0].Path)
	}
	if !body.Results[0].Organizer {
		t.Error("the row was found *through* the Organizer but reports organizer=false")
	}
}

// TestSuiteSearchNegativeMatchesReturnTheComplement: Burp's "negative matches" lists the items the
// term is absent from. Anything else is a different feature under the same checkbox.
func TestSuiteSearchNegativeMatchesReturnTheComplement(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)
	addSearchExchange(t, s, "beta", core.SourceProxy)

	positive := runSearch(t, s, "q=needle")
	if len(positive.Results) != 1 || positive.Results[0].Path != "/alpha" {
		t.Fatalf("positive search returned %d rows, want only /alpha", len(positive.Results))
	}

	negative := runSearch(t, s, "q=needle&negate=1")
	if len(negative.Results) != 1 {
		t.Fatalf("negative search returned %d rows, want only the exchange without the term", len(negative.Results))
	}
	if negative.Results[0].Path != "/beta" {
		t.Errorf("negative search returned %q, want /beta", negative.Results[0].Path)
	}
	if negative.Results[0].MatchCount != 0 {
		t.Errorf("a negative match reports match_count = %d, want 0", negative.Results[0].MatchCount)
	}
	if !negative.Negate {
		t.Error("the response does not say it was a negative search")
	}
}

// TestSuiteSearchInScopeOnlyHonoursTheEngagementScope: "in scope only" has to mean the same thing
// here as everywhere else, or the checkbox is a filter that lies.
func TestSuiteSearchInScopeOnlyHonoursTheEngagementScope(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)
	addSearchExchange(t, s, "beta", core.SourceProxy)
	s.scope.AddInclude("alpha.test")

	body := runSearch(t, s, "q=HTTP&in_scope=1")
	if len(body.Results) != 1 {
		t.Fatalf("in-scope search returned %d rows, want only the in-scope host", len(body.Results))
	}
	if body.Results[0].Host != "alpha.test" {
		t.Errorf("in-scope search returned host %q, want alpha.test", body.Results[0].Host)
	}
}

// TestSuiteSearchEmptyTermDescribesTheFacility: an absent q is not a search and not an error. The
// console needs the tool vocabulary to draw the dialog at all, and the precedent is the client's own
// compileHistorySearch contract — "empty text means no search is active".
func TestSuiteSearchEmptyTermDescribesTheFacility(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)

	for _, query := range []string{"", "q=", "q=%20%20"} {
		rec := get(t, s, "/api/search?"+query)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/search?%s: status = %d, want 200", query, rec.Code)
		}
		var body suiteSearchResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		if len(body.Results) != 0 {
			t.Errorf("query %q returned %d rows, want none: a blank term searches for nothing", query, len(body.Results))
		}
		if len(body.ToolOptions) == 0 {
			t.Errorf("query %q returned no tool vocabulary, so the dialog cannot draw its checklist", query)
		}
		if body.Tools == nil {
			t.Errorf("query %q returned a null tools field, want []", query)
		}
	}
}

// TestSuiteSearchVocabularyIsTheOneTheEndpointAccepts: the options are served so the client cannot
// offer a tool the endpoint refuses. That is only true if every served id is accepted, so this
// asserts the pair agrees rather than asserting the list's contents.
func TestSuiteSearchVocabularyIsTheOneTheEndpointAccepts(t *testing.T) {
	s := newTestServer()
	addSearchExchange(t, s, "alpha", core.SourceProxy)

	body := runSearch(t, s, "q=needle")
	if len(body.ToolOptions) == 0 {
		t.Fatal("no tool options were served")
	}
	for _, option := range body.ToolOptions {
		rec := get(t, s, "/api/search?q=needle&tools="+option.ID)
		if rec.Code != http.StatusOK {
			t.Errorf("the served tool %q was refused by the endpoint: %d %s", option.ID, rec.Code, rec.Body.String())
		}
		if option.Label == "" {
			t.Errorf("tool %q has no label, so the checklist would render a blank row", option.ID)
		}
	}
}

// TestSuiteSearchRefusesAnUnknownTool: a filter naming a tool this build does not have would
// otherwise select nothing, and a search that returns no rows because of a typo is indistinguishable
// from one that returns no rows because the term is absent.
func TestSuiteSearchRefusesAnUnknownTool(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/search?q=needle&tools=not-a-tool")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown tool", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not-a-tool") {
		t.Errorf("body = %q, want it to name the unknown tool", rec.Body.String())
	}
}

// TestSuiteSearchCapsOffsetsPerMessageAndCountsThemAnyway: the wire carries offsets, not bytes, but
// offsets are still unbounded in principle — a one-byte term in a megabyte of body is a million
// matches. The cap belongs on the record, and match_count has to carry the truth so the console can
// say "the first 200" rather than showing 200 as if it were all of them.
func TestSuiteSearchCapsOffsetsPerMessageAndCountsThemAnyway(t *testing.T) {
	s := newTestServer()
	occurrences := suiteSearchMaxMatchesPerMessage + 37
	body := strings.Repeat("x", occurrences)
	raw := "POST /spam HTTP/1.1\r\nHost: spam.test\r\n\r\n" + body
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Host: "spam.test", Port: 80, Method: "POST", Path: "/spam", Source: core.SourceProxy})

	result := runSearch(t, s, "q=x&area=body")
	if len(result.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(result.Results))
	}
	row := result.Results[0]
	if row.MatchCount != occurrences {
		t.Errorf("match_count = %d, want %d (the true total)", row.MatchCount, occurrences)
	}
	if len(row.Matches) != suiteSearchMaxMatchesPerMessage {
		t.Errorf("matches = %d, want the cap of %d", len(row.Matches), suiteSearchMaxMatchesPerMessage)
	}
	if !row.MatchesTruncated {
		t.Error("matches_truncated = false while the recorded offsets stop at the cap")
	}
}

// TestSuiteSearchSaysWhenTheLimitCutTheAnswerOff: a full page of results is not the same statement as
// "these are all of them", and a caller that cannot tell the two apart will report the first as the
// second.
func TestSuiteSearchSaysWhenTheLimitCutTheAnswerOff(t *testing.T) {
	s := newTestServer()
	for i := 0; i < 4; i++ {
		raw := fmt.Sprintf("GET /p%d HTTP/1.1\r\nHost: h.test\r\nX-N: needle\r\n\r\n", i)
		id, err := s.store.Put([]byte(raw), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put request: %v", err)
		}
		s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(id), Host: "h.test", Port: 80, Method: "GET", Path: fmt.Sprintf("/p%d", i), Source: core.SourceProxy})
	}

	full := runSearch(t, s, "q=needle")
	if full.Truncated {
		t.Errorf("a search that returned %d of 4 rows reports truncated", len(full.Results))
	}
	if full.Returned != len(full.Results) {
		t.Errorf("returned = %d but results holds %d", full.Returned, len(full.Results))
	}

	capped := runSearch(t, s, "q=needle&limit=2")
	if len(capped.Results) != 2 {
		t.Fatalf("limit=2 returned %d rows", len(capped.Results))
	}
	if !capped.Truncated {
		t.Error("a search stopped at its limit did not say the answer was cut off")
	}
	if capped.Scanned == 0 {
		t.Error("scanned = 0, so a caller cannot tell a scan that found nothing from one that never ran")
	}
}

// TestSuiteSearchRefusesAnUnrecognisedAxis mirrors the endpoint's treatment of enum fields
// everywhere else: a value it does not know is refused, never coerced to a nearby one, because
// silently answering a different question is worse than an error.
func TestSuiteSearchRefusesAnUnrecognisedAxis(t *testing.T) {
	s := newTestServer()
	for _, query := range []string{"q=needle&location=somewhere", "q=needle&area=payload", "q=needle&limit=0"} {
		rec := get(t, s, "/api/search?"+query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET /api/search?%s: status = %d, want 400", query, rec.Code)
		}
	}
}
