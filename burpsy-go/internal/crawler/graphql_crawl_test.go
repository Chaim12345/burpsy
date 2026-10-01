package crawler

// Two crawl-level GraphQL assertions that graphql_test.go does not cover (burpsy-react-ui-bwwg,
// criterion 4).
//
// graphql_test.go (the parser's own tests plus its crawl-level sends) establishes that an
// introspection answer is READ correctly and that the query is sent and counted when the key is on.
// These two are the remainder that can still silently fail, and each is stated here rather than
// folded into that file because they assert different properties of a DIFFERENT part of the path:
//
//   - an answer that IS GraphQL but cannot be parsed must be a COUNTED SKIP, not a silent
//     "0 operations" — the honest-counting half of the criterion, which the registration test
//     covers only as a census (the reason exists in SkipAll) and never as a recorded skip;
//   - a guessed path is probed ONCE per origin — the dedupe that stops a two-hundred-page site
//     from being probed four times per page, which no test covers at all.
//
// Every assertion here is on the run's own record (what was fetched, what was skipped), not on the
// parser's return value: a reader wired into nothing reports the same green suite as one wired into
// the frontier.

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

// graphqlOverlayTarget serves pages on one origin plus a GraphQL endpoint that answers an
// introspection query. The endpoint is a real route so that the probe is observable as a fetch.
func graphqlOverlayTarget(t *testing.T, answer string, extra map[string]servedPage) *httptest.Server {
	t.Helper()
	pages := map[string]servedPage{
		"/":        {"<html><body><a href=\"/a\">a</a></body></html>", "text/html"},
		"/a":       {"<html><body><a href=\"/b\">b</a></body></html>", "text/html"},
		"/b":       {"<html><body><p>b</p></body></html>", "text/html"},
		"/graphql": {answer, "application/json"},
	}
	for path, page := range extra {
		pages[path] = page
	}
	return sitemapTarget(t, pages)
}

// overlayIntrospectionAnswer is the smallest schema that names an operation: one OBJECT type with one
// field carrying one argument. A SCALAR (String) is present so the reader's kind filter is exercised.
const overlayIntrospectionAnswer = `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
  {"name":"Query","kind":"OBJECT","fields":[{"name":"user","args":[{"name":"id"}]}]},
  {"name":"String","kind":"SCALAR","fields":null}
]}}}`

// The honest-counting half of criterion 4: an endpoint that answers WITH the GraphQL shape (data and
// __schema are both present) but whose answer cannot be read into operations is SkipGraphQLUnparsed —
// a counted skip with its own reason, never a silent zero.
//
// A caller reading the report without this reason would conclude the target exposes no GraphQL
// operations, which is false: the endpoint answered, the crawl asked, and READING the answer is what
// failed. That is exactly the distinction SkipAPIUnparsed preserves for documents and this reason
// exists to preserve for answers.
func TestAnUnparseableIntrospectionAnswerIsCountedAsItsOwnSkip(t *testing.T) {
	// data.__schema present (so it IS a GraphQL answer) but not a schema the reader can walk: the
	// shapes are wrong, the body is valid JSON, and the endpoint also reports errors — which is a
	// real, separately-readable fact and not the same answer as "no schema".
	broken := `{"data":{"__schema":{"queryType":42}},"errors":[{"message":"introspection is disabled"}]}`
	srv := graphqlOverlayTarget(t, broken, nil)

	cfg := newHarness().config(srv.URL + "/")
	cfg.PerformGraphQLIntrospection, cfg.GuessHiddenGraphQLEndpoints = true, true
	rep := run(t, cfg)

	if !fetchedAny(rep, "/graphql") {
		t.Fatalf("the crawl never asked /graphql; fetches: %v", fetchLog(rep))
	}
	if !skippedWith(rep, SkipGraphQLUnparsed) {
		t.Errorf("an unparseable introspection answer did not record SkipGraphQLUnparsed; the operator "+
			"is told the target exposes no GraphQL operations, which is false. Counts: %+v", rep.Skips.Counts)
	}
	if rep.GraphQLEndpointsFound != 0 {
		t.Errorf("GraphQLEndpointsFound = %d from an answer that could not be read; a number that came "+
			"from nowhere is worse than a zero the reader earned", rep.GraphQLEndpointsFound)
	}
}

// The guess's dedupe: a common path is probed ONCE per origin, whatever the crawl finds on it.
//
// The probe pass runs after EVERY visit, keyed on the origin — so a two-hundred-page site is probed
// once per path, not eight hundred times. The set that makes that true is guessedGraphQL, and a
// crawl whose dedupe failed would send a request per page: traffic the operator did not ask for,
// against a switch Burp ships OFF precisely because guessing is speculative work.
func TestAGuessedPathIsProbedOncePerOrigin(t *testing.T) {
	// Three pages on one origin, all crawled: the guess must fire once, not per page.
	srv := graphqlOverlayTarget(t, overlayIntrospectionAnswer, nil)

	cfg := newHarness().config(srv.URL + "/")
	cfg.PerformGraphQLIntrospection, cfg.GuessHiddenGraphQLEndpoints = true, true
	rep := run(t, cfg)

	// Compared by PATH, not by substring: "api/graphql" contains "/graphql", and a substring filter
	// would count another path's probe as a second POST to this one — the failure the test would
	// then report against correct code. The GET the crawl also makes of /graphql (the endpoint is
	// admitted as a location once the answer declares operations) is deliberately not counted: the
	// assertion is about the GUESS, not about the fetch the answer earned.
	posts := 0
	for _, f := range rep.Fetches {
		if f.Method != "POST" {
			continue
		}
		if u, err := url.Parse(f.URL); err == nil && u.Path == "/graphql" {
			posts++
		}
	}
	if posts != 1 {
		t.Errorf("POSTs to /graphql = %d, want exactly 1: the guess probes each path once per origin, "+
			"and a re-probe per page is a request the operator did not ask for. Fetches: %v",
			posts, fetchLog(rep))
	}
}
