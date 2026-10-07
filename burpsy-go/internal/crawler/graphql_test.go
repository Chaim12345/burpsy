package crawler

// GraphQL discovery tests (burpsy-react-ui-bwwg, criterion 4).
//
// The load-bearing property here is different from the document readers'. Those fetch something and
// read it; this one SENDS a POST of its own, so the properties worth proving are about the request —
// that it goes through the scope chokepoint like everything else, that it counts against the crawl's
// request bound, and that it does nothing at all unless the operator's configuration asks.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// introspectionAnswer is a minimal but real introspection answer: three root operations, one nested
// type, and the meta-fields every schema carries.
const introspectionAnswer = `{"data":{"__schema":{
  "queryType":{"name":"Query"},
  "types":[
    {"name":"Query","kind":"OBJECT","fields":[
      {"name":"user","args":[{"name":"id"}]},
      {"name":"users","args":[]},
      {"name":"__typename","args":[]}
    ]},
    {"name":"Mutation","kind":"OBJECT","fields":[
      {"name":"createUser","args":[{"name":"input"}]}
    ]},
    {"name":"String","kind":"SCALAR","fields":[]}
  ]}}}`

// graphqlTarget serves a GraphQL endpoint at /graphql that answers introspection, and records every
// request it receives.
type graphqlTarget struct {
	*httptest.Server
	mu       sync.Mutex
	received []string
}

func newGraphQLTarget(t *testing.T) *graphqlTarget {
	t.Helper()
	g := &graphqlTarget{}
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.received = append(g.received, r.Method+" "+r.URL.Path)
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			// A GraphQL server answers introspection only to a POST carrying the query; a GET here
			// gets whatever the app returns for a browser, which is usually nothing useful. The
			// fixture answers the schema only to the POST, because that is the only request shape
			// whose answer a reader may treat as an introspection result.
			_, _ = w.Write([]byte(introspectionAnswer))
			return
		}
		// What a real GraphQL server answers a bare GET with: introspection is what the URL is FOR, and
		// many servers answer any query with the schema — or with the errors envelope when the query
		// was missing. Either marks this URL as GraphQL, and that mark is the only signal a crawler
		// has, which is why the reader's probe looks for `__schema` or `errors` and not for `data`.
		// A `{"data":{"__typename":...}}` reply would NOT do: every JSON API has a `data` key, and
		// probing on it would POST an introspection query to every JSON endpoint the crawl meets.
		_, _ = w.Write([]byte(`{"errors":[{"message":"Must provide query string"}]}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	})
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Server.Close)
	return g
}

func (g *graphqlTarget) sawIntrospection() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.received {
		if r == "POST /graphql" {
			return true
		}
	}
	return false
}

func TestAnIntrospectionAnswerYieldsItsOperations(t *testing.T) {
	ops, failure := ParseGraphQLOperations([]byte(introspectionAnswer))
	if failure != "" {
		t.Fatalf("a valid introspection answer reported a failure: %s", failure)
	}
	// Query.user, Query.users and Mutation.createUser. The __typename meta-field is NOT an
	// operation — every GraphQL server answers it on any object, and requesting it as a crawl
	// frontier item would send requests no schema declares.
	if len(ops) != 3 {
		t.Fatalf("parsed %d operations (%+v), want 3: two Query fields and one Mutation field", len(ops), ops)
	}
	byID := map[string]APIDocEndpoint{}
	for _, op := range ops {
		byID[op.OperationID] = op
	}
	if op, ok := byID["Query.user"]; !ok {
		t.Error("Query.user was not yielded")
	} else if op.Method != "POST" {
		t.Errorf("Query.user method = %q, want POST: a GraphQL operation is a POST body, not a path", op.Method)
	}
	if _, ok := byID["Query.__typename"]; ok {
		t.Error("the __typename meta-field was yielded as an operation")
	}
	// Argument names are what makes the operation followable — they are the field's inputs.
	if op := byID["Query.user"]; len(op.Parameters) != 1 || op.Parameters[0] != "id" {
		t.Errorf("Query.user parameters = %v, want [id]", op.Parameters)
	}
}

func TestAnAnswerThatIsNotGraphQLIsNeitherAnOperationNorAFailure(t *testing.T) {
	// Every POST the crawl makes against a non-GraphQL URL lands here. Reporting a failure or an
	// operation would fill the ledger with noise that buries the one endpoint that mattered.
	for _, body := range []string{
		`{"ok":true}`,
		`<html><body>not graphql</body></html>`,
		`{"data":{"user":{"id":1}}}`,
	} {
		ops, failure := ParseGraphQLOperations([]byte(body))
		if len(ops) != 0 || failure != "" {
			t.Errorf("body %q yielded %d ops and failure %q; want none of either", body, len(ops), failure)
		}
	}
}

func TestAGraphQLEndpointWithIntrospectionOffIsReportedRatherThanCountedAsZero(t *testing.T) {
	// A well-formed GraphQL answer carrying only errors is a GraphQL endpoint that refuses
	// introspection. That is a real, reportable fact — and it is NOT "this target has no GraphQL".
	const refused = `{"errors":[{"message":"GraphQL introspection is disabled"}]}`
	ops, failure := ParseGraphQLOperations([]byte(refused))
	if len(ops) != 0 {
		t.Errorf("an error-only answer yielded %d operations", len(ops))
	}
	if failure == "" {
		t.Error("an introspection-disabled endpoint reported no failure; an operator would read the " +
			"empty list as \"this target has no GraphQL API\"")
	}
	if !strings.Contains(failure, "introspection is disabled") {
		t.Errorf("failure = %q, want the endpoint's own message quoted", failure)
	}
}

// The end-to-end claim: with introspection on, the crawl POSTs the query and admits what comes back.
func TestACrawlWithIntrospectionOnSendsTheQueryAndCountsItsOperations(t *testing.T) {
	g := newGraphQLTarget(t)

	cfg := newHarness().config(g.URL + "/graphql")
	cfg.PerformGraphQLIntrospection = true
	rep := run(t, cfg)

	if !g.sawIntrospection() {
		t.Errorf("no POST /graphql was sent; fetches were %v", fetchLog(rep))
	}
	if rep.GraphQLEndpointsFound < 3 {
		t.Errorf("GraphQLEndpointsFound = %d, want the 3 operations the answer declares", rep.GraphQLEndpointsFound)
	}
}

// With the switch OFF, nothing is sent and nothing is reported. This is the refusal-first property:
// a crawler must not POST of its own initiative unless an operator asked.
func TestACrawlWithIntrospectionOffSendsNothing(t *testing.T) {
	g := newGraphQLTarget(t)

	cfg := newHarness().config(g.URL + "/graphql")
	rep := run(t, cfg)

	if g.sawIntrospection() {
		t.Errorf("a POST /graphql was sent with the switch off; fetches were %v", fetchLog(rep))
	}
	if rep.GraphQLEndpointsFound != 0 {
		t.Errorf("GraphQLEndpointsFound = %d with the switch off", rep.GraphQLEndpointsFound)
	}
}

// The request bound is a claim about traffic, and an introspection query IS traffic. A crawl that
// sent it past its own budget and still reported a bounded request count would be reporting a
// number that is not true.
func TestAnIntrospectionQueryIsRefusedWhenTheRequestBoundIsSpent(t *testing.T) {
	g := newGraphQLTarget(t)

	cfg := newHarness().config(g.URL + "/graphql")
	cfg.PerformGraphQLIntrospection = true
	cfg.Limits.MaxRequests = 1 // the seed itself consumes it
	rep := run(t, cfg)

	if rep.GraphQLEndpointsFound > 0 {
		t.Errorf("GraphQLEndpointsFound = %d after the request bound was spent", rep.GraphQLEndpointsFound)
	}
	// The bound is recorded as its own reason, because "0 GraphQL endpoints" alone would read as
	// "this target has none" when the crawl simply ran out of budget.
	if !skippedWith(rep, SkipGraphQLIntrospection) {
		t.Errorf("a probe refused by the request bound recorded no reason; counts: %+v", rep.Skips.Counts)
	}
}

// The hidden-endpoint guess is off by default in Burp's own shipped configuration, and this
// implementation honours that: guessing sends traffic nobody asked for.
func TestTheHiddenGraphQLGuessIsOffUnlessAskedFor(t *testing.T) {
	g := newGraphQLTarget(t)

	cfg := newHarness().config(g.URL + "/")
	rep := run(t, cfg)

	// No probe at all: nothing asked for a guess, so the reader is not even armed.
	if g.sawIntrospection() {
		t.Errorf("the hidden-endpoint guess ran with the switch off; fetches were %v", fetchLog(rep))
	}
	if rep.GraphQLEndpointsFound != 0 {
		t.Errorf("GraphQLEndpointsFound = %d with both switches off", rep.GraphQLEndpointsFound)
	}
	// No skip either. The reason fires only where an endpoint DID answer with a schema the crawl could
	// not read; an ordinary page is neither an operation nor a failure, and recording one would fill the
	// ledger with noise for every page a crawl touches.
	if skippedWith(rep, SkipGraphQLUnparsed) {
		t.Error("an ordinary HTML page was reported as an unreadable GraphQL answer; that reason " +
			"fires only where the endpoint answered with a schema")
	}
}

// Every new GraphQL reason is fully registered — the four tables an enum member must appear in, where
// a missing entry panics at runtime rather than failing to compile.
func TestTheGraphQLSkipReasonsAreFullyRegistered(t *testing.T) {
	for _, tc := range []struct {
		reason Skip
		name   string
		cat    SkipCategory
	}{
		{SkipGraphQLUnparsed, "graphql-unparsed", CategoryResponse},
		{SkipGraphQLIntrospection, "graphql-not-probed", CategoryLimit},
	} {
		found := false
		for _, s := range SkipAll {
			if s == tc.reason {
				found = true
			}
		}
		if !found {
			t.Errorf("%v is not in SkipAll, so its counts could never be reported", tc.reason)
		}
		if got := tc.reason.String(); got != tc.name {
			t.Errorf("String() = %q, want %q", got, tc.name)
		}
		if got := tc.reason.Category(); got != tc.cat {
			t.Errorf("Category() = %v, want %v", got, tc.cat)
		}
		if strings.TrimSpace(tc.reason.Explanation()) == "" {
			t.Errorf("Explanation() for %v is empty", tc.reason)
		}
	}
}

// Kills the "probe accepts any JSON body" mutation, which the guess-off test cannot: it seeds an HTML
// page, where the probe is false for a different reason (the body is not JSON at all). This one feeds
// the crawl a JSON body that DOES carry a GraphQL envelope's `data` key but is NOT a schema — the
// exact case where a sloppy probe would introspect every JSON endpoint a crawl touches.
func TestAJSONBodyThatIsNotASchemaIsNotIntrospected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			t.Errorf("the crawl introspected a JSON endpoint that is not a GraphQL schema")
		}
		w.Header().Set("Content-Type", "application/json")
		// `data` present, `__schema` absent — a GraphQL-shaped envelope that carries no schema.
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":1}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/api/data")
	cfg.PerformGraphQLIntrospection = true
	rep := run(t, cfg)

	if rep.GraphQLEndpointsFound != 0 {
		t.Errorf("GraphQLEndpointsFound = %d for an ordinary JSON API response", rep.GraphQLEndpointsFound)
	}
	if skippedWith(rep, SkipGraphQLUnparsed) {
		t.Error("an ordinary JSON response was reported as an unreadable GraphQL answer")
	}
}
