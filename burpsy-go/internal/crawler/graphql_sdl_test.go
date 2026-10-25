package crawler

import (
	"fmt"
	"strings"

	"reflect"
	"testing"
)

// SDL import (burpsy-react-ui-4xqt.2, the third named gqlparser use): a GraphQL schema
// document met during a crawl is an API definition like any other, read through the pinned
// gqlparser - this is the import gaps.md's API-definition section refuses today.
const schemaDocument = `type Query {
  book(title: String!): Book
  author(id: ID): Author
}

type Mutation {
  addBook(title: String!): Book
}

type Book {
  title: String
  author: Author
}

type Author {
  name: String
}
`

// Bar (i): a served SDL document yields its operations through ParseAPIDocument, derived the
// way the introspection reader derives them - every object type's fields, types and fields
// and arguments sorted, so a schema and an introspection of that schema admit the same
// frontier.
func TestSDLImportsAsAPIDocument(t *testing.T) {
	format, eps, failure := ParseAPIDocument("text/plain", []byte(schemaDocument))
	if format == APIDocNone {
		t.Fatal("a GraphQL schema document was refused: the sniffer knows no SDL")
	}
	if failure != "" {
		t.Fatalf("a well-formed schema failed to load: %s", failure)
	}
	want := []APIDocEndpoint{
		{Method: "POST", OperationID: "Author.name", Parameters: []string{}, Summary: "Author name"},
		{Method: "POST", OperationID: "Book.author", Parameters: []string{}, Summary: "Book author"},
		{Method: "POST", OperationID: "Book.title", Parameters: []string{}, Summary: "Book title"},
		{Method: "POST", OperationID: "Mutation.addBook", Parameters: []string{"title"}, Summary: "Mutation addBook"},
		{Method: "POST", OperationID: "Query.author", Parameters: []string{"id"}, Summary: "Query author"},
		{Method: "POST", OperationID: "Query.book", Parameters: []string{"title"}, Summary: "Query book"},
	}
	if !reflect.DeepEqual(eps, want) {
		t.Fatalf("schema operations:\n got %+v\nwant %+v", eps, want)
	}
}

// Bar (ii): a body that announces SDL and then breaks - unterminated, or a schema no server
// could run - is a named failure, not a silent zero.
func TestBrokenSDLIsANamedFailure(t *testing.T) {
	for name, body := range map[string]string{
		"unterminated":  "type Query {\n  book(title: String!): Book\n",
		"no query root": "type Book {\n  title: String\n}\n\ntype Query {\n  broken(: String\n}\n",
	} {
		if _, _, failure := ParseAPIDocument("text/plain", []byte(body)); failure == "" {
			t.Errorf("%s: broken SDL degraded to a silent zero", name)
		}
	}
	// A schema document with no Query root at all never sniffs (the markers are the root
	// declarations), so it keeps today's answer: not an API document, not an error.
	if format, _, _ := ParseAPIDocument("text/plain", []byte("type Book {\n  title: String\n}\n")); format != APIDocNone {
		t.Error("a type-only document with no root operation type is not an importable schema; it must not announce itself")
	}
}

// Bar (iii): no recognition widening. Text that mentions the shape without being SDL - a
// TypeScript type alias above all - stays not an API document.
func TestSDLImportDoesNotWidenRecognition(t *testing.T) {
	for name, body := range map[string]string{
		"typescript alias": "type Query = { book: string }\n",
		"prose":            "the type Query { shape is discussed in the docs\n",
		"json":             `{"type Query {": true}`,
		"html":             "<html><body>type Query { book }</body></html>",
	} {
		if format, _, _ := ParseAPIDocument("text/plain", []byte(body)); format != APIDocNone {
			t.Errorf("%s: non-SDL text recognised as %s", name, format)
		}
	}
}

// End-to-end: a schema document reached by a crawl has its operations ADMITTED against the
// endpoint the document came from, counted once as GraphQL endpoints, not generic API ones.
func TestASchemaDocumentReachedByACrawlHasItsOperationsAdmitted(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/":               {"<html><body><a href=\"/schema.graphql\">schema</a></body></html>", "text/html"},
		"/schema.graphql": {schemaDocument, "text/plain"},
	})

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions = true
	rep := run(t, cfg)

	if rep.APIDocumentsRead != 1 {
		t.Errorf("APIDocumentsRead = %d, want 1; fetches were %v", rep.APIDocumentsRead, fetchLog(rep))
	}
	if rep.GraphQLEndpointsFound != 6 {
		t.Errorf("GraphQLEndpointsFound = %d, want the 6 operations the schema declares; skips %+v", rep.GraphQLEndpointsFound, rep.Skips.Counts)
	}
	if rep.APIEndpointsFound != 0 {
		t.Errorf("APIEndpointsFound = %d; a schema document's operations count as GraphQL endpoints, not REST ones", rep.APIEndpointsFound)
	}
}

// The failure half end-to-end: a document that announces SDL but is broken is a counted skip
// with the API-definition reason, never "0 endpoints".
func TestABrokenSchemaDocumentIsCountedAsItsOwnSkip(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/":               {"<html><body><a href=\"/schema.graphql\">schema</a></body></html>", "text/html"},
		"/schema.graphql": {"type Query {\n  book(title: String!): Book\n", "text/plain"},
	})

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions = true
	rep := run(t, cfg)

	if !skippedWith(rep, SkipAPIUnparsed) {
		t.Errorf("a broken schema document did not record SkipAPIUnparsed; counts: %+v", rep.Skips.Counts)
	}
	if rep.GraphQLEndpointsFound != 0 {
		t.Errorf("GraphQLEndpointsFound = %d for a document that could not be read", rep.GraphQLEndpointsFound)
	}
}

// ---- pre-review fix round: the sniff contract and its pins --------------------------------

// The sniffer accepts exactly the root-declaration shapes gqlparser parses in conventional
// SDL: whitespace (spaces or tabs) before the brace, an implements-clause, applied
// directives, and the minified brace-adjacent form. Each shape is pinned.
func TestConventionalRootDeclarationsAreRecognised(t *testing.T) {
	for name, doc := range map[string]string{
		"tab before brace":  "type Query\t{\n\tbook: Book\n}\n\ntype Book {\n\ttitle: String\n}\n",
		"multi-space":       "type Query   {\n  book: Book\n}\n\ntype Book {\n  title: String\n}\n",
		"implements clause": "interface Node {\n  id: ID\n}\n\ntype Query implements Node {\n  id: ID\n  book: Book\n}\n\ntype Book {\n  title: String\n}\n",
		"directive":         "type Query @key(fields: \"id\") {\n  id: ID\n}\n",
		"minified":          "type Query{book:Book} type Book{title:String}",
	} {
		format, eps, failure := ParseAPIDocument("text/plain", []byte(doc))
		if format == APIDocNone {
			t.Errorf("%s: a conventional root declaration gqlparser parses was refused by the sniffer", name)
			continue
		}
		if failure != "" {
			t.Errorf("%s: %s", name, failure)
			continue
		}
		if len(eps) == 0 {
			t.Errorf("%s: no operations read", name)
		}
	}
	// The accepted subset, stated exactly: "extend type" (a schema extension is not a
	// standalone schema) and the TypeScript alias ("type Query = {...}", where the "=" is no
	// SDL continuation) stay silent.
	for name, doc := range map[string]string{
		"extension":        "extend type Query {\n  extra: String\n}\n",
		"typescript alias": "type Query = { book: string }\n",
	} {
		if format, _, _ := ParseAPIDocument("text/plain", []byte(doc)); format != APIDocNone {
			t.Errorf("%s: outside the accepted subset but recognised as %s", name, format)
		}
	}
}

// The content-type hint is a media-type allowlist, not a substring: graphql-response+json
// announces an introspection ANSWER and the JSON path owns it, with or without the marker.
func TestGraphQLContentTypesRouteByMediaTypeNotSubstring(t *testing.T) {
	if format, _, failure := ParseAPIDocument("application/graphql-response+json", []byte(`{"errors":[{"message":"denied"}]}`)); format != APIDocNone {
		t.Errorf("a graphql-response body with no schema result routed to %s (failure %q); it is not an API document", format, failure)
	}
	if format, _, _ := ParseAPIDocument("application/graphql-response+json", []byte(introspectionDocument)); format != APIDocGraphQLIntrospection {
		t.Errorf("a graphql-response answer carrying a schema sorted as %s, want graphql-introspection", format)
	}
	// The allowlist carries the sniff when the root declaration sits beyond the head window,
	// parameters and all.
	padded := "# " + strings.Repeat("x", 5000) + "\n" + schemaDocument
	if format, _, failure := ParseAPIDocument("application/graphql; charset=utf-8", []byte(padded)); format != APIDocGraphQLSDL || failure != "" {
		t.Errorf("allowlisted media type with the marker beyond the head: format %s failure %q", format, failure)
	}
}

// The token bound has teeth: an over-bound schema document fails with the limit named, it
// does not parse unbounded.
func TestOversizedSchemaDocumentHitsTheTokenBoundAsANamedFailure(t *testing.T) {
	var b strings.Builder
	b.WriteString("type Query {\n")
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&b, "  f%06d: String\n", i)
	}
	b.WriteString("}\n")
	_, _, failure := ParseAPIDocument("text/plain", []byte(b.String()))
	if !strings.Contains(failure, "token limit") {
		t.Fatalf("an over-bound schema document must name the token limit, got %q", failure)
	}
}

// The paired parity pin: one schema in its two document forms - SDL and introspection
// result - admits the same frontier.
const schemaAsIntrospection = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[
{"name":"Query","kind":"OBJECT","fields":[{"name":"book","args":[{"name":"title"}]},{"name":"author","args":[{"name":"id"}]}]},
{"name":"Mutation","kind":"OBJECT","fields":[{"name":"addBook","args":[{"name":"title"}]}]},
{"name":"Book","kind":"OBJECT","fields":[{"name":"title","args":[]},{"name":"author","args":[]}]},
{"name":"Author","kind":"OBJECT","fields":[{"name":"name","args":[]}]},
{"name":"String","kind":"SCALAR","fields":null},
{"name":"ID","kind":"SCALAR","fields":null}
]}}}`

func TestASchemaAndItsIntrospectionAdmitTheSameFrontier(t *testing.T) {
	fromIntrospection, failure := ParseGraphQLOperations([]byte(schemaAsIntrospection))
	if failure != "" {
		t.Fatalf("introspection form: %s", failure)
	}
	format, fromSDL, failure := ParseAPIDocument("text/plain", []byte(schemaDocument))
	if format == APIDocNone || failure != "" {
		t.Fatalf("SDL form: format %s failure %q", format, failure)
	}
	if !reflect.DeepEqual(fromSDL, fromIntrospection) {
		t.Fatalf("the two forms of one schema diverged:\n   SDL: %+v\nanswer: %+v", fromSDL, fromIntrospection)
	}
}

// The both-flags e2e (pre-review): with parse_api_definitions AND
// perform_graphql_introspection on, a schema document still has exactly one admission owner -
// the document path, because the live reader judges JSON only.
func TestADualSwitchCrawlAdmitsASchemaDocumentOnce(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/":               {"<html><body><a href=\"/schema.graphql\">schema</a></body></html>", "text/html"},
		"/schema.graphql": {schemaDocument, "text/plain"},
	})

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions = true
	cfg.PerformGraphQLIntrospection = true
	rep := run(t, cfg)

	if rep.GraphQLEndpointsFound != 6 {
		t.Errorf("GraphQLEndpointsFound = %d, want exactly the 6 operations (one admission owner per body); fetches: %v",
			rep.GraphQLEndpointsFound, fetchLog(rep))
	}
	if rep.APIDocumentsRead != 1 {
		t.Errorf("APIDocumentsRead = %d, want 1: the live reader is JSON-only, so the document path owns a schema document even when armed", rep.APIDocumentsRead)
	}
}
