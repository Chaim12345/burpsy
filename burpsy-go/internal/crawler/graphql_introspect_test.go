package crawler

import (
	"reflect"
	"strings"
	"testing"
)

// A saved introspection result, reduced-query shape (burpsy-react-ui-4xqt.1): the document
// form of the answer graphql.go reads from a live endpoint.
const introspectionDocument = `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
{"name":"Query","kind":"OBJECT","fields":[{"name":"search","args":[{"name":"q"},{"name":"limit"}]},{"name":"health","args":[]}]},
{"name":"String","kind":"SCALAR","fields":null},
{"name":"Genre","kind":"ENUM","fields":null}
]}}}`

// A parity fixture the current reader already reads: the operation list is pinned byte for
// byte, so the gqlparser-anchored loader cannot drift what a tolerated answer yields.
const introspectionParityAnswer = `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
{"name":"Query","kind":"OBJECT","fields":[{"name":"book","args":[{"name":"title"}]},{"name":"author","args":[]},{"name":"__secret","args":[]}]},
{"name":"Book","kind":"OBJECT","fields":[{"name":"title","args":[]},{"name":"author","args":[]}]},
{"name":"Genre","kind":"ENUM","fields":null}
]}}}`

// Bar (i): a saved introspection result met as a document yields its operations through
// ParseAPIDocument, the same "loading" the live answer path gets. Today the sniffer declines
// it - it is JSON, and JSON means OpenAPI or nothing.
func TestIntrospectionResultLoadsAsAPIDocument(t *testing.T) {
	format, eps, failure := ParseAPIDocument("application/json", []byte(introspectionDocument))
	if format == APIDocNone {
		t.Fatal("a saved introspection result was refused: the sniffer knows OpenAPI, Swagger and WSDL only")
	}
	if failure != "" {
		t.Fatalf("a well-formed introspection result failed to load: %s", failure)
	}
	want := []APIDocEndpoint{
		{Method: "POST", OperationID: "Query.health", Parameters: []string{}, Summary: "Query health"},
		{Method: "POST", OperationID: "Query.search", Parameters: []string{"limit", "q"}, Summary: "Query search"},
	}
	if !reflect.DeepEqual(eps, want) {
		t.Fatalf("introspection document operations:\n got %+v\nwant %+v", eps, want)
	}
}

// Bar (ii): a body that announces a schema but is structurally broken - no types, and no
// errors to blame - is a named failure, not a silent zero. A real introspection result always
// carries types; zero of both means the shape only looked like a schema. Pinned on BOTH the
// document path and the live answer path.
func TestIntrospectionResultStructurallyBrokenIsANamedFailure(t *testing.T) {
	broken := `{"data":{"__schema":{}}}`
	if _, failure := ParseGraphQLOperations([]byte(broken)); failure == "" {
		t.Fatal("live path: an empty __schema with no errors degraded to a silent zero")
	}
	if _, _, failure := ParseAPIDocument("application/json", []byte(broken)); failure == "" {
		t.Fatal("document path: an empty __schema with no errors degraded to a silent zero")
	}
}

// Bar (iii): the tolerated-answer parity pin. The current reader's operation list for this
// answer is pinned exactly - order (types sorted, fields sorted), the __-prefixed field skip,
// the enum skip, sorted args, the empty-args shape - so the loader's path cannot drift it.
func TestIntrospectionOperationsParity(t *testing.T) {
	ops, failure := ParseGraphQLOperations([]byte(introspectionParityAnswer))
	if failure != "" {
		t.Fatalf("the parity answer must keep loading: %s", failure)
	}
	want := []APIDocEndpoint{
		{Method: "POST", OperationID: "Book.author", Parameters: []string{}, Summary: "Book author"},
		{Method: "POST", OperationID: "Book.title", Parameters: []string{}, Summary: "Book title"},
		{Method: "POST", OperationID: "Query.author", Parameters: []string{}, Summary: "Query author"},
		{Method: "POST", OperationID: "Query.book", Parameters: []string{"title"}, Summary: "Query book"},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("parity broken:\n got %+v\nwant %+v", ops, want)
	}
}

// Bar (iv): no recognition widening. JSON that is not an introspection result stays not an
// API document, on the document path and the answer path alike.
func TestIntrospectionImportDoesNotWidenRecognition(t *testing.T) {
	for _, body := range []string{
		`{"data":{"user":{"name":"bob"}}}`,
		`{"errors":[{"message":"introspection denied"}]}`,
		`{"data":{"__schema":null}}`,
	} {
		if format, _, _ := ParseAPIDocument("application/json", []byte(body)); format != APIDocNone {
			t.Fatalf("non-introspection JSON %s recognised as %s", body, format)
		}
	}
	// And the errors-only body keeps its existing live-path meaning: GraphQL, introspection
	// disabled - a named fact, still not zero-ops silence.
	_, failure := ParseGraphQLOperations([]byte(`{"errors":[{"message":"introspection denied"}]}`))
	if !strings.Contains(failure, "introspection denied") {
		t.Fatalf("the errors-only answer lost its named failure: %q", failure)
	}
}
