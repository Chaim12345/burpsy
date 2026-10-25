package crawler

import (
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
		"unterminated": "type Query {\n  book(title: String!): Book\n",
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
