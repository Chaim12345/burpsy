package graphqlmap

import (
	"strings"
	"testing"
)

func scalar(name string) *TypeRef { return &TypeRef{Kind: "SCALAR", Name: name} }

// The cap is reported, never silent: a schema with more root fields than the bound says so.
func TestOperationsReportsTheCap(t *testing.T) {
	s := &Schema{QueryType: "Query", Types: []Type{{Kind: "OBJECT", Name: "Query", Fields: []Field{
		{Name: "b", Type: scalar("String")}, {Name: "a", Type: scalar("String")}, {Name: "c", Type: scalar("String")},
	}}}}
	ops, truncated := s.Operations(2)
	if !truncated || len(ops) != 2 || ops[0].Field != "a" || ops[1].Field != "b" {
		t.Fatalf("ops %+v truncated %v, want a,b sorted and truncated", ops, truncated)
	}
	all, truncated := s.Operations(0)
	if truncated || len(all) != 3 {
		t.Fatalf("an uncapped run = %d truncated %v", len(all), truncated)
	}
}

// A list of non-null input renders as GraphQL type syntax, and an object at the depth bound or an
// interface still gets a selection set — a document without one does not validate.
func TestOperationDocumentsValidateStructurally(t *testing.T) {
	list := &TypeRef{Kind: "NON_NULL", OfType: &TypeRef{Kind: "LIST", OfType: &TypeRef{Kind: "NON_NULL", OfType: scalar("ID")}}}
	s := &Schema{QueryType: "Query", Types: []Type{
		{Kind: "OBJECT", Name: "Query", Fields: []Field{
			{Name: "nodes", Args: []InputValue{{Name: "ids", Type: list}}, Type: &TypeRef{Kind: "INTERFACE", Name: "Node"}},
		}},
		{Kind: "INTERFACE", Name: "Node"},
	}}
	ops, _ := s.Operations(0)
	if len(ops) != 1 {
		t.Fatalf("ops = %+v", ops)
	}
	doc := ops[0].Document
	if !strings.Contains(doc, "query queryNodes($ids: [ID!]!)") || !strings.Contains(doc, "nodes(ids: $ids) { __typename }") {
		t.Fatalf("document = %q", doc)
	}
	if v, ok := ops[0].Variables["ids"].([]any); !ok || len(v) != 0 {
		t.Fatalf("a list placeholder = %#v, want []", ops[0].Variables["ids"])
	}
}
