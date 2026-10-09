package graphqlmap

// One runnable document per root operation of an introspected schema — what Burp's "Save GraphQL
// queries to site map" turns an introspection answer into (burp.Zu6: for every QUERY and MUTATION
// root field, build a request carrying that operation and add it to the site map unrequested).
//
// The documents are written with variables rather than inline literals, the shape Burp's builder
// produces (it hands the query, the placement and a variables object to the request writer): an
// operator who opens one in Repeater edits values in `variables`, not in the middle of a query
// string, and a typed variable keeps the server's own coercion rules in play.

import (
	"fmt"
	"sort"
	"strings"
)

// Operation is one generated document.
type Operation struct {
	// Kind is "query" or "mutation".
	Kind string
	// Field is the root field the document calls.
	Field string
	// Name is the document's operation name, unique within one schema's output.
	Name string
	// Document is the GraphQL text.
	Document string
	// Variables holds one placeholder per declared variable, typed to its scalar: "" for String and
	// ID, 0 for Int and Float, false for Boolean, the first value for an enum, {} for an input
	// object, [] for a list.
	Variables map[string]any
}

// selectionDepth bounds how far an object-typed result is expanded. Two levels names the fields an
// operator recognises without generating the schema's whole graph for every operation.
const selectionDepth = 2

// Operations renders a document for every root query and mutation field, sorted by kind then
// field, capped at max. truncated reports that the cap dropped some — a bound that is reported, not
// silent. Subscriptions are not generated: Burp's builder walks QUERY and MUTATION only, and a
// subscription document is not a request a site map item can replay.
func (s *Schema) Operations(max int) (ops []Operation, truncated bool) {
	byName := make(map[string]*Type, len(s.Types))
	for i := range s.Types {
		byName[s.Types[i].Name] = &s.Types[i]
	}
	roots := []struct{ kind, typeName, fallback string }{
		{"query", s.QueryType, "Query"},
		{"mutation", s.MutationType, "Mutation"},
	}
	ops = []Operation{}
	for _, root := range roots {
		name := root.typeName
		if name == "" {
			name = root.fallback
		}
		typ := byName[name]
		if typ == nil {
			continue
		}
		fields := append([]Field(nil), typ.Fields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		for _, field := range fields {
			if strings.HasPrefix(field.Name, "__") {
				continue
			}
			if max > 0 && len(ops) >= max {
				return ops, true
			}
			ops = append(ops, s.operationFor(root.kind, field, byName))
		}
	}
	return ops, false
}

func (s *Schema) operationFor(kind string, field Field, byName map[string]*Type) Operation {
	opName := operationName(kind, field.Name)
	vars := map[string]any{}
	var decls, args []string
	for _, arg := range field.Args {
		if arg.Name == "" || arg.Type == nil {
			continue
		}
		decls = append(decls, fmt.Sprintf("$%s: %s", arg.Name, renderTypeRef(arg.Type)))
		args = append(args, fmt.Sprintf("%s: $%s", arg.Name, arg.Name))
		vars[arg.Name] = placeholder(arg.Type, byName)
	}
	var b strings.Builder
	b.WriteString(kind)
	b.WriteString(" ")
	b.WriteString(opName)
	if len(decls) > 0 {
		b.WriteString("(" + strings.Join(decls, ", ") + ")")
	}
	b.WriteString(" {\n  ")
	b.WriteString(field.Name)
	if len(args) > 0 {
		b.WriteString("(" + strings.Join(args, ", ") + ")")
	}
	b.WriteString(selection(field.Type, byName, selectionDepth, "  "))
	b.WriteString("\n}")
	return Operation{Kind: kind, Field: field.Name, Name: opName, Document: b.String(), Variables: vars}
}

// operationName is a valid GraphQL name: the kind and the field, the field's first letter raised.
func operationName(kind, field string) string {
	if field == "" {
		return kind
	}
	return kind + strings.ToUpper(field[:1]) + field[1:]
}

// renderTypeRef writes a type reference in GraphQL syntax: NON_NULL as a trailing "!", LIST as [ ].
func renderTypeRef(t *TypeRef) string {
	if t == nil {
		return "String"
	}
	switch t.Kind {
	case "NON_NULL":
		return renderTypeRef(t.OfType) + "!"
	case "LIST":
		return "[" + renderTypeRef(t.OfType) + "]"
	default:
		if t.Name == "" {
			return "String"
		}
		return t.Name
	}
}

// placeholder is a value of the argument's type that a server will parse.
func placeholder(t *TypeRef, byName map[string]*Type) any {
	for cur := t; cur != nil; cur = cur.OfType {
		switch cur.Kind {
		case "LIST":
			return []any{}
		case "NON_NULL":
			continue
		}
		switch cur.Name {
		case "Int", "Float":
			return 0
		case "Boolean":
			return false
		case "String", "ID":
			return ""
		}
		if typ := byName[cur.Name]; typ != nil {
			switch typ.Kind {
			case "ENUM":
				if len(typ.EnumValues) > 0 {
					return typ.EnumValues[0].Name
				}
				return ""
			case "INPUT_OBJECT":
				return map[string]any{}
			}
		}
		return ""
	}
	return ""
}

// selection is the result type's selection set: nothing for a scalar or enum, the scalar fields
// (and objects down to depth) for an object, and __typename where nothing else is selectable — an
// interface or union, or an object at the depth bound — because a document with an object-typed
// field and no selection set does not validate.
func selection(t *TypeRef, byName map[string]*Type, depth int, indent string) string {
	named := t.Named()
	typ := byName[named]
	if typ == nil || typ.Kind == "SCALAR" || typ.Kind == "ENUM" {
		return ""
	}
	if typ.Kind != "OBJECT" || depth <= 0 {
		return " { __typename }"
	}
	fields := append([]Field(nil), typ.Fields...)
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	var lines []string
	for _, f := range fields {
		if strings.HasPrefix(f.Name, "__") || requiresArgs(f) {
			continue
		}
		sub := byName[f.Type.Named()]
		if sub == nil || sub.Kind == "SCALAR" || sub.Kind == "ENUM" {
			lines = append(lines, indent+"  "+f.Name)
			continue
		}
		if depth > 1 {
			lines = append(lines, indent+"  "+f.Name+selection(f.Type, byName, depth-1, indent+"  "))
		}
	}
	if len(lines) == 0 {
		return " { __typename }"
	}
	return " {\n" + strings.Join(lines, "\n") + "\n" + indent + "}"
}

// requiresArgs reports a field that cannot be selected without arguments the generator would have
// to invent — a NON_NULL argument with no default.
func requiresArgs(f Field) bool {
	for _, a := range f.Args {
		if a.Type != nil && a.Type.Kind == "NON_NULL" && a.DefaultValue == nil {
			return true
		}
	}
	return false
}
