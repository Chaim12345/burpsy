package graphqlmap

// Introspection and schema modelling, ported from attacks.dump_schema.
//
// The Python tool carries two documents: a full IntrospectionQuery for GraphQL > 14 and a
// fragment-first form for older servers. Both are kept, because a server that rejects one
// frequently answers the other, and collapsing them to one loses endpoints.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// IntrospectionModern is attacks.dump_schema's graphversion > 14 document.
const IntrospectionModern = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } ` +
	`subscriptionType { name } types { ...FullType } directives { name description locations ` +
	`args { ...InputValue } } } } ` +
	`fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name ` +
	`description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } ` +
	`inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) ` +
	`{ name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } ` +
	`fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } ` +
	`fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ` +
	`ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }`

// IntrospectionLegacy is the fragment-first document for servers that reject the modern one.
const IntrospectionLegacy = `fragment FullType on __Type { kind name description ` +
	`fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } ` +
	`isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } ` +
	`enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } ` +
	`possibleTypes { ...TypeRef } } ` +
	`fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } ` +
	`fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ` +
	`ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } ` +
	`query IntrospectionQuery { __schema { queryType { name } mutationType { name } ` +
	`types { ...FullType } directives { name description locations args { ...InputValue } } } }`

// MinimalIntrospection is the cheapest probe that still proves introspection is on.
const MinimalIntrospection = `{__schema{types{name}}}`

// TypeRef is a possibly-wrapped type reference.
type TypeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *TypeRef `json:"ofType"`
}

// Named unwraps NON_NULL and LIST wrappers to the underlying type name.
func (t *TypeRef) Named() string {
	for cur := t; cur != nil; cur = cur.OfType {
		if cur.Name != "" {
			return cur.Name
		}
	}
	return ""
}

// InputValue is one argument or input field.
type InputValue struct {
	Name         string   `json:"name"`
	Type         *TypeRef `json:"type"`
	DefaultValue *string  `json:"defaultValue"`
}

// Field is one field of a type.
type Field struct {
	Name string       `json:"name"`
	Args []InputValue `json:"args"`
	Type *TypeRef     `json:"type"`
}

// Type is one schema type.
type Type struct {
	Kind        string       `json:"kind"`
	Name        string       `json:"name"`
	Fields      []Field      `json:"fields"`
	InputFields []InputValue `json:"inputFields"`
}

// Schema is the introspected schema.
type Schema struct {
	QueryType        string
	MutationType     string
	SubscriptionType string
	Types            []Type
	// Document records which introspection document the server answered, so a caller can
	// report how the schema was obtained rather than implying one canonical probe.
	Document string
}

// ObjectTypes returns the OBJECT types excluding introspection's own __-prefixed ones, which
// is the set dump_schema prints.
func (s *Schema) ObjectTypes() []Type {
	var out []Type
	for _, t := range s.Types {
		if t.Kind == "OBJECT" && !strings.HasPrefix(t.Name, "__") {
			out = append(out, t)
		}
	}
	return out
}

// FieldNames is the flat list of field and argument names, which the Python tool feeds into
// its autocompleter and which a caller can use as an insertion-point inventory.
func (s *Schema) FieldNames() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(n string) {
		if n == "" {
			return
		}
		if _, dup := seen[n]; dup {
			return
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	for _, t := range s.ObjectTypes() {
		for _, f := range t.Fields {
			add(f.Name)
			for _, a := range f.Args {
				add(a.Name)
			}
		}
	}
	return out
}

// StringArguments returns every field argument whose underlying type is String or ID — the
// arguments worth injecting into, because they accept arbitrary text.
type ArgumentRef struct {
	Type     string
	Field    string
	Argument string
	TypeName string
}

func (s *Schema) StringArguments() []ArgumentRef {
	var out []ArgumentRef
	for _, t := range s.ObjectTypes() {
		for _, f := range t.Fields {
			for _, a := range f.Args {
				name := a.Type.Named()
				switch name {
				case "String", "ID":
					out = append(out, ArgumentRef{Type: t.Name, Field: f.Name, Argument: a.Name, TypeName: name})
				}
			}
		}
	}
	return out
}

// MutationTemplates renders a candidate mutation per mutation field, substituting a literal
// for each argument's scalar type. This is dump_schema's "(?) mutation{...}" suggestion,
// returned instead of printed.
func (s *Schema) MutationTemplates() []string {
	var out []string
	for _, t := range s.ObjectTypes() {
		if !strings.EqualFold(strings.TrimSpace(t.Name), "mutation") &&
			!strings.EqualFold(strings.TrimSpace(t.Name), "mutations") {
			continue
		}
		for _, f := range t.Fields {
			var args []string
			for _, a := range f.Args {
				args = append(args, a.Name+":"+scalarLiteral(a.Type.Named()))
			}
			out = append(out, fmt.Sprintf("mutation{%s(%s){ result }}", f.Name, strings.Join(args, ",")))
		}
	}
	return out
}

// scalarLiteral is the substitution dump_schema performs on the argument type list.
func scalarLiteral(typeName string) string {
	switch typeName {
	case "String", "ID":
		return `"string"`
	case "Boolean":
		return "true"
	case "Int", "Float":
		return "1"
	}
	return `"string"`
}

// Introspect tries the modern document, then the legacy one.
//
// Both are attempted because a server rejecting the modern form often answers the legacy one;
// giving up after the first would report introspection as disabled on a server that has it on.
func (c *Client) Introspect(ctx context.Context) (*Schema, error) {
	var firstErr error
	for _, doc := range []struct{ name, query string }{
		{"modern", IntrospectionModern},
		{"legacy", IntrospectionLegacy},
	} {
		res, err := c.Execute(ctx, doc.query)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		schema, err := ParseSchema(res.Data)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		schema.Document = doc.name
		return schema, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("graphqlmap: no introspection document was answered")
	}
	return nil, firstErr
}

// ParseSchema decodes a __schema payload.
func ParseSchema(data json.RawMessage) (*Schema, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("graphqlmap: introspection returned no data")
	}
	var env struct {
		Schema struct {
			QueryType        *struct{ Name string } `json:"queryType"`
			MutationType     *struct{ Name string } `json:"mutationType"`
			SubscriptionType *struct{ Name string } `json:"subscriptionType"`
			Types            []Type                 `json:"types"`
		} `json:"__schema"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	if len(env.Schema.Types) == 0 {
		return nil, fmt.Errorf("graphqlmap: introspection returned no types")
	}
	s := &Schema{Types: env.Schema.Types}
	if env.Schema.QueryType != nil {
		s.QueryType = env.Schema.QueryType.Name
	}
	if env.Schema.MutationType != nil {
		s.MutationType = env.Schema.MutationType.Name
	}
	if env.Schema.SubscriptionType != nil {
		s.SubscriptionType = env.Schema.SubscriptionType.Name
	}
	return s, nil
}

// IntrospectionEnabled is the cheap check: does the endpoint answer a minimal __schema query.
func (c *Client) IntrospectionEnabled(ctx context.Context) (bool, error) {
	res, err := c.Execute(ctx, MinimalIntrospection)
	if err != nil {
		return false, err
	}
	if res.HasErrors() {
		return false, nil
	}
	s, err := ParseSchema(res.Data)
	return err == nil && s != nil && len(s.Types) > 0, nil
}

// FieldSuggestions extracts the field names a server offers in its error messages when a
// query names an unknown field ("Cannot query field X ... Did you mean Y?"). This is the
// GraphQL Field Suggestions item on the Python tool's TODO list.
func FieldSuggestions(messages []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, msg := range messages {
		i := strings.Index(strings.ToLower(msg), "did you mean")
		if i < 0 {
			continue
		}
		for _, tok := range strings.FieldsFunc(msg[i:], func(r rune) bool {
			return r != '"' && r != '\'' && !isIdentRune(r)
		}) {
			name := strings.Trim(tok, `"' ?.,`)
			if name == "" || strings.EqualFold(name, "did") || strings.EqualFold(name, "you") ||
				strings.EqualFold(name, "mean") || strings.EqualFold(name, "or") {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

func isIdentRune(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// SuggestionProbe is the smallest query that provokes a suggestion: a field that cannot exist.
func SuggestionProbe(unknownField string) string {
	if unknownField == "" {
		unknownField = "bsyNoSuchField"
	}
	return "query{" + unknownField + "}"
}
