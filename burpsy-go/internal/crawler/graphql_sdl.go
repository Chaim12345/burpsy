package crawler

import (
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
)

// graphQLSDLTokenLimit bounds the lexer work on one schema document, the same bound the
// scanner's ingestion gate puts on a query document (graphql_ingest.go). The bounded parse
// path, not gqlparser.LoadSchema: LoadSchema alone parses with no limit, and this input came
// off a target.
const graphQLSDLTokenLimit = 1 << 18

// looksLikeSDLDocument is the sniff half of SDL recognition: the line openings of a schema
// document's root operation types, "type Query {" and friends. Line-anchored so prose that
// mentions the shape ("the type Query { ...") and TypeScript aliases ("type Query = {...")
// do not announce themselves; the validity call belongs to the parser, the same division of
// labour every other sniff branch uses.
func looksLikeSDLDocument(head string) bool {
	for _, line := range strings.Split(head, "\n") {
		l := strings.TrimSpace(strings.ToLower(line))
		for _, root := range []string{"type query", "type mutation", "type subscription"} {
			if strings.HasPrefix(l, root+" {") || strings.HasPrefix(l, root+"{") {
				return true
			}
		}
	}
	return false
}

// parseGraphQLSDL reads a GraphQL schema document - SDL, as servers publish it at
// /schema.graphql and repositories carry it - through the pinned gqlparser, and derives
// operations the way the introspection reader (ParseGraphQLOperations) derives them from a
// result: every object type's fields are operations, types and fields and arguments sorted,
// so a schema and an introspection of that schema admit the same frontier (the parity bar,
// burpsy-react-ui-4xqt.2).
//
// The prelude is prepended exactly as gqlparser.LoadSchema does (validator.Prelude first),
// because a schema document refers to the builtins without declaring them.
func parseGraphQLSDL(body []byte) ([]APIDocEndpoint, string) {
	sd, err := parser.ParseSchemasWithLimit(graphQLSDLTokenLimit, validator.Prelude,
		&ast.Source{Name: "schema", Input: string(body)})
	if err != nil {
		return nil, "the document announced itself as a GraphQL schema and could not be parsed: " + err.Error()
	}
	schema, err := validator.ValidateSchemaDocument(sd)
	if err != nil {
		return nil, "the document announced itself as a GraphQL schema and is not a valid one: " + err.Error()
	}
	var ops []APIDocEndpoint
	for _, typeName := range sortedKeys(schema.Types) {
		def := schema.Types[typeName]
		// Mirror the introspection reader: a SCALAR or ENUM has no fields to request, an
		// INTERFACE or UNION's implementations are OBJECTs reached on their own entries, and
		// the builtins the prelude brought in are not the target's surface.
		if def.BuiltIn || strings.HasPrefix(def.Name, "__") || def.Kind != ast.Object {
			continue
		}
		fields := make([]string, 0, len(def.Fields))
		byName := make(map[string]*ast.FieldDefinition, len(def.Fields))
		for _, f := range def.Fields {
			// __typename and the __-prefixed meta-fields are not operations; every server
			// answers them on any object.
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			fields = append(fields, f.Name)
			byName[f.Name] = f
		}
		sortStringsInPlace(fields)
		for _, fieldName := range fields {
			args := make([]string, 0, len(byName[fieldName].Arguments))
			for _, a := range byName[fieldName].Arguments {
				if a.Name != "" && len(args) < apiDefMaxParams {
					args = append(args, a.Name)
				}
			}
			sortStringsInPlace(args)
			ops = append(ops, APIDocEndpoint{
				Method:      "POST",
				OperationID: typeName + "." + fieldName,
				// The path is the ENDPOINT the document came from, set by the caller: this
				// reader is given the document, not the request.
				Parameters: args,
				Summary:    typeName + " " + fieldName,
			})
			if len(ops) >= graphqlMaxOperations {
				return ops, ""
			}
		}
	}
	return ops, ""
}
